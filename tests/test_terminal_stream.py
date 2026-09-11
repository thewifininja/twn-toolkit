import socket
import socketserver
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.distributed_terminal import attachment_ticket, attach_terminal, relay_path, relay
from twn_toolkit.distributed_transport import EnrollmentClient, EnrollmentServer
from twn_toolkit.investigations import InvestigationStore
from twn_toolkit.remote_sessions import RemoteSessionManager, RemoteSessionStore
from twn_toolkit.terminal_stream import open_owner_stream, receive_frame, send_frame, close_socket
from test_remote_sessions import wait_for_state


def test_streams_preserve_poll_allowance_and_listener_control_reserve():
    from twn_toolkit.distributed_polling import LongPollBudget
    budget = LongPollBudget(3, 2)
    with budget.slot('agent') as regular, budget.slot('agent') as interactive:
        assert regular and interactive
        with budget.slot('agent', channel='terminal', per_agent=8) as terminal:
            assert terminal
            with budget.slot('other') as overflow:
                assert not overflow
            assert budget.stats()['agents'] == 1
        assert budget.stats()['active'] == 2
    assert budget.stats()['active'] == 0


def test_relay_drains_last_output_before_end_of_stream():
    source, left = socket.socketpair()
    right, destination = socket.socketpair()
    destination.settimeout(3)
    data = b'final-output-' * 40000
    with ThreadPoolExecutor(max_workers=2) as workers:
        pumping = workers.submit(relay, left, right)
        def send():
            source.sendall(data)
            source.shutdown(socket.SHUT_WR)
        sending = workers.submit(send)
        received = bytearray()
        while True:
            chunk = destination.recv(65536)
            if not chunk:
                break
            received.extend(chunk)
        sending.result(timeout=3)
        pumping.result(timeout=3)
    source.close()
    destination.close()
    assert received == data


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b'ready> ')
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


@pytest.fixture
def echo_session(tmp_path):
    server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    store = RemoteSessionStore(str(tmp_path / 'agent'))
    manager = RemoteSessionManager(store, InvestigationStore(str(tmp_path / 'agent')))
    session = manager.start_session(user_id='viewer', username='Viewer', title='Echo', protocol='telnet',
                                    host='127.0.0.1', port=server.server_address[1], remote_username='', password='',
                                    record_transcript=False, allow_unknown_hosts=False, allow_legacy_algorithms=False)
    wait_for_state(store, session['id'], 'running')
    try:
        yield manager, session
    finally:
        manager.stop_session(session['id'], user_id='viewer')
        manager.close()
        server.shutdown()
        server.server_close()


def next_output(connection, text):
    result = ''
    for _ in range(8):
        frame = receive_frame(connection)
        if frame['type'] == 'output':
            result += ''.join(chunk['output'] for chunk in frame['chunks'])
            if text in result:
                return frame
    raise AssertionError(f'No expected output: {text}')


def test_owner_stream_input_output_detach_and_replay(echo_session):
    manager, session = echo_session
    connection = open_owner_stream(manager, session['id'], 'viewer', 0)
    first = next_output(connection, 'ready> ')
    assert not any(key.startswith('_') for key in first['session'])
    send_frame(connection, {'type': 'input', 'sequence': 1, 'data': 'hello'})
    next_output(connection, 'hello')
    close_socket(connection)
    assert manager.store.get_session(session['id'])['state'] == 'running'
    replay = open_owner_stream(manager, session['id'], 'viewer', first['next_cursor'])
    next_output(replay, 'hello')
    close_socket(replay)


def test_owner_stream_rejects_another_user(echo_session):
    manager, session = echo_session
    with pytest.raises(ValueError):
        open_owner_stream(manager, session['id'], 'other-user', 0)


def test_multiple_viewers_and_duplicate_input_sequence(echo_session):
    manager, session = echo_session
    first = open_owner_stream(manager, session['id'], 'viewer', 0)
    second = open_owner_stream(manager, session['id'], 'viewer', 0)
    next_output(first, 'ready> ')
    next_output(second, 'ready> ')
    send_frame(first, {'type': 'input', 'sequence': 1, 'data': 'once'})
    page = next_output(first, 'once')
    next_output(second, 'once')
    send_frame(first, {'type': 'input', 'sequence': 1, 'data': 'duplicate'})
    with pytest.raises((EOFError, OSError)):
        while True:
            receive_frame(first)
    send_frame(second, {'type': 'input', 'sequence': 1, 'data': 'next'})
    page = next_output(second, 'next')
    replay = manager.store.output_page(session['id'], user_id='viewer')
    assert 'duplicate' not in ''.join(chunk['output'] for chunk in replay['chunks'])
    close_socket(first)
    close_socket(second)


def test_cross_origin_websocket_is_rejected_before_upgrade(tmp_path):
    from twn_toolkit.app import create_app
    app = create_app(str(tmp_path))
    app.testing = True
    response = app.test_client().get('/tools/remote-terminal/sessions/nope/stream',
                                     headers={'Upgrade': 'websocket', 'Origin': 'https://other.example'})
    assert response.status_code == 403


def test_delegated_stream_url_stays_relative(tmp_path):
    from twn_toolkit.app import create_app
    from twn_toolkit.remote_sessions import public_remote_session
    app = create_app(str(tmp_path))
    with app.test_request_context(environ_overrides={'SCRIPT_NAME': '/agents/test/ui'}):
        result = public_remote_session({'id': 'fixture'})
    assert result['stream_url'] == '/agents/test/ui/tools/remote-terminal/sessions/fixture/stream'


def test_owner_wait_has_no_output_queries_when_idle(echo_session, monkeypatch):
    import time
    manager, session = echo_session
    connection = open_owner_stream(manager, session['id'], 'viewer', 0)
    next_output(connection, 'ready> ')
    time.sleep(.1)
    queries = []
    original = manager.store.output_page
    monkeypatch.setattr(manager.store, 'output_page', lambda *a, **k: (queries.append(1), original(*a, **k))[1])
    time.sleep(.3)
    assert queries == []
    close_socket(connection)


def test_mtls_outbound_relay_and_single_use_ticket(tmp_path, echo_session):
    manager, session = echo_session
    instance = manager.store.instance_path
    server = EnrollmentServer(tmp_path / 'hub', '127.0.0.1', 0)
    server.start()
    server.enrollment_window.open(5)
    settings = DistributedSettingsStore(instance)
    settings.save({**settings.get(), 'role': 'agent', 'agent_mainframe_url': f'https://127.0.0.1:{server.port}'})
    client = EnrollmentClient(instance, f'https://127.0.0.1:{server.port}')
    try:
        client.begin('Loopback')
        agent = server.agent_store.list('pending')[0]
        server.agent_store.set_state(agent['id'], 'approved')
        client.poll()
        for attempt in range(8):
            with attachment_ticket(server.instance_path) as (ticket, listener):
                attach_terminal(instance, {'ticket': ticket, 'user_id': 'viewer', 'session_id': session['id'], 'after': 0})
                connection, _ = listener.accept()
                connection.settimeout(3)
                assert receive_frame(connection) == {'agent_id': agent['id']}
                send_frame(connection, {'type': 'ready'})
                next_output(connection, 'ready> ')
                send_frame(connection, {'type': 'input', 'sequence': 1, 'data': f'tunneled-{attempt}'})
                next_output(connection, f'tunneled-{attempt}')
                if attempt == 7:
                    server.agent_store.set_state(agent['id'], 'revoked')
                    send_frame(connection, {'type': 'input', 'sequence': 2, 'data': 'revoked-input'})
                    with pytest.raises((EOFError, ConnectionResetError)):
                        while True:
                            receive_frame(connection)
                close_socket(connection)
            assert not relay_path(server.instance_path, ticket).exists()
            assert manager.store.get_session(session['id'])['state'] == 'running'
            with manager.store._connect() as db:
                assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            replay = manager.store.output_page(session['id'], user_id='viewer')
            assert 'revoked-input' not in ''.join(chunk['output'] for chunk in replay['chunks'])

    finally:
        server.stop()


@pytest.mark.parametrize('ticket', ['../bad', '', None, '0'*200])
def test_invalid_ticket_cannot_select_an_ipc_path(tmp_path, ticket):
    with pytest.raises(ValueError):
        relay_path(tmp_path, ticket)
