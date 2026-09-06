"""Exercise actual sockets and child processes rather than yielding mock chunks."""
import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from twn_toolkit.diagnostic_tools import MAX_API_RESPONSE, send_api_request
from twn_toolkit.network_tools import ToolInputError


@pytest.fixture
def endpoint():
    seen = []
    finished = threading.Event()
    stop = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.do_GET()

        def do_GET(self):
            seen.append((self.command, self.path))
            try:
                if self.path == '/headers':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                    while not stop.wait(.05):
                        self.connection.sendall(b'x')
                else:
                    self.send_response(200)
                    data = b'x' * (MAX_API_RESPONSE + 1) if self.path == '/large' else b'OK'
                    self.send_header('Content-Length', '10000' if self.path == '/body' else str(len(data)))
                    self.end_headers()
                    if self.path == '/body':
                        while not stop.wait(.05):
                            self.wfile.write(b'x')
                            self.wfile.flush()
                    else:
                        self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                finished.set()

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', seen, finished
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize('path', ['/headers', '/body'])
def test_trickle_is_interrupted_and_post_is_not_retried(endpoint, path, monkeypatch):
    base, seen, finished = endpoint
    children = []
    original = subprocess.Popen

    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, 'Popen', launch)
    started = time.monotonic()
    with pytest.raises(ToolInputError, match='may have executed'):
        send_api_request('POST', base + path, body='one operation', timeout=1)
    assert time.monotonic() - started < 3
    assert seen == [('POST', path)]
    assert children[0].poll() is not None
    assert children[0].stdout.closed
    assert finished.wait(2), 'timed-out socket remained open'
    assert send_api_request('GET', base + '/ok', timeout=3)['body'] == 'OK'


def test_response_cap_and_source_checkout_with_other_cwd(endpoint, monkeypatch, tmp_path):
    base, _, _ = endpoint
    monkeypatch.chdir(tmp_path)
    response = send_api_request('GET', base + '/large', timeout=3)
    assert response['truncated']
    assert response['bytes'] == MAX_API_RESPONSE
    assert len(response['body']) == MAX_API_RESPONSE


def test_stalled_system_resolver_is_killed_and_reaped(monkeypatch):
    original = subprocess.Popen
    children = []

    def launch(args, **kwargs):
        # Fault injection in the real child; production exposes no test mode.
        code = ('import socket,time; socket.getaddrinfo=lambda *a,**k: time.sleep(60); '
                'from twn_toolkit.api_request_worker import main; main()')
        child = original([args[0], '-c', code], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, 'Popen', launch)
    started = time.monotonic()
    with pytest.raises(ToolInputError, match='deadline exceeded'):
        send_api_request('GET', 'http://resolver.example/', timeout=1)
    assert time.monotonic() - started < 3
    assert children[0].poll() is not None


def test_child_deadline_without_caller_timeout():
    root = str(Path(__file__).resolve().parents[1])
    code = ('import socket,time; socket.getaddrinfo=lambda *a,**k: time.sleep(60); '
            'from twn_toolkit.api_request_worker import main; main()')
    import os
    with subprocess.Popen([sys.executable, '-c', code], cwd=root,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as child:
        payload = {'parent': os.getpid(), 'deadline': time.monotonic() + 1,
                   'request': {'method': 'GET', 'url': 'http://resolver.example/'}}
        child.communicate(json.dumps(payload).encode(), timeout=3)
        assert child.returncode == 124


def test_invalid_request_never_starts_a_child(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('invalid input spawned a child')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    for url, timeout in [('http://example.test:bad/', 1), ('http://example.test/', float('nan'))]:
        with pytest.raises(ToolInputError):
            send_api_request('GET', url, timeout=timeout)


def test_child_exits_when_original_parent_is_gone():
    root = str(Path(__file__).resolve().parents[1])
    with subprocess.Popen([sys.executable, '-m', 'twn_toolkit.api_request_worker'], cwd=root,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as child:
        # PID zero cannot be this child's parent; no request should be sent.
        payload = {'parent': 0, 'deadline': time.monotonic() + 30,
                   'request': {'method': 'GET', 'url': 'http://127.0.0.1:1/'}}
        child.communicate(json.dumps(payload).encode(), timeout=3)
        assert child.returncode == 124
