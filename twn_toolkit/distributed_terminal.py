"""Ephemeral terminal relays over the existing authenticated outbound listener.

Only attachment uses the job queue. Keystrokes and output never become jobs.
Each ticket is random, single-viewer, tied to an approved Agent, and exists only
while its Mainframe web worker is waiting for that Agent.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from .terminal_stream import close_socket, receive_frame, send_frame, open_owner_stream

CAPABILITY = ("system.terminal.stream", "1")
_agent_viewers = threading.BoundedSemaphore(8)


def relay_path(instance, token):
    if not isinstance(token, str) or not re.fullmatch(r"[a-f0-9]{48}", token):
        raise ValueError("Invalid terminal attachment ticket.")
    digest = hashlib.sha256(str(Path(instance).resolve()).encode()).hexdigest()[:12]
    root = Path('/tmp') / ('twn-ts-' + digest)
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("Terminal relay directory is not privately owned.")
    os.chmod(root, 0o700)
    return root / (token + '.sock')


@contextmanager
def attachment_ticket(instance):
    token = secrets.token_hex(24)
    path = relay_path(instance, token)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(1)
        listener.settimeout(20)
        yield token, listener
    finally:
        listener.close()
        path.unlink(missing_ok=True)


def relay(left, right, authorized=lambda: True):
    from .terminal_socket_pump import pump
    pump(left, right, lambda source, data, queue: queue(right if source is left else left, data),
         authorized=authorized, limit=256 * 1024)


def accept_agent_attachment(server, handler, payload):
    agent_id = server._approved_certificate_agent(handler.connection.getpeercert(binary_form=True))
    # Share the listener's total/control reserve, without consuming the Agent's
    # ordinary job-poll allowance (which would force idle reconnect chatter).
    with server.poll_budget.slot(agent_id, channel="terminal", per_agent=8) as admitted:
        if not admitted:
            raise ValueError("Terminal relay capacity is busy.")
        path = relay_path(server.instance_path, payload.get('ticket'))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as local:
            local.settimeout(10)
            local.connect(str(path))
            send_frame(local, {'agent_id': agent_id})
            if receive_frame(local).get('type') != 'ready':
                raise ValueError('Terminal attachment was rejected.')
            handler.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            handler.send_response(101)
            handler.send_header('Connection', 'Upgrade')
            handler.send_header('Upgrade', 'twn-terminal-v1')
            handler.end_headers()
            handler.wfile.flush()
            handler.close_connection = True
            def authorized():
                agent = server.agent_store.get(agent_id)
                return not server._stopping.is_set() and agent and agent['state'] == 'approved'
            relay(handler.connection, local, authorized)


def _connect_mainframe(instance, token):
    from .distributed_agents import DistributedSettingsStore
    from .distributed_transport import EnrollmentClient
    settings = DistributedSettingsStore(instance).get()
    if settings['role'] != 'agent':
        raise ValueError('Terminal attachment requires Agent mode.')
    client = EnrollmentClient(instance, settings['agent_mainframe_url'], settings['agent_mainframe_fallback_url'])
    context = ssl.create_default_context(cafile=str(client.ca_path))
    context.load_cert_chain(str(client.certificate_path), str(client.identity_store.path))
    for address in client.mainframe_urls:
        parsed = urlsplit(address)
        connection = None
        raw = None
        try:
            raw = socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection = context.wrap_socket(raw, server_hostname=parsed.hostname)
            data = json.dumps({'ticket': token}).encode()
            header = (f'POST /v1/terminal/connect HTTP/1.1\r\nHost: {parsed.netloc}\r\n'
                      f'Content-Type: application/json\r\nContent-Length: {len(data)}\r\n'
                      'Connection: Upgrade\r\nUpgrade: twn-terminal-v1\r\n\r\n').encode()
            connection.sendall(header + data)
            response = bytearray()
            while not response.endswith(b'\r\n\r\n') and len(response) < 16384:
                chunk = connection.recv(1)
                if not chunk:
                    raise OSError('Terminal attachment closed.')
                response.extend(chunk)
            if not bytes(response).split(b'\r\n', 1)[0].split()[1:2] == [b'101']:
                raise OSError('Terminal attachment rejected.')
            return connection
        except (OSError, ValueError):
            if connection:
                connection.close()
            elif raw:
                raw.close()
    raise ValueError('Could not attach the terminal to the Mainframe.')


def attach_terminal(instance, inputs):
    from .remote_sessions import RemoteSessionStore
    token = inputs.get('ticket')
    relay_path(instance, token)  # Validate before starting any background work.
    user_id, session_id, after = inputs.get('user_id'), inputs.get('session_id'), inputs.get('after')
    if not isinstance(user_id, str) or not user_id or not isinstance(session_id, str) or not session_id:
        raise ValueError('Invalid terminal attachment identity.')
    if type(after) is not int or after < 0:
        raise ValueError('Invalid terminal attachment cursor.')
    if not _agent_viewers.acquire(blocking=False):
        raise ValueError('Terminal viewer capacity reached.')
    try:
        owner = open_owner_stream(RemoteSessionStore(str(instance)), session_id, user_id, after)
    except Exception:
        _agent_viewers.release()
        raise

    def connected():
        remote = None
        try:
            remote = _connect_mainframe(instance, token)
            relay(owner, remote)
        except (OSError, ValueError):
            pass  # Browser falls back/reconnects; input is never retried.
        finally:
            close_socket(owner)
            if remote:
                close_socket(remote)
            _agent_viewers.release()
    try:
        threading.Thread(target=connected, daemon=True, name='terminal-outbound').start()
    except Exception:
        close_socket(owner)
        _agent_viewers.release()
        raise
    return {'attachment_started': True}
