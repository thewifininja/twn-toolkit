"""WSGI terminal upgrades using wsproto, with no concurrent TLS socket access."""
from functools import wraps
import json
import struct

from flask import Response, request
from wsproto import ConnectionType
from wsproto.events import AcceptConnection, CloseConnection, TextMessage, BytesMessage, Ping, Pong
from wsproto.handshake import H11Handshake
from wsproto.utilities import ProtocolError

from .terminal_socket_pump import pump
from .terminal_stream import MAX_FRAME, MAX_INPUT_FRAME, close_socket


class TerminalWebSocket:
    def __init__(self):
        self.socket = request.environ.get('gunicorn.socket') or request.environ.get('werkzeug.socket')
        if self.socket is None:
            raise ValueError('This web server does not support terminal upgrades.')
        self.closed = False
        handshake = H11Handshake(ConnectionType.SERVER)
        handshake.initiate_upgrade_connection(
            [(name.encode('latin-1'), value.encode('latin-1')) for name, value in request.headers],
            request.full_path,
        )
        list(handshake.events())
        self.socket.settimeout(10)
        self.socket.sendall(handshake.send(AcceptConnection()))
        self.protocol = handshake.connection

    def close(self, reason=1000):
        if self.closed:
            return
        self.closed = True
        try:
            self.socket.settimeout(2)
            self.socket.sendall(self.protocol.send(CloseConnection(code=reason)))
        except (OSError, ProtocolError):
            pass
        finally:
            close_socket(self.socket)

    def run(self, owner, authorized):
        fragments = []
        fragment_bytes = 0
        owner_buffer = bytearray()
        pong_received = True
        self.socket.sendall(self.protocol.send(TextMessage(data='{"type":"ready"}')))

        def consume(source, data, queue):
            nonlocal fragment_bytes, pong_received
            if source is self.socket:
                self.protocol.receive_data(data)
                for event in self.protocol.events():
                    if isinstance(event, CloseConnection):
                        raise EOFError('Viewer disconnected.')
                    if isinstance(event, Ping):
                        queue(self.socket, self.protocol.send(event.response()))
                    elif isinstance(event, Pong):
                        pong_received = True
                    elif isinstance(event, BytesMessage):
                        raise ValueError('Terminal input must be text.')
                    elif isinstance(event, TextMessage):
                        fragment_bytes += len(event.data.encode())
                        if fragment_bytes > MAX_INPUT_FRAME:
                            raise ValueError('Terminal input is too large.')
                        fragments.append(event.data)
                        if not event.message_finished:
                            continue
                        text = ''.join(fragments)
                        fragments.clear()
                        fragment_bytes = 0
                        value = json.loads(text)
                        if not isinstance(value, dict) or value.get('type') != 'input':
                            raise ValueError('Invalid terminal input.')
                        encoded = text.encode()
                        queue(owner, struct.pack('!I', len(encoded)) + encoded)
            else:
                owner_buffer.extend(data)
                while len(owner_buffer) >= 4:
                    size = struct.unpack('!I', owner_buffer[:4])[0]
                    if not 0 < size <= MAX_FRAME:
                        raise ValueError('Terminal output frame is too large.')
                    if len(owner_buffer) < size + 4:
                        break
                    raw = bytes(owner_buffer[4:size+4])
                    del owner_buffer[:size+4]
                    # Validate before exposing output from the authenticated relay.
                    if not isinstance(json.loads(raw), dict):
                        raise ValueError('Invalid terminal output.')
                    queue(self.socket, self.protocol.send(TextMessage(data=raw.decode())))

        def keepalive(queue):
            nonlocal pong_received
            if not pong_received:
                raise EOFError('Viewer keepalive expired.')
            pong_received = False
            queue(self.socket, self.protocol.send(Ping(payload=b'twn')))

        try:
            pump(self.socket, owner, consume, authorized=authorized, tick=keepalive)
        except ProtocolError:
            pass
        finally:
            self.closed = True  # pump has closed both sockets in its owning thread.


def websocket_route(app, path):
    """Register an authenticated Flask route whose response upgrades the socket."""
    def decorate(function):
        @wraps(function)
        def upgraded(*args, **kwargs):
            websocket = TerminalWebSocket()
            try:
                function(websocket, *args, **kwargs)
            finally:
                websocket.close()

            class UpgradedResponse(Response):
                def __call__(self, environ, start_response):
                    if 'gunicorn.socket' in environ:
                        raise StopIteration()
                    return super().__call__(environ, start_response)
            return UpgradedResponse()
        app.route(path, websocket=True)(upgraded)
        return upgraded
    return decorate
