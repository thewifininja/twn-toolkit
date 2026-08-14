from __future__ import annotations

import re
import select
import socket
from typing import Callable


IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

BINARY = 0
ECHO = 1
SUPPRESS_GO_AHEAD = 3
TERMINAL_TYPE = 24
WINDOW_SIZE = 31

TERMINAL_TYPE_IS = 0
TERMINAL_TYPE_SEND = 1

_USERNAME_PROMPT = re.compile(
    r"(?:login|user(?:\s*name)?)\s*[:>]\s*$", re.IGNORECASE
)
_PASSWORD_PROMPT = re.compile(r"password\s*[:>]\s*$", re.IGNORECASE)


class TelnetChannel:
    """Small synchronous Telnet client shaped like an interactive SSH channel."""

    def __init__(
        self,
        connection: socket.socket,
        *,
        username: str,
        password: str,
        width: int,
        height: int,
    ) -> None:
        self.connection = connection
        self.username = username
        self._password = password
        self.width = width
        self.height = height
        self.closed = False
        self._pending = bytearray()
        self._local_options: set[int] = set()
        self._remote_options: set[int] = set()
        self._login_tail = ""
        self._username_sent = False
        self._password_sent = False

    def settimeout(self, timeout: float) -> None:
        self.connection.settimeout(timeout)

    def recv_ready(self) -> bool:
        if self.closed:
            return False
        readable, _writable, _exceptional = select.select(
            [self.connection], [], [], 0
        )
        return bool(readable)

    def recv(self, size: int) -> bytes | None:
        raw = self.connection.recv(size)
        if not raw:
            self.closed = True
            return b""
        visible = self._consume(raw)
        if visible:
            self._answer_login_prompt(visible)
            return visible
        return None

    def exit_status_ready(self) -> bool:
        return self.closed

    def sendall(self, data: bytes) -> None:
        if self.closed:
            raise OSError("Telnet connection is closed")
        normalized = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        normalized = normalized.replace(b"\n", b"\r\n").replace(
            bytes((IAC,)), bytes((IAC, IAC))
        )
        self.connection.sendall(normalized)

    def resize_pty(self, *, width: int, height: int) -> None:
        self.width = width
        self.height = height
        if WINDOW_SIZE in self._local_options:
            self._send_window_size()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._password = ""
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()

    def _consume(self, raw: bytes) -> bytes:
        data = bytes(self._pending) + raw
        self._pending.clear()
        visible = bytearray()
        index = 0
        while index < len(data):
            if data[index] != IAC:
                visible.append(data[index])
                index += 1
                continue
            if index + 1 >= len(data):
                self._pending.extend(data[index:])
                break
            command = data[index + 1]
            if command == IAC:
                visible.append(IAC)
                index += 2
                continue
            if command in {DO, DONT, WILL, WONT}:
                if index + 2 >= len(data):
                    self._pending.extend(data[index:])
                    break
                self._negotiate(command, data[index + 2])
                index += 3
                continue
            if command == SB:
                end = data.find(bytes((IAC, SE)), index + 2)
                if end < 0:
                    self._pending.extend(data[index:])
                    break
                self._subnegotiate(data[index + 2 : end])
                index = end + 2
                continue
            index += 2
        return bytes(visible)

    def _negotiate(self, command: int, option: int) -> None:
        if command == DO:
            supported = option in {BINARY, SUPPRESS_GO_AHEAD, TERMINAL_TYPE, WINDOW_SIZE}
            if supported:
                if option not in self._local_options:
                    self._local_options.add(option)
                    self._send_command(WILL, option)
                    if option == WINDOW_SIZE:
                        self._send_window_size()
            else:
                self._send_command(WONT, option)
            return
        if command == DONT:
            if option in self._local_options:
                self._local_options.discard(option)
                self._send_command(WONT, option)
            return
        if command == WILL:
            supported = option in {BINARY, ECHO, SUPPRESS_GO_AHEAD}
            if supported:
                if option not in self._remote_options:
                    self._remote_options.add(option)
                    self._send_command(DO, option)
            else:
                self._send_command(DONT, option)
            return
        if option in self._remote_options:
            self._remote_options.discard(option)
            self._send_command(DONT, option)

    def _subnegotiate(self, payload: bytes) -> None:
        if (
            len(payload) >= 2
            and payload[0] == TERMINAL_TYPE
            and payload[1] == TERMINAL_TYPE_SEND
            and TERMINAL_TYPE in self._local_options
        ):
            self._send_raw(
                bytes((IAC, SB, TERMINAL_TYPE, TERMINAL_TYPE_IS))
                + b"xterm-256color"
                + bytes((IAC, SE))
            )

    def _answer_login_prompt(self, visible: bytes) -> None:
        text = visible.decode("utf-8", errors="ignore").replace("\x00", "")
        self._login_tail = (self._login_tail + text)[-1024:]
        line = re.split(r"[\r\n]", self._login_tail)[-1]
        if not self._username_sent and self.username and _USERNAME_PROMPT.search(line):
            self._send_credentials(self.username)
            self._username_sent = True
            self._login_tail = ""
            return
        if not self._password_sent and self._password and _PASSWORD_PROMPT.search(line):
            self._send_credentials(self._password)
            self._password = ""
            self._password_sent = True
            self._login_tail = ""

    def _send_credentials(self, value: str) -> None:
        encoded = value.encode("utf-8").replace(
            bytes((IAC,)), bytes((IAC, IAC))
        )
        self._send_raw(encoded + b"\r\n")

    def _send_command(self, command: int, option: int) -> None:
        self._send_raw(bytes((IAC, command, option)))

    def _send_window_size(self) -> None:
        payload = self.width.to_bytes(2, "big") + self.height.to_bytes(2, "big")
        payload = payload.replace(bytes((IAC,)), bytes((IAC, IAC)))
        self._send_raw(bytes((IAC, SB, WINDOW_SIZE)) + payload + bytes((IAC, SE)))

    def _send_raw(self, data: bytes) -> None:
        if self.closed:
            raise OSError("Telnet connection is closed")
        self.connection.sendall(data)


def open_telnet_channel(
    *,
    hostname: str,
    port: int,
    username: str,
    password: str,
    width: int,
    height: int,
    timeout: float = 15,
    socket_factory: Callable[..., socket.socket] = socket.create_connection,
) -> TelnetChannel:
    connection = socket_factory((hostname, port), timeout=timeout)
    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    connection.settimeout(0.25)
    return TelnetChannel(
        connection,
        username=username,
        password=password,
        width=width,
        height=height,
    )


__all__ = ["TelnetChannel", "open_telnet_channel"]
