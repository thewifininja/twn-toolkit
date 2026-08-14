from __future__ import annotations

import unittest
from collections import deque

from twn_toolkit.telnet_client import (
    DO,
    ECHO,
    IAC,
    SB,
    SE,
    TERMINAL_TYPE,
    TERMINAL_TYPE_IS,
    TERMINAL_TYPE_SEND,
    WILL,
    WINDOW_SIZE,
    TelnetChannel,
)


class FakeSocket:
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = deque(chunks)
        self.sent: list[bytes] = []
        self.timeout = 0.0
        self.closed = False

    def recv(self, _size: int) -> bytes:
        return self.chunks.popleft() if self.chunks else b""

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def shutdown(self, _how: int) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class TelnetChannelTests(unittest.TestCase):
    def channel(self, *chunks: bytes) -> tuple[TelnetChannel, FakeSocket]:
        connection = FakeSocket(*chunks)
        return (
            TelnetChannel(
                connection,  # type: ignore[arg-type]
                width=100,
                height=32,
            ),
            connection,
        )

    def test_negotiates_options_without_guessing_login_prompts(self) -> None:
        channel, connection = self.channel(
            bytes((IAC, WILL, ECHO, IAC, DO, WINDOW_SIZE)) + b"Username: ",
            b"Password: ",
        )

        self.assertEqual(channel.recv(4096), b"Username: ")
        self.assertIn(bytes((IAC, DO, ECHO)), connection.sent)
        self.assertIn(bytes((IAC, WILL, WINDOW_SIZE)), connection.sent)
        self.assertNotIn(b"netadmin\r\n", connection.sent)

        self.assertEqual(channel.recv(4096), b"Password: ")
        self.assertNotIn(b"cleartext-secret\r\n", connection.sent)

    def test_terminal_type_and_resize_subnegotiation(self) -> None:
        channel, connection = self.channel(
            bytes((IAC, DO, TERMINAL_TYPE)),
            bytes((IAC, SB, TERMINAL_TYPE, TERMINAL_TYPE_SEND, IAC, SE)),
            bytes((IAC, DO, WINDOW_SIZE)),
        )

        self.assertIsNone(channel.recv(4096))
        self.assertIsNone(channel.recv(4096))
        self.assertIn(
            bytes((IAC, SB, TERMINAL_TYPE, TERMINAL_TYPE_IS))
            + b"xterm-256color"
            + bytes((IAC, SE)),
            connection.sent,
        )
        self.assertIsNone(channel.recv(4096))
        channel.resize_pty(width=120, height=40)
        expected_size = bytes((0, 120, 0, 40))
        self.assertTrue(
            any(
                item.startswith(bytes((IAC, SB, WINDOW_SIZE)))
                and expected_size in item
                for item in connection.sent
            )
        )

    def test_user_input_uses_network_newlines_and_escapes_iac(self) -> None:
        channel, connection = self.channel()

        channel.sendall(b"show clock\rnext\n" + bytes((IAC,)))

        self.assertEqual(
            connection.sent[-1],
            b"show clock\r\nnext\r\n" + bytes((IAC, IAC)),
        )

    def test_close_clears_and_closes_connection(self) -> None:
        channel, connection = self.channel()

        channel.close()

        self.assertTrue(channel.closed)
        self.assertTrue(connection.closed)
        self.assertEqual(channel.exit_status_ready(), True)


if __name__ == "__main__":
    unittest.main()
