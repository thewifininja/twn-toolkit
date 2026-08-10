from __future__ import annotations

import array
import errno
import os
import socket
import struct
import unittest
from unittest import mock

from twn_toolkit.macos_network_broker import (
    BROKER_ENVIRONMENT,
    BrokeredSocket,
    _broker_candidate,
    _recv_descriptor,
    request_connected_descriptor,
)


class MacosNetworkBrokerClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_path = os.environ.get(BROKER_ENVIRONMENT)

    def tearDown(self) -> None:
        if self.previous_path is None:
            os.environ.pop(BROKER_ENVIRONMENT, None)
        else:
            os.environ[BROKER_ENVIRONMENT] = self.previous_path

    def test_socket_create_connection_receives_brokered_descriptor(self) -> None:
        os.environ[BROKER_ENVIRONMENT] = "/var/run/example.sock"
        broker_end, peer_end = socket.socketpair()
        handed_off = os.dup(broker_end.fileno())
        with (
            mock.patch.object(socket, "socket", BrokeredSocket),
            mock.patch(
                "twn_toolkit.macos_network_broker.request_connected_descriptor",
                return_value=handed_off,
            ) as request,
        ):
            connection = socket.create_connection(("192.0.2.10", 443), timeout=2)
        broker_end.close()
        try:
            self.assertEqual(connection.fileno(), handed_off)
            connection.sendall(b"hello")
            self.assertEqual(peer_end.recv(5), b"hello")
            peer_end.sendall(b"world")
            self.assertEqual(connection.recv(5), b"world")
        finally:
            connection.close()
            peer_end.close()

        request.assert_called_once_with(
            "/var/run/example.sock",
            "192.0.2.10",
            443,
            family_code=4,
            timeout=2.0,
        )

    def test_socket_create_connection_adopts_brokered_tcp_descriptor(self) -> None:
        os.environ[BROKER_ENVIRONMENT] = "/var/run/example.sock"
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
        except PermissionError as exc:
            listener.close()
            self.skipTest(f"loopback bind unavailable: {exc}")
        listener.listen(1)
        broker_end = socket.create_connection(listener.getsockname())
        peer_end, _address = listener.accept()
        listener.close()

        def hand_off_descriptor(*_args: object, **_kwargs: object) -> int:
            sender, receiver = socket.socketpair()
            descriptors = array.array("i", [broker_end.fileno()])
            sender.sendmsg(
                [struct.pack("!I", 0)],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)],
            )
            handed_off = _recv_descriptor(receiver)
            sender.close()
            receiver.close()
            broker_end.close()
            return handed_off

        with (
            mock.patch.object(socket, "socket", BrokeredSocket),
            mock.patch(
                "twn_toolkit.macos_network_broker.request_connected_descriptor",
                side_effect=hand_off_descriptor,
            ),
        ):
            connection = socket.create_connection(("192.0.2.10", 22), timeout=2)
        try:
            peer_end.sendall(b"SSH-2.0-test\r\n")
            self.assertEqual(connection.recv(16), b"SSH-2.0-test\r\n")
        finally:
            connection.close()
            peer_end.close()

    def test_protocol_request_is_bounded_and_network_ordered(self) -> None:
        channel = mock.Mock()
        channel.recvmsg.return_value = (
            struct.pack("!I", errno.EHOSTUNREACH),
            [],
            0,
            None,
        )
        with (
            mock.patch(
                "twn_toolkit.macos_network_broker._ORIGINAL_SOCKET",
                return_value=channel,
            ),
            self.assertRaises(OSError) as raised,
        ):
            request_connected_descriptor(
                "/var/run/example.sock",
                "192.0.2.10",
                443,
                family_code=4,
                timeout=2,
            )
        self.assertEqual(raised.exception.errno, errno.EHOSTUNREACH)
        request = channel.sendall.call_args.args[0]
        self.assertEqual(request[:4], b"TWNB")
        self.assertEqual(request[4:8], bytes((1, 4, 1, 0)))
        self.assertEqual(struct.unpack("!H", request[12:14])[0], 443)
        host_length = struct.unpack("!H", request[14:16])[0]
        self.assertEqual(request[16 : 16 + host_length], b"192.0.2.10")
        channel.connect.assert_called_once_with("/var/run/example.sock")
        channel.close.assert_called_once()

    def test_descriptor_response_returns_a_noninheritable_socket(self) -> None:
        sender, receiver = socket.socketpair()
        first, first_peer = socket.socketpair()
        descriptors = array.array("i", [first.fileno()])
        sender.sendmsg(
            [struct.pack("!I", 0)],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)],
        )
        received = _recv_descriptor(receiver)
        try:
            self.assertFalse(os.get_inheritable(received))
            os.write(received, b"ok")
            self.assertEqual(first_peer.recv(2), b"ok")
        finally:
            os.close(received)
            sender.close()
            receiver.close()
            first.close()
            first_peer.close()

    def test_broker_errno_is_returned_by_connect_ex(self) -> None:
        os.environ[BROKER_ENVIRONMENT] = "/var/run/example.sock"
        connection = BrokeredSocket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(2)
        try:
            with mock.patch(
                "twn_toolkit.macos_network_broker.request_connected_descriptor",
                side_effect=OSError(errno.EHOSTUNREACH, "No route to host"),
            ):
                self.assertEqual(
                    connection.connect_ex(("192.0.2.11", 22)),
                    errno.EHOSTUNREACH,
                )
        finally:
            connection.close()

    def test_loopback_and_nonblocking_sockets_bypass_broker(self) -> None:
        os.environ[BROKER_ENVIRONMENT] = "/var/run/example.sock"
        self.assertIsNone(
            _broker_candidate(
                socket.AF_INET,
                socket.SOCK_STREAM,
                ("127.0.0.1", 5050),
                1.0,
            )
        )
        self.assertIsNone(
            _broker_candidate(
                socket.AF_INET6,
                socket.SOCK_STREAM,
                ("::1", 5050, 0, 0),
                1.0,
            )
        )
        self.assertIsNone(
            _broker_candidate(
                socket.AF_INET,
                socket.SOCK_STREAM,
                ("192.168.1.1", 22),
                0.0,
            )
        )


if __name__ == "__main__":
    unittest.main()
