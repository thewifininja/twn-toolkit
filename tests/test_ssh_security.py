from __future__ import annotations

import errno
import os
import unittest
from unittest.mock import MagicMock, patch

from twn_toolkit.ssh_security import (
    close_ssh_client,
    disabled_ssh_algorithms,
    format_ssh_connection_error,
    open_ssh_client,
)


class SSHSecurityTests(unittest.TestCase):
    def test_sha1_rsa_is_disabled_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                disabled_ssh_algorithms(),
                {"keys": ["ssh-rsa"], "pubkeys": ["ssh-rsa"]},
            )

    def test_explicit_environment_override_allows_legacy_appliances(self) -> None:
        with patch.dict(os.environ, {"TWN_ALLOW_LEGACY_SSH_RSA": "true"}):
            self.assertIsNone(disabled_ssh_algorithms())

    def test_scoped_override_allows_legacy_appliances(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(
                disabled_ssh_algorithms(allow_legacy_algorithms=True)
            )

    def test_macos_local_network_denial_is_unwrapped_from_paramiko_shape(self) -> None:
        class WrappedConnectionError(Exception):
            def __init__(self) -> None:
                super().__init__("Unable to connect to port 22")
                self.errors = {
                    ("192.0.2.10", 22): OSError(
                        errno.EHOSTUNREACH, "No route to host"
                    )
                }

        with patch("twn_toolkit.ssh_security.platform.system", return_value="Darwin"):
            message = format_ssh_connection_error(WrappedConnectionError())

        self.assertIn("macOS may be blocking local-network access", message)
        self.assertIn("toolkit TCP Port Scanner", message)
        self.assertIn("Terminal connection does not test the same", message)

    def test_non_macos_unreachable_error_keeps_generic_message(self) -> None:
        error = OSError(errno.EHOSTUNREACH, "No route to host")
        with patch("twn_toolkit.ssh_security.platform.system", return_value="Linux"):
            message = format_ssh_connection_error(error)
        self.assertEqual(
            message,
            f"OSError: [Errno {errno.EHOSTUNREACH}] No route to host",
        )

    def test_banner_failure_closes_inactive_socket_and_retries_once(self) -> None:
        first = MagicMock()
        first.connect.side_effect = Exception("Error reading SSH protocol banner")
        first_transport = first.get_transport.return_value
        second = MagicMock()
        with patch("paramiko.SSHClient", side_effect=[first, second]), patch(
            "twn_toolkit.ssh_security.time.sleep"
        ) as sleep:
            connected = open_ssh_client(
                hostname="192.0.2.10",
                port=22,
                username="admin",
                password="secret",
                allow_unknown_hosts=True,
                connect_timeout=8,
                auth_timeout=8,
            )

        self.assertIs(connected, second)
        first.close.assert_called_once_with()
        first_transport.sock.close.assert_called_once_with()
        sleep.assert_called_once_with(0.25)
        self.assertEqual(second.connect.call_args.kwargs["banner_timeout"], 15)

    def test_non_banner_failure_is_not_retried(self) -> None:
        client = MagicMock()
        client.connect.side_effect = OSError("offline")
        with patch("paramiko.SSHClient", return_value=client) as factory, self.assertRaises(
            OSError
        ):
            open_ssh_client(
                hostname="192.0.2.10",
                port=22,
                username="admin",
                password="secret",
                allow_unknown_hosts=False,
            )
        factory.assert_called_once_with()

    def test_close_ssh_client_closes_inactive_transport_socket(self) -> None:
        client = MagicMock()
        transport = client.get_transport.return_value
        close_ssh_client(client)
        client.close.assert_called_once_with()
        transport.sock.close.assert_called_once_with()

    def test_close_ssh_client_does_not_mask_connection_error(self) -> None:
        client = MagicMock()
        transport = client.get_transport.return_value
        client.close.side_effect = RuntimeError("cleanup failed")
        close_ssh_client(client)
        transport.sock.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
