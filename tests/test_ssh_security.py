from __future__ import annotations

import errno
import base64
import hashlib
import hmac
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from twn_toolkit.ssh_security import (
    SSHKnownHostsError,
    close_ssh_client,
    disabled_ssh_algorithms,
    forget_ssh_known_host,
    format_ssh_connection_error,
    open_ssh_client,
    ssh_host_key_mismatch,
    ssh_key_fingerprint,
)


class SSHSecurityTests(unittest.TestCase):
    class FakeKey:
        def __init__(self, value: bytes, name: str = "ssh-ed25519") -> None:
            self.value = value
            self.name = name

        def asbytes(self) -> bytes:
            return self.value

        def get_name(self) -> str:
            return self.name

    class BadHostKeyException(Exception):
        def __init__(self, hostname: str, key: object, expected_key: object) -> None:
            super().__init__("raw base64 key material that must not be rendered")
            self.hostname = hostname
            self.key = key
            self.expected_key = expected_key

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

    def test_changed_host_key_is_formatted_without_raw_key_material(self) -> None:
        expected = self.FakeKey(b"saved-key")
        presented = self.FakeKey(b"presented-key", "ecdsa-sha2-nistp256")
        error = self.BadHostKeyException("192.0.2.20", presented, expected)

        mismatch = ssh_host_key_mismatch(error)
        message = format_ssh_connection_error(error)

        self.assertEqual(mismatch["hostname"], "192.0.2.20")
        self.assertEqual(
            mismatch["expected_fingerprint"], ssh_key_fingerprint(expected)
        )
        self.assertEqual(
            mismatch["presented_fingerprint"], ssh_key_fingerprint(presented)
        )
        self.assertIn("SSH host identity changed", message)
        self.assertNotIn("raw base64 key material", message)

    def test_forget_known_host_removes_only_matching_identity(self) -> None:
        saved_key = b"saved-host-key"
        fingerprint = self._fingerprint(saved_key)
        encoded = base64.b64encode(saved_key).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            known_hosts = Path(directory) / "known_hosts"
            known_hosts.write_text(
                f"192.0.2.20,alias.example ssh-ed25519 {encoded} comment\n"
                f"192.0.2.30 ssh-ed25519 {encoded}\n",
                encoding="utf-8",
            )
            known_hosts.chmod(0o600)

            result = forget_ssh_known_host(
                "192.0.2.20",
                22,
                fingerprint,
                known_hosts_path=known_hosts,
            )

            self.assertEqual(result["removed_entries"], 1)
            self.assertEqual(known_hosts.stat().st_mode & 0o777, 0o600)
            remaining = known_hosts.read_text(encoding="utf-8")
            self.assertIn(f"alias.example ssh-ed25519 {encoded} comment", remaining)
            self.assertIn(f"192.0.2.30 ssh-ed25519 {encoded}", remaining)
            self.assertNotIn("192.0.2.20", remaining)

    def test_forget_known_host_supports_hashed_nonstandard_port_entries(self) -> None:
        saved_key = b"saved-host-key"
        fingerprint = self._fingerprint(saved_key)
        encoded = base64.b64encode(saved_key).decode("ascii")
        identity = "[192.0.2.20]:2222"
        salt = b"01234567890123456789"
        digest = hmac.new(salt, identity.encode("utf-8"), hashlib.sha1).digest()
        hashed = "|1|{}|{}".format(
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
        with tempfile.TemporaryDirectory() as directory:
            known_hosts = Path(directory) / "known_hosts"
            known_hosts.write_text(
                f"{hashed} ssh-ed25519 {encoded}\n",
                encoding="utf-8",
            )

            result = forget_ssh_known_host(
                "192.0.2.20",
                2222,
                fingerprint,
                known_hosts_path=known_hosts,
            )

            self.assertEqual(result["identity"], identity)
            self.assertEqual(known_hosts.read_text(encoding="utf-8"), "")

    def test_forget_known_host_rejects_stale_expected_fingerprint(self) -> None:
        saved_key = b"saved-host-key"
        encoded = base64.b64encode(saved_key).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            known_hosts = Path(directory) / "known_hosts"
            original = f"192.0.2.20 ssh-ed25519 {encoded}\n"
            known_hosts.write_text(original, encoding="utf-8")

            with self.assertRaisesRegex(
                SSHKnownHostsError,
                "changed after these results",
            ):
                forget_ssh_known_host(
                    "192.0.2.20",
                    22,
                    self._fingerprint(b"different-key"),
                    known_hosts_path=known_hosts,
                )

            self.assertEqual(known_hosts.read_text(encoding="utf-8"), original)

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

    @staticmethod
    def _fingerprint(value: bytes) -> str:
        return "SHA256:" + base64.b64encode(hashlib.sha256(value).digest()).decode(
            "ascii"
        ).rstrip("=")


if __name__ == "__main__":
    unittest.main()
