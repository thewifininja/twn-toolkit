from __future__ import annotations

import errno
import os
import unittest
from unittest.mock import patch

from twn_toolkit.ssh_security import (
    disabled_ssh_algorithms,
    format_ssh_connection_error,
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


if __name__ == "__main__":
    unittest.main()
