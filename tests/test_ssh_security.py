from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from twn_toolkit.ssh_security import disabled_ssh_algorithms


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


if __name__ == "__main__":
    unittest.main()
