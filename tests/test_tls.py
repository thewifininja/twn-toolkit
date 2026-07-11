from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509

from twn_toolkit import create_app
from twn_toolkit.tls_tools import (
    generate_self_signed_certificate,
    tls_paths,
    validate_certificate_pair,
)


class TlsToolsTests(unittest.TestCase):
    def test_generated_certificate_is_enabled_valid_and_contains_requested_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cert_path, key_path = generate_self_signed_certificate(
                directory, extra_names=["toolkit.example.test", "192.0.2.10"]
            )
            certificate = validate_certificate_pair(cert_path, key_path)
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            self.assertIn("toolkit.example.test", san.get_values_for_type(x509.DNSName))
            self.assertIn("192.0.2.10", [str(value) for value in san.get_values_for_type(x509.IPAddress)])
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(tls_paths(directory)[2].exists())

    def test_private_key_with_broad_permissions_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cert_path, key_path = generate_self_signed_certificate(directory)
            os.chmod(key_path, 0o644)
            with self.assertRaisesRegex(ValueError, "permissions"):
                validate_certificate_pair(cert_path, key_path)

    def test_https_environment_enables_secure_session_cookie(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"TWN_TOOLKIT_HTTPS": "1"}
        ):
            app = create_app(directory)
            self.assertTrue(app.config["SESSION_COOKIE_SECURE"])
            self.assertEqual(app.config["PREFERRED_URL_SCHEME"], "https")


if __name__ == "__main__":
    unittest.main()
