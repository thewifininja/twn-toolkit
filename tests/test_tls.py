from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509

from twn_toolkit import create_app
from twn_toolkit.server_settings import (
    ServerSettingsStore,
    normalize_instance_name,
    normalize_preferred_fqdn,
)
from twn_toolkit.tls_tools import (
    certificate_status,
    generate_self_signed_certificate,
    regenerate_self_signed_certificate,
    tls_paths,
    validate_certificate_pair,
)


class TlsToolsTests(unittest.TestCase):
    def test_server_identity_is_syntax_validated_without_dns(self) -> None:
        self.assertEqual(normalize_instance_name(" WiFi-Tools "), "wifi-tools")
        self.assertEqual(
            normalize_preferred_fqdn(" WiFi-Tools.Home.Arpa "),
            "wifi-tools.home.arpa",
        )
        with self.assertRaises(ValueError):
            normalize_instance_name("bad name")
        for invalid in (
            "single-label",
            "https://toolkit.example",
            "toolkit.example:5050",
            "-bad.example",
            "bad_.example",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_preferred_fqdn(invalid)

    def test_server_identity_persists_and_appears_in_page_title(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ServerSettingsStore(directory)
            store.save(
                "0.0.0.0", "10.0.0.0/8", "Home-Tools", "tools.home.arpa"
            )
            self.assertEqual(store.get()["instance_name"], "home-tools")
            app = create_app(directory)
            app.config["TESTING"] = True
            response = app.test_client().get("/settings")
            self.assertIn(
                b"Settings \xc2\xb7 home-tools \xc2\xb7 The WiFi Ninja",
                response.data,
            )

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

    def test_certificate_status_reports_preferred_fqdn_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            generate_self_signed_certificate(
                directory, extra_names=["tools.example.test"]
            )
            covered = certificate_status(directory, "tools.example.test")
            missing = certificate_status(directory, "other.example.test")
            self.assertTrue(covered["valid"])
            self.assertTrue(covered["fqdn_covered"])
            self.assertFalse(missing["fqdn_covered"])

    def test_regeneration_replaces_certificate_and_adds_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cert_path, _key_path = generate_self_signed_certificate(directory)
            original = cert_path.read_bytes()
            regenerate_self_signed_certificate(
                directory, extra_names=["new-tools.example.test"]
            )
            self.assertNotEqual(cert_path.read_bytes(), original)
            self.assertTrue(
                certificate_status(directory, "new-tools.example.test")["fqdn_covered"]
            )

    def test_https_environment_enables_secure_session_cookie(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"TWN_TOOLKIT_HTTPS": "1"}
        ):
            app = create_app(directory)
            self.assertTrue(app.config["SESSION_COOKIE_SECURE"])
            self.assertEqual(app.config["PREFERRED_URL_SCHEME"], "https")


if __name__ == "__main__":
    unittest.main()
