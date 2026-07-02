from __future__ import annotations

import socket
import unittest
from unittest.mock import Mock, patch

from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.radius_eap_tools import radius_eap_authenticate


SERVER = {
    "name": "Primary",
    "host": "radius.example",
    "port": 1812,
    "secret": "shared-secret",
}
CREDENTIALS = {"username": "alice@example.com", "password": "user-password"}


class RadiusEapToolTests(unittest.TestCase):
    def test_peap_mschapv2_builds_request_scoped_supplicant_config(self) -> None:
        completed = Mock(
            returncode=0,
            stdout=(
                "password - hexdump_ascii(len=13):\n"
                "75 73 65 72 2d 70 61 73 73 77 6f 72 64 user-password\n"
                "RADIUS packet exchange\nSUCCESS\n"
            ),
        )
        captured_config = []

        def run(command, **_kwargs):
            config_path = command[command.index("-c") + 1]
            with open(config_path, encoding="utf-8") as handle:
                captured_config.append(handle.read())
            self.assertIn("-a", command)
            self.assertIn("192.0.2.10", command)
            return completed

        with (
            patch("twn_toolkit.radius_eap_tools.shutil.which", return_value="/usr/bin/eapol_test"),
            patch(
                "twn_toolkit.radius_eap_tools.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.10", 1812))],
            ),
            patch("twn_toolkit.radius_eap_tools.subprocess.run", side_effect=run),
        ):
            result = radius_eap_authenticate(
                [SERVER],
                CREDENTIALS,
                "peap-mschapv2",
                timeout=3,
                ca_certificate=b"test CA",
                anonymous_identity="anonymous@example.com",
                server_domain="radius.example.com",
            )
        self.assertEqual(result[0]["status"], "Access-Accept")
        self.assertNotIn("75 73 65 72", result[0]["transcript"])
        self.assertIn("eap=PEAP", captured_config[0])
        self.assertIn('phase2="auth=MSCHAPV2"', captured_config[0])
        self.assertIn('domain_suffix_match="radius.example.com"', captured_config[0])

    def test_eap_tls_requires_client_certificate_and_key(self) -> None:
        with patch("twn_toolkit.radius_eap_tools.shutil.which", return_value="/usr/bin/eapol_test"):
            with self.assertRaises(ToolInputError):
                radius_eap_authenticate(
                    [SERVER],
                    CREDENTIALS,
                    "eap-tls",
                    timeout=3,
                    ca_certificate=b"test CA",
                )

    def test_reports_missing_eapol_test(self) -> None:
        with patch("twn_toolkit.radius_eap_tools.shutil.which", return_value=None):
            with self.assertRaisesRegex(ToolInputError, "eapol_test"):
                radius_eap_authenticate(
                    [SERVER],
                    CREDENTIALS,
                    "peap-mschapv2",
                    timeout=3,
                    ca_certificate=b"test CA",
                )


if __name__ == "__main__":
    unittest.main()
