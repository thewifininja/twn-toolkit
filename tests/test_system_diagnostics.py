from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from twn_toolkit.system_diagnostics import (
    _linux_network_capability,
    _macos_bpf_capability,
    command_dependencies,
)


class SystemDiagnosticsTests(unittest.TestCase):
    def test_command_inventory_covers_optional_integrations_without_openssl(self) -> None:
        available = {
            "ping": "/sbin/ping",
            "traceroute": "/usr/sbin/traceroute",
            "ifconfig": "/sbin/ifconfig",
            "systemctl": "/bin/systemctl",
            "ps": "/bin/ps",
            "sha256sum": "/usr/bin/sha256sum",
        }
        with (
            mock.patch(
                "twn_toolkit.system_diagnostics.shutil.which",
                side_effect=lambda name: available.get(name),
            ),
            mock.patch(
                "twn_toolkit.system_diagnostics.ping_engine_capability",
                return_value={"accelerated": False, "detail": "fping is unavailable."},
            ),
        ):
            dependencies = command_dependencies(system="Linux")

        by_name = {dependency["name"]: dependency for dependency in dependencies}
        self.assertNotIn("openssl", by_name)
        self.assertIn("eapol_test", by_name)
        self.assertIn("certbot", by_name)
        self.assertIn("ip or ifconfig", by_name)
        self.assertTrue(by_name["ip or ifconfig"]["available"])
        self.assertTrue(by_name["eapol_test"]["optional"])

    def test_macos_bpf_reports_permissions_for_current_service_account(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chmod_bpf = Path(temporary) / "org.wireshark.ChmodBPF.plist"
            chmod_bpf.touch()
            with (
                mock.patch("twn_toolkit.system_diagnostics.CHMOD_BPF_PLIST", chmod_bpf),
                mock.patch(
                    "twn_toolkit.system_diagnostics.Path.glob",
                    return_value=[Path("/dev/bpf0")],
                ),
                mock.patch("twn_toolkit.system_diagnostics.os.access", return_value=True),
                mock.patch(
                    "twn_toolkit.system_diagnostics._current_account",
                    return_value=("toolkit", ["access_bpf", "staff"]),
                ),
            ):
                capability = _macos_bpf_capability()

        self.assertTrue(capability["available"])
        self.assertEqual(capability["status"], "Ready")
        self.assertIn("toolkit can read and write /dev/bpf0", capability["detail"])
        self.assertIn("ChmodBPF is installed", capability["detail"])

    def test_linux_capability_reports_partial_effective_set(self) -> None:
        with mock.patch(
            "twn_toolkit.system_diagnostics._linux_effective_capabilities",
            return_value={"CAP_NET_RAW"},
        ):
            capability = _linux_network_capability()

        self.assertFalse(capability["available"])
        self.assertEqual(capability["status"], "Partial")
        self.assertIn("CAP_NET_ADMIN", capability["detail"])


if __name__ == "__main__":
    unittest.main()
