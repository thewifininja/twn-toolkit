from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit.system_identity import (
    TOOLKIT_START_MARKER,
    collect_system_identity,
    startup_event,
    write_toolkit_start_marker,
)


class SystemIdentityTests(unittest.TestCase):
    def test_toolkit_start_marker_is_private_and_changes_per_complete_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = write_toolkit_start_marker(temporary)
            second = write_toolkit_start_marker(temporary)
            path = Path(temporary) / TOOLKIT_START_MARKER
            saved = json.loads(path.read_text(encoding="utf-8"))

            self.assertNotEqual(first["id"], second["id"])
            self.assertEqual(saved, second)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_identity_builds_current_addresses_and_access_urls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = Path(temporary)
            (instance / "twn-toolkit.scheme").write_text("https\n", encoding="utf-8")
            (instance / "twn-toolkit.host").write_text("0.0.0.0\n", encoding="utf-8")
            (instance / "twn-toolkit.port").write_text("5050\n", encoding="utf-8")
            marker = write_toolkit_start_marker(instance)
            addresses = [
                {"address": "192.0.2.25", "family": "ipv4", "interface": "eth0"},
                {"address": "2001:db8::25", "family": "ipv6", "interface": "eth0"},
            ]
            with patch(
                "twn_toolkit.system_identity.ServerSettingsStore.get",
                return_value={
                    "listen_host": "0.0.0.0",
                    "allowed_networks": [],
                    "instance_name": "branch-pi",
                    "preferred_fqdn": "branch-pi.home.arpa",
                },
            ), patch(
                "twn_toolkit.system_identity._local_addresses",
                return_value=(addresses, "192.0.2.25"),
            ), patch(
                "twn_toolkit.system_identity._boot_identity",
                return_value={"id": "boot-a", "occurred_at": 100.0},
            ), patch(
                "twn_toolkit.system_identity.socket.gethostname",
                return_value="branch-pi.local",
            ):
                identity = collect_system_identity(instance)

            toolkit = identity["toolkit"]
            self.assertEqual(toolkit["instance_name"], "branch-pi")
            self.assertEqual(toolkit["primary_ipv4"], "192.0.2.25")
            self.assertEqual(
                toolkit["urls"],
                [
                    "https://branch-pi.home.arpa:5050",
                    "https://192.0.2.25:5050",
                    "https://[2001:db8::25]:5050",
                    "https://127.0.0.1:5050",
                ],
            )
            self.assertEqual(identity["startup"]["toolkit_start_id"], marker["id"])

    def test_startup_event_selects_boot_or_toolkit_generation(self) -> None:
        identity = {
            "startup": {
                "boot_id": "boot-a",
                "boot_started_at": 100.0,
                "toolkit_start_id": "start-a",
                "toolkit_started_at": 110.0,
            }
        }
        self.assertEqual(startup_event(identity, "host_boot")["key"], "boot-a")
        toolkit = startup_event(identity, "toolkit_start")
        self.assertEqual((toolkit["key"], toolkit["occurred_at"]), ("start-a", 110.0))


if __name__ == "__main__":
    unittest.main()
