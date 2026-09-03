from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit.network_interface_events import (
    collect_interface_snapshot,
    compare_snapshots,
    evaluate_interface_change,
    filter_snapshot,
)


class NetworkInterfaceEventTests(unittest.TestCase):
    def test_linux_iproute2_output_is_distribution_independent(self) -> None:
        output = json.dumps([{"ifname": "enp1s0", "addr_info": [
            {"family": "inet", "local": "192.0.2.10", "prefixlen": 24},
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64},
        ]}])
        completed = type("Completed", (), {"returncode": 0, "stdout": output})()
        for distribution in ("debian", "arch"):
            with self.subTest(distribution=distribution), patch(
                "twn_toolkit.network_interface_events.platform.system", return_value="Linux"
            ), patch(
                "twn_toolkit.network_interface_events.shutil.which", return_value="/usr/bin/ip"
            ), patch(
                "twn_toolkit.network_interface_events.subprocess.run", return_value=completed
            ):
                self.assertEqual(
                    collect_interface_snapshot()["enp1s0"][0]["address"],
                    "192.0.2.10/24",
                )

    def test_filters_noisy_addresses_and_compares_sets(self) -> None:
        snapshot = {
            "lo": [{"address": "127.0.0.1/8", "temporary": False}],
            "eth0": [{"address": "192.0.2.10/24", "temporary": False}],
            "veth123": [{"address": "10.0.0.1/24", "temporary": False}],
        }
        current = filter_snapshot(snapshot)
        self.assertEqual(list(current), ["eth0"])
        changed = compare_snapshots(
            {"eth0": [{"address": "192.0.2.9/24"}]}, current
        )
        self.assertEqual(changed["changes"][0]["added_addresses"], ["192.0.2.10/24"])
        self.assertEqual(changed["changes"][0]["removed_addresses"], ["192.0.2.9/24"])

    def test_macos_ifconfig_normalizes_ipv4_ipv6_and_scope(self) -> None:
        output = """en0: flags=8863<UP> mtu 1500
\tinet 192.0.2.20 netmask 0xffffff00 broadcast 192.0.2.255
\tinet6 fe80::1234%en0 prefixlen 64 secured scopeid 0x4
"""
        completed = type("Completed", (), {"returncode": 0, "stdout": output})()
        with patch(
            "twn_toolkit.network_interface_events.platform.system",
            return_value="Darwin",
        ), patch(
            "twn_toolkit.network_interface_events.shutil.which",
            return_value="/sbin/ifconfig",
        ), patch(
            "twn_toolkit.network_interface_events.subprocess.run",
            return_value=completed,
        ):
            snapshot = collect_interface_snapshot()

        self.assertEqual(snapshot["en0"][0]["address"], "192.0.2.20/24")
        self.assertEqual(snapshot["en0"][1]["address"], "fe80::1234/64")

    def test_baseline_survives_restart_and_change_fires_once_after_stabilizing(self) -> None:
        config = {"families": ["ipv4"], "stabilization_seconds": 5}
        original = {"eth0": [{"address": "192.0.2.10/24", "temporary": False}]}
        changed = {"eth0": [{"address": "192.0.2.11/24", "temporary": False}]}
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(evaluate_interface_change(directory, "a1", config, snapshot=original, now=1).met)
            self.assertFalse(evaluate_interface_change(directory, "a1", config, snapshot=changed, now=2).met)
            fired = evaluate_interface_change(directory, "a1", config, snapshot=changed, now=7)
            self.assertTrue(fired.met)
            self.assertEqual(fired.evidence["changes"][0]["removed_addresses"], ["192.0.2.10/24"])
            self.assertFalse(evaluate_interface_change(directory, "a1", config, snapshot=changed, now=8).met)
            self.assertTrue((Path(directory) / "automation-network-baselines" / "a1.json").exists())


if __name__ == "__main__":
    unittest.main()
