from __future__ import annotations

import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.auth import AuthStore
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.wol_tools import (
    available_wol_interfaces,
    build_magic_packet,
    format_wol_targets,
    parse_wol_targets,
    run_wake_on_lan,
)


INTERFACES = [
    {"name": "eth0", "address": "192.0.2.10", "broadcast": "192.0.2.255"}
]


class FakeSocket:
    def __init__(self) -> None:
        self.options = []
        self.bound = None
        self.sent = []
        self.closed = False

    def setsockopt(self, *args):
        self.options.append(args)

    def bind(self, address):
        self.bound = address

    def sendto(self, packet, address):
        self.sent.append((packet, address))
        return len(packet)

    def close(self):
        self.closed = True


def _setup_admin(client) -> None:
    client.post(
        "/setup",
        data={
            "username": "admin",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )


class WakeOnLanToolTests(unittest.TestCase):
    def test_parses_devices_and_formats_normalized_targets(self) -> None:
        targets = parse_wol_targets(
            "Office PC | 00-11-22-33-44-54 | pc.example.test\n"
            "Lab server | 02:00:00:00:00:01\n"
            "02.00.00.00.00.02"
        )

        self.assertEqual(
            targets,
            [
                {
                    "name": "Office PC",
                    "mac": "00:11:22:33:44:54",
                    "host": "pc.example.test",
                },
                {
                    "name": "Lab server",
                    "mac": "02:00:00:00:00:01",
                    "host": "",
                },
                {"name": "", "mac": "02:00:00:00:00:02", "host": ""},
            ],
        )
        self.assertIn(
            "Office PC | 00:11:22:33:44:54 | pc.example.test",
            format_wol_targets(targets),
        )

    def test_rejects_duplicate_multicast_and_malformed_targets(self) -> None:
        with self.assertRaisesRegex(ToolInputError, "listed more than once"):
            parse_wol_targets(
                "First | 02:00:00:00:00:01\nSecond | 02-00-00-00-00-01"
            )
        with self.assertRaisesRegex(ToolInputError, "unicast"):
            parse_wol_targets("01:00:5e:00:00:01")
        with self.assertRaisesRegex(ToolInputError, "use MAC"):
            parse_wol_targets("Too | many | separators | here")

    def test_builds_standard_102_byte_magic_packet(self) -> None:
        packet = build_magic_packet("02:00:00:00:00:01")

        self.assertEqual(len(packet), 102)
        self.assertEqual(packet[:6], b"\xff" * 6)
        self.assertEqual(packet[6:], bytes.fromhex("020000000001") * 16)

    def test_interface_discovery_filters_loopback_and_prefers_local_broadcasts(self) -> None:
        details = {
            "lo0": {"address": "127.0.0.1", "broadcast": "127.255.255.255"},
            "utun0": {"address": "198.19.0.2", "broadcast": ""},
            "en0": {"address": "192.0.2.10", "broadcast": "192.0.2.255"},
        }
        with (
            patch(
                "twn_toolkit.wol_tools.socket.if_nameindex",
                return_value=[(1, "lo0"), (2, "utun0"), (3, "en0")],
            ),
            patch("twn_toolkit.wol_tools.sys.platform", "darwin"),
            patch(
                "twn_toolkit.wol_tools._ifconfig_interface",
                side_effect=lambda name: details[name],
            ),
        ):
            interfaces = available_wol_interfaces()

        self.assertEqual([item["name"] for item in interfaces], ["en0", "utun0"])
        self.assertEqual(interfaces[0]["broadcast"], "192.0.2.255")

    def test_sends_bounded_packets_to_local_broadcast_and_confirms_awake(self) -> None:
        fake_socket = FakeSocket()

        def ping_runner(hosts, _timeout):
            return [
                {"host": host, "reachable": True, "latency_ms": 1.25}
                for host in hosts
            ]

        with patch("twn_toolkit.wol_tools.socket.socket", return_value=fake_socket):
            outcome = run_wake_on_lan(
                [
                    {
                        "name": "Office PC",
                        "mac": "02:00:00:00:00:01",
                        "host": "192.0.2.25",
                    }
                ],
                interface_name="eth0",
                destination_mode="local",
                port=9,
                repeats=3,
                verify=True,
                verify_timeout=5,
                interfaces=INTERFACES,
                ping_runner=ping_runner,
            )

        self.assertEqual(fake_socket.bound, ("192.0.2.10", 0))
        self.assertEqual(len(fake_socket.sent), 3)
        self.assertTrue(
            all(address == ("192.0.2.255", 9) for _packet, address in fake_socket.sent)
        )
        self.assertTrue(all(len(packet) == 102 for packet, _address in fake_socket.sent))
        self.assertTrue(fake_socket.closed)
        self.assertEqual(outcome["packets_sent"], 3)
        self.assertEqual(outcome["confirmed_awake"], 1)
        self.assertEqual(outcome["results"][0]["verification"], "awake")

    def test_custom_destination_supports_directed_broadcast_or_relay(self) -> None:
        fake_socket = FakeSocket()
        with patch("twn_toolkit.wol_tools.socket.socket", return_value=fake_socket):
            outcome = run_wake_on_lan(
                [{"name": "", "mac": "02:00:00:00:00:01", "host": ""}],
                interface_name="eth0",
                destination_mode="custom",
                custom_destination="10.20.30.255",
                port=7,
                repeats=1,
                interfaces=INTERFACES,
            )

        self.assertEqual(outcome["destination"], "10.20.30.255")
        self.assertEqual(fake_socket.sent[0][1], ("10.20.30.255", 7))
        self.assertEqual(outcome["results"][0]["verification"], "not_requested")

    def test_socket_open_failure_returns_per_device_error(self) -> None:
        with patch(
            "twn_toolkit.wol_tools.socket.socket",
            side_effect=OSError("sender unavailable"),
        ):
            outcome = run_wake_on_lan(
                [{"name": "", "mac": "02:00:00:00:00:01", "host": ""}],
                interface_name="eth0",
                destination_mode="local",
                interfaces=INTERFACES,
            )

        self.assertEqual(outcome["packets_sent"], 0)
        self.assertEqual(outcome["send_failures"], 1)
        self.assertIn("sender unavailable", outcome["results"][0]["send_error"])

    def test_route_renders_results_records_activity_and_omits_targets_from_audit(self) -> None:
        target_text = "Private workstation | 02:00:00:00:00:01 | secret-host.internal"
        outcome = {
            "interface": "eth0",
            "source_address": "192.0.2.10",
            "destination": "192.0.2.255",
            "destination_mode": "local",
            "port": 9,
            "repeats": 3,
            "verify": True,
            "verify_timeout": 20,
            "results": [
                {
                    "name": "Private workstation",
                    "mac": "02:00:00:00:00:01",
                    "host": "secret-host.internal",
                    "packets_sent": 3,
                    "send_status": "sent",
                    "send_error": "",
                    "verification": "awake",
                    "latency_ms": 1.5,
                }
            ],
            "device_count": 1,
            "packets_sent": 3,
            "send_failures": 0,
            "confirmed_awake": 1,
            "verification_configured": 1,
            "elapsed_ms": 12.5,
        }
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            with (
                patch(
                    "twn_toolkit.wol_routes.available_wol_interfaces",
                    return_value=INTERFACES,
                ),
                patch("twn_toolkit.wol_routes.run_wake_on_lan", return_value=outcome),
            ):
                response = app.test_client().post(
                    "/tools/wake-on-lan",
                    data={
                        "targets": target_text,
                        "interface": "eth0",
                        "destination_mode": "local",
                        "port": "9",
                        "repeats": "3",
                        "verify": "1",
                        "verify_timeout": "20",
                    },
                )
            summary = ActivityStore(instance).summary()
            event = AuditStore(instance).recent(1)[0]
            audit_database = Path(instance, "audit.sqlite3").read_bytes()

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Wake request complete", response.data)
        self.assertIn(b"Confirmed awake", response.data)
        self.assertEqual(summary["counters"]["wol"]["devices"], 1)
        self.assertEqual(summary["counters"]["wol"]["packets"], 3)
        self.assertEqual(summary["counters"]["wol"]["confirmed"], 1)
        self.assertEqual(event["action"], "wol.send.run_succeeded")
        self.assertNotIn(b"secret-host.internal", audit_database)
        self.assertNotIn(b"02:00:00:00:00:01", audit_database)

    def test_saved_groups_are_backed_up_and_audited_without_device_values(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            response = client.post(
                "/tools/wake-on-lan/profiles",
                data={
                    "name": "Office",
                    "values": "Office PC | 02:00:00:00:00:01 | private.internal",
                },
            )
            saved = json.loads(
                Path(instance, "wol_target_profiles.json").read_text(encoding="utf-8")
            )
            event = AuditStore(instance).recent(1)[0]
            audit_database = Path(instance, "audit.sqlite3").read_bytes()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(saved[0]["name"], "Office")
        self.assertEqual(saved[0]["targets"][0]["mac"], "02:00:00:00:00:01")
        self.assertEqual(event["action"], "wol.profile_created")
        self.assertEqual(event["details"]["changes"][-1]["field"], "verification host count")
        self.assertNotIn(b"private.internal", audit_database)
        self.assertNotIn(b"02:00:00:00:00:01", audit_database)

    def test_access_profile_grants_wol_routes_without_other_network_tools(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            client = app.test_client()
            _setup_admin(client)
            store = AuthStore(instance)
            profile = store.save_access_profile(
                name="Wake devices",
                tool_ids=["tools.wake_on_lan"],
            )
            store.create_user(
                "operator",
                "a different long password",
                access_profile_ids=[profile["id"]],
            )
            client.post("/logout")
            client.post(
                "/login",
                data={"username": "operator", "password": "a different long password"},
            )
            with patch(
                "twn_toolkit.wol_routes.available_wol_interfaces",
                return_value=INTERFACES,
            ):
                allowed = client.get("/tools/wake-on-lan")
            denied = client.get("/tools/dns-response")

        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(denied.status_code, 403)
        self.assertIn(b"Wake-on-LAN", allowed.data)


if __name__ == "__main__":
    unittest.main()
