from __future__ import annotations

import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.fortigate import FortiGateError
from twn_toolkit.fortigate_routes import managed_switch_order, switch_order_moves
from twn_toolkit.network_tools import (
    _extract_ssh_prompt,
    _read_ssh_command,
    _ssh_host,
    _ping_host,
    ToolInputError,
    parse_dns_servers,
    parse_ping_targets,
    parse_radius_attributes,
    parse_ssh_commands,
    parse_ssh_targets,
    subtract_subnets,
    validate_hosts,
)
from twn_toolkit.tasks import TaskResult


class NetworkToolTests(unittest.TestCase):
    def test_ping_timeout_does_not_expose_subprocess_command(self) -> None:
        with patch(
            "twn_toolkit.network_tools.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["/sbin/ping", "192.0.2.1"], 1.25),
        ):
            result = _ping_host("192.0.2.1", 1)
        self.assertFalse(result["reachable"])
        self.assertNotIn("error", result)

    def test_ssh_commands_support_per_command_timeout_overrides(self) -> None:
        commands = parse_ssh_commands(
            ["get system status", "[timeout=600] diag debug report"], 300
        )
        self.assertEqual(
            commands,
            [
                {"command": "get system status", "timeout": 300},
                {"command": "diag debug report", "timeout": 600},
            ],
        )
        with self.assertRaisesRegex(ToolInputError, "between 1 and 3600"):
            parse_ssh_commands(["[timeout=3601] show report"], 300)
        with self.assertRaisesRegex(ToolInputError, "Combined command timeout budget"):
            parse_ssh_commands(["[timeout=2000] one", "[timeout=2000] two"], 300)

    def test_ssh_targets_support_optional_friendly_names(self) -> None:
        self.assertEqual(
            parse_ssh_targets(
                "Basement Switch = 192.0.2.20\ncore-switch.example.com"
            ),
            [
                {"label": "Basement Switch", "host": "192.0.2.20"},
                {"label": "", "host": "core-switch.example.com"},
            ],
        )

    def test_ssh_command_waits_for_the_original_device_prompt(self) -> None:
        class Channel:
            def __init__(self) -> None:
                self.chunks = [
                    b"diag debug report\r\ncollecting...\r\n",
                    b"finished\r\nDXHS-BSMT-SW5 # ",
                ]

            def recv_ready(self) -> bool:
                return bool(self.chunks)

            def recv(self, _size: int) -> bytes:
                return self.chunks.pop(0)

        prompt = _extract_ssh_prompt("Welcome\r\nDXHS-BSMT-SW5 # ")
        output, completed = _read_ssh_command(Channel(), 600, prompt)
        self.assertEqual(prompt, "DXHS-BSMT-SW5 #")
        self.assertTrue(completed)
        self.assertIn("finished", output)

    def test_ssh_command_timeout_returns_partial_output(self) -> None:
        class Channel:
            def recv_ready(self) -> bool:
                return False

        with patch("twn_toolkit.network_tools.time.monotonic", side_effect=[0, 0, 2]), patch(
            "twn_toolkit.network_tools.time.sleep"
        ):
            output, completed = _read_ssh_command(
                Channel(), 1, "DXHS-BSMT-SW5 #"
            )
        self.assertEqual(output, "")
        self.assertFalse(completed)

    def test_ssh_capture_limit_does_not_prevent_prompt_detection(self) -> None:
        class Channel:
            def __init__(self) -> None:
                self.chunks = [b"abcdefghijklmnop", b"\r\nSWITCH-1 # "]

            def recv_ready(self) -> bool:
                return bool(self.chunks)

            def recv(self, _size: int) -> bytes:
                return self.chunks.pop(0)

        output, completed = _read_ssh_command(
            Channel(), 300, "SWITCH-1 #", capture_limit=10
        )
        self.assertTrue(completed)
        self.assertTrue(output.startswith("abcdefghij"))
        self.assertIn("capture limit", output)

    def test_ssh_host_stops_after_a_timed_out_command(self) -> None:
        client = MagicMock()
        channel = MagicMock()
        client.invoke_shell.return_value = channel
        with patch("paramiko.SSHClient", return_value=client), patch(
            "twn_toolkit.network_tools._read_channel", return_value="SWITCH-1 # "
        ), patch(
            "twn_toolkit.network_tools._read_ssh_command",
            return_value=("partial diagnostic output", False),
        ):
            result = _ssh_host(
                "switch-1",
                "admin",
                "secret",
                [
                    {"command": "diag debug report", "timeout": 600},
                    {"command": "get system status", "timeout": 300},
                ],
                22,
                True,
                False,
                0,
            )
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["timed_out_command"], "diag debug report")
        channel.send.assert_called_once_with("diag debug report\n")

    def test_switch_order_keeps_name_primary_and_description_separate(self) -> None:
        switches = managed_switch_order(
            [
                {
                    "switch-id": "S124ENTF00000001",
                    "name": "MDF-SW01",
                    "description": "Main distribution frame",
                    "sn": "S124ENTF00000001",
                },
                {
                    "switch-id": "S124ENTF00000002",
                    "description": "Second-floor closet",
                },
            ]
        )
        self.assertEqual(switches[0]["name"], "MDF-SW01")
        self.assertEqual(switches[0]["description"], "Main distribution frame")
        self.assertEqual(switches[1]["name"], "S124ENTF00000002")
        self.assertEqual(switches[1]["description"], "Second-floor closet")

    def test_builds_minimal_switch_order_moves(self) -> None:
        self.assertEqual(
            switch_order_moves(
                ["switch-c", "switch-a", "switch-b"],
                ["switch-a", "switch-b", "switch-c"],
            ),
            [{"switch_id": "switch-c", "after": "switch-b"}],
        )
        self.assertEqual(
            switch_order_moves(
                ["switch-c", "switch-b", "switch-a"],
                ["switch-a", "switch-b", "switch-c"],
            ),
            [
                {"switch_id": "switch-b", "after": "switch-a"},
                {"switch_id": "switch-c", "after": "switch-b"},
            ],
        )

    def test_switch_order_apply_returns_friendly_permission_error(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            client.post(
                "/profiles",
                data={
                    "name": "ReadOnly",
                    "host": "https://fortigate.example",
                    "api_key": "secret",
                    "default_vdom": "root",
                },
            )
            switches = [
                {"switch-id": "switch-a", "name": "Switch A"},
                {"switch-id": "switch-b", "name": "Switch B"},
            ]

            with (
                patch(
                    "twn_toolkit.fortigate_routes.FortiGateClient.get_managed_switches",
                    return_value=switches,
                ),
                patch(
                    "twn_toolkit.fortigate_routes.FortiGateClient.move_managed_switch_after",
                    side_effect=FortiGateError("raw permission detail", status_code=403),
                ),
            ):
                response = client.post(
                    "/fortigate/switch-order/apply",
                    data={
                        "profile": "ReadOnly",
                        "vdom": "root",
                        "switch_id": ["switch-b", "switch-a"],
                    },
                )
            summary = ActivityStore(instance).summary()
            audit_event = AuditStore(instance).recent(1)[0]
            audit_database = (Path(instance) / "audit.sqlite3").read_bytes()

        self.assertEqual(response.status_code, 502)
        payload = response.get_json()
        self.assertIn("did not allow the reorder", payload["user_message"])
        self.assertIn("read-write access", payload["user_message"])
        self.assertEqual(payload["detail"], "raw permission detail")
        self.assertEqual(payload["completed_moves"], [])
        self.assertEqual(summary["counters"]["fortinet"]["api_calls"], 2)
        self.assertEqual(summary["counters"]["fortinet"]["failures"], 1)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(summary["recent"][0]["title"], "Applied FortiSwitch order")
        self.assertEqual(audit_event["action"], "fortigate.switch_order_failed")
        self.assertEqual(audit_event["details"]["outcome"], "failed")
        self.assertEqual(audit_event["details"]["completed move count"], 0)
        self.assertNotIn(b"secret", audit_database)

    def test_fortigate_exports_and_renames_have_bounded_audit_events(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            client.post(
                "/profiles",
                data={
                    "name": "Lab",
                    "host": "https://fortigate.example",
                    "api_key": "profile-secret",
                    "default_vdom": "root",
                },
            )

            with patch(
                "twn_toolkit.fortigate_routes.ExportTask.run",
                return_value="serial,name\nraw-export-value,Private Switch\n",
            ):
                export = client.post(
                    "/tasks/export-switches/run",
                    data={"profile": "Lab"},
                )
            with patch(
                "twn_toolkit.fortigate_routes.RenameTask.run_entries",
                return_value=[
                    TaskResult(1, "Lobby AP", "Lobby AP New", "root", "success", "Updated.")
                ],
            ):
                rename = client.post(
                    "/tasks/rename-aps/rename",
                    data={
                        "profile": "Lab",
                        "identifier": ["AP-1"],
                        "current_name": ["Lobby AP"],
                        "new_name": ["Lobby AP New"],
                        "vdom": ["root"],
                    },
                )
            events = AuditStore(instance).recent(2)
            audit_database = (Path(instance) / "audit.sqlite3").read_bytes()

            with patch(
                "twn_toolkit.fortigate_routes.RenameTask.run_entries",
                return_value=[
                    TaskResult(1, "Lobby AP", "Lobby AP New", "root", "planned", "Would update.")
                ],
            ):
                dry_run = client.post(
                    "/tasks/rename-aps/rename",
                    data={
                        "profile": "Lab",
                        "identifier": ["AP-1"],
                        "current_name": ["Lobby AP"],
                        "new_name": ["Lobby AP New"],
                        "vdom": ["root"],
                        "dry_run": "on",
                    },
                )
            event_count_after_dry_run = len(AuditStore(instance).recent(10))

        self.assertEqual(export.status_code, 200)
        self.assertEqual(rename.status_code, 200)
        self.assertEqual(dry_run.status_code, 200)
        self.assertEqual(
            [event["action"] for event in events],
            ["fortigate.objects_renamed", "fortigate.export_succeeded"],
        )
        rename_event = events[0]
        self.assertEqual(rename_event["details"]["outcome"], "success")
        self.assertEqual(rename_event["details"]["successful object count"], 1)
        self.assertEqual(event_count_after_dry_run, 3)
        self.assertNotIn(b"profile-secret", audit_database)
        self.assertNotIn(b"raw-export-value", audit_database)

    def test_subtracts_ipv4_and_ipv6_networks(self) -> None:
        self.assertEqual(
            subtract_subnets(
                "10.0.0.0/24, 2001:db8::/126",
                "10.0.0.64/26, 2001:db8::/127",
            ),
            ["10.0.0.0/26", "10.0.0.128/25", "2001:db8::2/127"],
        )

    def test_rejects_shell_like_host_input(self) -> None:
        with self.assertRaises(ToolInputError):
            validate_hosts("127.0.0.1; whoami")

    def test_parses_optional_ping_target_names(self) -> None:
        self.assertEqual(
            parse_ping_targets("Core Router = 192.0.2.1\n8.8.8.8"),
            [
                {"label": "Core Router", "host": "192.0.2.1"},
                {"label": "", "host": "8.8.8.8"},
            ],
        )

    def test_rejects_out_of_range_ipv4_shaped_ping_targets(self) -> None:
        for value in ("192.0.2.256", "999.999.999.999", "1.2.3.4.5"):
            with self.subTest(value=value), self.assertRaises(ToolInputError):
                parse_ping_targets(value)

    def test_parses_named_dns_servers_and_rejects_hostnames(self) -> None:
        self.assertEqual(
            parse_dns_servers("Cloudflare = 1.1.1.1\nGoogle IPv6 = 2001:4860:4860::8888"),
            [
                {"label": "Cloudflare", "address": "1.1.1.1"},
                {"label": "Google IPv6", "address": "2001:4860:4860::8888"},
            ],
        )
        with self.assertRaises(ToolInputError):
            parse_dns_servers("resolver.example.com")

    def test_parses_named_and_raw_radius_attributes(self) -> None:
        attributes = parse_radius_attributes(
            "NAS-Identifier = HQ-WLC\nNAS-IP-Address = 192.0.2.10\n#9:1 = 010203"
        )
        self.assertEqual(attributes[0]["name"], "NAS-Identifier")
        self.assertEqual(attributes[1]["value"], "192.0.2.10")
        self.assertEqual(
            attributes[2],
            {"name": "9:1", "value": "010203", "raw": True},
        )

    def test_ping_activity_records_batched_counters(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            start = client.post(
                "/tools/ping/activity",
                json={"event": "start", "run_id": "run-1", "targets": 2},
            )
            checkpoint = client.post(
                "/tools/ping/activity",
                json={
                    "event": "checkpoint",
                    "run_id": "run-1",
                    "probes_sent": 6,
                    "replies_received": 5,
                },
            )
            final = client.post(
                "/tools/ping/activity",
                json={
                    "event": "final",
                    "run_id": "run-1",
                    "probes_sent": 2,
                    "replies_received": 1,
                },
            )
            summary = ActivityStore(instance).summary()

        self.assertEqual(start.status_code, 200)
        self.assertEqual(checkpoint.status_code, 200)
        self.assertEqual(final.status_code, 200)
        self.assertEqual(summary["counters"]["ping"]["sessions_started"], 1)
        self.assertEqual(summary["counters"]["ping"]["targets_started"], 2)
        self.assertEqual(summary["counters"]["ping"]["probes_sent"], 8)
        self.assertEqual(summary["counters"]["ping"]["replies_received"], 6)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(summary["scoreboard"][0]["username"], "test-user")
        self.assertEqual(summary["scoreboard"][0]["actions"], 1)
        self.assertEqual(summary["recent"][0]["title"], "Stopped ping run")
        self.assertEqual(summary["recent"][1]["title"], "Started ping run")

    @patch("twn_toolkit.fortigate_routes.FortiGateClient.test_connection")
    def test_fortigate_profile_test_records_api_activity(self, test_connection) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            client.post(
                "/profiles",
                data={
                    "name": "Lab",
                    "host": "https://fortigate.example",
                    "api_key": "secret",
                    "default_vdom": "root",
                },
            )
            test_connection.return_value = {"version": "v7.6"}

            response = client.post("/profiles/Lab/test", follow_redirects=True)
            summary = ActivityStore(instance).summary()
            audit_event = AuditStore(instance).recent(1)[0]
            audit_database = Path(instance, "audit.sqlite3").read_bytes()

        self.assertIn(b"Connection OK: v7.6", response.data)
        self.assertEqual(summary["counters"]["fortinet"]["api_calls"], 1)
        self.assertEqual(summary["counters"]["fortinet"]["failures"], 0)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(summary["scoreboard"][0]["username"], "test-user")
        self.assertEqual(summary["scoreboard"][0]["actions"], 1)
        self.assertEqual(summary["recent"][0]["title"], "Tested FortiGate profile")
        self.assertEqual(summary["recent"][0]["detail"], "Lab: v7.6")
        self.assertEqual(audit_event["action"], "fortigate.profile_test_succeeded")
        self.assertEqual(audit_event["details"]["outcome"], "succeeded")
        self.assertNotIn(b"secret", audit_database)

    def test_tool_routes(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            self.assertIn(b"DNS Lookup Tester", client.get("/").data)
            home_page = client.get("/")
            self.assertIn(b"brand/dragon-mark-128.png", home_page.data)
            self.assertIn(b"brand/favicon-32.png", home_page.data)
            favicon = client.get("/favicon.ico")
            self.assertEqual(favicon.status_code, 200)
            self.assertEqual(favicon.mimetype, "image/png")
            favicon.close()
            self.assertIn(b"RADIUS Authentication Test", client.get("/").data)
            self.assertIn(b"Wi-Fi / LAN Speed Test", client.get("/").data)
            self.assertIn(b"Certificate Chain Inspector", client.get("/").data)
            self.assertIn(b"DHCP Discover", client.get("/").data)
            self.assertIn(b"Path MTU Tester", client.get("/").data)
            self.assertIn(b"Webhook / API Tester", client.get("/").data)
            self.assertIn(b"Syslog Tools", client.get("/").data)
            self.assertIn(b"Wi-Fi / LAN Speed Test", client.get("/tools/").data)
            self.assertIn(b"Certificate Chain Inspector", client.get("/tools/").data)
            self.assertEqual(client.get("/tools/certificate-inspector").status_code, 200)
            ip_page = client.get(
                "/tools/whats-my-ip",
                environ_base={"REMOTE_ADDR": "192.0.2.44"},
            )
            self.assertEqual(ip_page.status_code, 200)
            self.assertIn(b"192.0.2.44", ip_page.data)
            self.assertIn(b"IPv4", ip_page.data)
            self.assertIn(b"https://api64.ipify.org?format=json", ip_page.data)
            self.assertIn(b"Your browser\xe2\x80\x99s public internet address", ip_page.data)
            self.assertIn(b"Toolkit server\xe2\x80\x99s public internet address", ip_page.data)
            self.assertIn(b"/tools/whats-my-ip/server-public", ip_page.data)
            self.assertIn(b'id="check-ip-again"', ip_page.data)
            self.assertIn("no-store", ip_page.headers["Cache-Control"])

            upstream = MagicMock()
            upstream.json.return_value = {"ip": "198.51.100.22"}
            upstream.raise_for_status.return_value = None
            with patch("twn_toolkit.ip_info_routes.requests.get", return_value=upstream):
                server_ip = client.get("/tools/whats-my-ip/server-public")
            self.assertEqual(
                server_ip.get_json(), {"ip": "198.51.100.22", "family": "IPv4"}
            )
            self.assertIn("no-store", server_ip.headers["Cache-Control"])

            speed_page = client.get("/tools/speed-test")
            self.assertEqual(speed_page.status_code, 200)
            self.assertIn(b"browser and the machine running the toolkit", speed_page.data)
            self.assertIn(b'id="speed-download-meter"', speed_page.data)
            self.assertIn(b'id="speed-upload-meter"', speed_page.data)
            self.assertIn(b"Dashboard", speed_page.data)
            self.assertIn(b"Network Tools", speed_page.data)
            self.assertIn(b'href="/fortigate"', speed_page.data)
            self.assertIn(b'href="/fortiauthenticator"', speed_page.data)
            self.assertIn(b'href="/tools/packet-replay"', speed_page.data)

            latency_response = client.get("/tools/speed-test/ping")
            self.assertEqual(latency_response.status_code, 204)
            self.assertIn("no-store", latency_response.headers["Cache-Control"])

            download_response = client.get("/tools/speed-test/download?bytes=1025")
            self.assertEqual(download_response.status_code, 200)
            self.assertEqual(len(download_response.data), 1025)
            self.assertEqual(download_response.headers["Content-Length"], "1025")
            self.assertEqual(download_response.headers["Content-Encoding"], "identity")
            self.assertEqual(
                client.get("/tools/speed-test/download?bytes=0").status_code,
                400,
            )

            upload_response = client.post(
                "/tools/speed-test/upload",
                data=b"x" * 4097,
                content_type="application/octet-stream",
            )
            self.assertEqual(upload_response.status_code, 200)
            self.assertEqual(upload_response.get_json()["bytes_received"], 4097)
            activity_response = client.post(
                "/tools/speed-test/activity",
                json={"download_bytes": 1025, "upload_bytes": 4097},
            )
            self.assertEqual(activity_response.status_code, 200)
            self.assertEqual(
                client.post(
                    "/tools/speed-test/upload",
                    data=b"",
                    content_type="application/octet-stream",
                ).status_code,
                411,
            )

            response = client.post(
                "/tools/subnet-excluder",
                data={"supernets": "10.0.0.0/24", "exclusions": "10.0.0.64/26"},
            )
            self.assertIn(b"10.0.0.128/25", response.data)

            ping_result = {
                "host": "localhost",
                "reachable": True,
                "latency_ms": 0.1,
                "elapsed_ms": 1.0,
            }
            with patch("twn_toolkit.ping_routes.ping_hosts", return_value=[ping_result]):
                response = client.post("/tools/ping/run", json={"hosts": "Localhost = localhost"})
            self.assertEqual(response.get_json()["results"], [{**ping_result, "label": "Localhost"}])

            response = client.post(
                "/tools/ping/validate",
                json={"hosts": "Gateway = 192.0.2.1\nexample.com"},
            )
            self.assertEqual(
                response.get_json()["targets"],
                [
                    {"label": "Gateway", "host": "192.0.2.1"},
                    {"label": "", "host": "example.com"},
                ],
            )
            response = client.post(
                "/tools/ping/validate", json={"hosts": "192.0.2.999"}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["targets"], [])
            self.assertEqual(response.get_json()["invalid"][0]["value"], "192.0.2.999")

            response = client.post(
                "/tools/ping/validate",
                json={"hosts": "Gateway = 192.0.2.1\n192.0.2.999\nexample.com"},
            )
            self.assertEqual(
                response.get_json()["targets"],
                [
                    {"label": "Gateway", "host": "192.0.2.1"},
                    {"label": "", "host": "example.com"},
                ],
            )
            self.assertEqual(response.get_json()["invalid"][0]["value"], "192.0.2.999")

            response = client.post(
                "/tools/ping/profiles",
                json={
                    "name": "Office",
                    "hosts": "Gateway = 192.0.2.1\n8.8.8.8",
                    "interval": 5,
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["profile"]["targets"][0]["label"], "Gateway")
            self.assertIn(b"Office", client.get("/tools/ping").data)

            response = client.post(
                "/tools/ping/profiles",
                json={
                    "name": "Branches",
                    "original_name": "Office",
                    "hosts": "192.0.2.2",
                    "interval": 3,
                },
            )
            self.assertEqual(response.status_code, 200)
            ping_page = client.get("/tools/ping").data
            self.assertIn(b"Branches", ping_page)
            self.assertNotIn(b">Office</option>", ping_page)

            response = client.post("/tools/ping/profiles/delete", json={"name": "Branches"})
            self.assertEqual(response.get_json()["deleted"], "Branches")

            response = client.post(
                "/tools/dns-response/profiles/hosts",
                data={"profile_name": "Public sites", "values": "Example = example.com"},
            )
            self.assertEqual(response.status_code, 200)
            response = client.post(
                "/tools/dns-response/profiles/servers",
                data={"profile_name": "Public DNS", "values": "Cloudflare = 1.1.1.1"},
            )
            self.assertEqual(response.status_code, 200)
            page = client.get("/tools/dns-response")
            self.assertIn(b"Public sites", page.data)
            self.assertIn(b"Public DNS", page.data)

            dns_result = {
                "host": "example.com",
                "host_label": "Example",
                "server": "1.1.1.1",
                "server_label": "Cloudflare",
                "record_type": "A",
                "status": "success",
                "answers": ["192.0.2.10"],
                "response_ms": 12.3,
            }
            with patch("twn_toolkit.dns_routes.dns_lookup_matrix", return_value=[dns_result]):
                response = client.post(
                    "/tools/dns-response",
                    data={
                        "hosts": "Example = example.com",
                        "servers": "Cloudflare = 1.1.1.1",
                        "record_type": "A",
                        "timeout": "3",
                    },
                )
            self.assertIn(b"192.0.2.10", response.data)
            self.assertIn(b"12.3 ms", response.data)

            response = client.post(
                "/tools/radius-test/profiles/servers",
                data={
                    "name": "Primary RADIUS",
                    "host": "192.0.2.40",
                    "port": "1812",
                    "secret": "shared-secret-not-rendered",
                },
            )
            self.assertEqual(response.status_code, 200)
            response = client.post(
                "/tools/radius-test/profiles/credentials",
                data={
                    "name": "Test User",
                    "username": "radius-test",
                    "password": "password-not-rendered",
                },
            )
            self.assertEqual(response.status_code, 200)
            response = client.post(
                "/tools/radius-test/profiles/attributes",
                data={
                    "name": "HQ WLAN",
                    "attributes": "NAS-Identifier = HQ-WLC\nNAS-IP-Address = 192.0.2.10",
                },
            )
            self.assertEqual(response.status_code, 200)
            radius_page = client.get("/tools/radius-test").data
            self.assertIn(b"Primary RADIUS", radius_page)
            self.assertIn(b"Test User", radius_page)
            self.assertIn(b"HQ WLAN", radius_page)
            self.assertNotIn(b"shared-secret-not-rendered", radius_page)
            self.assertNotIn(b"password-not-rendered", radius_page)
            with patch("twn_toolkit.radius_routes.platform.system", return_value="Darwin"):
                mac_radius_page = client.get("/tools/radius-test").data
            self.assertIn(b"macOS EAP compatibility", mac_radius_page)
            self.assertIn(b'class="platform-warning"', mac_radius_page)
            self.assertIn(b"standard Homebrew formula", mac_radius_page)

            response = client.post(
                "/tools/radius-test/profiles/servers",
                data={
                    "original_name": "Primary RADIUS",
                    "name": "Primary RADIUS",
                    "host": "192.0.2.41",
                    "port": "1812",
                    "secret": "",
                },
            )
            self.assertEqual(response.status_code, 200)
            radius_page = client.get("/tools/radius-test").data
            self.assertIn(b"192.0.2.41", radius_page)
            self.assertNotIn(b"shared-secret-not-rendered", radius_page)

            radius_result = {
                "server_name": "Primary RADIUS",
                "server": "192.0.2.40",
                "port": 1812,
                "status": "Access-Accept",
                "response_ms": 8.4,
                "attributes": [{"name": "Reply-Message", "value": "Welcome"}],
            }
            with patch("twn_toolkit.radius_routes.radius_authenticate", return_value=[radius_result]) as auth:
                response = client.post(
                    "/tools/radius-test",
                    data={
                        "server_names": "Primary RADIUS",
                        "credential_name": "Test User",
                        "protocol": "pap",
                        "timeout": "3",
                        "retries": "1",
                        "attribute_profile": "HQ WLAN",
                    },
                )
            self.assertIn(b"Access-Accept", response.data)
            self.assertIn(b"Reply-Message", response.data)
            self.assertNotIn(b"password-not-rendered", response.data)
            auth.assert_called_once()
            summary = ActivityStore(instance).summary()
            self.assertEqual(summary["counters"]["radius"]["attempts"], 1)
            self.assertEqual(summary["counters"]["actions"]["total"], 5)
            self.assertEqual(summary["recent"][0]["title"], "Ran RADIUS test")

            with patch(
                "twn_toolkit.ssh_routes.run_ssh_hosts",
                return_value=[{"host": "switch-1", "host_label": "Closet Switch", "status": "success", "output": "ok"}],
            ) as ssh_run:
                response = client.post(
                    "/tools/multi-ssh",
                    data={
                        "hosts": "Closet Switch = switch-1",
                        "username": "admin",
                        "password": "not-rendered",
                        "port": "22",
                        "commands": "show version",
                        "confirm_execution": "on",
                    },
                )
            self.assertIn(b"ok", response.data)
            self.assertIn(b"Closet Switch", response.data)
            self.assertIn(b'data-address="switch-1"', response.data)
            self.assertNotIn(b"not-rendered", response.data)
            self.assertIn(b"Download all results", response.data)
            self.assertIn(b"Download this host", response.data)
            self.assertIn(b"multi-ssh-export.js", response.data)
            self.assertEqual(
                ssh_run.call_args.kwargs["hosts"],
                [{"label": "Closet Switch", "host": "switch-1"}],
            )
            ssh_event = AuditStore(instance).recent(1)[0]
            audit_database = Path(instance, "audit.sqlite3").read_bytes()
            self.assertEqual(
                ssh_event["action"], "ssh.multi_host_execution.run_succeeded"
            )
            self.assertEqual(ssh_event["details"]["host count"], 1)
            self.assertEqual(ssh_event["details"]["command count"], 1)
            self.assertNotIn(b"not-rendered", audit_database)
            self.assertNotIn(b"show version", audit_database)
            summary = ActivityStore(instance).summary()
            self.assertEqual(summary["counters"]["ip"]["lookups"], 1)
            self.assertEqual(summary["counters"]["speedtest"]["runs"], 1)
            self.assertEqual(summary["counters"]["speedtest"]["bytes_transferred"], 5122)
            self.assertEqual(summary["counters"]["subnet"]["calculations"], 1)
            self.assertEqual(summary["counters"]["subnet"]["networks"], 2)
            self.assertEqual(summary["counters"]["dns"]["queries"], 1)
            self.assertEqual(summary["counters"]["radius"]["attempts"], 1)
            self.assertEqual(summary["counters"]["ssh"]["hosts"], 1)
            self.assertEqual(summary["counters"]["ssh"]["commands"], 1)
            self.assertEqual(summary["counters"]["actions"]["total"], 6)
            self.assertEqual(summary["recent"][0]["title"], "Ran Multi-SSH")


if __name__ == "__main__":
    unittest.main()
