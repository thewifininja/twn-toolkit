from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.auth import AuthStore
from twn_toolkit.iperf_tools import (
    iperf3_capability,
    run_iperf3_client,
    run_iperf3_server,
    validate_iperf3_client_config,
    validate_iperf3_server_config,
)
from twn_toolkit.network_tools import ToolInputError


TCP_PAYLOAD = {
    "start": {
        "version": "iperf 3.18",
        "system_info": "Darwin test-host",
        "connected": [
            {
                "local_host": "192.0.2.10",
                "local_port": 50123,
                "remote_host": "192.0.2.20",
                "remote_port": 5201,
            }
        ],
        "test_start": {
            "protocol": "TCP",
            "duration": 10,
            "num_streams": 2,
            "reverse": 1,
        },
    },
    "intervals": [
        {
            "sum": {
                "start": 0,
                "end": 1,
                "seconds": 1,
                "bytes": 112_500_000,
                "bits_per_second": 900_000_000,
                "retransmits": 1,
                "sender": True,
            }
        }
    ],
    "end": {
        "sum_sent": {
            "seconds": 10,
            "bytes": 1_250_000_000,
            "bits_per_second": 1_000_000_000,
            "retransmits": 3,
            "sender": True,
        },
        "sum_received": {
            "seconds": 10,
            "bytes": 1_225_000_000,
            "bits_per_second": 980_000_000,
            "sender": False,
        },
        "cpu_utilization_percent": {
            "host_total": 7.25,
            "remote_total": 5.5,
        },
    },
}

UDP_PAYLOAD = {
    "start": {
        "version": "iperf 3.18",
        "connected": [
            {
                "local_host": "192.0.2.10",
                "local_port": 50124,
                "remote_host": "192.0.2.20",
                "remote_port": 5201,
            }
        ],
        "test_start": {
            "protocol": "UDP",
            "duration": 5,
            "num_streams": 1,
            "reverse": 0,
        },
    },
    "intervals": [],
    "end": {
        "sum_sent": {
            "seconds": 5,
            "bytes": 62_500_000,
            "bits_per_second": 100_000_000,
            "packets": 50_000,
            "sender": True,
        },
        "sum_received": {
            "seconds": 5,
            "bytes": 61_875_000,
            "bits_per_second": 99_000_000,
            "packets": 50_000,
            "lost_packets": 500,
            "lost_percent": 1.0,
            "jitter_ms": 0.42,
            "sender": False,
        },
    },
}


class IperfToolTests(unittest.TestCase):
    def test_capability_requires_existing_iperf3_binary(self) -> None:
        with patch("twn_toolkit.iperf_tools.shutil.which", return_value=None):
            missing = iperf3_capability()
        self.assertFalse(missing["available"])
        self.assertIn("not installed", missing["detail"])

        version = subprocess.CompletedProcess(
            ["/usr/bin/iperf3", "--version"],
            0,
            "iperf 3.18\n",
            "",
        )
        with (
            patch(
                "twn_toolkit.iperf_tools.shutil.which",
                return_value="/usr/bin/iperf3",
            ),
            patch(
                "twn_toolkit.iperf_tools.subprocess.run",
                return_value=version,
            ),
        ):
            available = iperf3_capability()
        self.assertTrue(available["available"])
        self.assertEqual(available["version"], "iperf 3.18")

    def test_client_builds_safe_command_and_normalizes_tcp_metrics(self) -> None:
        completed = subprocess.CompletedProcess(
            ["/usr/bin/iperf3"],
            0,
            json.dumps(TCP_PAYLOAD),
            "",
        )
        with (
            patch(
                "twn_toolkit.iperf_tools._iperf3_executable",
                return_value="/usr/bin/iperf3",
            ),
            patch(
                "twn_toolkit.iperf_tools.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            result = run_iperf3_client(
                {
                    "host": "iperf.example.test",
                    "port": 5201,
                    "protocol": "tcp",
                    "family": "ipv4",
                    "duration_seconds": 10,
                    "parallel_streams": 2,
                    "bind_address": "192.0.2.10",
                    "reverse": True,
                    "udp_megabits": 100,
                }
            )

        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/iperf3")
        self.assertIn("-R", command)
        self.assertIn("-4", command)
        self.assertNotIn("-u", command)
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(result["receiver"]["megabits_per_second"], 980.0)
        self.assertEqual(result["sender"]["retransmits"], 3)
        self.assertEqual(result["intervals"][0]["megabits_per_second"], 900.0)
        self.assertEqual(result["direction"], "reverse")
        self.assertEqual(result["cpu"]["host_total"], 7.25)

    def test_udp_client_sets_target_rate_and_reports_loss(self) -> None:
        completed = subprocess.CompletedProcess(
            ["/usr/bin/iperf3"],
            0,
            json.dumps(UDP_PAYLOAD),
            "",
        )
        with (
            patch(
                "twn_toolkit.iperf_tools._iperf3_executable",
                return_value="/usr/bin/iperf3",
            ),
            patch(
                "twn_toolkit.iperf_tools.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            result = run_iperf3_client(
                {
                    "host": "192.0.2.20",
                    "port": 5201,
                    "protocol": "udp",
                    "family": "auto",
                    "duration_seconds": 5,
                    "parallel_streams": 1,
                    "bind_address": "",
                    "reverse": False,
                    "udp_megabits": 100,
                }
            )

        command = run.call_args.args[0]
        self.assertIn("-u", command)
        self.assertEqual(command[command.index("-b") + 1], "100M")
        self.assertEqual(result["receiver"]["lost_percent"], 1.0)
        self.assertEqual(result["receiver"]["jitter_ms"], 0.42)

    def test_server_is_one_shot_and_normalizes_result(self) -> None:
        class FakeProcess:
            returncode = 0

            def communicate(self, timeout=None):
                return json.dumps(TCP_PAYLOAD), ""

        with (
            patch(
                "twn_toolkit.iperf_tools._iperf3_executable",
                return_value="/usr/bin/iperf3",
            ),
            patch(
                "twn_toolkit.iperf_tools.subprocess.Popen",
                return_value=FakeProcess(),
            ) as popen,
        ):
            result = run_iperf3_server(
                {
                    "bind_address": "0.0.0.0",
                    "port": 5201,
                    "window_seconds": 30,
                }
            )

        command = popen.call_args.args[0]
        self.assertIn("-s", command)
        self.assertIn("-1", command)
        self.assertIn("-J", command)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(result["mode"], "server")
        self.assertEqual(result["receiver"]["megabits_per_second"], 980.0)

    def test_server_timeout_terminates_listener(self) -> None:
        class TimeoutProcess:
            returncode = None

            def __init__(self):
                self.calls = 0
                self.terminated = False

            def communicate(self, timeout=None):
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired(["iperf3"], timeout)
                return "", ""

            def terminate(self):
                self.terminated = True

            def kill(self):
                raise AssertionError("clean termination should not require kill")

        process = TimeoutProcess()
        with (
            patch(
                "twn_toolkit.iperf_tools._iperf3_executable",
                return_value="/usr/bin/iperf3",
            ),
            patch(
                "twn_toolkit.iperf_tools.subprocess.Popen",
                return_value=process,
            ),
            self.assertRaisesRegex(ToolInputError, "server window closed"),
        ):
            run_iperf3_server(
                {
                    "bind_address": "127.0.0.1",
                    "port": 5201,
                    "window_seconds": 5,
                }
            )
        self.assertTrue(process.terminated)

    def test_rejects_unbounded_or_invalid_settings(self) -> None:
        valid_client = {
            "host": "example.test",
            "port": 5201,
            "protocol": "tcp",
            "family": "auto",
            "duration_seconds": 10,
            "parallel_streams": 1,
            "udp_megabits": 100,
        }
        with self.assertRaisesRegex(ToolInputError, "between 1 and 60"):
            validate_iperf3_client_config(
                {**valid_client, "duration_seconds": 61}
            )
        with self.assertRaisesRegex(ToolInputError, "between 1 and 20"):
            validate_iperf3_client_config(
                {**valid_client, "parallel_streams": 21}
            )
        with self.assertRaisesRegex(ToolInputError, "IPv4 or IPv6"):
            validate_iperf3_server_config(
                {
                    "bind_address": "all-interfaces",
                    "port": 5201,
                    "window_seconds": 30,
                }
            )

    def test_routes_require_authorization_and_record_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            capability = {
                "available": True,
                "executable": "/usr/bin/iperf3",
                "version": "iperf 3.18",
                "detail": "iperf 3.18",
            }
            with patch(
                "twn_toolkit.iperf_routes.iperf3_capability",
                return_value=capability,
            ):
                page = client.get("/tools/iperf3")
            self.assertIn(b"Run as client", page.data)
            self.assertIn(b"Listen as server", page.data)
            self.assertIn(b"one-shot", page.data)

            with (
                patch(
                    "twn_toolkit.iperf_routes.iperf3_capability",
                    return_value=capability,
                ),
                patch(
                    "twn_toolkit.iperf_routes.run_iperf3_client",
                    return_value={
                        **_route_result("client"),
                        "raw_json": json.dumps(TCP_PAYLOAD),
                    },
                ) as client_run,
            ):
                unauthorized = client.post(
                    "/tools/iperf3",
                    data={
                        "action": "client",
                        "client_host": "192.0.2.20",
                    },
                )
                response = client.post(
                    "/tools/iperf3",
                    data={
                        "action": "client",
                        "client_host": "192.0.2.20",
                        "client_port": "5201",
                        "client_protocol": "tcp",
                        "client_family": "auto",
                        "client_duration_seconds": "10",
                        "client_parallel_streams": "2",
                        "client_bind_address": "",
                        "client_reverse": "on",
                        "client_udp_megabits": "100",
                        "client_authorized": "on",
                    },
                )
            self.assertIn(b"Confirm that you are authorized", unauthorized.data)
            self.assertIn(b"TCP throughput result", response.data)
            self.assertIn(b"980.0 Mbps", response.data)
            client_run.assert_called_once()

            with (
                patch(
                    "twn_toolkit.iperf_routes.iperf3_capability",
                    return_value=capability,
                ),
                patch(
                    "twn_toolkit.iperf_routes.run_iperf3_server",
                    return_value={
                        **_route_result("server"),
                        "raw_json": json.dumps(TCP_PAYLOAD),
                    },
                ) as server_run,
            ):
                response = client.post(
                    "/tools/iperf3",
                    data={
                        "action": "server",
                        "server_bind_address": "0.0.0.0",
                        "server_port": "5201",
                        "server_window_seconds": "90",
                        "server_authorized": "on",
                    },
                )
            self.assertIn(b"Server test complete", response.data)
            server_run.assert_called_once()

            summary = ActivityStore(instance).summary()
            self.assertEqual(summary["counters"]["speedtest"]["runs"], 2)
            self.assertEqual(
                summary["counters"]["speedtest"]["bytes_transferred"],
                2_500_000_000,
            )
            event = AuditStore(instance).recent(1)[0]
            self.assertEqual(event["action"], "iperf3.server.run_succeeded")
            self.assertNotIn(
                b"iperf.example.test",
                Path(instance, "audit.sqlite3").read_bytes(),
            )

    def test_access_profile_controls_iperf3_route(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )
            store = AuthStore(instance)
            profile = store.save_access_profile(
                name="Throughput operators",
                tool_ids=["tools.iperf3"],
            )
            store.create_user(
                "throughput",
                "a different long password",
                access_profile_ids=[profile["id"]],
            )
            store.create_user(
                "unassigned",
                "another different password",
            )

            client.post("/logout")
            client.post(
                "/login",
                data={
                    "username": "throughput",
                    "password": "a different long password",
                },
            )
            self.assertEqual(client.get("/tools/iperf3").status_code, 200)

            client.post("/logout")
            client.post(
                "/login",
                data={
                    "username": "unassigned",
                    "password": "another different password",
                },
            )
            self.assertEqual(client.get("/tools/iperf3").status_code, 403)


def _route_result(mode: str) -> dict:
    return {
        "mode": mode,
        "protocol": "TCP",
        "direction": "reverse",
        "version": "iperf 3.18",
        "system_info": "",
        "connection": {
            "local_host": "192.0.2.10",
            "local_port": 50123,
            "remote_host": "192.0.2.20",
            "remote_port": 5201,
        },
        "sender": {
            "megabits_per_second": 1000.0,
            "bytes_display": "1.16 GiB",
            "retransmits": 3,
        },
        "receiver": {
            "megabits_per_second": 980.0,
            "bytes_display": "1.14 GiB",
        },
        "intervals": [],
        "cpu": {"host_total": 7.25, "remote_total": 5.5},
        "transferred_bytes": 1_250_000_000,
        "transferred_display": "1.16 GiB",
        "command": "iperf3",
        "raw_json_truncated": False,
    }


if __name__ == "__main__":
    unittest.main()
