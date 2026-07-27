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
from twn_toolkit.iperf_server import (
    IperfJsonStreamCollector,
    IperfServerStore,
    run_managed_iperf3_server,
)
from twn_toolkit.iperf_tools import (
    iperf3_capability,
    run_iperf3_client,
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

    def test_json_stream_collector_builds_independent_server_result(self) -> None:
        collector = IperfJsonStreamCollector(
            config={"bind_address": "0.0.0.0", "port": 5201},
            command=["/usr/bin/iperf3", "-s", "--json-stream"],
        )
        self.assertEqual(
            collector.feed(
                json.dumps({"event": "start", "data": TCP_PAYLOAD["start"]})
            ),
            (None, ""),
        )
        collector.feed(
            json.dumps(
                {
                    "event": "interval",
                    "data": TCP_PAYLOAD["intervals"][0],
                }
            )
        )
        result, error = collector.feed(
            json.dumps({"event": "end", "data": TCP_PAYLOAD["end"]})
        )
        self.assertEqual(error, "")
        self.assertIsNotNone(result)
        self.assertEqual(result["mode"], "server")
        self.assertEqual(result["receiver"]["megabits_per_second"], 980.0)
        self.assertIsNone(collector.test_started_monotonic)

    def test_managed_server_store_retains_newest_source_results(self) -> None:
        result = {
            **_route_result("server"),
            "raw_json": json.dumps(TCP_PAYLOAD),
        }
        second = {
            **result,
            "connection": {
                **result["connection"],
                "remote_host": "198.51.100.24",
                "remote_port": 50124,
            },
        }
        with tempfile.TemporaryDirectory() as instance:
            store = IperfServerStore(instance)
            with patch(
                "twn_toolkit.iperf_server._iperf3_executable",
                return_value="/usr/bin/iperf3",
            ):
                session_id = store.create(
                    {"bind_address": "0.0.0.0", "port": 5201},
                    created_by="user-1",
                    created_by_username="operator",
                )
            session = store.begin(session_id)
            self.assertTrue(session["active"])
            self.assertTrue(store.record_result(session_id, result))
            self.assertTrue(store.record_result(session_id, second))

            results = store.recent_results("user-1")
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["source_ip"], "198.51.100.24")
            self.assertEqual(results[1]["source_ip"], "192.0.2.20")
            self.assertEqual(results[0]["summary_megabits_per_second"], 1000.0)
            self.assertEqual(store.recent_results("another-user"), [])

            stopping = store.request_stop(session_id, user_id="user-1")
            self.assertEqual(stopping["status"], "stopping")
            self.assertTrue(store.stop_requested(session_id))
            self.assertEqual(store.clear_results("user-1"), 2)
            self.assertEqual(store.recent_results("user-1"), [])

    def test_managed_server_history_is_bounded_per_user(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = IperfServerStore(instance)
            with patch(
                "twn_toolkit.iperf_server._iperf3_executable",
                return_value="/usr/bin/iperf3",
            ):
                session_id = store.create(
                    {"bind_address": "127.0.0.1", "port": 5201},
                    created_by="user-1",
                    created_by_username="operator",
                )
            store.begin(session_id)
            with patch(
                "twn_toolkit.iperf_server.IPERF_SERVER_RESULT_LIMIT",
                2,
            ):
                for source_port in (50001, 50002, 50003):
                    result = {
                        **_route_result("server"),
                        "connection": {
                            **_route_result("server")["connection"],
                            "remote_port": source_port,
                        },
                        "raw_json": json.dumps(TCP_PAYLOAD),
                    }
                    store.record_result(session_id, result)
            results = store.recent_results("user-1")
            self.assertEqual(
                [result["source_port"] for result in results],
                [50003, 50002],
            )

    def test_managed_server_store_allows_only_one_active_server_per_user(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = IperfServerStore(instance)
            with patch(
                "twn_toolkit.iperf_server._iperf3_executable",
                return_value="/usr/bin/iperf3",
            ):
                store.create(
                    {"bind_address": "127.0.0.1", "port": 5201},
                    created_by="user-1",
                    created_by_username="operator",
                )
                with self.assertRaisesRegex(
                    ToolInputError, "Stop your active"
                ):
                    store.create(
                        {"bind_address": "127.0.0.1", "port": 5202},
                        created_by="user-1",
                        created_by_username="operator",
                    )

    def test_managed_server_uses_streaming_process_and_stops_on_request(self) -> None:
        class RunningProcess:
            pid = 102
            returncode = None
            stdout = object()

            def __init__(self):
                self.terminated = False

            def poll(self):
                return None if not self.terminated else -15

            def send_signal(self, _signal):
                self.terminated = True
                self.returncode = -15

            def wait(self, timeout=None):
                return self.returncode

        class FakeSelector:
            def register(self, _stream, _event):
                return None

            def select(self, timeout=None):
                return []

            def close(self):
                return None

        process = RunningProcess()
        with (
            patch(
                "twn_toolkit.iperf_server._iperf3_executable",
                return_value="/usr/bin/iperf3",
            ),
            patch(
                "twn_toolkit.iperf_server.subprocess.Popen",
                return_value=process,
            ) as popen,
            patch(
                "twn_toolkit.iperf_server.selectors.DefaultSelector",
                return_value=FakeSelector(),
            ),
        ):
            outcome = run_managed_iperf3_server(
                {
                    "bind_address": "127.0.0.1",
                    "port": 5201,
                },
                should_stop=lambda: True,
                result_completed=lambda _result: None,
            )
        command = popen.call_args.args[0]
        self.assertIn("--json-stream", command)
        self.assertIn("--forceflush", command)
        self.assertNotIn("shell", popen.call_args.kwargs)
        self.assertEqual(outcome, "stopped")
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
        with (
            self.assertRaisesRegex(ToolInputError, "between 1 and 60")
        ):
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
                }
            )

    def test_routes_manage_server_lifecycle_and_private_result_cards(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )
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
            self.assertIn(b"Manage server", page.data)
            self.assertIn(b"Start server", page.data)
            self.assertIn(b"collapsed result cards", page.data)

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
                    "twn_toolkit.iperf_server._iperf3_executable",
                    return_value="/usr/bin/iperf3",
                ),
                patch(
                    "twn_toolkit.iperf_server.IperfServerStore.launch"
                ) as launch,
            ):
                unauthorized_server = client.post(
                    "/tools/iperf3/server/start",
                    data={
                        "server_bind_address": "0.0.0.0",
                        "server_port": "5201",
                    },
                )
                started = client.post(
                    "/tools/iperf3/server/start",
                    data={
                        "server_bind_address": "0.0.0.0",
                        "server_port": "5201",
                        "server_authorized": "on",
                    },
                )
            self.assertEqual(unauthorized_server.status_code, 302)
            self.assertEqual(started.status_code, 302)
            launch.assert_called_once()

            user_id = "test-user"
            managed_store = IperfServerStore(instance)
            active = managed_store.active_for_user(user_id)
            self.assertIsNotNone(active)
            active = managed_store.begin(active["id"])
            managed_store.record_result(
                active["id"],
                {
                    **_route_result("server"),
                    "raw_json": json.dumps(TCP_PAYLOAD),
                },
            )

            status = client.get(
                f"/tools/iperf3/server/{active['id']}/status"
            )
            self.assertEqual(status.status_code, 200)
            self.assertEqual(status.get_json()["result_count"], 1)
            self.assertIn("192.0.2.20", status.get_json()["results_html"])
            self.assertIn("Full iPerf3 JSON", status.get_json()["results_html"])

            stopped = client.post(
                f"/tools/iperf3/server/{active['id']}/stop"
            )
            self.assertEqual(stopped.status_code, 302)
            self.assertTrue(managed_store.stop_requested(active["id"]))
            cleared = client.post("/tools/iperf3/server/results/clear")
            self.assertEqual(cleared.status_code, 302)
            self.assertEqual(managed_store.recent_results(user_id), [])

            summary = ActivityStore(instance).summary()
            self.assertEqual(summary["counters"]["speedtest"]["runs"], 1)
            self.assertEqual(
                summary["counters"]["speedtest"]["bytes_transferred"],
                1_250_000_000,
            )
            event = AuditStore(instance).recent(1)[0]
            self.assertEqual(
                event["action"],
                "iperf3.server.run_history cleared",
            )
            self.assertNotIn(
                b"iperf.example.test",
                Path(instance, "audit.sqlite3").read_bytes(),
            )
            self.assertNotIn(
                b"192.0.2.20",
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
            self.assertEqual(
                client.post("/tools/iperf3/server/start").status_code,
                302,
            )

            client.post("/logout")
            client.post(
                "/login",
                data={
                    "username": "unassigned",
                    "password": "another different password",
                },
            )
            self.assertEqual(client.get("/tools/iperf3").status_code, 403)
            self.assertEqual(
                client.post("/tools/iperf3/server/start").status_code,
                403,
            )


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
