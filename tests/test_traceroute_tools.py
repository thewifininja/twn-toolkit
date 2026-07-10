from __future__ import annotations

import socket
import subprocess
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.traceroute_tools import (
    parse_traceroute_output,
    run_traceroute,
    stream_traceroute,
)


TRACE_OUTPUT = """traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  gateway.local (192.168.1.1)  1.201 ms  0.992 ms  1.004 ms
 2  10.20.0.1  6.301 ms  6.114 ms  6.221 ms
 3  * * *
 4  edge.example.net (93.184.216.34)  21.410 ms  20.908 ms  21.002 ms
"""


class TracerouteToolTests(unittest.TestCase):
    def test_parses_named_bare_and_unanswered_hops(self) -> None:
        hops = parse_traceroute_output(TRACE_OUTPUT)
        self.assertEqual(len(hops), 4)
        self.assertEqual(hops[0]["name"], "gateway.local")
        self.assertEqual(hops[0]["addresses"], ["192.168.1.1"])
        self.assertEqual(hops[1]["addresses"], ["10.20.0.1"])
        self.assertFalse(hops[2]["responded"])
        self.assertEqual(hops[2]["loss_percent"], 100)
        self.assertAlmostEqual(hops[3]["average_ms"], 21.107, places=3)
        ipv6_hop = parse_traceroute_output(" 1  localhost  0.105 ms  0.116 ms  0.097 ms")[0]
        self.assertEqual(ipv6_hop["name"], "localhost")

    def test_runs_trace_and_detects_destination(self) -> None:
        completed = subprocess.CompletedProcess(["traceroute"], 0, TRACE_OUTPUT, "")
        with (
            patch(
                "twn_toolkit.traceroute_tools.socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("93.184.216.34", 0))
                ],
            ),
            patch("twn_toolkit.traceroute_tools.shutil.which", return_value="/usr/sbin/traceroute"),
            patch("twn_toolkit.traceroute_tools.subprocess.run", return_value=completed),
        ):
            result = run_traceroute("example.com", max_hops=30, probes=3, timeout=2)
        self.assertTrue(result["reached"])
        self.assertEqual(result["hop_count"], 4)
        self.assertEqual(result["responding_hops"], 3)
        self.assertIn("/usr/sbin/traceroute", result["command"])

    def test_validates_trace_limits(self) -> None:
        with self.assertRaises(ToolInputError):
            run_traceroute("example.com", probes=4)
        with self.assertRaises(ToolInputError):
            run_traceroute("example.com", method="tcp")
        with self.assertRaises(ToolInputError):
            run_traceroute("example.com", timeout=1.5)

    def test_streams_output_and_hops_before_completion(self) -> None:
        class FakeProcess:
            def __init__(self):
                self.stdout = StringIO(TRACE_OUTPUT)
                self.returncode = None

            def wait(self, timeout=None):
                self.returncode = 0
                return 0

            def poll(self):
                return self.returncode

            def terminate(self):
                self.returncode = -15

            def kill(self):
                self.returncode = -9

        prepared = {
            "host": "example.com",
            "resolved_family": socket.AF_INET,
            "destination_addresses": {"93.184.216.34"},
            "method": "udp",
            "max_hops": 30,
            "probes": 3,
            "timeout": 2,
            "command": ["/usr/sbin/traceroute", "example.com"],
        }
        with patch("twn_toolkit.traceroute_tools.subprocess.Popen", return_value=FakeProcess()):
            events = list(stream_traceroute(prepared))
        event_types = [event["type"] for event in events]
        self.assertEqual(event_types[0], "start")
        self.assertEqual(event_types.count("hop"), 4)
        self.assertEqual(event_types[-1], "complete")
        self.assertTrue(events[-1]["reached"])

    def test_route_renders_visual_and_text_results(self) -> None:
        result = {
            "host": "example.com",
            "family": "IPv4",
            "method": "UDP",
            "raw_output": TRACE_OUTPUT,
            "hops": parse_traceroute_output(TRACE_OUTPUT),
            "hop_count": 4,
            "responding_hops": 3,
            "reached": True,
            "destination_addresses": ["93.184.216.34"],
        }
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            with patch("twn_toolkit.traceroute_routes.run_traceroute", return_value=result):
                response = app.test_client().post(
                    "/tools/traceroute",
                    data={
                        "host": "example.com",
                        "family": "auto",
                        "method": "udp",
                        "max_hops": "30",
                        "probes": "3",
                        "timeout": "2",
                    },
                )
            summary = ActivityStore(instance).summary()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"destination reached", response.data)
        self.assertIn(b"gateway.local", response.data)
        self.assertIn(b"Text Output", response.data)
        self.assertEqual(summary["counters"]["traceroute"]["completed"], 1)
        self.assertEqual(summary["counters"]["traceroute"]["hops"], 4)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(summary["recent"][0]["title"], "Ran traceroute")

    def test_streaming_route_records_completed_trace_activity(self) -> None:
        events = [
            {"type": "start", "host": "example.com", "family": "IPv4", "method": "UDP"},
            {"type": "hop", "hop": {"number": 1, "responded": True}},
            {"type": "complete", "reached": True, "hop_count": 1, "responding_hops": 1},
        ]
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            with (
                patch(
                    "twn_toolkit.traceroute_routes.prepare_traceroute",
                    return_value={
                        "host": "example.com",
                        "family": "auto",
                        "method": "udp",
                        "max_hops": 30,
                        "probes": 3,
                        "timeout": 2,
                        "command": ["traceroute", "example.com"],
                    },
                ),
                patch("twn_toolkit.traceroute_routes.stream_traceroute", return_value=events),
            ):
                response = app.test_client().post(
                    "/tools/traceroute/run",
                    json={"host": "example.com"},
                )
                payload = response.get_data(as_text=True)
            summary = ActivityStore(instance).summary()

        self.assertEqual(response.status_code, 200)
        self.assertIn('"type":"complete"', payload)
        self.assertEqual(summary["counters"]["traceroute"]["completed"], 1)
        self.assertEqual(summary["counters"]["traceroute"]["hops"], 1)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(summary["scoreboard"][0]["metrics"][0]["key"], "traceroute.completed")

    def test_traceroute_host_profile_crud(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            response = client.post(
                "/tools/traceroute/profiles",
                data={"name": "Public Targets", "values": "Example = example.com\n192.0.2.10"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["profile"]["count"], 2)
            page = client.get("/tools/traceroute").data
            self.assertIn(b"Public Targets", page)
            self.assertNotIn(b"built-in method values", page)
            response = client.post(
                "/tools/traceroute/profiles/delete",
                data={"name": "Public Targets"},
            )
            self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
