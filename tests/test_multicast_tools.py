from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.auth import AuthStore
from twn_toolkit.multicast_tools import (
    TEST_PACKET_HEADER,
    MulticastTestCancelled,
    _collect_multicast,
    build_test_packet,
    decode_test_packet,
    normalize_multicast_config,
    parse_rtp_header,
    receive_multicast,
    send_multicast,
)
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.tool_catalog import TOOL_BY_ID, tool_id_for_endpoint


INTERFACES = [
    {"name": "en0", "address": "192.0.2.10", "index": 1},
    {"name": "en1", "address": "198.51.100.10", "index": 2},
]


def _base_config(**overrides):
    config = {
        "mode": "listen",
        "group": "239.192.10.20",
        "port": 5000,
        "duration": 10,
        "membership": "asm",
        "source": "",
        "receive_interface": "en1",
        "send_interface": "en0",
        "stream_format": "generic",
        "rtp_clock_rate": 90000,
        "packet_size": 1200,
        "rate": 1,
        "rate_unit": "mbps",
        "ttl": 8,
        "dscp": 0,
        "source_port": 0,
        "loopback": False,
    }
    config.update(overrides)
    return config


def _listen_result():
    return {
        "mode": "listen",
        "status": "success",
        "summary": "Received 20 multicast packets.",
        "group": "239.192.10.20",
        "group_scope": "administratively scoped",
        "port": 5000,
        "membership": "ASM",
        "warnings": [],
        "packets_received": 20,
        "bytes_received": 24000,
        "average_packets_per_second": 2.0,
        "average_megabits_per_second": 0.0192,
        "ignored_source_packets": 0,
        "maximum_gap_ms": 5.2,
        "sources": [
            {
                "address": "192.0.2.50",
                "port": 4000,
                "packets": 20,
                "bytes": 24000,
                "first_seen_seconds": 0.1,
                "last_seen_seconds": 9.8,
                "expected": True,
            }
        ],
        "source_limit_reached": False,
        "timeline": [{"second": 0, "packets": 20, "bytes": 24000}],
        "test_payload": {"detected": False, "packets": 0, "sessions": []},
        "rtp_streams": [],
        "limitations": ["Generic UDP cannot prove exact loss."],
    }


class MulticastToolTests(unittest.TestCase):
    def test_normalizes_listener_sender_and_path_modes(self) -> None:
        listener = normalize_multicast_config(_base_config(), interfaces=INTERFACES)
        self.assertEqual(listener["receive_interface"]["address"], "198.51.100.10")
        self.assertEqual(listener["group_scope"], "administratively scoped")

        sender = normalize_multicast_config(
            _base_config(mode="send", group="232.1.2.3", rate=100, rate_unit="pps"),
            interfaces=INTERFACES,
        )
        self.assertEqual(sender["requested_packets"], 1000)
        self.assertEqual(sender["packets_per_second"], 100)

        path = normalize_multicast_config(
            _base_config(mode="path", group="232.1.2.3", membership="ssm"),
            interfaces=INTERFACES,
        )
        self.assertEqual(path["source"], "192.0.2.10")
        self.assertEqual(path["stream_format"], "twn")
        self.assertFalse(path["loopback"])

    def test_rejects_invalid_groups_interfaces_and_unbounded_sends(self) -> None:
        for config in (
            _base_config(group="192.0.2.10"),
            _base_config(receive_interface="missing"),
            _base_config(mode="path", receive_interface="en0", send_interface="en0"),
            _base_config(mode="listen", group="232.1.2.3", membership="asm"),
            _base_config(mode="send", rate=50_001, rate_unit="pps"),
        ):
            with self.subTest(config=config), self.assertRaises(ToolInputError):
                normalize_multicast_config(config, interfaces=INTERFACES)

    def test_builds_and_decodes_sequenced_test_payload(self) -> None:
        packet = build_test_packet("0011223344556677", 42, 123456789, 1200)
        self.assertEqual(len(packet), 1200)
        self.assertGreaterEqual(len(packet), TEST_PACKET_HEADER.size)
        self.assertEqual(
            decode_test_packet(packet),
            {
                "session_id": "0011223344556677",
                "sequence": 42,
                "sent_ns": 123456789,
                "size": 1200,
            },
        )
        self.assertIsNone(decode_test_packet(b"not a test packet"))

    def test_parses_rtp_v2_header(self) -> None:
        payload = bytes([0x80, 0xE0]) + (123).to_bytes(2, "big") + (456).to_bytes(4, "big") + (789).to_bytes(4, "big")
        self.assertEqual(
            parse_rtp_header(payload),
            {
                "payload_type": 96,
                "marker": 1,
                "sequence": 123,
                "timestamp": 456,
                "ssrc": 789,
                "header_size": 12,
            },
        )
        self.assertIsNone(parse_rtp_header(b"\x40" + bytes(20)))

    def test_collector_aggregates_sources_timeline_and_sequences(self) -> None:
        packet = build_test_packet("0011223344556677", 4, 123, 100)
        receiver = Mock()
        receiver.recvfrom.return_value = (packet, ("192.0.2.50", 4000))
        config = normalize_multicast_config(
            _base_config(duration=1, stream_format="twn"), interfaces=INTERFACES
        )
        with patch(
            "twn_toolkit.multicast_tools.time.monotonic",
            side_effect=[0.0, 0.1, 1.1, 1.1],
        ):
            result = _collect_multicast(receiver, config, started=0.0, started_wall=0.0)
        self.assertEqual(result["packets_received"], 1)
        self.assertEqual(result["sources"][0]["address"], "192.0.2.50")
        self.assertEqual(result["test_payload"]["sessions"][0]["first_sequence"], 4)
        self.assertEqual(result["minimum_packet_bytes"], 100)
        self.assertEqual(result["maximum_packet_bytes"], 100)

    def test_collector_emits_live_receive_progress(self) -> None:
        packet = build_test_packet("0011223344556677", 4, 123, 100)
        receiver = Mock()
        receiver.recvfrom.return_value = (packet, ("192.0.2.50", 4000))
        config = normalize_multicast_config(
            _base_config(duration=1, stream_format="twn"), interfaces=INTERFACES
        )
        events = []
        with patch(
            "twn_toolkit.multicast_tools.time.monotonic",
            side_effect=[0.0, 0.1, 1.1, 1.1],
        ):
            _collect_multicast(
                receiver,
                config,
                started=0.0,
                started_wall=0.0,
                progress=events.append,
            )
        self.assertEqual(events[-1]["phase"], "receiving")
        self.assertEqual(events[-1]["packets_received"], 1)
        self.assertEqual(events[-1]["top_sources"][0]["address"], "192.0.2.50")
        self.assertEqual(events[-1]["timeline"][0]["packets"], 1)

    def test_sender_sets_interface_ttl_dscp_and_emits_test_packet(self) -> None:
        fake_socket = Mock()
        fake_socket.getsockname.return_value = ("192.0.2.10", 42000)
        fake_socket.sendto.side_effect = lambda payload, _destination: len(payload)
        config = normalize_multicast_config(
            _base_config(mode="send", duration=1, rate=1, rate_unit="pps"),
            interfaces=INTERFACES,
        )
        with (
            patch("twn_toolkit.multicast_tools.socket.socket", return_value=fake_socket),
            patch(
                "twn_toolkit.multicast_tools.time.monotonic",
                side_effect=[0.0, 0.1, 0.2, 0.3, 1.0],
            ),
            patch("twn_toolkit.multicast_tools.time.sleep"),
        ):
            result = send_multicast(config, session_id="0011223344556677")
        payload, destination = fake_socket.sendto.call_args.args
        self.assertEqual(destination, ("239.192.10.20", 5000))
        self.assertEqual(decode_test_packet(payload)["sequence"], 0)
        self.assertEqual(result["packets_sent"], 1)
        self.assertEqual(result["source_port"], 42000)

    def test_receiver_uses_source_specific_membership_layout(self) -> None:
        fake_socket = Mock()
        config = normalize_multicast_config(
            _base_config(membership="ssm", source="192.0.2.50"),
            interfaces=INTERFACES,
        )
        with (
            patch("twn_toolkit.multicast_tools.socket.socket", return_value=fake_socket),
            patch("twn_toolkit.multicast_tools._collect_multicast", return_value={"status": "success"}),
        ):
            result = receive_multicast(config)
        self.assertEqual(result["status"], "success")
        membership_calls = [
            call
            for call in fake_socket.setsockopt.call_args_list
            if call.args[0] == socket.IPPROTO_IP and call.args[1] not in {socket.IP_ADD_MEMBERSHIP}
        ]
        self.assertTrue(membership_calls)
        request = membership_calls[-1].args[2]
        group = socket.inet_aton("239.192.10.20")
        source = socket.inet_aton("192.0.2.50")
        local = socket.inet_aton("198.51.100.10")
        self.assertEqual(request, group + source + local if __import__("sys").platform == "darwin" else group + local + source)

    def test_receiver_allows_shared_multicast_ports(self) -> None:
        fake_socket = Mock()
        config = normalize_multicast_config(
            _base_config(group="224.0.0.251", port=5353, duration=1),
            interfaces=INTERFACES,
        )
        with (
            patch("twn_toolkit.multicast_tools.socket.socket", return_value=fake_socket),
            patch(
                "twn_toolkit.multicast_tools._collect_multicast",
                return_value={"status": "success"},
            ),
        ):
            receive_multicast(config)
        fake_socket.setsockopt.assert_any_call(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )
        if hasattr(socket, "SO_REUSEPORT"):
            fake_socket.setsockopt.assert_any_call(
                socket.SOL_SOCKET,
                socket.SO_REUSEPORT,
                1,
            )
        fake_socket.bind.assert_called_once_with(("", 5353))

    def test_sender_honors_stream_cancellation(self) -> None:
        fake_socket = Mock()
        fake_socket.getsockname.return_value = ("192.0.2.10", 42000)
        config = normalize_multicast_config(
            _base_config(mode="send", duration=1, rate=1, rate_unit="pps"),
            interfaces=INTERFACES,
        )
        cancelled = threading.Event()
        cancelled.set()
        with (
            patch("twn_toolkit.multicast_tools.socket.socket", return_value=fake_socket),
            patch(
                "twn_toolkit.multicast_tools.time.monotonic",
                side_effect=[0.0],
            ),
            self.assertRaises(MulticastTestCancelled),
        ):
            send_multicast(config, cancelled=cancelled)

    def test_route_renders_report_records_bounded_activity_and_is_grantable(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )
            capability = {"available": True, "interfaces": INTERFACES, "asm": True, "ssm": True, "detail": "2 interfaces"}
            with (
                patch("twn_toolkit.multicast_routes.multicast_capability", return_value=capability),
                patch("twn_toolkit.multicast_routes.run_multicast_test", return_value=_listen_result()),
            ):
                page = client.post(
                    "/tools/multicast",
                    data={
                        **{key: str(value) for key, value in _base_config().items()},
                        "authorized": "on",
                    },
                )
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Received 20 multicast packets", page.data)
            self.assertIn(b"Download JSON", page.data)
            summary = ActivityStore(instance).summary()
            self.assertEqual(summary["counters"]["multicast"]["tests"], 1)
            self.assertEqual(summary["counters"]["multicast"]["packets_received"], 20)
            event = AuditStore(instance).recent(1)[0]
            self.assertEqual(event["action"], "multicast.run_success")
            self.assertNotIn("239.192.10.20", str(event["details"]))

            store = AuthStore(instance)
            profile = store.save_access_profile(name="Multicast only", tool_ids=["tools.multicast"])
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
            with patch("twn_toolkit.multicast_routes.multicast_capability", return_value=capability):
                self.assertEqual(client.get("/tools/multicast").status_code, 200)
            self.assertEqual(client.get("/tools/packet-replay").status_code, 403)

        self.assertIn("tools.multicast", TOOL_BY_ID)
        self.assertEqual(tool_id_for_endpoint("tools.multicast"), "tools.multicast")

    def test_live_route_streams_progress_and_completed_report(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
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
                "interfaces": INTERFACES,
                "asm": True,
                "ssm": True,
                "detail": "2 interfaces",
            }

            def run_live(_config, *, interfaces, progress, cancelled):
                self.assertEqual(interfaces, INTERFACES)
                self.assertFalse(cancelled.is_set())
                progress(
                    {
                        "type": "progress",
                        "phase": "receiving",
                        "elapsed_seconds": 0.5,
                        "remaining_seconds": 0.5,
                        "packets_received": 10,
                        "bytes_received": 12000,
                        "sources": 1,
                        "timeline": [{"second": 0, "packets": 10, "bytes": 12000}],
                    }
                )
                return _listen_result()

            with (
                patch(
                    "twn_toolkit.multicast_routes.multicast_capability",
                    return_value=capability,
                ),
                patch(
                    "twn_toolkit.multicast_routes.run_multicast_test",
                    side_effect=run_live,
                ),
            ):
                response = client.post(
                    "/tools/multicast/live",
                    json={**_base_config(duration=1), "authorized": True},
                )
                events = [
                    json.loads(line)
                    for line in response.data.decode().splitlines()
                ]

            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                [event["type"] for event in events],
                ["progress", "complete"],
            )
            self.assertIn("Received 20 multicast packets", events[-1]["html"])
            summary = ActivityStore(instance).summary()
            self.assertEqual(summary["counters"]["multicast"]["tests"], 1)
            self.assertEqual(
                summary["counters"]["multicast"]["packets_received"],
                20,
            )
            audit = AuditStore(instance).recent(1)[0]
            self.assertEqual(audit["action"], "multicast.stream.run_started")
            self.assertNotIn("239.192.10.20", str(audit["details"]))


if __name__ == "__main__":
    unittest.main()
