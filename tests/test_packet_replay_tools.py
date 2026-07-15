from __future__ import annotations

import struct
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.packet_replay_tools import (
    parse_hex_packet,
    parse_packet_capture,
    parse_single_packet_capture,
    prepare_replay_plan,
    send_replay_frames,
)


IPV4_UDP_FRAME = bytes.fromhex(
    "ffffffffffff0200000000010800"
    "450000200001000040110000c0000201c6336402"
    "14e914e9000c000074657374"
)


def one_packet_pcap(packet: bytes) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 2, len(packet), len(packet))
    return header + record + packet


def multi_packet_pcap(*packets: bytes) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for index, packet in enumerate(packets, start=1):
        records.append(struct.pack("<IIII", index, 0, len(packet), len(packet)) + packet)
    return header + b"".join(records)


class PacketReplayToolTests(unittest.TestCase):
    def test_parses_hex_with_separators(self) -> None:
        packet = parse_hex_packet("ff:ff ff-ff.ff_ff 02 00 00 00 00 01 08 06")
        self.assertEqual(packet, bytes.fromhex("ffffffffffff0200000000010806"))

    def test_parses_single_packet_pcap(self) -> None:
        self.assertEqual(parse_single_packet_capture(one_packet_pcap(IPV4_UDP_FRAME)), IPV4_UDP_FRAME)

    def test_parses_multi_packet_pcap(self) -> None:
        second = IPV4_UDP_FRAME.replace(b"test", b"next")
        self.assertEqual(
            parse_packet_capture(multi_packet_pcap(IPV4_UDP_FRAME, second)),
            [IPV4_UDP_FRAME, second],
        )

    def test_single_packet_parser_still_rejects_multi_packet_pcap(self) -> None:
        data = multi_packet_pcap(IPV4_UDP_FRAME, IPV4_UDP_FRAME)
        with self.assertRaises(ToolInputError):
            parse_single_packet_capture(data)

    def test_prepares_vlan_fanout_and_notes(self) -> None:
        plan = prepare_replay_plan(
            IPV4_UDP_FRAME,
            source_mac="02-00-00-00-00-99",
            vlan_action="replace",
            vlan_ids="10,20",
            repeat_count=2,
            interval_seconds=0.5,
        )
        self.assertEqual(plan.summary["source_mac"], "02:00:00:00:00:99")
        self.assertEqual(plan.summary["packet_count"], 1)
        self.assertEqual(plan.summary["vlan_targets"], [10, 20])
        self.assertEqual(plan.summary["frame_count"], 4)
        self.assertEqual(plan.frames[0][12:16], bytes.fromhex("8100000a"))
        self.assertEqual(plan.frames[1][12:16], bytes.fromhex("81000014"))
        self.assertIn("81 00 00 0a 08 00", plan.summary["first_replay_header_hex"])
        self.assertIn("Destination MAC is broadcast.", plan.warnings)
        self.assertTrue(any("VLAN fanout" in note for note in plan.summary["notes"]))

    def test_keep_vlan_tags_ignores_vlan_fanout_text(self) -> None:
        plan = prepare_replay_plan(
            IPV4_UDP_FRAME,
            vlan_action="keep",
            vlan_ids="untagged,10-12",
            repeat_count=1,
            interval_seconds=0.5,
        )
        self.assertEqual(plan.summary["vlan_targets"], [])
        self.assertEqual(plan.summary["vlan_target_labels"], [])
        self.assertEqual(plan.summary["frame_count"], 1)
        self.assertEqual(plan.frames, [IPV4_UDP_FRAME])

    def test_prepares_vlan_ranges_untagged_and_priority_tagged(self) -> None:
        plan = prepare_replay_plan(
            IPV4_UDP_FRAME,
            vlan_action="replace",
            vlan_ids="untagged,10-11,0",
            repeat_count=1,
            interval_seconds=0.5,
        )
        self.assertEqual(plan.summary["vlan_targets"], [None, 10, 11, 0])
        self.assertEqual(
            plan.summary["vlan_target_labels"],
            ["untagged", "10", "11", "0 (priority tag)"],
        )
        self.assertEqual(plan.summary["frame_count"], 4)
        self.assertEqual(plan.frames[0][12:14], bytes.fromhex("0800"))
        self.assertEqual(plan.frames[1][12:16], bytes.fromhex("8100000a"))
        self.assertEqual(plan.frames[2][12:16], bytes.fromhex("8100000b"))
        self.assertEqual(plan.frames[3][12:16], bytes.fromhex("81000000"))

    def test_notes_macos_vlan_capture_filter(self) -> None:
        with patch("twn_toolkit.packet_replay_tools.sys.platform", "darwin"):
            plan = prepare_replay_plan(
                IPV4_UDP_FRAME,
                vlan_action="replace",
                vlan_ids="10",
                repeat_count=1,
                interval_seconds=0.5,
            )
        self.assertTrue(any("macOS" in note and "VLAN-aware capture filter" in note for note in plan.summary["notes"]))

    def test_prepares_multi_packet_plan(self) -> None:
        second = IPV4_UDP_FRAME.replace(b"test", b"next")
        plan = prepare_replay_plan(
            [IPV4_UDP_FRAME, second],
            repeat_count=2,
            interval_seconds=0.5,
        )
        self.assertEqual(plan.summary["packet_count"], 2)
        self.assertEqual(plan.summary["frame_count"], 4)
        self.assertEqual(plan.frames, [IPV4_UDP_FRAME, second, IPV4_UDP_FRAME, second])

    def test_allows_large_repeat_and_vlan_fanout(self) -> None:
        plan = prepare_replay_plan(
            IPV4_UDP_FRAME,
            vlan_action="replace",
            vlan_ids="1-25",
            repeat_count=25,
            interval_seconds=1.0,
        )
        self.assertEqual(plan.summary["frame_count"], 625)
        self.assertEqual(len(plan.frames), 625)

    def test_linux_sender_uses_raw_socket(self) -> None:
        sent_frames: list[bytes] = []

        class FakeSocket:
            def __enter__(self) -> "FakeSocket":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def bind(self, address: tuple[str, int]) -> None:
                self.address = address

            def send(self, frame: bytes) -> int:
                sent_frames.append(frame)
                return len(frame)

        with (
            patch("twn_toolkit.packet_replay_tools.sys.platform", "linux"),
            patch("twn_toolkit.packet_replay_tools.socket.AF_PACKET", 17, create=True),
            patch("twn_toolkit.packet_replay_tools.socket.SOCK_RAW", 3),
            patch("twn_toolkit.packet_replay_tools.socket.socket", return_value=FakeSocket()),
            patch("twn_toolkit.packet_replay_tools.time.sleep"),
        ):
            result = send_replay_frames(
                [IPV4_UDP_FRAME, IPV4_UDP_FRAME],
                interface="eth0",
                interval_seconds=0.1,
            )
        self.assertEqual(result["sent"], 2)
        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["method"], "linux raw socket")
        self.assertIn("kernel accepted", result["detail"])
        self.assertEqual(sent_frames, [IPV4_UDP_FRAME, IPV4_UDP_FRAME])

    def test_darwin_sender_forces_scapy_pcap(self) -> None:
        sent_packets = []
        closed = []

        class FakeSocket:
            def __init__(self, *, iface: str) -> None:
                self.iface = iface

            def send(self, packet: bytes) -> int:
                sent_packets.append((self.iface, packet))
                return len(packet)

            def close(self) -> None:
                closed.append(True)

        class FakeConf:
            use_pcap = False
            L2socket = FakeSocket

        with (
            patch("twn_toolkit.packet_replay_tools.sys.platform", "darwin"),
            patch.dict(
                "sys.modules",
                {
                    "scapy": object(),
                    "scapy.all": type(
                        "FakeScapyAll",
                        (),
                        {
                            "conf": FakeConf,
                        },
                    ),
                    "scapy.error": type(
                        "FakeScapyError",
                        (),
                        {"Scapy_Exception": Exception},
                    ),
                },
            ),
        ):
            result = send_replay_frames(
                [IPV4_UDP_FRAME],
                interface="en0",
                interval_seconds=0.1,
            )
        self.assertTrue(FakeConf.use_pcap)
        self.assertEqual(result["sent"], 1)
        self.assertEqual(result["method"], "scapy/libpcap raw socket")
        self.assertEqual(sent_packets, [("en0", IPV4_UDP_FRAME)])
        self.assertEqual(closed, [True])

    def test_darwin_vlan_sender_uses_scapy_bpf(self) -> None:
        sent_packets = []

        class FakeSocket:
            def __init__(self, *, iface: str) -> None:
                self.iface = iface

            def send(self, packet: bytes) -> int:
                sent_packets.append((self.iface, packet))
                return len(packet)

            def close(self) -> None:
                pass

        class FakeConf:
            use_pcap = True
            L2socket = FakeSocket

        plan = prepare_replay_plan(
            IPV4_UDP_FRAME,
            vlan_action="replace",
            vlan_ids="10",
            repeat_count=1,
            interval_seconds=0.1,
        )

        with (
            patch("twn_toolkit.packet_replay_tools.sys.platform", "darwin"),
            patch.dict(
                "sys.modules",
                {
                    "scapy": object(),
                    "scapy.all": type(
                        "FakeScapyAll",
                        (),
                        {
                            "conf": FakeConf,
                        },
                    ),
                    "scapy.error": type(
                        "FakeScapyError",
                        (),
                        {"Scapy_Exception": Exception},
                    ),
                },
            ),
        ):
            result = send_replay_frames(
                plan.frames,
                interface="en0",
                interval_seconds=0.1,
            )
        self.assertFalse(FakeConf.use_pcap)
        self.assertEqual(result["method"], "scapy/BPF raw socket")
        self.assertEqual(sent_packets, [("en0", plan.frames[0])])
        self.assertEqual(sent_packets[0][1][12:16], bytes.fromhex("8100000a"))

    def test_route_previews_packet(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            with patch(
                "twn_toolkit.packet_replay_routes.available_interfaces",
                return_value=[{"name": "eth0", "mac": "02:00:00:00:00:01"}],
            ):
                response = app.test_client().post(
                    "/tools/packet-replay",
                    data={
                        "interface": "eth0",
                        "packet_hex": IPV4_UDP_FRAME.hex(),
                        "vlan_action": "keep",
                        "repeat_count": "1",
                        "interval_seconds": "1",
                        "action": "preview",
                    },
                )
            preview_summary = ActivityStore(instance).summary()
            preview_events = AuditStore(instance).recent(10)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Replay preview", response.data)
        self.assertIn(b"IPv4 / UDP", response.data)
        self.assertIn(b"Destination MAC is broadcast.", response.data)
        self.assertIn(b"First replay header bytes", response.data)
        self.assertEqual(preview_summary["counters"]["actions"]["total"], 0)
        self.assertEqual(preview_summary["counters"]["packet_replay"]["frames"], 0)
        self.assertEqual(preview_events, [])

    def test_route_sends_without_typed_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            with (
                patch(
                    "twn_toolkit.packet_replay_routes.available_interfaces",
                    return_value=[{"name": "eth0", "mac": "02:00:00:00:00:01"}],
                ),
                patch(
                    "twn_toolkit.packet_replay_routes.send_replay_frames",
                    return_value={
                        "sent": 1,
                        "attempted": 1,
                        "interface": "eth0",
                        "elapsed_seconds": 0.01,
                        "method": "test sender",
                    },
                ) as sender,
            ):
                response = app.test_client().post(
                    "/tools/packet-replay",
                    data={
                        "interface": "eth0",
                        "packet_hex": IPV4_UDP_FRAME.hex(),
                        "vlan_action": "keep",
                        "repeat_count": "1",
                        "interval_seconds": "1",
                        "action": "send",
                    },
                )
            summary = ActivityStore(instance).summary()
            event = AuditStore(instance).recent(1)[0]
            audit_database = Path(instance, "audit.sqlite3").read_bytes()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sender.call_count, 1)
        self.assertIn(b"Send request completed", response.data)
        self.assertEqual(summary["counters"]["packet_replay"]["frames"], 1)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)
        self.assertEqual(event["action"], "packet_replay.run_succeeded")
        self.assertEqual(event["details"]["frame count"], 1)
        self.assertNotIn(IPV4_UDP_FRAME.hex().encode(), audit_database)

    def test_route_sends_confirmed_plan(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            with (
                patch(
                    "twn_toolkit.packet_replay_routes.available_interfaces",
                    return_value=[{"name": "eth0", "mac": "02:00:00:00:00:01"}],
                ),
                patch(
                    "twn_toolkit.packet_replay_routes.send_replay_frames",
                    return_value={
                        "sent": 1,
                        "attempted": 1,
                        "interface": "eth0",
                        "elapsed_seconds": 0.01,
                        "method": "test sender",
                        "detail": "test detail",
                    },
                ) as sender,
            ):
                response = app.test_client().post(
                    "/tools/packet-replay",
                    data={
                        "interface": "eth0",
                        "packet_hex": IPV4_UDP_FRAME.hex(),
                        "vlan_action": "keep",
                        "repeat_count": "1",
                        "interval_seconds": "1",
                        "action": "send",
                    },
                )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sender.call_count, 1)
        self.assertNotIn(b"Send requested for interface", response.data)
        self.assertIn(b"Send request completed: 1 frame accepted by test sender", response.data)
        self.assertIn(b"test detail", response.data)

    def test_route_sends_previously_uploaded_packet(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            with patch(
                "twn_toolkit.packet_replay_routes.available_interfaces",
                return_value=[{"name": "eth0", "mac": "02:00:00:00:00:01"}],
            ):
                preview = client.post(
                    "/tools/packet-replay",
                    data={
                        "interface": "eth0",
                        "packet_file": (BytesIO(one_packet_pcap(IPV4_UDP_FRAME)), "one.pcap"),
                        "vlan_action": "keep",
                        "repeat_count": "1",
                        "interval_seconds": "1",
                        "action": "preview",
                    },
                    content_type="multipart/form-data",
                )
            self.assertEqual(preview.status_code, 200)
            self.assertIn(b'name="prepared_packet_hex"', preview.data)
            with (
                patch(
                    "twn_toolkit.packet_replay_routes.available_interfaces",
                    return_value=[{"name": "eth0", "mac": "02:00:00:00:00:01"}],
                ),
                patch(
                    "twn_toolkit.packet_replay_routes.send_replay_frames",
                    return_value={
                        "sent": 1,
                        "attempted": 1,
                        "interface": "eth0",
                        "elapsed_seconds": 0.01,
                        "method": "test sender",
                    },
                ) as sender,
            ):
                response = client.post(
                    "/tools/packet-replay",
                    data={
                        "interface": "eth0",
                        "packet_hex": "",
                        "prepared_packet_hex": IPV4_UDP_FRAME.hex(),
                        "vlan_action": "keep",
                        "repeat_count": "1",
                        "interval_seconds": "1",
                        "action": "send",
                    },
                )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sender.call_count, 1)
        sent_frames = sender.call_args.args[0]
        self.assertEqual(sent_frames, [IPV4_UDP_FRAME])
        self.assertIn(b"Send request completed: 1 frame accepted", response.data)

    def test_route_sends_previously_uploaded_multi_packet_capture(self) -> None:
        second = IPV4_UDP_FRAME.replace(b"test", b"next")
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            with patch(
                "twn_toolkit.packet_replay_routes.available_interfaces",
                return_value=[{"name": "eth0", "mac": "02:00:00:00:00:01"}],
            ):
                preview = client.post(
                    "/tools/packet-replay",
                    data={
                        "interface": "eth0",
                        "packet_file": (
                            BytesIO(multi_packet_pcap(IPV4_UDP_FRAME, second)),
                            "two.pcap",
                        ),
                        "vlan_action": "keep",
                        "repeat_count": "1",
                        "interval_seconds": "1",
                        "action": "preview",
                    },
                    content_type="multipart/form-data",
                )
            self.assertEqual(preview.status_code, 200)
            self.assertIn(b"2 source packets", preview.data)
            with (
                patch(
                    "twn_toolkit.packet_replay_routes.available_interfaces",
                    return_value=[{"name": "eth0", "mac": "02:00:00:00:00:01"}],
                ),
                patch(
                    "twn_toolkit.packet_replay_routes.send_replay_frames",
                    return_value={
                        "sent": 2,
                        "attempted": 2,
                        "interface": "eth0",
                        "elapsed_seconds": 0.01,
                        "method": "test sender",
                    },
                ) as sender,
            ):
                response = client.post(
                    "/tools/packet-replay",
                    data={
                        "interface": "eth0",
                        "packet_hex": "",
                        "prepared_packet_hex": f"{IPV4_UDP_FRAME.hex()}|{second.hex()}",
                        "vlan_action": "keep",
                        "repeat_count": "1",
                        "interval_seconds": "1",
                        "action": "send",
                    },
                )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sender.call_count, 1)
        sent_frames = sender.call_args.args[0]
        self.assertEqual(sent_frames, [IPV4_UDP_FRAME, second])
        self.assertIn(b"Send request completed: 2 frames accepted", response.data)


if __name__ == "__main__":
    unittest.main()
