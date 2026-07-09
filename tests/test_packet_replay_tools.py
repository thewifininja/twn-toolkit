from __future__ import annotations

import struct
import tempfile
import unittest
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.packet_replay_tools import (
    parse_hex_packet,
    parse_single_packet_capture,
    prepare_replay_plan,
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


class PacketReplayToolTests(unittest.TestCase):
    def test_parses_hex_with_separators(self) -> None:
        packet = parse_hex_packet("ff:ff ff-ff.ff_ff 02 00 00 00 00 01 08 06")
        self.assertEqual(packet, bytes.fromhex("ffffffffffff0200000000010806"))

    def test_parses_single_packet_pcap(self) -> None:
        self.assertEqual(parse_single_packet_capture(one_packet_pcap(IPV4_UDP_FRAME)), IPV4_UDP_FRAME)

    def test_rejects_multi_packet_pcap(self) -> None:
        data = one_packet_pcap(IPV4_UDP_FRAME) + one_packet_pcap(IPV4_UDP_FRAME)[24:]
        with self.assertRaises(ToolInputError):
            parse_single_packet_capture(data)

    def test_prepares_vlan_fanout_and_warnings(self) -> None:
        plan = prepare_replay_plan(
            IPV4_UDP_FRAME,
            source_mac="02-00-00-00-00-99",
            vlan_action="replace",
            vlan_ids="10,20",
            repeat_count=2,
            interval_seconds=0.5,
        )
        self.assertEqual(plan.summary["source_mac"], "02:00:00:00:00:99")
        self.assertEqual(plan.summary["vlan_targets"], [10, 20])
        self.assertEqual(plan.summary["frame_count"], 4)
        self.assertEqual(plan.frames[0][12:16], bytes.fromhex("8100000a"))
        self.assertEqual(plan.frames[1][12:16], bytes.fromhex("81000014"))
        self.assertIn("Destination MAC is broadcast.", plan.warnings)

    def test_limits_total_frames(self) -> None:
        with self.assertRaises(ToolInputError):
            prepare_replay_plan(
                IPV4_UDP_FRAME,
                vlan_action="replace",
                vlan_ids="1 2 3 4 5 6",
                repeat_count=20,
                interval_seconds=1.0,
            )

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
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Replay preview", response.data)
        self.assertIn(b"IPv4 / UDP", response.data)
        self.assertIn(b"Destination MAC is broadcast.", response.data)

    def test_route_requires_send_confirmation(self) -> None:
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
                        "action": "send",
                    },
                )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Type &#34;SEND&#34; to confirm packet transmission.', response.data)


if __name__ == "__main__":
    unittest.main()
