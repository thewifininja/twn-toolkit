from __future__ import annotations

import socket
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.dhcp_tools import (
    DHCP_MAGIC_COOKIE,
    _build_dhcp_discover_frame,
    _build_ipv4_udp_frame,
    _decode_option,
    _discover_offers_macos_bpf,
    _extract_dhcp_udp_payload,
    _internet_checksum,
    build_discover,
    discover_offers,
    parse_offer,
    parse_parameter_request_list,
)
from twn_toolkit.network_tools import ToolInputError


def make_offer(transaction_id: int, message_type: int = 2) -> bytes:
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2,
        1,
        6,
        0,
        transaction_id,
        0,
        0,
        b"\0" * 4,
        socket.inet_aton("192.0.2.50"),
        b"\0" * 4,
        b"\0" * 4,
        bytes.fromhex("020000000001") + b"\0" * 10,
        b"\0" * 64,
        b"\0" * 128,
    )
    options = (
        DHCP_MAGIC_COOKIE
        + bytes((53, 1, message_type))
        + bytes((54, 4))
        + socket.inet_aton("192.0.2.1")
        + bytes((1, 4))
        + socket.inet_aton("255.255.255.0")
        + bytes((51, 4))
        + (3600).to_bytes(4, "big")
        + b"\xff"
    )
    return header + options


class FakeSocket:
    def __init__(self, responses: list[bytes]):
        self.responses = list(responses)
        self.sent = []
        self.bound = None
        self.closed = False

    def setsockopt(self, *_args):
        pass

    def bind(self, address):
        self.bound = address

    def sendto(self, packet, address):
        self.sent.append((packet, address))

    def settimeout(self, _timeout):
        pass

    def recvfrom(self, _size):
        if self.responses:
            return self.responses.pop(0), ("192.0.2.1", 67)
        raise socket.timeout

    def close(self):
        self.closed = True


class DHCPToolTests(unittest.TestCase):
    def test_parses_named_and_numbered_parameter_request_list(self) -> None:
        self.assertEqual(
            parse_parameter_request_list("Subnet Mask, Router, 6, Domain Name, 119"),
            [1, 3, 6, 15, 119],
        )
        with self.assertRaises(ToolInputError):
            parse_parameter_request_list("Router, definitely-not-an-option")

    def test_builds_discover_with_requested_parameters(self) -> None:
        packet = build_discover(0x12345678, "02:00:00:00:00:01", [1, 3, 6])
        self.assertEqual(packet[0], 1)
        self.assertEqual(struct.unpack_from("!I", packet, 4)[0], 0x12345678)
        self.assertEqual(packet[10:12], b"\x80\x00")
        self.assertEqual(packet[236:240], DHCP_MAGIC_COOKIE)
        self.assertIn(bytes((53, 1, 1)), packet[240:])
        self.assertIn(bytes((55, 3, 1, 3, 6)), packet[240:])
        self.assertNotIn(bytes((53, 1, 3)), packet[240:])

    def test_decodes_offer_and_ignores_non_offer(self) -> None:
        offer = parse_offer(make_offer(77), 77, ("192.0.2.1", 67))
        self.assertIsNotNone(offer)
        self.assertEqual(offer["offered_address"], "192.0.2.50")
        self.assertEqual(offer["server_address"], "192.0.2.1")
        values = {item["code"]: item["value"] for item in offer["options"]}
        self.assertEqual(values[1], "255.255.255.0")
        self.assertEqual(values[51], "3600 seconds")
        self.assertIsNone(parse_offer(make_offer(77, message_type=5), 77, ("192.0.2.1", 67)))
        self.assertIsNone(parse_offer(make_offer(78), 77, ("192.0.2.1", 67)))

    def test_decodes_capwap_controller_ipv4_addresses(self) -> None:
        self.assertEqual(_decode_option(138, bytes.fromhex("0a 67 fe 01")), "10.103.254.1")
        self.assertEqual(
            _decode_option(138, bytes.fromhex("0a 67 fe 01 0a 67 fe 02")),
            "10.103.254.1, 10.103.254.2",
        )

    def test_discover_sends_exactly_one_discover_and_collects_offer(self) -> None:
        transaction_id = 0x10203040
        fake = FakeSocket([make_offer(transaction_id)])
        with (
            patch("twn_toolkit.dhcp_tools.sys.platform", "linux"),
            patch("twn_toolkit.dhcp_tools.socket.if_nameindex", return_value=[(2, "eth0")]),
            patch("twn_toolkit.dhcp_tools.socket.socket", return_value=fake),
            patch("twn_toolkit.dhcp_tools.os.urandom", return_value=transaction_id.to_bytes(4, "big")),
            patch(
                "twn_toolkit.dhcp_tools.time.monotonic",
                side_effect=[100.0, 100.01, 100.075, 100.21],
            ),
        ):
            offers = discover_offers("eth0", "02:00:00:00:00:01", [1, 3, 6], timeout=0.2)
        self.assertEqual(len(fake.sent), 1)
        self.assertEqual(fake.sent[0][1], ("255.255.255.255", 67))
        self.assertIn(bytes((53, 1, 1)), fake.sent[0][0])
        self.assertNotIn(bytes((53, 1, 3)), fake.sent[0][0])
        self.assertEqual(offers[0]["offered_address"], "192.0.2.50")
        self.assertEqual(offers[0]["response_time_ms"], 75.0)
        self.assertTrue(fake.closed)

    def test_builds_macos_bpf_discover_as_valid_ethernet_ipv4_udp(self) -> None:
        discover = build_discover(0x12345678, "02:00:00:00:00:01", [1, 3, 6])
        frame = _build_dhcp_discover_frame(discover, "02:11:22:33:44:55")

        self.assertEqual(frame[:6], b"\xff" * 6)
        self.assertEqual(frame[6:12], bytes.fromhex("021122334455"))
        self.assertEqual(struct.unpack_from("!H", frame, 12)[0], 0x0800)
        self.assertEqual(socket.inet_ntoa(frame[26:30]), "0.0.0.0")
        self.assertEqual(socket.inet_ntoa(frame[30:34]), "255.255.255.255")
        self.assertEqual(struct.unpack_from("!HH", frame, 34), (68, 67))
        self.assertEqual(_internet_checksum(frame[14:34]), 0)
        self.assertEqual(frame[42:], discover)

    def test_extracts_offer_from_plain_and_vlan_ethernet_frames(self) -> None:
        offer = make_offer(77)
        frame = _build_ipv4_udp_frame(
            offer,
            source_mac="02:11:22:33:44:55",
            destination_mac="ff:ff:ff:ff:ff:ff",
            source_address="192.0.2.1",
            destination_address="255.255.255.255",
            source_port=67,
            destination_port=68,
        )

        self.assertEqual(
            _extract_dhcp_udp_payload(frame),
            (offer, ("192.0.2.1", 67)),
        )
        vlan_frame = frame[:12] + b"\x81\x00\x00\x64" + frame[12:]
        self.assertEqual(
            _extract_dhcp_udp_payload(vlan_frame),
            (offer, ("192.0.2.1", 67)),
        )
        self.assertIsNone(_extract_dhcp_udp_payload(frame[:34] + b"\x00\x44" + frame[36:]))

    def test_macos_bpf_backend_opens_listener_before_sending_and_deduplicates(self) -> None:
        transaction_id = 0x10203040
        offer = make_offer(transaction_id)
        offer_frame = _build_ipv4_udp_frame(
            offer,
            source_mac="02:11:22:33:44:55",
            destination_mac="ff:ff:ff:ff:ff:ff",
            source_address="192.0.2.1",
            destination_address="255.255.255.255",
            source_port=67,
            destination_port=68,
        )
        events = []

        class FakePacket:
            def __init__(self, captured_at):
                self.time = captured_at

            def __bytes__(self):
                return offer_frame

        class FakeSocket:
            def __init__(self, role):
                self.role = role

            def send(self, frame):
                events.append(("send", frame))

            def close(self):
                events.append(("close", self.role))

        class FakeConf:
            use_pcap = False

            def L2listen(self, **kwargs):
                events.append(("listen", kwargs))
                return FakeSocket("listener")

            def L2socket(self, **kwargs):
                events.append(("sender", kwargs))
                return FakeSocket("sender")

        scapy = types.ModuleType("scapy")
        scapy_all = types.ModuleType("scapy.all")
        scapy_error = types.ModuleType("scapy.error")
        scapy_all.conf = FakeConf()

        def fake_sniff(**kwargs):
            events.append(("sniff", kwargs))
            return [FakePacket(500.036), FakePacket(500.12)]

        scapy_all.sniff = fake_sniff
        scapy_error.Scapy_Exception = type("Scapy_Exception", (Exception,), {})
        modules = {"scapy": scapy, "scapy.all": scapy_all, "scapy.error": scapy_error}
        discover = build_discover(transaction_id, "02:00:00:00:00:01", [1, 3, 6])
        with (
            patch.dict(sys.modules, modules),
            patch("twn_toolkit.dhcp_tools.interface_mac", return_value="02:11:22:33:44:55"),
            patch("twn_toolkit.dhcp_tools.time.time", return_value=500.0),
        ):
            offers = _discover_offers_macos_bpf(
                "en0",
                discover,
                transaction_id,
                timeout=0.2,
            )

        self.assertEqual([event[0] for event in events[:4]], ["listen", "sender", "send", "sniff"])
        self.assertEqual(len(offers), 1)
        self.assertEqual(offers[0]["offered_address"], "192.0.2.50")
        self.assertEqual(offers[0]["response_time_ms"], 36.0)
        self.assertTrue(scapy_all.conf.use_pcap)

    def test_discover_dispatches_to_bpf_on_macos_without_opening_udp_socket(self) -> None:
        transaction_id = 0x10203040
        with (
            patch("twn_toolkit.dhcp_tools.sys.platform", "darwin"),
            patch("twn_toolkit.dhcp_tools.socket.if_nameindex", return_value=[(2, "en0")]),
            patch("twn_toolkit.dhcp_tools.os.urandom", return_value=transaction_id.to_bytes(4, "big")),
            patch("twn_toolkit.dhcp_tools._discover_offers_macos_bpf", return_value=[]) as bpf,
            patch("twn_toolkit.dhcp_tools.socket.socket") as udp_socket,
        ):
            offers = discover_offers("en0", "02:00:00:00:00:01", [1, 3, 6], timeout=0.2)

        self.assertEqual(offers, [])
        bpf.assert_called_once()
        udp_socket.assert_not_called()

    def test_macos_bpf_permission_error_explains_persistent_user_access(self) -> None:
        class DeniedConf:
            use_pcap = False

            def L2listen(self, **_kwargs):
                raise PermissionError("denied")

        scapy = types.ModuleType("scapy")
        scapy_all = types.ModuleType("scapy.all")
        scapy_error = types.ModuleType("scapy.error")
        scapy_all.conf = DeniedConf()
        scapy_all.sniff = lambda **_kwargs: []
        scapy_error.Scapy_Exception = type("Scapy_Exception", (Exception,), {})
        modules = {"scapy": scapy, "scapy.all": scapy_all, "scapy.error": scapy_error}

        with patch.dict(sys.modules, modules):
            with self.assertRaisesRegex(ToolInputError, "ChmodBPF.*do not run.*root"):
                _discover_offers_macos_bpf(
                    "en0",
                    build_discover(77, "02:00:00:00:00:01", [1, 3, 6]),
                    77,
                    timeout=0.2,
                )

    def test_route_renders_discover_results(self) -> None:
        offer = {
            "offered_address": "192.0.2.50",
            "server_address": "192.0.2.1",
            "source_address": "192.0.2.1",
            "relay_address": "0.0.0.0",
            "next_server": "",
            "response_time_ms": 18.4,
            "options": [
                {"code": 1, "name": "Subnet Mask", "value": "255.255.255.0", "hex": "ff ff ff 00"}
            ],
        }
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            with (
                patch(
                    "twn_toolkit.dhcp_routes.available_interfaces",
                    return_value=[{"name": "eth0", "mac": "02:00:00:00:00:01"}],
                ),
                patch("twn_toolkit.dhcp_routes.discover_offers", return_value=[offer]),
            ):
                response = app.test_client().post(
                    "/tools/dhcp-discover",
                    data={
                        "interface": "eth0",
                        "mac": "02:00:00:00:00:01",
                        "parameters": "1, 3, 6",
                        "timeout": "1",
                    },
                )
            summary = ActivityStore(instance).summary()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Offer: 192.0.2.50", response.data)
        self.assertIn(b"responded in <strong>18.4 ms</strong>", response.data)
        self.assertIn(b"Response time", response.data)
        self.assertIn(b"Subnet Mask", response.data)
        self.assertIn(b"never sends a DHCP Request", response.data)
        self.assertIn(b"macOS sends and captures", response.data)
        self.assertEqual(summary["counters"]["dhcp"]["discovers"], 1)
        self.assertEqual(summary["counters"]["dhcp"]["offers"], 1)
        self.assertEqual(summary["counters"]["actions"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
