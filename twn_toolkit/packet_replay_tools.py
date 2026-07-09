from __future__ import annotations

import re
import struct
import time
from dataclasses import dataclass
from typing import Any

from .network_tools import ToolInputError


MAX_PACKET_BYTES = 9216
MAX_UPLOAD_BYTES = 256 * 1024
MAX_REPEATS = 20
MAX_TOTAL_FRAMES = 100
MIN_INTERVAL_SECONDS = 0.1
MAX_INTERVAL_SECONDS = 60.0
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
MULTICAST_PREFIXES = ("01:00:5e", "33:33")


@dataclass(frozen=True)
class ReplayPlan:
    original: bytes
    frames: list[bytes]
    summary: dict[str, Any]
    warnings: list[str]


def parse_hex_packet(value: str) -> bytes:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if not cleaned:
        raise ToolInputError("Paste packet hex or upload a single-packet capture.")
    if len(cleaned) % 2:
        raise ToolInputError("Packet hex must contain an even number of hex digits.")
    try:
        packet = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ToolInputError("Packet hex contains invalid characters.") from exc
    return _validate_frame_size(packet)


def parse_single_packet_capture(data: bytes) -> bytes:
    if len(data) > MAX_UPLOAD_BYTES:
        raise ToolInputError("Capture upload is too large. Upload one packet, not a full trace.")
    if len(data) < 24:
        raise ToolInputError("Upload a classic PCAP or paste raw packet hex.")

    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
    else:
        raise ToolInputError("Only classic single-packet PCAP uploads are supported right now.")

    if len(data) < 40:
        raise ToolInputError("The PCAP does not contain a packet record.")
    _ts_sec, _ts_frac, included_length, original_length = struct.unpack_from(
        f"{endian}IIII", data, 24
    )
    if included_length != original_length:
        raise ToolInputError("The packet in the PCAP is truncated. Export the full packet.")
    start = 40
    end = start + included_length
    if len(data) < end:
        raise ToolInputError("The PCAP packet record is incomplete.")
    remaining = data[end:]
    if remaining.strip(b"\0"):
        raise ToolInputError("Upload a PCAP containing exactly one packet.")
    return _validate_frame_size(data[start:end])


def prepare_replay_plan(
    packet: bytes,
    *,
    source_mac: str = "",
    destination_mac: str = "",
    vlan_action: str = "keep",
    vlan_ids: str = "",
    repeat_count: int = 1,
    interval_seconds: float = 1.0,
) -> ReplayPlan:
    original = _validate_frame_size(packet)
    repeat_count = _validate_repeat_count(repeat_count)
    interval_seconds = _validate_interval(interval_seconds)
    vlan_values = _parse_vlan_ids(vlan_ids)
    if vlan_values and vlan_action == "keep":
        raise ToolInputError("Choose Add/replace VLAN tag when entering VLAN IDs.")
    if vlan_action not in {"keep", "replace", "remove"}:
        raise ToolInputError("Choose a valid VLAN handling option.")

    base = _rewrite_macs(
        original,
        source_mac=_normalize_mac_optional(source_mac),
        destination_mac=_normalize_mac_optional(destination_mac),
    )
    vlan_targets = vlan_values if vlan_values else [None]
    if len(vlan_targets) * repeat_count > MAX_TOTAL_FRAMES:
        raise ToolInputError(f"Packet replay is limited to {MAX_TOTAL_FRAMES} total frames.")

    one_pass_frames = [
        _apply_vlan(base, vlan_action=vlan_action, vlan_id=vlan_id) for vlan_id in vlan_targets
    ]
    frames = []
    for _ in range(repeat_count):
        frames.extend(one_pass_frames)

    summary = decode_frame(one_pass_frames[0])
    summary["repeat_count"] = repeat_count
    summary["interval_seconds"] = interval_seconds
    summary["vlan_targets"] = vlan_values
    summary["frame_count"] = len(frames)
    summary["bytes_per_frame"] = len(one_pass_frames[0])
    summary["total_bytes"] = sum(len(frame) for frame in frames)
    return ReplayPlan(
        original=original,
        frames=frames,
        summary=summary,
        warnings=_warnings(summary, repeat_count=repeat_count, vlan_count=len(vlan_targets)),
    )


def decode_frame(frame: bytes) -> dict[str, Any]:
    frame = _validate_frame_size(frame)
    destination = _format_mac(frame[0:6])
    source = _format_mac(frame[6:12])
    offset = 12
    vlans = []
    ethertype = struct.unpack_from("!H", frame, offset)[0]
    while ethertype in VLAN_ETHERTYPES:
        if len(frame) < offset + 4:
            raise ToolInputError("The Ethernet frame has an incomplete VLAN header.")
        tag = struct.unpack_from("!H", frame, offset + 2)[0]
        vlans.append(
            {
                "ethertype": f"0x{ethertype:04x}",
                "id": tag & 0x0FFF,
                "pcp": (tag >> 13) & 0x7,
                "dei": (tag >> 12) & 0x1,
            }
        )
        offset += 4
        if len(frame) < offset + 2:
            raise ToolInputError("The Ethernet frame ends before the inner EtherType.")
        ethertype = struct.unpack_from("!H", frame, offset)[0]
    payload_offset = offset + 2
    summary: dict[str, Any] = {
        "destination_mac": destination,
        "source_mac": source,
        "ethertype": f"0x{ethertype:04x}",
        "vlans": vlans,
        "length": len(frame),
        "broadcast": destination == "ff:ff:ff:ff:ff:ff",
        "multicast": destination.startswith(MULTICAST_PREFIXES),
        "protocol": _ether_type_name(ethertype),
        "details": [],
    }
    if ethertype == 0x0800 and len(frame) >= payload_offset + 20:
        _decode_ipv4(frame[payload_offset:], summary)
    elif ethertype == 0x86DD and len(frame) >= payload_offset + 40:
        _decode_ipv6(frame[payload_offset:], summary)
    return summary


def send_replay_frames(
    frames: list[bytes],
    *,
    interface: str,
    interval_seconds: float,
) -> dict[str, Any]:
    if not interface:
        raise ToolInputError("Choose a network interface.")
    if not frames:
        raise ToolInputError("There are no frames to send.")
    interval_seconds = _validate_interval(interval_seconds)
    try:
        from scapy.all import Ether, sendp  # type: ignore[import-not-found]
        from scapy.error import Scapy_Exception  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ToolInputError(
            "Raw packet sending requires Scapy. Run the installer again or install requirements."
        ) from exc

    started = time.time()
    try:
        for index, frame in enumerate(frames):
            sendp(Ether(frame), iface=interface, verbose=False)
            if index < len(frames) - 1:
                time.sleep(interval_seconds)
    except PermissionError as exc:
        raise ToolInputError(
            "Packet replay needs raw packet permissions. Start the toolkit with suitable privileges "
            "or grant the Python process packet-capture/raw-socket access for the selected interface."
        ) from exc
    except OSError as exc:
        raise ToolInputError(f"Packet replay failed on interface {interface}: {exc}") from exc
    except Scapy_Exception as exc:
        raise ToolInputError(f"Packet replay failed on interface {interface}: {exc}") from exc
    return {
        "sent": len(frames),
        "interface": interface,
        "elapsed_seconds": round(time.time() - started, 3),
    }


def _validate_frame_size(packet: bytes) -> bytes:
    if len(packet) < 14:
        raise ToolInputError("Packet must include a complete Ethernet header.")
    if len(packet) > MAX_PACKET_BYTES:
        raise ToolInputError(f"Packet is too large. Maximum supported size is {MAX_PACKET_BYTES} bytes.")
    return packet


def _validate_repeat_count(value: int) -> int:
    try:
        count = int(value)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Repeat count must be a whole number.") from exc
    if not 1 <= count <= MAX_REPEATS:
        raise ToolInputError(f"Repeat count must be between 1 and {MAX_REPEATS}.")
    return count


def _validate_interval(value: float) -> float:
    try:
        interval = float(value)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Interval must be a number of seconds.") from exc
    if not MIN_INTERVAL_SECONDS <= interval <= MAX_INTERVAL_SECONDS:
        raise ToolInputError(
            f"Interval must be between {MIN_INTERVAL_SECONDS:g} and {MAX_INTERVAL_SECONDS:g} seconds."
        )
    return interval


def _parse_vlan_ids(value: str) -> list[int]:
    if not (value or "").strip():
        return []
    vlans = []
    for part in re.split(r"[\s,]+", value.strip()):
        if not part:
            continue
        try:
            vlan_id = int(part, 10)
        except ValueError as exc:
            raise ToolInputError("VLAN IDs must be numbers from 1 through 4094.") from exc
        if not 1 <= vlan_id <= 4094:
            raise ToolInputError("VLAN IDs must be numbers from 1 through 4094.")
        if vlan_id not in vlans:
            vlans.append(vlan_id)
    if len(vlans) > 20:
        raise ToolInputError("VLAN fanout is limited to 20 VLANs at a time.")
    return vlans


def _normalize_mac_optional(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(cleaned) != 12:
        raise ToolInputError("MAC addresses must contain 12 hex digits.")
    return ":".join(cleaned[index : index + 2] for index in range(0, 12, 2)).lower()


def _rewrite_macs(packet: bytes, *, source_mac: str, destination_mac: str) -> bytes:
    frame = bytearray(packet)
    if destination_mac:
        frame[0:6] = bytes.fromhex(destination_mac.replace(":", ""))
    if source_mac:
        frame[6:12] = bytes.fromhex(source_mac.replace(":", ""))
    return bytes(frame)


def _apply_vlan(packet: bytes, *, vlan_action: str, vlan_id: int | None) -> bytes:
    untagged = _remove_vlan_tags(packet) if vlan_action in {"replace", "remove"} else packet
    if vlan_action == "remove" or vlan_id is None:
        return untagged
    original_ethertype = untagged[12:14]
    vlan_header = b"\x81\x00" + struct.pack("!H", vlan_id & 0x0FFF)
    return untagged[:12] + vlan_header + original_ethertype + untagged[14:]


def _remove_vlan_tags(packet: bytes) -> bytes:
    offset = 12
    ethertype = struct.unpack_from("!H", packet, offset)[0]
    while ethertype in VLAN_ETHERTYPES:
        offset += 4
        if len(packet) < offset + 2:
            raise ToolInputError("The Ethernet frame has an incomplete VLAN stack.")
        ethertype = struct.unpack_from("!H", packet, offset)[0]
    return packet[:12] + packet[offset:]


def _decode_ipv4(payload: bytes, summary: dict[str, Any]) -> None:
    ihl = (payload[0] & 0x0F) * 4
    if len(payload) < ihl or ihl < 20:
        return
    proto = payload[9]
    summary["protocol"] = f"IPv4 / {_ip_protocol_name(proto)}"
    summary["details"].extend(
        [
            {"name": "Source IP", "value": ".".join(str(byte) for byte in payload[12:16])},
            {"name": "Destination IP", "value": ".".join(str(byte) for byte in payload[16:20])},
            {"name": "TTL", "value": str(payload[8])},
        ]
    )
    _decode_ports(payload[ihl:], proto, summary)


def _decode_ipv6(payload: bytes, summary: dict[str, Any]) -> None:
    proto = payload[6]
    summary["protocol"] = f"IPv6 / {_ip_protocol_name(proto)}"
    summary["details"].extend(
        [
            {"name": "Source IP", "value": _format_ipv6(payload[8:24])},
            {"name": "Destination IP", "value": _format_ipv6(payload[24:40])},
            {"name": "Hop limit", "value": str(payload[7])},
        ]
    )
    _decode_ports(payload[40:], proto, summary)


def _decode_ports(payload: bytes, proto: int, summary: dict[str, Any]) -> None:
    if proto not in {6, 17} or len(payload) < 4:
        return
    source_port, destination_port = struct.unpack_from("!HH", payload, 0)
    summary["details"].extend(
        [
            {"name": "Source port", "value": str(source_port)},
            {"name": "Destination port", "value": str(destination_port)},
        ]
    )


def _warnings(summary: dict[str, Any], *, repeat_count: int, vlan_count: int) -> list[str]:
    warnings = []
    if summary.get("broadcast"):
        warnings.append("Destination MAC is broadcast.")
    elif summary.get("multicast"):
        warnings.append("Destination MAC is multicast.")
    if vlan_count > 1:
        warnings.append(f"VLAN fanout will send one copy on each of {vlan_count} VLANs per repeat.")
    if repeat_count > 10:
        warnings.append("Repeat count is above 10.")
    return warnings


def _format_mac(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)


def _format_ipv6(value: bytes) -> str:
    groups = [f"{struct.unpack_from('!H', value, index)[0]:x}" for index in range(0, 16, 2)]
    return ":".join(groups)


def _ether_type_name(value: int) -> str:
    return {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}.get(value, "Ethernet")


def _ip_protocol_name(value: int) -> str:
    return {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(value, f"IP protocol {value}")
