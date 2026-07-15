from __future__ import annotations

import re
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any

from .network_tools import ToolInputError


MAX_PACKET_BYTES = 9216
MAX_UPLOAD_BYTES = 256 * 1024
MAX_REPLAY_FRAMES = 10_000
MAX_REPLAY_DURATION_SECONDS = 300.0
MIN_INTERVAL_SECONDS = 0.1
MAX_INTERVAL_SECONDS = 60.0
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
MULTICAST_PREFIXES = ("01:00:5e", "33:33")
UNTAGGED_VLAN_TARGET = None


@dataclass(frozen=True)
class ReplayPlan:
    original: bytes
    originals: list[bytes]
    frames: list[bytes]
    summary: dict[str, Any]
    warnings: list[str]


def parse_hex_packet(value: str) -> bytes:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if not cleaned:
        raise ToolInputError("Paste packet hex or upload a packet capture.")
    if len(cleaned) % 2:
        raise ToolInputError("Packet hex must contain an even number of hex digits.")
    try:
        packet = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ToolInputError("Packet hex contains invalid characters.") from exc
    return _validate_frame_size(packet)


def parse_single_packet_capture(data: bytes) -> bytes:
    packets = parse_packet_capture(data)
    if len(packets) != 1:
        raise ToolInputError("Upload a PCAP containing exactly one packet.")
    return packets[0]


def parse_packet_capture(data: bytes) -> list[bytes]:
    if len(data) > MAX_UPLOAD_BYTES:
        raise ToolInputError("Capture upload is too large. Upload a smaller packet capture.")
    if len(data) < 24:
        raise ToolInputError("Upload a classic PCAP or paste raw packet hex.")

    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
    else:
        raise ToolInputError("Only classic PCAP uploads are supported right now.")

    _magic, _major, _minor, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack_from(
        f"{endian}IHHIIII", data, 0
    )
    if linktype != 1:
        raise ToolInputError("Packet replay PCAP uploads must use Ethernet link type.")

    if len(data) < 40:
        raise ToolInputError("The PCAP does not contain a packet record.")

    packets = []
    offset = 24
    while offset < len(data):
        remaining = data[offset:]
        if not remaining.strip(b"\0"):
            break
        if len(remaining) < 16:
            raise ToolInputError("The PCAP packet record is incomplete.")
        _ts_sec, _ts_frac, included_length, original_length = struct.unpack_from(
            f"{endian}IIII", data, offset
        )
        if included_length != original_length:
            raise ToolInputError("A packet in the PCAP is truncated. Export full packets.")
        start = offset + 16
        end = start + included_length
        if len(data) < end:
            raise ToolInputError("The PCAP packet record is incomplete.")
        packets.append(_validate_frame_size(data[start:end]))
        offset = end
    if not packets:
        raise ToolInputError("The PCAP does not contain a packet record.")
    return packets


def encode_prepared_packets(packets: list[bytes]) -> str:
    return "|".join(packet.hex() for packet in packets)


def parse_prepared_packets(value: str) -> list[bytes]:
    packets = []
    for packet_hex in (value or "").split("|"):
        if packet_hex.strip():
            packets.append(parse_hex_packet(packet_hex))
    if not packets:
        raise ToolInputError("Paste packet hex or upload a packet capture.")
    return packets


def prepare_replay_plan(
    packet: bytes | list[bytes],
    *,
    source_mac: str = "",
    destination_mac: str = "",
    vlan_action: str = "keep",
    vlan_ids: str = "",
    repeat_count: int = 1,
    interval_seconds: float = 1.0,
) -> ReplayPlan:
    originals = [_validate_frame_size(candidate) for candidate in _coerce_packets(packet)]
    repeat_count = _validate_repeat_count(repeat_count)
    interval_seconds = _validate_interval(interval_seconds)
    if vlan_action not in {"keep", "replace", "remove"}:
        raise ToolInputError("Choose a valid VLAN handling option.")
    vlan_values = [] if vlan_action == "keep" else _parse_vlan_targets(vlan_ids)

    source_mac = _normalize_mac_optional(source_mac)
    destination_mac = _normalize_mac_optional(destination_mac)
    base_frames = [
        _rewrite_macs(original, source_mac=source_mac, destination_mac=destination_mac)
        for original in originals
    ]
    vlan_targets = vlan_values if vlan_values else [UNTAGGED_VLAN_TARGET]
    one_pass_frames = [
        _apply_vlan(base, vlan_action=vlan_action, vlan_id=vlan_id)
        for base in base_frames
        for vlan_id in vlan_targets
    ]
    frame_count = len(one_pass_frames) * repeat_count
    if frame_count > MAX_REPLAY_FRAMES:
        raise ToolInputError(
            f"Replay plans may contain at most {MAX_REPLAY_FRAMES:,} total frames."
        )
    scheduled_duration = max(0, frame_count - 1) * interval_seconds
    if scheduled_duration > MAX_REPLAY_DURATION_SECONDS:
        raise ToolInputError(
            "Replay timing may span at most 5 minutes. Reduce the repeat count, "
            "VLAN fanout, source packet count, or interval."
        )
    frames = []
    for _ in range(repeat_count):
        frames.extend(one_pass_frames)

    summary = decode_frame(one_pass_frames[0])
    summary["packet_count"] = len(originals)
    summary["repeat_count"] = repeat_count
    summary["interval_seconds"] = interval_seconds
    summary["vlan_targets"] = vlan_values
    summary["vlan_target_labels"] = [_format_vlan_target(vlan_id) for vlan_id in vlan_values]
    summary["frame_count"] = len(frames)
    summary["bytes_per_frame"] = len(one_pass_frames[0])
    summary["total_bytes"] = sum(len(frame) for frame in frames)
    summary["first_replay_header_hex"] = one_pass_frames[0][:22].hex(" ")
    summary["notes"] = _notes(
        summary,
        repeat_count=repeat_count,
        vlan_count=len(vlan_targets),
        has_vlan_targets=any(vlan_id is not None for vlan_id in vlan_targets),
    )
    return ReplayPlan(
        original=originals[0],
        originals=originals,
        frames=frames,
        summary=summary,
        warnings=_warnings(
            summary,
            repeat_count=repeat_count,
            vlan_count=len(vlan_targets),
            has_vlan_targets=any(vlan_id is not None for vlan_id in vlan_targets),
        ),
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
    if sys.platform.startswith("linux") and hasattr(socket, "AF_PACKET"):
        return _send_replay_frames_linux_socket(
            frames,
            interface=interface,
            interval_seconds=interval_seconds,
        )

    return _send_replay_frames_scapy(
        frames,
        interface=interface,
        interval_seconds=interval_seconds,
    )


def _send_replay_frames_linux_socket(
    frames: list[bytes],
    *,
    interface: str,
    interval_seconds: float,
) -> dict[str, Any]:
    started = time.time()
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as raw_socket:
            raw_socket.bind((interface, 0))
            for index, frame in enumerate(frames):
                sent = raw_socket.send(frame)
                if sent != len(frame):
                    raise ToolInputError(
                        f"Packet replay sent only {sent} of {len(frame)} bytes on {interface}."
                    )
                if index < len(frames) - 1:
                    time.sleep(interval_seconds)
    except PermissionError as exc:
        raise ToolInputError(
            "Packet replay needs Linux CAP_NET_RAW or root privileges for raw Ethernet sockets. "
            "Start the toolkit with suitable privileges on a dedicated diagnostic host, or grant "
            "CAP_NET_RAW to the Python interpreter used by the toolkit."
        ) from exc
    except OSError as exc:
        raise ToolInputError(f"Packet replay failed on interface {interface}: {exc}") from exc
    return {
        "sent": len(frames),
        "attempted": len(frames),
        "interface": interface,
        "elapsed_seconds": round(time.time() - started, 3),
        "method": "linux raw socket",
        "detail": "The kernel accepted each raw Ethernet frame for transmission.",
    }


def _send_replay_frames_scapy(
    frames: list[bytes],
    *,
    interface: str,
    interval_seconds: float,
) -> dict[str, Any]:
    try:
        from scapy.all import conf  # type: ignore[import-not-found]
        from scapy.error import Scapy_Exception  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ToolInputError(
            "Raw packet sending requires Scapy. Run the installer again or install requirements."
        ) from exc
    darwin_tagged_send = sys.platform == "darwin" and any(_frame_has_vlan(frame) for frame in frames)
    if sys.platform == "darwin":
        conf.use_pcap = not darwin_tagged_send

    started = time.time()
    handed_to_backend = 0
    l2_socket = None
    try:
        l2_socket = conf.L2socket(iface=interface)
        for index, frame in enumerate(frames):
            sent = l2_socket.send(frame)
            if isinstance(sent, int) and sent != len(frame):
                raise ToolInputError(
                    f"Packet replay handed only {sent} of {len(frame)} bytes to Scapy on {interface}."
                )
            handed_to_backend += 1
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
    finally:
        if l2_socket is not None:
            try:
                l2_socket.close()
            except (AttributeError, OSError, Scapy_Exception):
                pass
    return {
        "sent": handed_to_backend,
        "attempted": len(frames),
        "interface": interface,
        "elapsed_seconds": round(time.time() - started, 3),
        "method": _scapy_sender_method(darwin_tagged_send=darwin_tagged_send),
        "detail": (
            "Scapy accepted the exact replay bytes shown in the preview. macOS does not provide a simple send-byte count here; "
            "verify on the wire with Wireshark/tcpdump on the selected interface or another host."
        ),
    }


def _validate_frame_size(packet: bytes) -> bytes:
    if len(packet) < 14:
        raise ToolInputError("Packet must include a complete Ethernet header.")
    if len(packet) > MAX_PACKET_BYTES:
        raise ToolInputError(f"Packet is too large. Maximum supported size is {MAX_PACKET_BYTES} bytes.")
    return packet


def _frame_has_vlan(frame: bytes) -> bool:
    if len(frame) < 14:
        return False
    return struct.unpack_from("!H", frame, 12)[0] in VLAN_ETHERTYPES


def _scapy_sender_method(*, darwin_tagged_send: bool) -> str:
    if sys.platform != "darwin":
        return "scapy raw socket"
    if darwin_tagged_send:
        return "scapy/BPF raw socket"
    return "scapy/libpcap raw socket"


def _coerce_packets(packet: bytes | list[bytes]) -> list[bytes]:
    if isinstance(packet, bytes):
        return [packet]
    if not packet:
        raise ToolInputError("There are no packets to replay.")
    return packet


def _validate_repeat_count(value: int) -> int:
    try:
        count = int(value)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Repeat count must be a whole number.") from exc
    if count < 1:
        raise ToolInputError("Repeat count must be at least 1.")
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


def _parse_vlan_targets(value: str) -> list[int | None]:
    if not (value or "").strip():
        return []
    vlans: list[int | None] = []
    for part in re.split(r"[\s,]+", value.strip()):
        if not part:
            continue
        if part.lower() in {"untagged", "none", "native"}:
            if UNTAGGED_VLAN_TARGET not in vlans:
                vlans.append(UNTAGGED_VLAN_TARGET)
            continue
        for vlan_id in _expand_vlan_token(part):
            if vlan_id not in vlans:
                vlans.append(vlan_id)
    return vlans


def _expand_vlan_token(value: str) -> list[int]:
    if "-" in value:
        start_text, end_text = value.split("-", 1)
        try:
            start = int(start_text, 10)
            end = int(end_text, 10)
        except ValueError as exc:
            raise ToolInputError(
                "VLAN targets must be numbers, ranges like 10-20, or the word untagged."
            ) from exc
        if start > end:
            raise ToolInputError("VLAN ranges must start at the lower VLAN ID.")
        _validate_vlan_id(start)
        _validate_vlan_id(end)
        return list(range(start, end + 1))
    try:
        vlan_id = int(value, 10)
    except ValueError as exc:
        raise ToolInputError(
            "VLAN targets must be numbers, ranges like 10-20, or the word untagged."
        ) from exc
    _validate_vlan_id(vlan_id)
    return [vlan_id]


def _validate_vlan_id(vlan_id: int) -> None:
    if not 0 <= vlan_id <= 4094:
        raise ToolInputError("VLAN IDs must be numbers from 0 through 4094.")


def _format_vlan_target(vlan_id: int | None) -> str:
    if vlan_id is None:
        return "untagged"
    if vlan_id == 0:
        return "0 (priority tag)"
    return str(vlan_id)


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


def _warnings(
    summary: dict[str, Any],
    *,
    repeat_count: int,
    vlan_count: int,
    has_vlan_targets: bool,
) -> list[str]:
    warnings = []
    if summary.get("broadcast"):
        warnings.append("Destination MAC is broadcast.")
    elif summary.get("multicast"):
        warnings.append("Destination MAC is multicast.")
    return warnings


def _notes(
    summary: dict[str, Any],
    *,
    repeat_count: int,
    vlan_count: int,
    has_vlan_targets: bool,
) -> list[str]:
    notes = []
    if repeat_count > 10:
        notes.append("Repeat count is above 10.")
    if vlan_count > 1:
        notes.append(f"VLAN fanout will send one copy on each of {vlan_count} targets per repeat.")
    if sys.platform == "darwin" and (summary.get("vlans") or has_vlan_targets):
        notes.append(
            "macOS VLAN replay uses Scapy's BPF raw-device path. If tcpdump or Wireshark does not show "
            "the frame, verify with a VLAN-aware capture filter such as 'vlan' or 'vlan and port 514'."
        )
    return notes


def _format_mac(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)


def _format_ipv6(value: bytes) -> str:
    groups = [f"{struct.unpack_from('!H', value, index)[0]:x}" for index in range(0, 16, 2)]
    return ":".join(groups)


def _ether_type_name(value: int) -> str:
    return {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}.get(value, "Ethernet")


def _ip_protocol_name(value: int) -> str:
    return {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(value, f"IP protocol {value}")
