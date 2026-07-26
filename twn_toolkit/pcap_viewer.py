from __future__ import annotations

from datetime import datetime
from pathlib import Path
import struct
from typing import Any

from scapy.config import conf
from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Raw
from scapy.utils import PcapReader

from .network_tools import ToolInputError


DEFAULT_PACKET_LIMIT = 100
MAX_PACKET_LIMIT = 200
MAX_PACKET_OFFSET = 1_000_000
SUPPORTED_CAPTURE_SUFFIXES = {".cap", ".pcap", ".pcapng"}
CLASSIC_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
MAX_CAPTURED_PACKET_BYTES = 16 * 1024 * 1024


def inspect_packet_capture(
    path: str | Path,
    *,
    start: int = 0,
    limit: int = DEFAULT_PACKET_LIMIT,
    allow_incomplete: bool = False,
    cursor: int | None = None,
) -> dict[str, Any]:
    """Return bounded packet-header summaries without exposing packet payloads."""
    try:
        start = int(start)
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Packet viewer position must be a whole number.") from exc
    if not 0 <= start <= MAX_PACKET_OFFSET:
        raise ToolInputError(
            f"Packet viewer position must be 0–{MAX_PACKET_OFFSET:,}."
        )
    if not 1 <= limit <= MAX_PACKET_LIMIT:
        raise ToolInputError(
            f"Packet viewer pages may contain 1–{MAX_PACKET_LIMIT} packets."
        )

    capture_path = Path(path)
    if not capture_path.is_file():
        if allow_incomplete:
            return _result([], start=start, has_more=False, waiting=True)
        raise ToolInputError("The packet capture file was not found.")
    if capture_path.suffix.casefold() not in SUPPORTED_CAPTURE_SUFFIXES:
        raise ToolInputError("Choose a .pcap, .pcapng, or .cap file.")
    if allow_incomplete and capture_path.stat().st_size < 24:
        return _result([], start=start, has_more=False, waiting=True)
    with capture_path.open("rb") as source:
        magic = source.read(4)
    if magic in CLASSIC_PCAP_MAGICS:
        return _inspect_classic_pcap(
            capture_path,
            start=start,
            limit=limit,
            allow_incomplete=allow_incomplete,
            cursor=cursor,
        )
    if cursor not in {None, 0}:
        raise ToolInputError("Refresh the packet viewer to restart this capture.")

    packets: list[dict[str, Any]] = []
    has_more = False
    reader = None
    try:
        reader = PcapReader(str(capture_path))
        for index, packet in enumerate(reader):
            if index < start:
                continue
            if len(packets) >= limit:
                has_more = True
                break
            packets.append(_safe_packet_summary(packet, number=index + 1))
    except (EOFError, OSError, Scapy_Exception, ValueError) as exc:
        if not allow_incomplete:
            detail = str(exc).strip()
            raise ToolInputError(
                f"Could not inspect this packet capture{f': {detail}' if detail else '.'}"
            ) from exc
    finally:
        if reader is not None:
            reader.close()

    return _result(
        packets,
        start=start,
        has_more=has_more,
        waiting=allow_incomplete and not packets and start == 0,
        next_cursor=None,
    )


def _result(
    packets: list[dict[str, Any]],
    *,
    start: int,
    has_more: bool,
    waiting: bool,
    next_cursor: int | None = None,
) -> dict[str, Any]:
    return {
        "packets": packets,
        "start": start,
        "next_start": start + len(packets),
        "has_more": has_more,
        "waiting": waiting,
        "next_cursor": next_cursor,
    }


def _inspect_classic_pcap(
    path: Path,
    *,
    start: int,
    limit: int,
    allow_incomplete: bool,
    cursor: int | None,
) -> dict[str, Any]:
    packets: list[dict[str, Any]] = []
    has_more = False
    with path.open("rb") as source:
        header = source.read(24)
        if len(header) < 24:
            if allow_incomplete:
                return _result([], start=start, has_more=False, waiting=True)
            raise ToolInputError("The classic PCAP header is incomplete.")
        endian, timestamp_scale = CLASSIC_PCAP_MAGICS[header[:4]]
        linktype = struct.unpack(f"{endian}I", header[20:24])[0]
        position = 24 if cursor in {None, 0} else _validate_cursor(cursor, path)
        records_to_skip = start if cursor in {None, 0} else 0
        source.seek(position)
        while True:
            record_position = source.tell()
            record_header = source.read(16)
            if not record_header:
                break
            if len(record_header) < 16:
                source.seek(record_position)
                break
            seconds, fraction, captured_length, wire_length = struct.unpack(
                f"{endian}IIII", record_header
            )
            if captured_length > MAX_CAPTURED_PACKET_BYTES:
                raise ToolInputError(
                    "A packet record exceeds the viewer's 16 MiB safety limit."
                )
            frame = source.read(captured_length)
            if len(frame) < captured_length:
                source.seek(record_position)
                break
            if records_to_skip:
                records_to_skip -= 1
                continue
            if len(packets) >= limit:
                has_more = True
                source.seek(record_position)
                break
            packets.append(
                _safe_packet_summary(
                    _decode_link_packet(
                        frame,
                        linktype=linktype,
                        timestamp=seconds + (fraction / timestamp_scale),
                        wire_length=wire_length,
                    ),
                    number=start + len(packets) + 1,
                )
            )
        next_cursor = source.tell()
    return _result(
        packets,
        start=start,
        has_more=has_more,
        waiting=allow_incomplete and not packets,
        next_cursor=next_cursor,
    )


def _validate_cursor(value: int, path: Path) -> int:
    try:
        cursor = int(value)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Packet viewer cursor must be a whole number.") from exc
    if not 24 <= cursor <= path.stat().st_size:
        raise ToolInputError("Refresh the packet viewer to restart this capture.")
    return cursor


def _decode_link_packet(
    frame: bytes,
    *,
    linktype: int,
    timestamp: float,
    wire_length: int,
) -> Any:
    layer_class = conf.l2types.get(linktype)
    packet = layer_class(frame) if layer_class else Raw(frame)
    packet.time = timestamp
    packet.wirelen = wire_length
    return packet


def _safe_packet_summary(packet: Any, *, number: int) -> dict[str, Any]:
    try:
        return _packet_summary(packet, number=number)
    except (AttributeError, IndexError, TypeError, ValueError):
        captured_length = len(bytes(packet))
        return {
            "number": number,
            "timestamp": float(getattr(packet, "time", 0) or 0),
            "time_display": "—",
            "source_mac": "",
            "destination_mac": "",
            "source_ip": "",
            "destination_ip": "",
            "source_port": None,
            "destination_port": None,
            "protocol": "Malformed",
            "detail": "Header could not be decoded",
            "vlan_ids": [],
            "captured_length": captured_length,
            "wire_length": int(
                getattr(packet, "wirelen", captured_length) or captured_length
            ),
        }


def _packet_summary(packet: Any, *, number: int) -> dict[str, Any]:
    timestamp = float(getattr(packet, "time", 0) or 0)
    source_mac = ""
    destination_mac = ""
    source_ip = ""
    destination_ip = ""
    source_port: int | None = None
    destination_port: int | None = None
    protocol = "Other"
    detail = ""
    vlan_ids: list[int] = []

    ethernet = packet.getlayer(Ether)
    if ethernet is not None:
        source_mac = str(ethernet.src or "")
        destination_mac = str(ethernet.dst or "")

    vlan = packet.getlayer(Dot1Q)
    while vlan is not None:
        vlan_ids.append(int(vlan.vlan))
        vlan = vlan.payload.getlayer(Dot1Q)

    ipv4 = packet.getlayer(IP)
    ipv6 = packet.getlayer(IPv6)
    arp = packet.getlayer(ARP)
    if ipv4 is not None:
        source_ip = str(ipv4.src or "")
        destination_ip = str(ipv4.dst or "")
        protocol = f"IP {int(ipv4.proto)}"
    elif ipv6 is not None:
        source_ip = str(ipv6.src or "")
        destination_ip = str(ipv6.dst or "")
        protocol = f"IPv6 {int(ipv6.nh)}"
    elif arp is not None:
        source_ip = str(arp.psrc or "")
        destination_ip = str(arp.pdst or "")
        protocol = "ARP"
        detail = "request" if int(arp.op) == 1 else "reply" if int(arp.op) == 2 else f"op {arp.op}"

    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    icmp = packet.getlayer(ICMP)
    if tcp is not None:
        protocol = "TCP"
        source_port = int(tcp.sport)
        destination_port = int(tcp.dport)
        detail = f"flags {tcp.sprintf('%TCP.flags%')}"
    elif udp is not None:
        protocol = "UDP"
        source_port = int(udp.sport)
        destination_port = int(udp.dport)
    elif icmp is not None:
        protocol = "ICMP"
        detail = f"type {int(icmp.type)}, code {int(icmp.code)}"
    elif ipv6 is not None and int(ipv6.nh) == 58:
        protocol = "ICMPv6"

    captured_length = len(bytes(packet))
    wire_length = int(getattr(packet, "wirelen", captured_length) or captured_length)
    return {
        "number": number,
        "timestamp": timestamp,
        "time_display": (
            datetime.fromtimestamp(timestamp)
            .astimezone()
            .strftime("%H:%M:%S.%f")[:-3]
            if timestamp
            else "—"
        ),
        "source_mac": source_mac,
        "destination_mac": destination_mac,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "detail": detail,
        "vlan_ids": vlan_ids,
        "captured_length": captured_length,
        "wire_length": wire_length,
    }
