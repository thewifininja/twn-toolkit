from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import ipaddress
import math
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable

from .network_tools import ToolInputError
from .wol_tools import available_wol_interfaces


MULTICAST_MIN_DURATION_SECONDS = 1
MULTICAST_MAX_DURATION_SECONDS = 300
MULTICAST_MIN_PACKET_SIZE = 64
MULTICAST_MAX_PACKET_SIZE = 9000
MULTICAST_MAX_PACKETS_PER_SECOND = 50_000
MULTICAST_MAX_MEGABITS = 200
MULTICAST_MAX_SEND_PACKETS = 1_000_000
MULTICAST_MAX_SOURCES = 100
MULTICAST_RECEIVE_BUFFER_BYTES = 4 * 1024 * 1024
MULTICAST_PROGRESS_INTERVAL_SECONDS = 0.25

TEST_PACKET_MAGIC = b"TWNMCST1"
TEST_PACKET_VERSION = 1
TEST_PACKET_HEADER = struct.Struct("!8sB7x8sQQ")

MulticastProgressCallback = Callable[[dict[str, Any]], None]


class MulticastTestCancelled(Exception):
    """Raised internally when a streamed multicast run is cancelled."""


@dataclass
class _Variance:
    count: int = 0
    mean: float = 0.0
    sum_squares: float = 0.0

    def add(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.sum_squares += delta * (value - self.mean)

    @property
    def standard_deviation(self) -> float:
        if self.count < 2:
            return 0.0
        return math.sqrt(self.sum_squares / (self.count - 1))


@dataclass
class _SequenceTracker:
    modulus: int
    seen: set[int] = field(default_factory=set)
    highest: int | None = None
    last_raw: int | None = None
    cycles: int = 0
    duplicates: int = 0
    out_of_order: int = 0

    def add(self, raw_sequence: int) -> int:
        if self.last_raw is not None:
            half = self.modulus // 2
            if raw_sequence < self.last_raw and self.last_raw - raw_sequence > half:
                self.cycles += 1
            elif raw_sequence > self.last_raw and raw_sequence - self.last_raw > half:
                extended = max(0, self.cycles - 1) * self.modulus + raw_sequence
                return self._record(extended, update_last=False)
        extended = self.cycles * self.modulus + raw_sequence
        self.last_raw = raw_sequence
        return self._record(extended, update_last=True)

    def _record(self, extended: int, *, update_last: bool) -> int:
        if extended in self.seen:
            self.duplicates += 1
        else:
            if self.highest is not None and extended < self.highest:
                self.out_of_order += 1
            self.seen.add(extended)
            self.highest = extended if self.highest is None else max(self.highest, extended)
        return extended

    @property
    def observed_missing(self) -> int:
        if not self.seen:
            return 0
        return max(0, max(self.seen) - min(self.seen) + 1 - len(self.seen))


def available_multicast_interfaces() -> list[dict[str, Any]]:
    """Return usable IPv4 interfaces with stable names, indexes, and addresses."""
    indexes = {name: index for index, name in socket.if_nameindex()}
    interfaces = []
    for item in available_wol_interfaces():
        flags = _interface_flags(item["name"])
        if flags and ("UP" not in flags or "MULTICAST" not in flags):
            continue
        interfaces.append({
            "name": item["name"],
            "address": item["address"],
            "index": indexes.get(item["name"], 0),
            "point_to_point": "POINTOPOINT" in flags,
            "broadcast": str(item.get("broadcast", "")),
        })
    return sorted(
        interfaces,
        key=lambda item: (
            bool(item["point_to_point"]),
            not bool(item["broadcast"]),
            item["name"],
        ),
    )


def multicast_capability() -> dict[str, Any]:
    interfaces = available_multicast_interfaces()
    return {
        "available": bool(interfaces),
        "interfaces": interfaces,
        "asm": True,
        "ssm": _source_membership_option() is not None,
        "detail": (
            f"{len(interfaces)} usable IPv4 interface"
            f"{'s' if len(interfaces) != 1 else ''} detected."
            if interfaces
            else "No usable non-loopback IPv4 interfaces were detected."
        ),
    }


def normalize_multicast_config(
    config: dict[str, Any],
    *,
    interfaces: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    known_interfaces = interfaces if interfaces is not None else available_multicast_interfaces()
    by_name = {str(item.get("name", "")): item for item in known_interfaces}
    mode = str(config.get("mode", "listen")).strip().lower()
    if mode not in {"listen", "send", "path"}:
        raise ToolInputError("Choose Listen, Send, or End-to-end path test mode.")

    try:
        group_address = ipaddress.IPv4Address(str(config.get("group", "")).strip())
    except ipaddress.AddressValueError as exc:
        raise ToolInputError("Enter a valid IPv4 multicast group address.") from exc
    if not group_address.is_multicast:
        raise ToolInputError("The group address must be in IPv4 multicast space (224.0.0.0/4).")

    try:
        port = int(config.get("port", 5000))
        duration = int(config.get("duration", 10))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("UDP port and duration must be whole numbers.") from exc
    if not 1 <= port <= 65535:
        raise ToolInputError("UDP port must be between 1 and 65,535.")
    if not MULTICAST_MIN_DURATION_SECONDS <= duration <= MULTICAST_MAX_DURATION_SECONDS:
        raise ToolInputError(
            f"Duration must be {MULTICAST_MIN_DURATION_SECONDS}–"
            f"{MULTICAST_MAX_DURATION_SECONDS} seconds."
        )

    membership = str(config.get("membership", "asm")).strip().lower()
    if membership not in {"asm", "ssm"}:
        raise ToolInputError("Choose any-source (ASM) or source-specific (SSM) membership.")
    source = (
        _optional_unicast_ipv4(config.get("source", ""), "expected source")
        if mode in {"listen", "path"}
        else ""
    )
    if (
        mode in {"listen", "path"}
        and group_address in ipaddress.IPv4Network("232.0.0.0/8")
        and membership != "ssm"
    ):
        raise ToolInputError("Groups in 232.0.0.0/8 require source-specific (SSM) membership.")
    if mode in {"listen", "path"} and membership == "ssm":
        if not source and mode != "path":
            raise ToolInputError("Source-specific membership requires an expected source IPv4 address.")
        if _source_membership_option() is None:
            raise ToolInputError("Source-specific multicast membership is unavailable on this host.")

    receive_interface = _selected_interface(
        config.get("receive_interface", ""), by_name, "receive"
    ) if mode in {"listen", "path"} else None
    send_interface = _selected_interface(
        config.get("send_interface", ""), by_name, "send"
    ) if mode in {"send", "path"} else None
    if mode == "path" and receive_interface["name"] == send_interface["name"]:
        raise ToolInputError(
            "End-to-end mode requires different send and receive interfaces so local loopback cannot create a false success."
        )
    if mode == "path" and membership == "ssm" and not source:
        source = str(send_interface["address"])

    stream_format = str(config.get("stream_format", "generic")).strip().lower()
    if stream_format not in {"generic", "rtp", "twn"}:
        raise ToolInputError("Choose Generic UDP, RTP, or TWN sequenced test payloads.")
    if mode == "path":
        stream_format = "twn"
    try:
        rtp_clock_rate = int(config.get("rtp_clock_rate", 90000))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("RTP clock rate must be a whole number.") from exc
    if not 1000 <= rtp_clock_rate <= 1_000_000_000:
        raise ToolInputError("RTP clock rate must be between 1,000 and 1,000,000,000 Hz.")

    normalized: dict[str, Any] = {
        "mode": mode,
        "group": str(group_address),
        "group_scope": multicast_group_scope(group_address),
        "port": port,
        "duration": duration,
        "membership": membership,
        "source": source,
        "receive_interface": receive_interface,
        "send_interface": send_interface,
        "stream_format": stream_format,
        "rtp_clock_rate": rtp_clock_rate,
        "warnings": _group_warnings(group_address),
    }
    for selected in (receive_interface, send_interface):
        if selected and selected.get("point_to_point"):
            normalized["warnings"].append(
                f"{selected['name']} is a point-to-point interface; multicast support depends on that tunnel or VPN."
            )

    if mode in {"send", "path"}:
        try:
            packet_size = int(config.get("packet_size", 1200))
            ttl = int(config.get("ttl", 8))
            dscp = int(config.get("dscp", 0))
            source_port = int(config.get("source_port", 0) or 0)
            rate = float(config.get("rate", 1))
        except (TypeError, ValueError) as exc:
            raise ToolInputError("Packet, rate, TTL, DSCP, and source-port settings must be numbers.") from exc
        if not MULTICAST_MIN_PACKET_SIZE <= packet_size <= MULTICAST_MAX_PACKET_SIZE:
            raise ToolInputError(
                f"UDP payload size must be {MULTICAST_MIN_PACKET_SIZE}–"
                f"{MULTICAST_MAX_PACKET_SIZE} bytes."
            )
        if not 1 <= ttl <= 255:
            raise ToolInputError("Multicast TTL must be between 1 and 255.")
        if not 0 <= dscp <= 63:
            raise ToolInputError("DSCP must be between 0 and 63.")
        if source_port and not 1 <= source_port <= 65535:
            raise ToolInputError("Source port must be 0 (automatic) or 1–65,535.")
        rate_unit = str(config.get("rate_unit", "mbps")).strip().lower()
        if rate_unit == "mbps":
            if not 0.01 <= rate <= MULTICAST_MAX_MEGABITS:
                raise ToolInputError(
                    f"Payload rate must be between 0.01 and {MULTICAST_MAX_MEGABITS} Mbps."
                )
            packets_per_second = rate * 1_000_000 / (packet_size * 8)
        elif rate_unit == "pps":
            if not 1 <= rate <= MULTICAST_MAX_PACKETS_PER_SECOND:
                raise ToolInputError(
                    f"Packet rate must be between 1 and {MULTICAST_MAX_PACKETS_PER_SECOND:,} packets per second."
                )
            packets_per_second = rate
        else:
            raise ToolInputError("Choose Mbps or packets per second for the send rate.")
        if packets_per_second > MULTICAST_MAX_PACKETS_PER_SECOND:
            raise ToolInputError(
                f"These settings require {packets_per_second:,.0f} packets per second; "
                f"the maximum is {MULTICAST_MAX_PACKETS_PER_SECOND:,}. Increase payload size or lower the rate."
            )
        requested_packets = max(1, int(duration * packets_per_second))
        if requested_packets > MULTICAST_MAX_SEND_PACKETS:
            raise ToolInputError(
                f"These settings would send {requested_packets:,} packets; "
                f"the maximum per test is {MULTICAST_MAX_SEND_PACKETS:,}."
            )
        normalized.update(
            {
                "packet_size": packet_size,
                "ttl": ttl,
                "dscp": dscp,
                "source_port": source_port,
                "rate": rate,
                "rate_unit": rate_unit,
                "packets_per_second": packets_per_second,
                "requested_packets": requested_packets,
                "loopback": bool(config.get("loopback", False)) if mode == "send" else False,
            }
        )
        if packet_size > 1472:
            normalized["warnings"].append(
                "Payloads above 1,472 bytes may fragment on a standard 1,500-byte IPv4 path."
            )
        if ttl > 32:
            normalized["warnings"].append(
                "The selected TTL can carry test traffic well beyond a typical site boundary."
            )
    return normalized


def run_multicast_test(
    config: dict[str, Any],
    *,
    interfaces: list[dict[str, Any]] | None = None,
    progress: MulticastProgressCallback | None = None,
    cancelled: threading.Event | None = None,
) -> dict[str, Any]:
    normalized = normalize_multicast_config(config, interfaces=interfaces)
    if normalized["mode"] == "listen":
        return receive_multicast(
            normalized,
            progress=progress,
            cancelled=cancelled,
        )
    if normalized["mode"] == "send":
        return send_multicast(
            normalized,
            progress=progress,
            cancelled=cancelled,
        )
    return run_multicast_path_test(
        normalized,
        progress=progress,
        cancelled=cancelled,
    )


def build_test_packet(session_id: str, sequence: int, sent_ns: int, size: int) -> bytes:
    try:
        session_bytes = bytes.fromhex(session_id)
    except ValueError as exc:
        raise ToolInputError("The multicast test session identifier is invalid.") from exc
    if len(session_bytes) != 8:
        raise ToolInputError("The multicast test session identifier must be eight bytes.")
    if size < TEST_PACKET_HEADER.size:
        raise ToolInputError(
            f"The multicast test payload must be at least {TEST_PACKET_HEADER.size} bytes."
        )
    header = TEST_PACKET_HEADER.pack(
        TEST_PACKET_MAGIC,
        TEST_PACKET_VERSION,
        session_bytes,
        int(sequence),
        int(sent_ns),
    )
    return header + bytes(size - len(header))


def decode_test_packet(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < TEST_PACKET_HEADER.size:
        return None
    magic, version, session_bytes, sequence, sent_ns = TEST_PACKET_HEADER.unpack_from(payload)
    if magic != TEST_PACKET_MAGIC or version != TEST_PACKET_VERSION:
        return None
    return {
        "session_id": session_bytes.hex(),
        "sequence": sequence,
        "sent_ns": sent_ns,
        "size": len(payload),
    }


def parse_rtp_header(payload: bytes) -> dict[str, int] | None:
    if len(payload) < 12 or payload[0] >> 6 != 2:
        return None
    csrc_count = payload[0] & 0x0F
    header_size = 12 + csrc_count * 4
    if len(payload) < header_size:
        return None
    sequence, timestamp, ssrc = struct.unpack_from("!HII", payload, 2)
    return {
        "payload_type": payload[1] & 0x7F,
        "marker": (payload[1] >> 7) & 1,
        "sequence": sequence,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "header_size": header_size,
    }


def receive_multicast(
    config: dict[str, Any],
    *,
    ready: threading.Event | None = None,
    readiness: dict[str, str] | None = None,
    progress: MulticastProgressCallback | None = None,
    cancelled: threading.Event | None = None,
) -> dict[str, Any]:
    interface = config["receive_interface"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    started_wall = time.time()
    started = time.monotonic()
    try:
        _emit_progress(
            progress,
            phase="joining",
            elapsed_seconds=0.0,
            remaining_seconds=float(config["duration"]),
            packets_received=0,
            bytes_received=0,
            sources=0,
        )
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        reuse_port = getattr(socket, "SO_REUSEPORT", None)
        if reuse_port is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, reuse_port, 1)
            except OSError:
                pass
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, MULTICAST_RECEIVE_BUFFER_BYTES)
        sock.bind(("", config["port"]))
        group = socket.inet_aton(config["group"])
        local = socket.inet_aton(interface["address"])
        if config["membership"] == "ssm":
            source = socket.inet_aton(config["source"])
            option = _source_membership_option()
            if option is None:  # pragma: no cover - normalization checks this
                raise ToolInputError("Source-specific membership is unavailable on this host.")
            if sys.platform == "darwin":
                membership_request = group + source + local
            else:
                membership_request = group + local + source
            sock.setsockopt(socket.IPPROTO_IP, option, membership_request)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group + local)
        if readiness is not None:
            readiness["status"] = "joined"
        if ready is not None:
            ready.set()
        if progress is not None:
            _emit_progress(
                progress,
                phase="joined",
                elapsed_seconds=round(time.monotonic() - started, 3),
                remaining_seconds=float(config["duration"]),
                packets_received=0,
                bytes_received=0,
                sources=0,
            )
        return _collect_multicast(
            sock,
            config,
            started=started,
            started_wall=started_wall,
            progress=progress,
            cancelled=cancelled,
        )
    except PermissionError as exc:
        raise ToolInputError(
            "The toolkit does not have permission to bind this UDP port or join on the selected interface."
        ) from exc
    except OSError as exc:
        raise ToolInputError(f"Could not receive multicast traffic: {exc.strerror or str(exc)}") from exc
    finally:
        if ready is not None and not ready.is_set():
            if readiness is not None:
                readiness["status"] = "error"
            ready.set()
        sock.close()


def _collect_multicast(
    sock: socket.socket,
    config: dict[str, Any],
    *,
    started: float,
    started_wall: float,
    progress: MulticastProgressCallback | None = None,
    cancelled: threading.Event | None = None,
) -> dict[str, Any]:
    interface = config["receive_interface"]
    deadline = started + config["duration"]
    packet_count = 0
    byte_count = 0
    first_packet_at: float | None = None
    last_packet_at: float | None = None
    max_gap_ms = 0.0
    interarrival = _Variance()
    packet_sizes = _Variance()
    minimum_packet_bytes: int | None = None
    maximum_packet_bytes: int | None = None
    timeline: dict[int, dict[str, int]] = {}
    sources: dict[tuple[str, int], dict[str, Any]] = {}
    ignored_sources = 0
    source_limit_reached = False
    test_sessions: dict[str, _SequenceTracker] = {}
    test_packets = 0
    rtp_streams: dict[int, dict[str, Any]] = {}
    last_progress_at = started - MULTICAST_PROGRESS_INTERVAL_SECONDS

    def emit_progress(now: float, *, force: bool = False) -> None:
        nonlocal last_progress_at
        if progress is None:
            return
        if not force and now - last_progress_at < MULTICAST_PROGRESS_INTERVAL_SECONDS:
            return
        last_progress_at = now
        elapsed = max(0.0, now - started)
        visible_sources = sorted(
            sources.values(),
            key=lambda item: (-item["packets"], item["address"], item["port"]),
        )[:5]
        _emit_progress(
            progress,
            phase="receiving",
            elapsed_seconds=round(elapsed, 3),
            remaining_seconds=round(max(0.0, config["duration"] - elapsed), 3),
            packets_received=packet_count,
            bytes_received=byte_count,
            packets_per_second=round(packet_count / max(0.001, elapsed), 2),
            megabits_per_second=round(
                byte_count * 8 / max(0.001, elapsed) / 1_000_000,
                4,
            ),
            sources=len(sources),
            unexpected_source_packets=ignored_sources,
            top_sources=[
                {
                    "address": item["address"],
                    "port": item["port"],
                    "packets": item["packets"],
                }
                for item in visible_sources
            ],
            timeline=[
                {
                    "second": second,
                    "packets": timeline.get(second, {}).get("packets", 0),
                    "bytes": timeline.get(second, {}).get("bytes", 0),
                }
                for second in range(max(1, min(config["duration"], int(elapsed) + 1)))
            ],
        )

    emit_progress(started, force=True)

    while True:
        _raise_if_cancelled(cancelled)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(0.25, remaining))
        try:
            payload, source_address = sock.recvfrom(65535)
        except socket.timeout:
            if progress is not None:
                emit_progress(time.monotonic())
            continue
        now = time.monotonic()
        source_ip, source_port = source_address[:2]
        if config.get("source") and source_ip != config["source"]:
            ignored_sources += 1
            if config["membership"] == "ssm":
                continue
        if packet_count == 0:
            first_packet_at = now
        if last_packet_at is not None:
            gap_ms = (now - last_packet_at) * 1000
            interarrival.add(gap_ms)
            max_gap_ms = max(max_gap_ms, gap_ms)
        last_packet_at = now
        packet_count += 1
        byte_count += len(payload)
        packet_sizes.add(float(len(payload)))
        minimum_packet_bytes = (
            len(payload)
            if minimum_packet_bytes is None
            else min(minimum_packet_bytes, len(payload))
        )
        maximum_packet_bytes = (
            len(payload)
            if maximum_packet_bytes is None
            else max(maximum_packet_bytes, len(payload))
        )
        bucket = max(0, int(now - started))
        timeline.setdefault(bucket, {"packets": 0, "bytes": 0})
        timeline[bucket]["packets"] += 1
        timeline[bucket]["bytes"] += len(payload)

        key = (source_ip, int(source_port))
        if key not in sources and len(sources) < MULTICAST_MAX_SOURCES:
            sources[key] = {
                "address": source_ip,
                "port": int(source_port),
                "packets": 0,
                "bytes": 0,
                "first_seen_seconds": round(now - started, 3),
                "last_seen_seconds": round(now - started, 3),
                "expected": not config.get("source") or source_ip == config.get("source"),
            }
        elif key not in sources:
            source_limit_reached = True
        if key in sources:
            sources[key]["packets"] += 1
            sources[key]["bytes"] += len(payload)
            sources[key]["last_seen_seconds"] = round(now - started, 3)

        test_packet = decode_test_packet(payload)
        if test_packet and config["stream_format"] in {"generic", "twn"}:
            tracker = test_sessions.setdefault(
                test_packet["session_id"], _SequenceTracker(2**64)
            )
            tracker.add(test_packet["sequence"])
            test_packets += 1

        if config["stream_format"] == "rtp":
            rtp = parse_rtp_header(payload)
            if rtp:
                stream = rtp_streams.setdefault(
                    rtp["ssrc"],
                    {
                        "ssrc": f"0x{rtp['ssrc']:08x}",
                        "tracker": _SequenceTracker(2**16),
                        "payload_types": set(),
                        "packets": 0,
                        "jitter_ticks": 0.0,
                        "previous_transit": None,
                    },
                )
                stream["tracker"].add(rtp["sequence"])
                stream["payload_types"].add(rtp["payload_type"])
                stream["packets"] += 1
                transit = now * config["rtp_clock_rate"] - rtp["timestamp"]
                if stream["previous_transit"] is not None:
                    difference = abs(transit - stream["previous_transit"])
                    stream["jitter_ticks"] += (difference - stream["jitter_ticks"]) / 16
                stream["previous_transit"] = transit
        emit_progress(now)

    elapsed = max(0.001, time.monotonic() - started)
    emit_progress(started + elapsed, force=True)
    result = {
        "mode": config["mode"],
        "status": "success" if packet_count else "no_data",
        "summary": (
            f"Received {packet_count:,} multicast packet{'s' if packet_count != 1 else ''}."
            if packet_count
            else "The group was joined, but no multicast data arrived."
        ),
        "group": config["group"],
        "group_scope": config["group_scope"],
        "port": config["port"],
        "membership": config["membership"].upper(),
        "source_filter": config.get("source", ""),
        "receive_interface": interface,
        "duration_seconds": round(elapsed, 3),
        "started_at": _iso_timestamp(started_wall),
        "packets_received": packet_count,
        "bytes_received": byte_count,
        "average_packets_per_second": round(packet_count / elapsed, 2),
        "average_megabits_per_second": round(byte_count * 8 / elapsed / 1_000_000, 4),
        "first_packet_delay_ms": (
            round((first_packet_at - started) * 1000, 3) if first_packet_at else None
        ),
        "last_packet_seconds": (
            round(last_packet_at - started, 3) if last_packet_at else None
        ),
        "maximum_gap_ms": round(max_gap_ms, 3),
        "average_interarrival_ms": round(interarrival.mean, 3),
        "interarrival_jitter_ms": round(interarrival.standard_deviation, 3),
        "minimum_packet_bytes": minimum_packet_bytes or 0,
        "maximum_packet_bytes": maximum_packet_bytes or 0,
        "average_packet_bytes": round(packet_sizes.mean, 1) if packet_count else 0,
        "ignored_source_packets": ignored_sources,
        "sources": sorted(sources.values(), key=lambda item: (-item["packets"], item["address"], item["port"])),
        "source_limit_reached": source_limit_reached,
        "timeline": [
            {
                "second": second,
                "packets": timeline.get(second, {}).get("packets", 0),
                "bytes": timeline.get(second, {}).get("bytes", 0),
            }
            for second in range(max(1, math.ceil(elapsed)))
        ],
        "test_payload": _test_payload_summary(test_sessions, test_packets),
        "rtp_streams": _rtp_summaries(rtp_streams, config["rtp_clock_rate"]),
        "warnings": list(config.get("warnings", [])),
        "limitations": _receive_limitations(config, packet_count),
    }
    return result


def send_multicast(
    config: dict[str, Any],
    *,
    session_id: str | None = None,
    progress: MulticastProgressCallback | None = None,
    cancelled: threading.Event | None = None,
) -> dict[str, Any]:
    interface = config["send_interface"]
    session_id = session_id or secrets.token_hex(8)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sent = 0
    sent_bytes = 0
    started_wall = time.time()
    started = time.monotonic()
    warning = ""
    last_progress_at = started - MULTICAST_PROGRESS_INTERVAL_SECONDS

    def emit_progress(now: float, *, force: bool = False) -> None:
        nonlocal last_progress_at
        if progress is None:
            return
        if not force and now - last_progress_at < MULTICAST_PROGRESS_INTERVAL_SECONDS:
            return
        last_progress_at = now
        elapsed = max(0.0, now - started)
        _emit_progress(
            progress,
            phase="sending",
            elapsed_seconds=round(elapsed, 3),
            remaining_seconds=round(max(0.0, config["duration"] - elapsed), 3),
            packets_sent=sent,
            packets_requested=int(config["requested_packets"]),
            bytes_sent=sent_bytes,
            packets_per_second=round(sent / max(0.001, elapsed), 2),
            megabits_per_second=round(
                sent_bytes * 8 / max(0.001, elapsed) / 1_000_000,
                4,
            ),
        )

    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface["address"]))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, int(config["ttl"]))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, int(bool(config["loopback"])))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, int(config["dscp"]) << 2)
        sock.bind((interface["address"], int(config["source_port"])))
        source_port = int(sock.getsockname()[1])
        packets_per_second = float(config["packets_per_second"])
        interval = 1.0 / packets_per_second
        deadline = started + config["duration"]
        emit_progress(started, force=True)
        for sequence in range(int(config["requested_packets"])):
            _raise_if_cancelled(cancelled)
            scheduled = started + sequence * interval
            remaining = scheduled - time.monotonic()
            if remaining > 0:
                if cancelled is not None:
                    if cancelled.wait(timeout=remaining):
                        raise MulticastTestCancelled
                else:
                    time.sleep(remaining)
            if time.monotonic() > deadline + interval:
                break
            packet = build_test_packet(
                session_id,
                sequence,
                time.time_ns(),
                int(config["packet_size"]),
            )
            try:
                delivered = sock.sendto(packet, (config["group"], config["port"]))
            except OSError as exc:
                if not sent:
                    raise
                warning = f"Sending stopped after {sent:,} packets: {exc.strerror or str(exc)}"
                break
            sent += 1
            sent_bytes += delivered
            if progress is not None:
                emit_progress(time.monotonic())
        if not warning:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                if cancelled is not None:
                    if cancelled.wait(timeout=remaining):
                        raise MulticastTestCancelled
                else:
                    time.sleep(remaining)
    except PermissionError as exc:
        raise ToolInputError(
            "The toolkit does not have permission to bind the selected source address or port."
        ) from exc
    except OSError as exc:
        raise ToolInputError(f"Could not send multicast traffic: {exc.strerror or str(exc)}") from exc
    finally:
        sock.close()
    elapsed = max(0.001, time.monotonic() - started)
    emit_progress(started + elapsed, force=True)
    warnings = list(config.get("warnings", []))
    if warning:
        warnings.append(warning)
    if sent < int(config["requested_packets"]):
        warnings.append(
            f"The host sent {sent:,} of {int(config['requested_packets']):,} scheduled packets; "
            "the requested pace may exceed this host or interface."
        )
    return {
        "mode": config["mode"],
        "status": "success" if sent else "error",
        "summary": f"Sent {sent:,} sequenced multicast packet{'s' if sent != 1 else ''}.",
        "group": config["group"],
        "group_scope": config["group_scope"],
        "port": config["port"],
        "send_interface": interface,
        "source_port": source_port,
        "duration_seconds": round(elapsed, 3),
        "started_at": _iso_timestamp(started_wall),
        "session_id": session_id,
        "packets_requested": int(config["requested_packets"]),
        "packets_sent": sent,
        "bytes_sent": sent_bytes,
        "packet_size": int(config["packet_size"]),
        "ttl": int(config["ttl"]),
        "dscp": int(config["dscp"]),
        "loopback": bool(config["loopback"]),
        "average_packets_per_second": round(sent / elapsed, 2),
        "average_megabits_per_second": round(sent_bytes * 8 / elapsed / 1_000_000, 4),
        "warnings": warnings,
        "limitations": [
            "A successful send confirms local socket delivery, not that any receiver obtained the stream."
        ],
    }


def run_multicast_path_test(
    config: dict[str, Any],
    *,
    progress: MulticastProgressCallback | None = None,
    cancelled: threading.Event | None = None,
) -> dict[str, Any]:
    session_id = secrets.token_hex(8)
    receive_config = {
        **config,
        "mode": "path",
        "stream_format": "twn",
        "duration": int(config["duration"]) + 1,
        "source": config["send_interface"]["address"] if config["membership"] == "ssm" else config.get("source", ""),
    }
    ready = threading.Event()
    readiness: dict[str, str] = {}

    def receiver_progress(event: dict[str, Any]) -> None:
        if progress is not None:
            progress({**event, "lane": "receive"})

    def sender_progress(event: dict[str, Any]) -> None:
        if progress is not None:
            progress({**event, "lane": "send"})

    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="twn-multicast") as executor:
        future = executor.submit(
            receive_multicast,
            receive_config,
            ready=ready,
            readiness=readiness,
            progress=receiver_progress,
            cancelled=cancelled,
        )
        if not ready.wait(timeout=3):
            raise ToolInputError("The multicast receiver did not become ready within three seconds.")
        if readiness.get("status") != "joined":
            return future.result()
        if cancelled is not None:
            if cancelled.wait(timeout=0.2):
                raise MulticastTestCancelled
        else:
            time.sleep(0.2)
        send_result = send_multicast(
            {**config, "loopback": False},
            session_id=session_id,
            progress=sender_progress,
            cancelled=cancelled,
        )
        receive_result = future.result()

    tracker_summary = next(
        (
            item
            for item in receive_result["test_payload"].get("sessions", [])
            if item["session_id"] == session_id
        ),
        None,
    )
    unique_received = int((tracker_summary or {}).get("unique_packets", 0))
    packets_sent = int(send_result["packets_sent"])
    lost = max(0, packets_sent - unique_received)
    loss_pct = round(lost * 100 / packets_sent, 4) if packets_sent else 0.0
    status = "success" if unique_received and lost == 0 else "degraded" if unique_received else "no_data"
    summary = (
        f"Received all {unique_received:,} sequenced packets across the selected interfaces."
        if status == "success"
        else f"Received {unique_received:,} of {packets_sent:,} sequenced packets ({loss_pct:g}% loss)."
        if unique_received
        else "The sender ran, but no sequenced test packets arrived on the receive interface."
    )
    return {
        "mode": "path",
        "status": status,
        "summary": summary,
        "group": config["group"],
        "group_scope": config["group_scope"],
        "port": config["port"],
        "membership": config["membership"].upper(),
        "session_id": session_id,
        "send_interface": config["send_interface"],
        "receive_interface": config["receive_interface"],
        "packets_sent": packets_sent,
        "packets_received": unique_received,
        "packets_lost": lost,
        "loss_percent": loss_pct,
        "duplicates": int((tracker_summary or {}).get("duplicates", 0)),
        "out_of_order": int((tracker_summary or {}).get("out_of_order", 0)),
        "send": send_result,
        "receive": receive_result,
        "warnings": list(dict.fromkeys([*send_result["warnings"], *receive_result["warnings"]])),
        "limitations": [
            "A successful dual-interface result proves that the host received its sequenced stream through the selected receive interface.",
            "Same-host results still depend on local routing and filtering behavior. Use separate sender and receiver toolkit hosts when you need independent endpoint evidence.",
            "This test does not identify which switch or router dropped traffic when delivery fails.",
        ],
    }


def multicast_group_scope(group: ipaddress.IPv4Address | str) -> str:
    parsed = ipaddress.IPv4Address(group)
    if parsed in ipaddress.IPv4Network("224.0.0.0/24"):
        return "link-local control"
    if parsed in ipaddress.IPv4Network("232.0.0.0/8"):
        return "source-specific"
    if parsed in ipaddress.IPv4Network("239.0.0.0/8"):
        return "administratively scoped"
    return "globally scoped or assigned"


def _selected_interface(
    value: object,
    by_name: dict[str, dict[str, Any]],
    role: str,
) -> dict[str, Any]:
    name = str(value).strip()
    selected = by_name.get(name)
    if not selected:
        raise ToolInputError(f"Select an available IPv4 {role} interface.")
    return {
        "name": name,
        "address": str(selected["address"]),
        "index": int(selected.get("index", 0)),
        "point_to_point": bool(selected.get("point_to_point", False)),
    }


def _optional_unicast_ipv4(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError as exc:
        raise ToolInputError(f"Enter a valid IPv4 {label} address.") from exc
    if (
        parsed.is_multicast
        or parsed.is_unspecified
        or parsed == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise ToolInputError(f"Enter a usable unicast IPv4 {label} address.")
    return str(parsed)


def _source_membership_option() -> int | None:
    exported = getattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", None)
    if exported is not None:
        return int(exported)
    if sys.platform.startswith("linux"):
        return 39
    if sys.platform == "darwin":
        return 70
    return None


def _interface_flags(name: str) -> set[str]:
    if sys.platform.startswith("linux"):
        try:
            value = int(Path(f"/sys/class/net/{name}/flags").read_text(encoding="ascii").strip(), 16)
        except (OSError, ValueError):
            return set()
        flags = set()
        if value & 0x1:
            flags.add("UP")
        if value & 0x10:
            flags.add("POINTOPOINT")
        if value & 0x1000:
            flags.add("MULTICAST")
        return flags
    binary = "/sbin/ifconfig" if os.path.exists("/sbin/ifconfig") else "ifconfig"
    try:
        completed = subprocess.run(
            [binary, name],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    match = re.search(r"<([^>]+)>", completed.stdout)
    return {flag.strip().upper() for flag in match.group(1).split(",")} if match else set()


def _group_warnings(group: ipaddress.IPv4Address) -> list[str]:
    warnings = []
    if group in ipaddress.IPv4Network("224.0.0.0/24"):
        warnings.append(
            "224.0.0.0/24 is link-local control space and is not forwarded by multicast routers."
        )
    elif group not in ipaddress.IPv4Network("239.0.0.0/8") and group not in ipaddress.IPv4Network("232.0.0.0/8"):
        warnings.append(
            "This is not administratively scoped or source-specific space; confirm the group assignment before sending."
        )
    return warnings


def _test_payload_summary(
    sessions: dict[str, _SequenceTracker], packet_count: int
) -> dict[str, Any]:
    return {
        "detected": bool(sessions),
        "packets": packet_count,
        "sessions": [
            {
                "session_id": session_id,
                "unique_packets": len(tracker.seen),
                "first_sequence": min(tracker.seen) if tracker.seen else None,
                "last_sequence": max(tracker.seen) if tracker.seen else None,
                "observed_missing": tracker.observed_missing,
                "duplicates": tracker.duplicates,
                "out_of_order": tracker.out_of_order,
            }
            for session_id, tracker in sorted(sessions.items())
        ],
    }


def _rtp_summaries(streams: dict[int, dict[str, Any]], clock_rate: int) -> list[dict[str, Any]]:
    return [
        {
            "ssrc": stream["ssrc"],
            "packets": stream["packets"],
            "payload_types": sorted(stream["payload_types"]),
            "observed_missing": stream["tracker"].observed_missing,
            "duplicates": stream["tracker"].duplicates,
            "out_of_order": stream["tracker"].out_of_order,
            "interarrival_jitter_ms": round(stream["jitter_ticks"] * 1000 / clock_rate, 3),
        }
        for stream in streams.values()
    ]


def _receive_limitations(config: dict[str, Any], packet_count: int) -> list[str]:
    limitations = []
    if config["stream_format"] == "generic" and packet_count:
        limitations.append(
            "Generic UDP payloads do not expose sequence numbers, so exact packet loss and reordering cannot be calculated."
        )
    if config["stream_format"] == "rtp" and not packet_count:
        limitations.append("RTP sequence analysis requires received RTP version 2 packets.")
    limitations.append(
        "Joining the local socket does not prove that upstream IGMP snooping, PIM, RPF, or multicast routing is configured correctly."
    )
    return limitations


def _iso_timestamp(value: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))


def _emit_progress(
    callback: MulticastProgressCallback | None,
    **event: Any,
) -> None:
    if callback is not None:
        callback({"type": "progress", **event})


def _raise_if_cancelled(cancelled: threading.Event | None) -> None:
    if cancelled is not None and cancelled.is_set():
        raise MulticastTestCancelled
