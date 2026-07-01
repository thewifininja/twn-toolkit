from __future__ import annotations

import math
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Any

from .network_tools import ToolInputError


NTP_EPOCH_OFFSET = 2_208_988_800
NTP_PACKET = struct.Struct("!BBBbiI4sQQQQ")
LEAP_STATES = {
    0: "No warning",
    1: "Last minute has 61 seconds",
    2: "Last minute has 59 seconds",
    3: "Clock not synchronized",
}


def test_ntp_server(
    host: str,
    port: int = 123,
    timeout: float = 3.0,
    samples: int = 4,
) -> dict[str, Any]:
    host = host.strip()
    if not host:
        raise ToolInputError("Enter an NTP server hostname or IP address.")
    if not 1 <= port <= 65535:
        raise ToolInputError("NTP port must be between 1 and 65535.")
    if not 0.2 <= timeout <= 15:
        raise ToolInputError("NTP timeout must be between 0.2 and 15 seconds.")
    if not 1 <= samples <= 10:
        raise ToolInputError("NTP samples must be between 1 and 10.")

    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise ToolInputError(f"Could not resolve NTP server '{host}': {exc}") from exc
    if not addresses:
        raise ToolInputError(f"Could not resolve NTP server '{host}'.")

    results: list[dict[str, Any]] = []
    for index in range(samples):
        results.append(_query_ntp(addresses, timeout))
        if index + 1 < samples:
            time.sleep(0.15)

    successful = [sample for sample in results if sample["status"] == "success"]
    offsets = [sample["offset_ms"] for sample in successful]
    delays = [sample["delay_ms"] for sample in successful]
    jitter = (
        math.sqrt(sum((value - sum(offsets) / len(offsets)) ** 2 for value in offsets) / (len(offsets) - 1))
        if len(offsets) > 1
        else 0.0
    )
    first = successful[0] if successful else None
    return {
        "host": host,
        "port": port,
        "resolved_address": first["server_address"] if first else "",
        "status": "success" if successful else "error",
        "successful_samples": len(successful),
        "total_samples": samples,
        "offset_ms": round(sum(offsets) / len(offsets), 3) if offsets else None,
        "delay_ms": round(sum(delays) / len(delays), 3) if delays else None,
        "jitter_ms": round(jitter, 3) if offsets else None,
        "stratum": first["stratum"] if first else None,
        "version": first["version"] if first else None,
        "leap": first["leap"] if first else None,
        "leap_text": first["leap_text"] if first else "",
        "reference_id": first["reference_id"] if first else "",
        "reference_time": first["reference_time"] if first else "",
        "root_delay_ms": first["root_delay_ms"] if first else None,
        "root_dispersion_ms": first["root_dispersion_ms"] if first else None,
        "precision_seconds": first["precision_seconds"] if first else None,
        "synchronized": bool(first and first["synchronized"]),
        "samples": results,
    }


def _query_ntp(addresses: list[tuple[Any, ...]], timeout: float) -> dict[str, Any]:
    last_error = "No response"
    for family, socktype, proto, _canonname, sockaddr in addresses:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            t1 = time.time()
            transmit_raw = _unix_to_ntp(t1)
            request = NTP_PACKET.pack(0x23, 0, 0, 0, 0, 0, b"\0\0\0\0", 0, 0, 0, transmit_raw)
            sock.sendto(request, sockaddr)
            packet, source = sock.recvfrom(512)
            t4 = time.time()
            return _parse_response(packet, source[0], transmit_raw, t1, t4)
        except (OSError, ValueError) as exc:
            last_error = str(exc)
        finally:
            sock.close()
    return {"status": "error", "error": last_error}


def _parse_response(
    packet: bytes,
    server_address: str,
    request_timestamp: int,
    t1: float,
    t4: float,
) -> dict[str, Any]:
    if len(packet) < NTP_PACKET.size:
        raise ValueError(f"Invalid NTP response: expected 48 bytes, received {len(packet)}.")
    (
        flags,
        stratum,
        poll,
        precision,
        root_delay,
        root_dispersion,
        reference_id,
        reference_timestamp,
        originate_timestamp,
        receive_timestamp,
        transmit_timestamp,
    ) = NTP_PACKET.unpack_from(packet)
    leap, version, mode = flags >> 6, (flags >> 3) & 0x07, flags & 0x07
    if mode not in {4, 5}:
        raise ValueError(f"Invalid NTP response mode {mode}.")
    if originate_timestamp != request_timestamp:
        raise ValueError("NTP response does not match the request timestamp.")
    if not receive_timestamp or not transmit_timestamp:
        raise ValueError("NTP server returned an incomplete timestamp.")

    t2 = _ntp_to_unix(receive_timestamp)
    t3 = _ntp_to_unix(transmit_timestamp)
    delay = (t4 - t1) - (t3 - t2)
    offset = ((t2 - t1) + (t3 - t4)) / 2
    return {
        "status": "success",
        "server_address": server_address,
        "version": version,
        "mode": mode,
        "stratum": stratum,
        "poll_seconds": 2**poll,
        "precision_seconds": 2**precision,
        "root_delay_ms": round(root_delay / 65536 * 1000, 3),
        "root_dispersion_ms": round(root_dispersion / 65536 * 1000, 3),
        "reference_id": _format_reference_id(reference_id, stratum),
        "reference_time": _format_ntp_time(reference_timestamp),
        "server_time": _format_ntp_time(transmit_timestamp),
        "leap": leap,
        "leap_text": LEAP_STATES[leap],
        "synchronized": leap != 3 and 1 <= stratum <= 15,
        "offset_ms": round(offset * 1000, 3),
        "delay_ms": round(max(0.0, delay) * 1000, 3),
    }


def _unix_to_ntp(timestamp: float) -> int:
    seconds = int(timestamp) + NTP_EPOCH_OFFSET
    fraction = int((timestamp - int(timestamp)) * 2**32)
    return (seconds << 32) | fraction


def _ntp_to_unix(timestamp: int) -> float:
    seconds, fraction = timestamp >> 32, timestamp & 0xFFFFFFFF
    return seconds - NTP_EPOCH_OFFSET + fraction / 2**32


def _format_ntp_time(timestamp: int) -> str:
    if not timestamp:
        return "Not provided"
    value = datetime.fromtimestamp(_ntp_to_unix(timestamp), tz=timezone.utc)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _format_reference_id(value: bytes, stratum: int) -> str:
    if stratum <= 1:
        text = value.rstrip(b"\0").decode("ascii", errors="replace")
        return text or value.hex().upper()
    return socket.inet_ntoa(value)
