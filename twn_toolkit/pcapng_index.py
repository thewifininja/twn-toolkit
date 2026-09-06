"""Bounded, disposable PCAPNG checkpoints for the packet-header viewer.

Only packet/interface metadata is indexed. No capture payloads, decryption
secrets, file handles, or Scapy reader objects survive a request.
Format: https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import os
from pathlib import Path
import struct
import threading
from typing import Any, BinaryIO, Callable

from .network_tools import ToolInputError

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
# Process-local performance budgets, independent of operator capture quotas.
CHECKPOINT_INTERVAL = 128
MAX_INDEXED_FILES = 16
MAX_CHECKPOINTS_PER_FILE = 128
MAX_CHECKPOINT_INTERFACE_REFERENCES = 4096
MAX_SECTION_INTERFACES = 4096


@dataclass(frozen=True)
class _Interface:
    linktype: int
    snaplen: int
    resolution: int = 1_000_000
    time_offset: int = 0


@dataclass(frozen=True)
class _Checkpoint:
    index: int = 0
    offset: int = 0
    endian: str = ""
    interfaces: tuple[_Interface, ...] = ()


@dataclass(frozen=True)
class PacketRecord:
    frame: bytes
    linktype: int
    timestamp: float
    wire_length: int


@dataclass(frozen=True)
class _PacketPosition:
    offset: int
    length: int
    interface: _Interface
    timestamp: float
    wire_length: int


# Keys identify a particular version of an already-opened file.
_indexes: OrderedDict[tuple, tuple[_Checkpoint, ...]] = OrderedDict()
_index_lock = threading.Lock()


def _signature(source: BinaryIO) -> tuple[int, ...]:
    stat = os.fstat(source.fileno())
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _lookup(key: tuple, start: int) -> tuple[_Checkpoint, tuple[_Checkpoint, ...]]:
    with _index_lock:
        points = _indexes.get(key, ())
        if points:
            _indexes.move_to_end(key)
        point = max((p for p in points if p.index <= start),
                    key=lambda p: p.index, default=_Checkpoint())
        return point, points


def _remember(points: OrderedDict[int, _Checkpoint], point: _Checkpoint) -> None:
    points[point.index] = point
    points.move_to_end(point.index)
    while (len(points) > MAX_CHECKPOINTS_PER_FILE
           or sum(len(p.interfaces) for p in points.values())
           > MAX_CHECKPOINT_INTERFACE_REFERENCES):
        points.popitem(last=False)


def _publish(key: tuple, points: OrderedDict[int, _Checkpoint]) -> None:
    with _index_lock:
        # Keep only one observed version per pathname. Concurrent requests may
        # publish older versions, but signature matching prevents their reuse.
        for stale in tuple(_indexes):
            if stale[0] == key[0] and stale != key:
                del _indexes[stale]
        combined = OrderedDict((p.index, p) for p in _indexes.get(key, ()))
        for point in points.values():
            _remember(combined, point)
        _indexes[key] = tuple(combined.values())
        _indexes.move_to_end(key)
        while len(_indexes) > MAX_INDEXED_FILES:
            _indexes.popitem(last=False)


class _Incomplete(Exception):
    pass


def _read(source: BinaryIO, count: int) -> bytes:
    value = source.read(count)
    if len(value) != count:
        raise _Incomplete
    return value


def _interface(source: BinaryIO, endian: str, body: int, end: int) -> _Interface:
    if end - body < 8:
        raise ToolInputError("The PCAPNG interface block is too short.")
    source.seek(body)
    linktype, snaplen = struct.unpack(endian + "HxxI", _read(source, 8))
    resolution, time_offset = 1_000_000, 0
    while source.tell() < end:
        if end - source.tell() < 4:
            raise ToolInputError("The PCAPNG interface option is incomplete.")
        code, length = struct.unpack(endian + "HH", _read(source, 4))
        option_end = source.tell() + ((length + 3) & ~3)
        if option_end > end:
            raise ToolInputError("The PCAPNG interface option exceeds its block.")
        if code == 0:
            if length:
                raise ToolInputError("The PCAPNG end-of-options marker is invalid.")
            break
        if code == 9:
            if length != 1:
                raise ToolInputError("The PCAPNG timestamp resolution is invalid.")
            value = _read(source, 1)[0]
            resolution = (2 if value & 128 else 10) ** (value & 127)
        elif code == 14:
            if length != 8:
                raise ToolInputError("The PCAPNG timestamp offset is invalid.")
            time_offset = struct.unpack(endian + "q", _read(source, 8))[0]
        source.seek(option_end)
    return _Interface(linktype, snaplen, resolution, time_offset)


def _block(source: BinaryIO, point: _Checkpoint, size: int,
           max_packet_bytes: int) -> tuple[_Checkpoint, _PacketPosition | None]:
    """Inspect one block without reading packet data or unrelated metadata."""
    source.seek(point.offset)
    header = _read(source, 12)
    endian = point.endian
    is_section = header[:4] == PCAPNG_MAGIC
    if is_section:
        endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(header[8:12], "")
    if not endian:
        raise ToolInputError("The PCAPNG section header is invalid.")
    kind, length = struct.unpack(endian + "II", header[:8])
    if length < 12 or length % 4:
        raise ToolInputError("The PCAPNG block length is invalid.")
    end = point.offset + length
    if end > size:
        raise _Incomplete
    source.seek(end - 4)
    if struct.unpack(endian + "I", _read(source, 4))[0] != length:
        raise ToolInputError("The PCAPNG block lengths do not match.")
    interfaces = point.interfaces
    body, body_end = point.offset + 8, end - 4
    if is_section:
        if length < 28:
            raise ToolInputError("The PCAPNG section header is too short.")
        source.seek(body + 4)
        if struct.unpack(endian + "H", _read(source, 2))[0] != 1:
            raise ToolInputError("The PCAPNG section version is unsupported.")
        interfaces = ()  # Interface identifiers restart in each section.
    elif kind == 1:
        if len(interfaces) >= MAX_SECTION_INTERFACES:
            raise ToolInputError("The PCAPNG section exceeds the viewer's interface limit.")
        interfaces += (_interface(source, endian, body, body_end),)
    elif kind in {2, 3, 6}:
        minimum = 4 if kind == 3 else 20
        if body_end - body < minimum:
            raise ToolInputError("The PCAPNG packet block is too short.")
        source.seek(body)
        if kind == 3:
            interface_id, ticks = 0, None
            wire_length = struct.unpack(endian + "I", _read(source, 4))[0]
            captured = wire_length  # Clamped to snaplen below, unless unlimited.
        elif kind == 2:
            interface_id, _, high, low, captured, wire_length = struct.unpack(
                endian + "HH4I", _read(source, 20))
            ticks = (high << 32) + low
        else:
            interface_id, high, low, captured, wire_length = struct.unpack(
                endian + "5I", _read(source, 20))
            ticks = (high << 32) + low
        if interface_id >= len(interfaces):
            raise ToolInputError("The PCAPNG packet references an unknown interface.")
        interface = interfaces[interface_id]
        if kind == 3 and interface.snaplen:
            captured = min(captured, interface.snaplen)
        if captured > max_packet_bytes:
            raise ToolInputError("A packet record exceeds the viewer's 16 MiB safety limit.")
        if body + minimum + ((captured + 3) & ~3) > body_end:
            raise ToolInputError("The PCAPNG packet length exceeds its block.")
        timestamp = 0.0 if ticks is None else ticks / interface.resolution + interface.time_offset
        packet = _PacketPosition(body + minimum, captured, interface, timestamp, wire_length)
        return _Checkpoint(point.index + 1, end, endian, interfaces), packet
    # Unknown blocks, name resolution, comments, and decryption secrets are
    # intentionally skipped: this viewer exposes only packet-header summaries.
    return _Checkpoint(point.index, end, endian, interfaces), None


def read_page(path: Path, *, start: int, limit: int, allow_incomplete: bool,
              max_packet_bytes: int,
              summarize: Callable[[PacketRecord, int], Any]) -> tuple[list[Any], bool]:
    packets: list[Any] = []
    has_more = False
    with path.open("rb") as source:
        signature = _signature(source)
        key = (str(path.resolve()), *signature)
        point, previous = _lookup(key, start)
        points = OrderedDict((p.index, p) for p in previous)
        size = signature[2]
        while point.offset < size:
            before = point
            try:
                following, packet = _block(source, before, size, max_packet_bytes)
            except _Incomplete as exc:
                if not allow_incomplete:
                    raise ToolInputError("The PCAPNG capture ends in an incomplete block.") from exc
                break
            if packet is not None:
                if before.index % CHECKPOINT_INTERVAL == 0 or before.index == start + limit:
                    _remember(points, before)
                if before.index >= start + limit:
                    has_more = True
                    break
                if before.index >= start:
                    source.seek(packet.offset)
                    try:
                        frame = _read(source, packet.length)
                    except _Incomplete as exc:
                        raise ToolInputError("The capture changed while it was being read; refresh the viewer.") from exc
                    packets.append(summarize(
                        PacketRecord(frame, packet.interface.linktype,
                                     packet.timestamp, packet.wire_length),
                        before.index + 1,
                    ))
            point = following
        _remember(points, point)
        if _signature(source) != signature:
            raise ToolInputError("The capture changed while it was being read; refresh the viewer.")
        _publish(key, points)
    return packets, has_more
