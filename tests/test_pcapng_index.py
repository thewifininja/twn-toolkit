from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import PcapNgWriter

from twn_toolkit import pcapng_index as index
from twn_toolkit import pcap_viewer as viewer
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.pcap_viewer import inspect_packet_capture


def block(kind, body, endian='<'):
    body += b'\x00' * (-len(body) % 4)
    length = len(body) + 12
    return struct.pack(endian + 'II', kind, length) + body + struct.pack(endian + 'I', length)


def section(endian='<'):
    return block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)


def option(code, value, endian='<'):
    return struct.pack(endian + 'HH', code, len(value)) + value + b'\x00' * (-len(value) % 4)


def interface(linktype=1, *, snaplen=65535, resolution=6, offset=0, endian='<'):
    options = option(9, bytes([resolution]), endian) + option(14, struct.pack(endian + 'q', offset), endian)
    return block(1, struct.pack(endian + 'HHI', linktype, 0, snaplen) + options + b'\x00' * 4, endian)


def packet(frame, *, interface_id=0, ticks=1_000_000, endian='<', kind=6):
    high, low = ticks >> 32, ticks & 0xffffffff
    if kind == 2:
        header = struct.pack(endian + 'HH4I', interface_id, 0, high, low, len(frame), len(frame))
    elif kind == 3:
        header = struct.pack(endian + 'I', len(frame))
    else:
        header = struct.pack(endian + '5I', interface_id, high, low, len(frame), len(frame))
    return block(kind, header + frame, endian)


class PcapngIndexTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'capture.pcapng'
        self.frame = bytes(Ether() / IP(src='192.0.2.1', dst='198.51.100.1') / UDP(sport=1, dport=2))
        with index._index_lock:
            index._indexes.clear()
        self.addCleanup(index._indexes.clear)

    def make_capture(self, count):
        # An independent writer also verifies compatibility beyond our fixtures.
        with PcapNgWriter(str(self.path)) as writer:
            for number in range(count):
                writer.write(Ether() / IP(src='192.0.2.1') / UDP(sport=number + 1, dport=53))

    def test_later_pages_resume_without_rescanning_or_decoding_prefix(self):
        self.make_capture(550)
        with patch.object(viewer, '_decode_link_packet', wraps=viewer._decode_link_packet) as decode:
            first = inspect_packet_capture(self.path, start=400, limit=50)
        self.assertEqual(decode.call_count, 50)
        self.assertEqual(first['packets'][0]['number'], 401)
        with patch.object(index, '_block', wraps=index._block) as read_block:
            second = inspect_packet_capture(self.path, start=450, limit=50)
        self.assertEqual(read_block.call_count, 51)
        self.assertEqual(second['packets'][0]['source_port'], 451)
        self.assertTrue(second['has_more'])
        final = inspect_packet_capture(self.path, start=500, limit=50)
        self.assertEqual(final['next_start'], 550)
        self.assertFalse(final['has_more'])
        # Returning to an earlier page still works, even after advancing the index.
        earlier = inspect_packet_capture(self.path, start=5, limit=3)
        self.assertEqual([p['number'] for p in earlier['packets']], [6, 7, 8])

    def test_multiple_interfaces_timestamps_and_opposite_endian_sections(self):
        raw_ip = bytes(IP(src='203.0.113.8') / UDP(sport=30, dport=40))
        self.path.write_bytes(
            section() + interface() + packet(self.frame)
            + interface(101, resolution=0x8a, offset=-2)
            + packet(raw_ip, interface_id=1, ticks=3072)
            + section('>') + interface(101, resolution=9, offset=10, endian='>')
            + packet(raw_ip, ticks=2_000_000_000, endian='>')
            + packet(raw_ip, ticks=3_000_000_000, endian='>')
        )
        pages = [inspect_packet_capture(self.path, start=n, limit=1) for n in range(4)]
        summaries = [p['packets'][0] for p in pages]
        self.assertEqual([p['timestamp'] for p in summaries], [1, 1, 12, 13])
        self.assertEqual([p['source_ip'] for p in summaries], ['192.0.2.1'] + ['203.0.113.8'] * 3)
        self.assertEqual(summaries[2]['protocol'], 'UDP')
        self.assertEqual(summaries[2]['source_mac'], '')

    def test_simple_and_obsolete_packet_blocks_and_unlimited_snaplen(self):
        self.path.write_bytes(section() + interface(snaplen=0)
                              + packet(self.frame, kind=3) + packet(self.frame, kind=2))
        result = inspect_packet_capture(self.path)
        self.assertEqual([p['protocol'] for p in result['packets']], ['UDP', 'UDP'])
        self.assertEqual(result['packets'][0]['captured_length'], len(self.frame))
        self.assertEqual(result['packets'][0]['timestamp'], 0)
        self.assertEqual(result['packets'][1]['timestamp'], 1)
        # SPB has no captured-length field: derive it from the interface snaplen.
        self.path.write_bytes(section() + interface(snaplen=14)
                              + block(3, struct.pack('<I', len(self.frame)) + self.frame[:14]))
        result = inspect_packet_capture(self.path)
        self.assertEqual(result['packets'][0]['captured_length'], 14)
        self.assertEqual(result['packets'][0]['wire_length'], len(self.frame))

    def test_out_of_calendar_range_timestamp_preserves_packet_headers(self):
        self.path.write_bytes(section() + interface(resolution=0, offset=2**63 - 1)
                              + packet(self.frame, ticks=2**64 - 1))
        summary = inspect_packet_capture(self.path)['packets'][0]
        self.assertEqual(summary['protocol'], 'UDP')
        self.assertEqual(summary['time_display'], '—')
        self.assertGreater(summary['timestamp'], 2**63)

    def test_file_growth_replacement_rewrite_and_truncation_invalidate_index(self):
        prefix = section() + interface()
        data = prefix + packet(self.frame) * 5
        self.path.write_bytes(data)
        inspect_packet_capture(self.path, start=3, limit=1)
        with self.path.open('ab') as stream:
            stream.write(packet(self.frame))
        self.assertEqual(inspect_packet_capture(self.path, start=5)['packets'][0]['number'], 6)
        changed = bytes(Ether() / IP(src='192.0.2.2') / UDP(sport=9, dport=10))
        # Same-sized rewrite; even restoring mtime cannot preserve the ctime identity.
        old = self.path.stat()
        self.path.write_bytes(prefix + packet(changed) * 6)
        os.utime(self.path, ns=(old.st_atime_ns, old.st_mtime_ns))
        self.assertEqual(inspect_packet_capture(self.path, start=4)['packets'][0]['source_ip'], '192.0.2.2')
        replacement = self.path.with_suffix('.new')
        replacement.write_bytes(prefix + packet(self.frame) * 6)
        replacement.replace(self.path)
        self.assertEqual(inspect_packet_capture(self.path, start=4)['packets'][0]['source_ip'], '192.0.2.1')
        self.path.write_bytes(prefix + packet(changed))
        self.assertEqual(inspect_packet_capture(self.path, start=4)['packets'], [])
        self.assertEqual(len(index._indexes), 1)

    def test_incomplete_tail_can_be_completed_without_losing_packet(self):
        first = section() + interface() + packet(self.frame)
        second = packet(self.frame)
        self.path.write_bytes(first + second[:18])
        page = inspect_packet_capture(self.path, allow_incomplete=True)
        self.assertEqual(len(page['packets']), 1)
        with self.assertRaisesRegex(ToolInputError, 'incomplete block'):
            inspect_packet_capture(self.path)
        self.path.write_bytes(first + second)
        resumed = inspect_packet_capture(self.path, start=page['next_start'], allow_incomplete=True)
        self.assertEqual([p['number'] for p in resumed['packets']], [2])

    def test_cache_limits_eviction_and_concurrent_pages(self):
        with patch.object(index, 'MAX_INDEXED_FILES', 2), \
             patch.object(index, 'MAX_CHECKPOINTS_PER_FILE', 3), \
             patch.object(index, 'MAX_CHECKPOINT_INTERFACE_REFERENCES', 2), \
             patch.object(index, 'CHECKPOINT_INTERVAL', 1):
            data = section() + interface() + packet(self.frame) * 20
            paths = [self.path.with_name(f'{n}.pcapng') for n in range(3)]
            for path in paths:
                path.write_bytes(data)
                inspect_packet_capture(path, start=15, limit=2)
            self.assertEqual(len(index._indexes), 2)
            self.assertNotIn(str(paths[0].resolve()), [k[0] for k in index._indexes])
            for points in index._indexes.values():
                self.assertLessEqual(len(points), 3)
                self.assertLessEqual(sum(len(p.interfaces) for p in points), 2)
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda n: inspect_packet_capture(paths[0], start=n, limit=1), range(12)))
            self.assertEqual([r['packets'][0]['number'] for r in results], list(range(1, 13)))
            self.assertLessEqual(len(index._indexes), 2)

    def test_skips_large_unknown_blocks_without_reading_contents(self):
        unknown = block(0x1234, b'x' * (2 * 1024 * 1024))
        self.path.write_bytes(section() + interface() + unknown + packet(self.frame))
        requested = []
        original = index._read
        def bounded_read(source, count):
            requested.append(count)
            return original(source, count)
        with patch.object(index, '_read', side_effect=bounded_read):
            result = inspect_packet_capture(self.path)
        self.assertEqual(result['packets'][0]['protocol'], 'UDP')
        self.assertLessEqual(max(requested), len(self.frame))

    def test_malformed_frame_does_not_hide_following_packets(self):
        self.path.write_bytes(section() + interface() + packet(b'\x00') + packet(self.frame))
        result = inspect_packet_capture(self.path)
        self.assertEqual(len(result['packets']), 2)
        self.assertEqual(result['packets'][0]['captured_length'], 1)
        self.assertEqual(result['packets'][1]['protocol'], 'UDP')

    def test_io_failure_is_reported_as_viewer_error(self):
        self.path.write_bytes(section() + interface() + packet(self.frame))
        with patch.object(index, '_block', side_effect=OSError('read failed')):
            with self.assertRaisesRegex(ToolInputError, 'Could not read'):
                inspect_packet_capture(self.path)
        self.assertFalse(index._indexes)

    def test_change_during_read_does_not_publish_checkpoints(self):
        self.path.write_bytes(section() + interface() + packet(self.frame))
        original = index._block
        def changing_read(*args):
            result = original(*args)
            if result[1] is not None:
                with self.path.open('ab') as stream:
                    stream.write(block(0x1234, b''))
            return result
        with patch.object(index, '_block', side_effect=changing_read):
            with self.assertRaisesRegex(ToolInputError, 'changed while'):
                inspect_packet_capture(self.path)
        self.assertFalse(index._indexes)

    def test_rejects_malformed_blocks_and_bounded_packet_or_interface_counts(self):
        prefix = section() + interface()
        invalid = {
            'length': prefix + struct.pack('<III', 6, 11, 11),
            'trailer': prefix + packet(self.frame)[:-4] + b'\x00' * 4,
            'interface': prefix + packet(self.frame, interface_id=1),
            'missing interface in new section': prefix + section() + packet(self.frame),
            'packet length': prefix + block(6, struct.pack('<5I', 0, 0, 0, 200, 200)),
            'short packet': prefix + block(6, b''),
            'short section': block(0x0a0d0d0a, struct.pack('<I', 0x1a2b3c4d)),
            'bad byte order': block(0x0a0d0d0a, b'xxxx' + b'\x00' * 12),
            'bad version': block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 2, 0, -1)),
            'option length': section() + block(1, struct.pack('<HHIHH', 1, 0, 65535, 9, 9)),
        }
        for label, data in invalid.items():
            with self.subTest(label=label):
                self.path.write_bytes(data)
                with self.assertRaises(ToolInputError):
                    inspect_packet_capture(self.path)
        self.path.write_bytes(prefix + packet(self.frame))
        with patch('twn_toolkit.pcap_viewer.MAX_CAPTURED_PACKET_BYTES', 10):
            with self.assertRaisesRegex(ToolInputError, 'safety limit'):
                inspect_packet_capture(self.path)
        self.path.write_bytes(prefix + interface() + packet(self.frame))
        with patch.object(index, 'MAX_SECTION_INTERFACES', 1):
            with self.assertRaisesRegex(ToolInputError, 'interface limit'):
                inspect_packet_capture(self.path)
