"""Finite parsing and regular-file reads for incoming configuration backups."""
import os
import stat

from .backup_source_reads import bounded_source_reads, source_json_loads, checked_source_json_text, SourceReadLimit

MAX_BACKUP_WIRE_BYTES = 64 * 1024 * 1024
MAX_PREVIEW_PLAIN_BYTES = MAX_BACKUP_WIRE_BYTES + 4096
MAX_PREVIEW_CIPHER_BYTES = 2 * MAX_PREVIEW_PLAIN_BYTES


def decode_backup_json(raw: bytes, *, preview=False, validate_only=False):
    if not isinstance(raw, bytes):
        raise ValueError("Backup JSON must be provided as bytes.")
    maximum = MAX_PREVIEW_PLAIN_BYTES if preview else MAX_BACKUP_WIRE_BYTES
    if len(raw) > maximum:
        raise ValueError('Configuration backup JSON exceeds the read limit.')
    try:
        with bounded_source_reads(maximum):
            if validate_only:
                checked_source_json_text(raw)
                return None
            return source_json_loads(raw)
    except SourceReadLimit as exc:
        raise ValueError(str(exc).replace('Backup source', 'Backup').replace('to export', 'to process')) from exc


def read_preview_file(path):
    """Gate one owned regular handle before allocation, including file growth."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PREVIEW_CIPHER_BYTES:
            raise ValueError('The retained import preview exceeds its file limit or is not a regular file.')
        parts = []
        used = 0
        while True:
            part = os.read(descriptor, min(65536, MAX_PREVIEW_CIPHER_BYTES-used+1))
            if not part:
                return b''.join(parts)
            used += len(part)
            if used > MAX_PREVIEW_CIPHER_BYTES:
                raise ValueError('The retained import preview exceeds its file limit.')
            parts.append(part)
    finally:
        os.close(descriptor)
