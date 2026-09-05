"""Cross-process transaction boundaries for the toolkit's local file stores.

Lock a stable sidecar, never the data file: atomic replacement changes the data
inode. Keep the lock file after release so every writer locks the same inode.
Readers can remain lock-free when writers publish complete files atomically.
"""

from __future__ import annotations

import fcntl
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


_held = threading.local()


@contextmanager
def file_transaction(path: str | Path) -> Iterator[None]:
    """Serialize a complete read/validate/write operation on a local file.

    Separate opens make flock serialize both threads and processes on Linux
    and macOS. Reentry in the same thread permits compound store operations.
    For transactions involving several files, acquire paths in sorted order.
    This is not a transaction across files: callers still own rollback.
    """
    target = Path(path).resolve()
    process_id = os.getpid()
    if getattr(_held, "process_id", None) != process_id:
        # A fork must not inherit the parent's permission to enter a transaction.
        # Close duplicate descriptors without unlocking the parent's open file.
        for descriptor in getattr(_held, "descriptors", {}).values():
            os.close(descriptor)
        _held.process_id = process_id
        _held.descriptors = {}
    descriptors = _held.descriptors
    if target in descriptors:
        yield
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(f".{target.name}.lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        descriptors[target] = descriptor
        try:
            yield
        finally:
            del descriptors[target]
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
