"""Cross-process outgoing transfer slots, owned until the host connection closes."""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import os
import time
from contextlib import contextmanager
from pathlib import Path

from .file_transactions import file_transaction
from .operational import OperationalSettingsStore


def _host_key(host):
    value = host.strip().lower().rstrip('.')
    try:
        value = str(ipaddress.ip_address(value))
    except ValueError:
        pass
    return hashlib.sha256(value.encode()).hexdigest().encode()


def _try_acquire(instance, host, *, directory='.transfer-admission', total_key='transfer_connections', host_key='transfer_host_connections', weight=1):
    root = Path(instance).resolve() / directory
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = _host_key(host)
    candidate = None
    try:
        with file_transaction(root / 'admission'):
            settings = OperationalSettingsStore(str(instance)).get()
            if weight not in (1, 2):
                raise ValueError('Invalid outgoing slot weight.')
            if weight > min(settings[total_key], settings[host_key]):
                raise ValueError(f'Configured limits cannot admit an operation requiring {weight} slots.')
            active = matching = 0
            slots = list(root.glob('slot-*'))
            for path in slots:
                descriptor = os.open(path, os.O_RDWR | os.O_CLOEXEC)
                try:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        record = os.pread(descriptor, 65, 0)
                        held_weight = record[64] if len(record) == 65 else 1
                        if held_weight not in (1, 2):
                            raise ValueError('An active outgoing slot has an invalid weight.')
                        active += held_weight
                        if record[:64] == target:
                            matching += held_weight
                    else:
                        if candidate is None:
                            candidate = descriptor
                            descriptor = None
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
            if active + weight > settings[total_key] or matching + weight > settings[host_key]:
                return None
            if candidate is None:
                candidate = os.open(root / f'slot-{len(slots)}', os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600)
                fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.ftruncate(candidate, 0)
            record = target + bytes([weight])
            if os.write(candidate, record) != len(record):
                raise OSError('Could not publish outgoing slot ownership.')
            descriptor, candidate = candidate, None
            return descriptor
    finally:
        if candidate is not None:
            os.close(candidate)


@contextmanager
def _transfer_slot(instance, host, deadline):
    """Wait inside the host deadline for transfer-specific capacity."""
    if not instance:
        # Standalone library calls retain their historical per-run policy.
        yield
        return
    descriptor = None
    try:
        while descriptor is None:
            try:
                remaining = deadline.remaining()
            except TimeoutError as exc:
                raise TimeoutError('Transfer capacity wait exceeded the host deadline; no connection was started.') from exc
            descriptor = _try_acquire(instance, host)
            if descriptor is None:
                time.sleep(min(.05, remaining))
        deadline.check()
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)


@contextmanager
def transfer_slot(instance, host, deadline, *, weight=1):
    from .outgoing_admission import outgoing_slot
    # Every caller acquires the common budget before the transfer-specific one.
    with outgoing_slot(instance, host, deadline=deadline, weight=weight):
        with _transfer_slot(instance, host, deadline):
            yield
