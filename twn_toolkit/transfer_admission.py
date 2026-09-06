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


def _try_acquire(instance, host):
    root = Path(instance).resolve() / '.transfer-admission'
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = _host_key(host)
    candidate = None
    try:
        with file_transaction(root / 'admission'):
            settings = OperationalSettingsStore(str(instance)).get()
            active = matching = 0
            slots = list(root.glob('slot-*'))
            for path in slots:
                descriptor = os.open(path, os.O_RDWR | os.O_CLOEXEC)
                try:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        active += 1
                        if os.pread(descriptor, 64, 0) == target:
                            matching += 1
                    else:
                        if candidate is None:
                            candidate = descriptor
                            descriptor = None
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
            if active >= settings['transfer_connections'] or matching >= settings['transfer_host_connections']:
                return None
            if candidate is None:
                candidate = os.open(root / f'slot-{len(slots)}', os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600)
                fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.ftruncate(candidate, 0)
            os.write(candidate, target)
            descriptor, candidate = candidate, None
            return descriptor
    finally:
        if candidate is not None:
            os.close(candidate)


@contextmanager
def transfer_slot(instance, host, deadline):
    """Wait inside the host deadline, holding no other slot while waiting."""
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
