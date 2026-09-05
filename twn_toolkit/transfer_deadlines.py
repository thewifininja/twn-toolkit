"""Operator transfer policy and transport-closing absolute deadlines."""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass

OUTGOING_TRANSFER_LIMITS = {
    "transfer_workers": (8, 1, 32, "Outgoing transfer workers", "Concurrent remote hosts per run."),
    "transfer_idle_seconds": (15, 1, 300, "Outgoing idle timeout (seconds)", "Bounds socket reads and writes."),
    "transfer_deadline_seconds": (300, 1, 86400, "Outgoing host deadline (seconds)", "Shared by connection setup and all requested files for one host."),
    "transfer_file_mib": (256, 1, 65536, "Outgoing per-file limit (MiB)", "Maximum bytes fetched for one remote file."),
    "transfer_run_mib": (1024, 1, 1048576, "Outgoing run limit (MiB)", "Shared download budget across all hosts in a run."),
}


def validate_transfer_limits(values):
    result = {}
    for key, (default, minimum, maximum, label, _help) in OUTGOING_TRANSFER_LIMITS.items():
        raw = values.get(key, default)
        try:
            if isinstance(raw, bool) or not isinstance(raw, (str, int)):
                raise ValueError
            number = int(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{label} must be a whole number.") from exc
        if not minimum <= number <= maximum:
            raise ValueError(f"{label} must be {minimum}–{maximum}.")
        result[key] = number
    return result


@dataclass(frozen=True)
class TransferPolicy:
    workers: int = 8
    idle_seconds: int = 15
    deadline_seconds: int = 300
    file_bytes: int = 256 * 1024**2
    run_bytes: int = 1024 * 1024**2

    @classmethod
    def from_settings(cls, settings):
        values = validate_transfer_limits(settings)
        return cls(values["transfer_workers"], values["transfer_idle_seconds"],
                   values["transfer_deadline_seconds"], values["transfer_file_mib"] * 1024**2,
                   values["transfer_run_mib"] * 1024**2)


def close_socket(sock):
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


class TransferDeadline:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds
        self._lock = threading.Lock()
        self._closers = {}
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True

    def remaining(self):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Remote host transfer deadline exceeded.")
        return remaining

    def check(self):
        self.remaining()

    def watch(self, name, closer):
        with self._lock:
            self._closers[name] = closer
        if time.monotonic() >= self.end:
            closer()
            self.check()

    def unwatch(self, name):
        with self._lock:
            self._closers.pop(name, None)

    def _expire(self):
        with self._lock:
            closers = list(self._closers.values())
        for closer in closers:
            try:
                closer()
            except Exception:
                pass

    def __enter__(self):
        self._timer.start()
        return self

    def __exit__(self, *_exc):
        self._timer.cancel()
        self._timer.join()
