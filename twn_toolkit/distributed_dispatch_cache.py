"""Bounded process-local apps and owner-isolated clients for Agent dispatch."""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .operational import OperationalSettingsStore

# Production workers serve one instance. Bound alternate instances used by
# embedding callers too; this process-wide guard is a code policy, not a UI knob.
MAX_CACHED_INSTANCES = 8
DISPATCH_CACHE_SWEEP_SECONDS = 60


class DispatchCacheBusy(ValueError):
    """Admission failed before invoking any HTTP handler."""


@dataclass
class _Client:
    value: Any = None
    lock: Any = field(default_factory=threading.Lock)
    users: int = 0
    last_used: float = 0.0


@dataclass
class _Instance:
    app: Any = None
    init_lock: Any = field(default_factory=threading.Lock)
    clients: dict[str, _Client] = field(default_factory=dict)
    limit: int = 32
    idle_seconds: int = 900
    last_used: float = 0.0

    @property
    def active(self):
        return any(client.users for client in self.clients.values())


class DispatchCache:
    def __init__(self, *, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._instances: dict[str, _Instance] = {}

    @staticmethod
    def _policy(entry, settings):
        entry.limit = int(settings["distributed_http_client_limit"])
        entry.idle_seconds = int(settings["distributed_http_client_idle_seconds"])

    @staticmethod
    def _evict_client(entry):
        idle = [(key, client) for key, client in entry.clients.items() if not client.users]
        if not idle:
            return False
        key, _ = min(idle, key=lambda pair: pair[1].last_used)
        del entry.clients[key]
        return True

    def _prune(self, now):
        for key, entry in list(self._instances.items()):
            for owner, client in list(entry.clients.items()):
                if not client.users and now - client.last_used >= entry.idle_seconds:
                    del entry.clients[owner]
            while len(entry.clients) > entry.limit and self._evict_client(entry):
                pass
            if not entry.clients and now - entry.last_used >= entry.idle_seconds:
                del self._instances[key]

    def prune(self, instance: Path):
        key = str(instance.resolve())
        settings = OperationalSettingsStore(key).get()
        with self._lock:
            if key in self._instances:
                self._policy(self._instances[key], settings)
            self._prune(self._clock())

    @contextmanager
    def borrow(self, instance: Path, owner: str, factory):
        key = str(instance.resolve())
        settings = OperationalSettingsStore(key).get()
        with self._lock:
            now = self._clock()
            if key in self._instances:
                self._policy(self._instances[key], settings)
            self._prune(now)
            entry = self._instances.get(key)
            if entry is None:
                if len(self._instances) >= MAX_CACHED_INSTANCES:
                    idle = [(name, item) for name, item in self._instances.items() if not item.active]
                    if not idle:
                        raise DispatchCacheBusy("Agent dispatcher is busy. No request was executed.")
                    oldest, _ = min(idle, key=lambda pair: pair[1].last_used)
                    del self._instances[oldest]
                entry = _Instance(last_used=now)
                self._policy(entry, settings)
                self._instances[key] = entry
            client = entry.clients.get(owner)
            if client is None:
                while len(entry.clients) >= entry.limit:
                    if not self._evict_client(entry):
                        raise DispatchCacheBusy("Agent dispatcher is busy. No request was executed.")
                client = _Client(last_used=now)
                entry.clients[owner] = client
            # Pin before waiting for initialization or the per-owner lock.
            client.users += 1
        try:
            # Slow initialization never holds the process-wide registry lock.
            with entry.init_lock:
                if entry.app is None:
                    entry.app = factory(key)
            yield entry.app, client
        finally:
            with self._lock:
                client.users -= 1
                entry.last_used = client.last_used = self._clock()
                self._prune(entry.last_used)

    def stats(self):
        """Counts for local measurements; no delegated identities or cookies."""
        with self._lock:
            return {
                "instances": len(self._instances),
                "clients": sum(len(entry.clients) for entry in self._instances.values()),
                "borrowers": sum(client.users for entry in self._instances.values() for client in entry.clients.values()),
            }
