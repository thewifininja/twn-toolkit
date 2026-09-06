"""Bounded long-poll admission and cooperative reconnect timing."""
from __future__ import annotations

import math
import random
import threading
import time
from contextlib import contextmanager

POLL_RETRY_SECONDS = 1.0
RETRY_INITIAL_SECONDS = 1.0
RETRY_MAX_SECONDS = 30.0
ENROLLMENT_POLL_SECONDS = 5.0
CONTROL_STATUS_SECONDS = 5.0
IDLE_POLL_PAUSE_SECONDS = 0.05


class PollCapacityError(RuntimeError):
    pass


class LongPollBudget:
    def __init__(self, limit, per_agent):
        self.limit = limit
        self.per_agent = per_agent
        self._lock = threading.Lock()
        self._agents = {}
        self._active = 0
        self._peak = 0

    @contextmanager
    def slot(self, agent_id):
        with self._lock:
            admitted = self._active < self.limit and self._agents.get(agent_id, 0) < self.per_agent
            if admitted:
                self._agents[agent_id] = self._agents.get(agent_id, 0) + 1
                self._active += 1
                self._peak = max(self._peak, self._active)
        try:
            yield admitted
        finally:
            if admitted:
                with self._lock:
                    self._active -= 1
                    self._agents[agent_id] -= 1
                    if not self._agents[agent_id]:
                        del self._agents[agent_id]

    def stats(self):
        with self._lock:
            return {"active": self._active, "peak": self._peak, "agents": len(self._agents)}


class RetryBackoff:
    def __init__(self, *, uniform=random.uniform):
        self._uniform = uniform
        self._ceiling = RETRY_INITIAL_SECONDS

    def reset(self):
        self._ceiling = RETRY_INITIAL_SECONDS

    def delay(self):
        ceiling = self._ceiling
        self._ceiling = min(RETRY_MAX_SECONDS, ceiling * 2)
        return self._uniform(ceiling / 2, ceiling)


def poll_retry_delay(response, *, uniform=random.uniform):
    delay = float(response.get("retry_after_seconds", 0) or 0)
    if not math.isfinite(delay) or delay < 0:
        raise ValueError("Invalid poll retry interval.")
    delay = min(RETRY_MAX_SECONDS, delay)
    return uniform(delay, min(RETRY_MAX_SECONDS, delay * 1.5)) if delay else IDLE_POLL_PAUSE_SECONDS


def pause(seconds, running):
    deadline = time.monotonic() + seconds
    while running():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.1, remaining))


class InteractivePollGate:
    """One outstanding interactive poll; execution and lease renewal stay outside."""
    def __init__(self):
        self.lock = threading.Lock()
        self.backoff = RetryBackoff()

    @contextmanager
    def enter(self, running):
        acquired = False
        while running():
            if self.lock.acquire(timeout=0.1):
                acquired = True
                break
        try:
            yield acquired
        finally:
            if acquired:
                self.lock.release()


def regular_poll_delay(status, backoff):
    state = status.get("state")
    if state == "disconnected":
        return backoff.delay()
    backoff.reset()
    if state not in {"approved", "connected"}:
        return ENROLLMENT_POLL_SECONDS
    delay = float(status.get("retry_after_seconds", IDLE_POLL_PAUSE_SECONDS))
    return min(RETRY_MAX_SECONDS, max(IDLE_POLL_PAUSE_SECONDS, delay))
