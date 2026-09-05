"""Independent liveness and progress reporting for the automation scheduler."""

from __future__ import annotations

import json
import math
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Mapping


AUTOMATION_HEARTBEAT_INTERVAL_SECONDS = 2.0
AUTOMATION_HEARTBEAT_MAX_AGE_SECONDS = 20.0


class AutomationHeartbeat:
    """Publish scheduler liveness even while its main loop is waiting on work.

    ``updated_at`` answers whether the worker process and its reporter thread
    are alive. The two progress timestamps answer separate questions: whether
    the scheduler loop is advancing and when tracked work last completed.
    """

    def __init__(
        self,
        path: Path,
        *,
        max_workers: int,
        interval_seconds: float = AUTOMATION_HEARTBEAT_INTERVAL_SECONDS,
    ) -> None:
        self.path = path
        self.max_workers = max_workers
        self.interval_seconds = max(0.05, float(interval_seconds))
        self._lock = threading.Lock()
        self._publish_lock = threading.Lock()
        self._stopped = threading.Event()
        self._thread = threading.Thread(
            target=self._publish_until_stopped,
            name="twn-automation-heartbeat",
            daemon=True,
        )
        now = time.time()
        self._payload: dict[str, Any] = {
            "pid": os.getpid(),
            "max_workers": max_workers,
            "state": "running",
            "scheduler_progress_at": now,
            "last_work_completion_at": None,
            "active": 0,
            "queued": 0,
            "tracked": 0,
            "active_checks": 0,
            "active_jobs": 0,
            "live_tools_active": 0,
            "live_tools_tracked": 0,
        }

    def start(self) -> None:
        self.publish()
        self._thread.start()

    def record_scheduler_cycle(
        self,
        futures: Mapping[object, Mapping[str, str]],
        live_futures: Mapping[object, str],
        *,
        completed_work: bool = False,
    ) -> None:
        now = time.time()
        items = list(futures.items())
        live_items = list(live_futures)
        with self._lock:
            self._payload.update(
                {
                    "scheduler_progress_at": now,
                    "active": sum(1 for future, _work in items if future.running()),
                    "queued": sum(
                        1 for future, _work in items if not future.running() and not future.done()
                    ),
                    "tracked": len(items),
                    "active_checks": sum(
                        1
                        for future, work in items
                        if work["kind"] == "check" and future.running()
                    ),
                    "active_jobs": sum(
                        1
                        for future, work in items
                        if work["kind"] == "job" and future.running()
                    ),
                    "live_tools_active": sum(1 for future in live_items if future.running()),
                    "live_tools_tracked": len(live_items),
                }
            )
            if completed_work:
                self._payload["last_work_completion_at"] = now

    def request_shutdown(self) -> None:
        with self._lock:
            self._payload["state"] = "stopping"
        self.publish()

    def close(self) -> None:
        self.request_shutdown()
        self._stopped.set()
        if self._thread.is_alive():
            self._thread.join(timeout=self.interval_seconds + 1.0)

    def publish(self) -> None:
        with self._lock:
            payload = {**self._payload, "updated_at": time.time()}
        with self._publish_lock:
            temporary = self.path.with_name(
                f".{self.path.name}.{secrets.token_hex(4)}.tmp"
            )
            temporary.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)

    def _publish_until_stopped(self) -> None:
        while not self._stopped.wait(self.interval_seconds):
            try:
                self.publish()
            except OSError as exc:
                print(
                    "Could not write automation heartbeat: "
                    f"{type(exc).__name__}: {exc}",
                    flush=True,
                )


def read_automation_heartbeat(
    path: Path,
    *,
    maximum_age: float = AUTOMATION_HEARTBEAT_MAX_AGE_SECONDS,
    now: float | None = None,
) -> dict[str, Any]:
    """Read a heartbeat without treating stale scheduler progress as a dead PID."""
    now = time.time() if now is None else now
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError
        updated_at = float(payload["updated_at"])
    except (OSError, TypeError, ValueError, KeyError):
        return {
            "fresh": False,
            "age": None,
            "scheduler_progress_age": None,
            "last_work_completion_age": None,
            "state": "unknown",
        }
    age = now - updated_at
    fresh = math.isfinite(age) and 0 <= age <= maximum_age
    return {
        "fresh": fresh,
        "age": max(0, int(age)) if math.isfinite(age) else None,
        "scheduler_progress_age": _timestamp_age(
            payload.get("scheduler_progress_at"), now
        ),
        "last_work_completion_age": _timestamp_age(
            payload.get("last_work_completion_at"), now
        ),
        "state": str(payload.get("state", "running")),
    }


def automation_heartbeat_fresh(path: Path, maximum_age: float) -> bool:
    return bool(read_automation_heartbeat(path, maximum_age=maximum_age)["fresh"])


def _timestamp_age(value: object, now: float) -> int | None:
    if value is None:
        return None
    try:
        age = now - float(value)
    except (TypeError, ValueError):
        return None
    return max(0, int(age)) if math.isfinite(age) else None
