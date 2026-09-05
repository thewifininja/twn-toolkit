from __future__ import annotations

import json
import time
from pathlib import Path

from twn_toolkit.automation_heartbeat import (
    AutomationHeartbeat,
    automation_heartbeat_fresh,
    read_automation_heartbeat,
)


class _Future:
    def __init__(self, *, running: bool, done: bool) -> None:
        self._running = running
        self._done = done

    def running(self) -> bool:
        return self._running

    def done(self) -> bool:
        return self._done


def test_heartbeat_separates_liveness_from_scheduler_progress(tmp_path: Path):
    path = tmp_path / "automation-heartbeat.json"
    reporter = AutomationHeartbeat(path, max_workers=3, interval_seconds=60)
    reporter.record_scheduler_cycle(
        {
            _Future(running=True, done=False): {"kind": "job"},
            _Future(running=False, done=False): {"kind": "check"},
        },
        {_Future(running=True, done=False): "live-1"},
    )
    reporter.publish()
    first = json.loads(path.read_text())
    time.sleep(0.01)
    reporter.publish()
    second = json.loads(path.read_text())

    assert second["updated_at"] > first["updated_at"]
    assert second["scheduler_progress_at"] == first["scheduler_progress_at"]
    assert second["active"] == 1
    assert second["queued"] == 1
    assert second["active_jobs"] == 1
    assert second["active_checks"] == 0
    assert second["live_tools_active"] == 1
    assert automation_heartbeat_fresh(path, 20)


def test_heartbeat_records_progress_and_shutdown_state(tmp_path: Path):
    path = tmp_path / "automation-heartbeat.json"
    reporter = AutomationHeartbeat(path, max_workers=1, interval_seconds=0.01)
    reporter.record_scheduler_cycle({}, {}, completed_work=True)
    reporter.start()
    first = json.loads(path.read_text())
    deadline = time.monotonic() + 1
    while True:
        payload = json.loads(path.read_text())
        if payload["updated_at"] > first["updated_at"]:
            break
        assert time.monotonic() < deadline
        time.sleep(0.01)
    reporter.request_shutdown()
    payload = json.loads(path.read_text())
    status = read_automation_heartbeat(path, now=float(payload["updated_at"]))

    assert payload["updated_at"] > first["updated_at"]
    assert payload["state"] == "stopping"
    assert payload["last_work_completion_at"] is not None
    assert status == {
        "fresh": True,
        "age": 0,
        "scheduler_progress_age": 0,
        "last_work_completion_age": 0,
        "state": "stopping",
    }
    reporter.close()


def test_scheduler_status_marks_a_stale_worker_unresponsive(tmp_path: Path):
    from twn_toolkit.automation_routes import _scheduler_status

    (tmp_path / "twn-automation.pid").write_text(f"{__import__('os').getpid()}\n")
    reporter = AutomationHeartbeat(
        tmp_path / "automation-heartbeat.json", max_workers=1, interval_seconds=60
    )
    reporter.record_scheduler_cycle({}, {})
    reporter.publish()

    running = _scheduler_status(tmp_path)
    assert running["running"]
    assert running["process_running"]
    assert running["scheduler_progress_age"] == 0

    payload = json.loads((tmp_path / "automation-heartbeat.json").read_text())
    payload["updated_at"] -= 30
    (tmp_path / "automation-heartbeat.json").write_text(json.dumps(payload))
    unresponsive = _scheduler_status(tmp_path)
    assert not unresponsive["running"]
    assert unresponsive["process_running"]


def test_launcher_uses_the_configurable_stop_timeout():
    source = Path(__file__).parents[1].joinpath("twn").read_text()

    assert 'max_attempts=$((STOP_TIMEOUT * 10))' in source
    assert 'Automation scheduler did not stop after ${STOP_TIMEOUT}s' in source


def test_malformed_heartbeat_is_not_fresh(tmp_path: Path):
    path = tmp_path / "automation-heartbeat.json"
    path.write_text('{"updated_at": "nan"}')

    assert not automation_heartbeat_fresh(path, 20)
    assert not read_automation_heartbeat(path)["fresh"]
