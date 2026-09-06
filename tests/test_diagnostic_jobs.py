from __future__ import annotations

import base64
import json
import socket
import subprocess
import sys
import time
from urllib.parse import urlencode

import pytest

from twn_toolkit import create_app
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import DiagnosticScheduler, execute_scan
from twn_toolkit.operational import OperationalSettingsStore

FORM = {"hosts": "127.0.0.1", "ports": "443", "timeout": "0.1", "concurrency": "1"}


def config():
    return {"form": {**FORM, "open_only": False}, "targets": [{"host": "127.0.0.1", "label": "private-target"}],
            "ports": [443], "username": "owner", "investigation_id": ""}


def result(port=443):
    return {"host": "127.0.0.1", "label": "private-target", "port": port,
            "status": "open", "service": "https", "detail": "", "elapsed_ms": 1}


def wait_finished(scheduler, job_id, owner="owner", timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        scheduler.tick()
        job = scheduler.store.get(job_id, owner)
        if job["state"] not in {"queued", "running", "cancel_requested"}:
            return job
        time.sleep(0.02)
    pytest.fail("diagnostic did not finish")


def test_real_subprocess_completes_scan_and_retains_encrypted_results(tmp_path):
    scheduler = DiagnosticScheduler(tmp_path)
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            settings = config()
            settings["ports"] = [listener.getsockname()[1]]
            job_id = scheduler.store.enqueue(user_id="owner", config=settings)
            job = wait_finished(scheduler, job_id)
        assert job["state"] == "succeeded"
        assert job["summary"]["stats"]["open"] == 1
        rows, count = scheduler.store.page(job_id, "owner")
        assert count == 1 and rows[0]["status"] == "open"
        assert b"private-target" not in scheduler.store.path.read_bytes()
        assert scheduler.store.get(job_id, "other") is None
        assert scheduler.store.page(job_id, "other") == ([], 0)
        assert job["config"]["targets"][0]["label"] == "private-target"
    finally:
        scheduler.close()


def test_web_submission_is_nonblocking_and_results_are_owner_scoped_and_paginated(tmp_path, monkeypatch):
    app = create_app(str(tmp_path))
    app.config.update(TESTING=True)
    client = app.test_client()
    monkeypatch.setattr("twn_toolkit.diagnostic_worker.scan_tcp_ports", lambda *args, **kwargs: pytest.fail("web executed scan"))
    response = client.post("/tools/port-scanner", data=FORM)
    assert response.status_code == 303
    url = response.headers["Location"]
    store = app.extensions["diagnostic_job_store"]
    job = store.claim()
    assert client.get("/health").status_code == 200
    page = client.get(url)
    assert b"Run in progress" in page.data and b"Cancel run" in page.data
    assert client.get(f"/tools/port-scanner/jobs/{job['id']}/status").json["state"] == "running"
    assert store.finish(job["id"], job["token"], [result(i) for i in range(150)], {"stats": {"combinations": 150, "open": 150, "closed": 0, "timeout": 0, "error": 0}})
    page = client.get(url)
    assert page.data.count(b"private-target") == 100
    assert b"Next page" in page.data
    assert client.get(url + "&page=2").data.count(b"private-target") == 50
    assert client.get("/tools/port-scanner?job=missing").status_code == 404
    assert client.post("/tools/port-scanner/jobs/missing/cancel").status_code == 404


def test_agent_dispatch_preserves_job_redirects_and_small_result_pages(tmp_path):
    from twn_toolkit.distributed_http import dispatch_http_request
    prefix = "/agents/test-agent/ui"
    def dispatch(path, method="GET", body="", user="owner"):
        return dispatch_http_request(tmp_path, {"method": method, "path": path, "prefix": prefix,
            "user": {"id": user, "username": user, "is_admin": True},
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": base64.b64encode(body.encode()).decode()})
    submitted = dispatch("/tools/port-scanner", "POST", urlencode(FORM))
    assert submitted["status"] == 303
    location = dict(submitted["headers"])["Location"]
    assert location.startswith(prefix + "/tools/port-scanner?job=")
    store = DiagnosticJobStore(tmp_path)
    job = store.claim()
    store.finish(job["id"], job["token"], [result(i) for i in range(150)],
                 {"stats": {"combinations": 150, "open": 150, "closed": 0, "timeout": 0, "error": 0}})
    page = dispatch(location.removeprefix(prefix))
    assert page["status"] == 200
    html = base64.b64decode(page["body"])
    assert html.count(b"private-target") == 100
    assert (prefix + "/tools/port-scanner?job=").encode() in html
    assert dispatch(location.removeprefix(prefix), user="intruder")["status"] == 404


def test_capacity_cancellation_and_restart_never_replay_claimed_work(tmp_path):
    policy = OperationalSettingsStore(str(tmp_path))
    policy.save({"diagnostic_user_limit": 1, "diagnostic_queue_limit": 1})
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id="owner", config=config())
    with pytest.raises(ValueError):
        store.enqueue(user_id="owner", config=config())
    store.cancel(job_id, "other")
    assert store.get(job_id, "owner")["state"] == "queued"
    store.cancel(job_id, "owner")
    assert store.claim() is None
    another = store.enqueue(user_id="owner", config=config())
    job = store.claim()
    store.recover()
    assert store.get(another, "owner")["state"] == "unknown"
    assert store.claim() is None
    assert not store.finish(another, job["token"], [result()], {})
    assert store.get(another, "owner")["summary"] == {}


@pytest.mark.parametrize("reason,expected", [("cancel", "cancelled"), ("deadline", "failed")])
def test_scheduler_terminates_owned_process_before_confirming_stop(tmp_path, monkeypatch, reason, expected):
    original = subprocess.Popen
    def sleeping_process(command, **kwargs):
        return original([sys.executable, "-c", "import sys,time; sys.stdin.buffer.read(); time.sleep(60)"], **kwargs)
    monkeypatch.setattr("twn_toolkit.diagnostic_worker.subprocess.Popen", sleeping_process)
    scheduler = DiagnosticScheduler(tmp_path)
    try:
        job_id = scheduler.store.enqueue(user_id="owner", config=config())
        scheduler.tick()
        process = scheduler.active[job_id]["process"]
        if reason == "cancel":
            scheduler.store.cancel(job_id, "owner")
            assert scheduler.store.get(job_id, "owner")["state"] == "cancel_requested"
        else:
            scheduler.active[job_id]["deadline"] = time.monotonic() - 1
        job = wait_finished(scheduler, job_id)
        assert process.poll() is not None
        assert job["state"] == expected
        assert scheduler.store.page(job_id, "owner") == ([], 0)
    finally:
        scheduler.close()


def test_history_capacity_prunes_old_terminal_runs_but_not_active_work(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({"diagnostic_history_limit": 1})
    store = DiagnosticJobStore(tmp_path)
    first = store.enqueue(user_id="owner", config=config())
    with pytest.raises(ValueError):
        store.enqueue(user_id="other", config=config())
    job = store.claim()
    store.finish(first, job["token"], [result()], {"stats": {}})
    with pytest.raises(ValueError):
        store.enqueue(user_id="other", config=config())
    store.release(first, job["token"])
    second = store.enqueue(user_id="other", config=config())
    assert store.get(first, "owner") is None
    assert store.get(second, "other")["state"] == "queued"
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM diagnostic_rows").fetchone()[0] == 0


@pytest.mark.parametrize("value", [0, 9, True, 1.5, float("inf"), "bad"])
def test_diagnostic_worker_policy_rejects_invalid_values(tmp_path, value):
    with pytest.raises(ValueError):
        OperationalSettingsStore(str(tmp_path)).save({"diagnostic_workers": value})


def test_all_diagnostic_slots_can_be_busy_while_http_navigation_and_cancel_return(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    original = subprocess.Popen
    monkeypatch.setattr("twn_toolkit.diagnostic_worker.subprocess.Popen",
        lambda command, **kwargs: original([sys.executable, "-c", "import sys,time; sys.stdin.buffer.read(); time.sleep(60)"], **kwargs))
    app = create_app(str(tmp_path))
    app.config.update(TESTING=True)
    scheduler = DiagnosticScheduler(tmp_path)
    try:
        for _ in range(2):
            scheduler.store.enqueue(user_id="test-user", config=config())
        scheduler.tick()
        assert len(scheduler.active) == 2
        def browse():
            client = app.test_client()
            assert client.get("/health").status_code == 200
            assert client.get("/tools/dns-response").status_code == 200
            queued = client.post("/tools/port-scanner", data=FORM)
            assert queued.status_code == 303
            job_id = queued.headers["Location"].split("job=")[1]
            assert client.get(f"/tools/port-scanner/jobs/{job_id}/status").json["state"] == "queued"
            assert client.post(f"/tools/port-scanner/jobs/{job_id}/cancel").status_code == 303
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(browse).result(timeout=5)
    finally:
        scheduler.close()
    assert not scheduler.active


def test_child_enforces_deadline_without_scheduler_ticks(tmp_path):
    import os
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id="owner", config=config())
    job = store.claim()
    code = (
        "import runpy,sys,time; import twn_toolkit.network_tools as n; "
        "n.scan_tcp_ports=lambda *a,**k: time.sleep(60); "
        "sys.argv=['diagnostic','--instance',sys.argv[1],'--job',sys.argv[2]]; "
        "runpy.run_module('twn_toolkit.diagnostic_worker',run_name='__main__')"
    )
    process = subprocess.Popen([sys.executable, "-c", code, str(tmp_path), job_id], stdin=subprocess.PIPE)
    try:
        process.communicate(json.dumps({"token": job["token"], "parent": os.getpid(), "timeout": 0.05}).encode(), timeout=10)
        assert process.returncode == 124
        assert store.page(job_id, "owner") == ([], 0)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_low_disk_rejects_submission_without_creating_work(tmp_path, monkeypatch):
    from collections import namedtuple
    usage = namedtuple("usage", "total used free")
    store = DiagnosticJobStore(tmp_path)
    monkeypatch.setattr("twn_toolkit.diagnostic_jobs.shutil.disk_usage", lambda path: usage(10**10, 10**10, 1))
    with pytest.raises(ValueError, match="free-disk reserve"):
        store.enqueue(user_id="owner", config=config())
    assert store.claim() is None


def test_completed_result_keeps_process_ownership_until_recording_has_finished(tmp_path, monkeypatch):
    original = subprocess.Popen
    monkeypatch.setattr("twn_toolkit.diagnostic_worker.subprocess.Popen",
        lambda command, **kwargs: original([sys.executable, "-c", "import sys,time; sys.stdin.buffer.read(); time.sleep(60)"], **kwargs))
    scheduler = DiagnosticScheduler(tmp_path)
    try:
        job_id = scheduler.store.enqueue(user_id="owner", config=config())
        scheduler.tick()
        work = scheduler.active[job_id]
        assert scheduler.store.finish(job_id, work["token"], [result()], {"stats": {}})
        scheduler.tick()
        assert work["process"].poll() is None
        assert "reason" not in work
        assert scheduler.store.owned(job_id, work["token"])["state"] == "succeeded"
        work["process"].terminate()
        work["process"].wait(timeout=5)
        scheduler.tick()
        assert scheduler.store.get(job_id, "owner")["state"] == "succeeded"
        assert scheduler.store.owned(job_id, work["token"]) is None
    finally:
        scheduler.close()


def test_real_daemon_scheduler_launches_diagnostics_without_repository_cwd(tmp_path):
    import os
    import signal
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    instance = tmp_path / "instance"
    instance.mkdir()
    pidfile = instance / "scheduler.pid"
    logfile = instance / "scheduler.log"
    store = DiagnosticJobStore(instance)
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    pid = None
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            settings = config()
            settings["ports"] = [listener.getsockname()[1]]
            job_id = store.enqueue(user_id="owner", config=settings)
            subprocess.run(
                [sys.executable, "-m", "twn_toolkit.automation_worker",
                 "--instance", str(instance), "--daemon",
                 "--pid-file", str(pidfile), "--log-file", str(logfile)],
                cwd=root, env=environment, check=True, timeout=10,
            )
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if pidfile.exists():
                    pid = int(pidfile.read_text())
                job = store.get(job_id, "owner")
                if job["state"] not in {"queued", "running", "cancel_requested"}:
                    break
                time.sleep(0.05)
            log = logfile.read_text() if logfile.exists() else ""
            assert job["state"] == "succeeded", (job["error"], log)
            assert job["summary"]["stats"]["open"] == 1
            assert "No module named" not in log
            # Linux confirms that this really exercised the daemon's cwd.
            if Path("/proc").is_dir() and pid is not None:
                assert os.readlink(f"/proc/{pid}/cwd") == "/"
    finally:
        if pid is None and pidfile.exists():
            pid = int(pidfile.read_text())
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 10
            while pidfile.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            if pidfile.exists():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
