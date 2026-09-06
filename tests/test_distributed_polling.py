from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager

import pytest

from twn_toolkit import distributed_polling as polling
from twn_toolkit import distributed_worker as worker
from twn_toolkit.distributed_jobs import DistributedJobStore
from twn_toolkit.distributed_transport import EnrollmentClient, EnrollmentServer, EnrollmentTransportError
from twn_toolkit.operational import OperationalSettingsStore


@pytest.mark.parametrize("agents", [1, 8, 25, 100])
def test_long_poll_budget_bounds_fleet_and_releases_all_agent_state(agents):
    budget = polling.LongPollBudget(24, 2)
    with ExitStack() as stack:
        admitted = sum(stack.enter_context(budget.slot(str(agent))) for agent in range(agents) for _ in range(2))
        assert admitted == min(agents * 2, 24)
        assert budget.stats()["active"] == admitted
        assert not stack.enter_context(budget.slot("0"))
    assert budget.stats() == {"active": 0, "peak": min(agents * 2, 24), "agents": 0}


def test_poll_slot_releases_on_exception():
    budget = polling.LongPollBudget(1, 1)
    with pytest.raises(RuntimeError):
        with budget.slot("agent") as admitted:
            assert admitted
            raise RuntimeError("fixture")
    assert budget.stats()["active"] == 0


def test_retry_backoff_grows_caps_and_resets():
    backoff = polling.RetryBackoff(uniform=lambda low, high: high)
    assert [backoff.delay() for _ in range(8)] == [1, 2, 4, 8, 16, 30, 30, 30]
    backoff.reset()
    assert backoff.delay() == 1
    low = polling.RetryBackoff(uniform=lambda low, high: low)
    assert [low.delay() for _ in range(3)] == [0.5, 1, 2]


@pytest.mark.parametrize("hint", [float("nan"), float("inf"), -1, "broken"])
def test_invalid_server_retry_hint_cannot_create_unbounded_sleep(hint):
    with pytest.raises(ValueError):
        polling.poll_retry_delay({"retry_after_seconds": hint})


def test_success_and_pending_statuses_do_not_busy_loop():
    backoff = polling.RetryBackoff(uniform=lambda low, high: high)
    assert polling.regular_poll_delay({"state": "disconnected"}, backoff) == 1
    assert polling.regular_poll_delay({"state": "disconnected"}, backoff) == 2
    assert polling.regular_poll_delay({"state": "not_enrolled"}, backoff) == 5
    assert polling.regular_poll_delay({"state": "pending"}, backoff) == 5
    assert polling.regular_poll_delay({"state": "approved", "retry_after_seconds": 1.25}, backoff) == 1.25
    assert polling.regular_poll_delay({"state": "disconnected"}, backoff) == 1
    assert polling.poll_retry_delay({"retry_after_seconds": 100}, uniform=lambda low, high: high) == 30


def test_pause_is_cooperative_without_sleeping_after_stop(monkeypatch):
    calls = []
    monkeypatch.setattr(polling.time, "sleep", lambda duration: calls.append(duration))
    polling.pause(30, lambda: False)
    assert calls == []


def enroll(server, root, name):
    client = EnrollmentClient(root, f"https://127.0.0.1:{server.port}")
    client.begin(name)
    agent = server.agent_store.list("pending")[0]
    server.agent_store.set_state(agent["id"], "approved")
    assert client.poll()["state"] == "approved"
    return client, agent["id"]


def test_real_tls_long_polls_leave_control_and_result_acknowledgement_headroom(tmp_path, monkeypatch):
    root = tmp_path / "mainframe"
    OperationalSettingsStore(str(root)).save({
        "distributed_listener_connections": 8, "distributed_control_reserve": 2,
    })
    server = EnrollmentServer(root, "127.0.0.1", 0)
    server.enrollment_window.open(5)
    full = threading.Event()
    original_slot = server.poll_budget.slot
    @contextmanager
    def observed_slot(agent):
        with original_slot(agent) as admitted:
            if server.poll_budget.stats()["active"] == 6:
                full.set()
            yield admitted
    monkeypatch.setattr(server.poll_budget, "slot", observed_slot)
    server.start()
    try:
        agents = [enroll(server, tmp_path / f"agent-{i}", f"Agent {i}") for i in range(3)]
        client, agent_id = agents[0]
        queued = server.job_store.enqueue(agent_id=agent_id, requester_id="owner", capability_id="system.identity", capability_version="1")
        job = client.heartbeat([])["jobs"][0]
        assert job["id"] == queued["id"]
        assert client.job_control(job, "start")["state"] == "running"
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(peer.interactive, wait_seconds=10) for peer, _ in agents for _ in range(2)]
            try:
                assert full.wait(10), "long polls did not occupy the configured budget"
                assert client.job_control(job, "renew")["state"] == "running"
                overloaded = client.interactive(
                    [{"id": job["id"], "attempt_token": job["attempt_token"], "state": "succeeded", "output": {"ok": True}}],
                    wait_seconds=10,
                )
                assert overloaded["state"] == "approved"
                assert overloaded["requests"] == []
                assert overloaded["retry_after_seconds"] == 1
                assert overloaded["acknowledgements"][0]["status"] == "accepted"
                assert server.job_store.get(job["id"])["state"] == "succeeded"
                # A legacy poller gets an error instead of spinning on empty success.
                with pytest.raises(EnrollmentTransportError):
                    client._request("POST", "/v1/interactive", {"protocol": 1, "job_protocol": 2, "wait_seconds": 10}, authenticated=True)
            finally:
                server._stopping.set()
            for future in futures:
                assert future.result(timeout=10)["requests"] == []
        assert server.poll_budget.stats() == {"active": 0, "peak": 6, "agents": 0}
    finally:
        server.stop()


def test_empty_poll_uses_read_only_probes_and_ready_work_still_requires_claim(tmp_path, monkeypatch):
    server = EnrollmentServer(tmp_path, "127.0.0.1", 0)
    traces = []
    write_flags = []
    original = server.job_store._connect
    @contextmanager
    def traced(**kwargs):
        write_flags.append(bool(kwargs.get("write", False)))
        with original(**kwargs) as db:
            db.set_trace_callback(traces.append)
            yield db
    monkeypatch.setattr(server.job_store, "_connect", traced)
    try:
        jobs, retry = server._poll_jobs("agent", "", 0.02, {"supports_poll_retry": True}, interval=0.005)
        assert (jobs, retry) == ([], 0)
        assert write_flags and not any(write_flags)
        assert traces and all("BEGIN IMMEDIATE" not in line and not line.startswith("UPDATE") for line in traces)
        queued = server.job_store.enqueue(agent_id="agent", requester_id="owner", capability_id="system.http.tunnel", capability_version="1", inputs={"body": "fixture"})
        jobs, _ = server._poll_jobs("agent", "", 0, {}, interval=0.005, capability_id="system.http.tunnel")
        assert jobs[0]["id"] == queued["id"]
        assert server.job_store.claim("agent") == []
        with original() as db:
            plan = db.execute("EXPLAIN QUERY PLAN SELECT 1 FROM distributed_jobs WHERE agent_id = ? AND state = 'queued' LIMIT 1", ("agent",)).fetchall()
        assert any("distributed_jobs_agent_queue" in row["detail"] for row in plan)
    finally:
        server.httpd.server_close()


def test_probe_respects_agent_activation_and_capability_without_consuming_work(tmp_path):
    store = DistributedJobStore(tmp_path)
    epoch = "11" * 16
    store.activate_agent("agent", epoch)
    queued = store.enqueue(agent_id="agent", requester_id="owner", capability_id="system.http.tunnel", capability_version="1")
    assert not store.has_queued("other")
    assert not store.has_queued("agent", activation_id="22" * 16)
    assert not store.has_queued("agent", exclude_capability_id="system.http.tunnel")
    assert store.has_queued("agent", activation_id=epoch, capability_id="system.http.tunnel")
    assert store.get(queued["id"])["state"] == "queued"


def test_interactive_gate_serializes_polling_but_allows_three_executions(tmp_path, monkeypatch):
    gate = polling.InteractivePollGate()
    running = threading.Event()
    running.set()
    first_poll = threading.Event()
    release_poll = threading.Event()
    executions = threading.Barrier(3)
    lock = threading.Lock()
    counts = {"calls": 0, "active": 0, "peak": 0, "executed": 0}
    class Client:
        def interactive(self, *_args, **_kwargs):
            with lock:
                counts["calls"] += 1
                number = counts["calls"]
                counts["active"] += 1
                counts["peak"] = max(counts["peak"], counts["active"])
            try:
                if number == 1:
                    first_poll.set()
                    assert release_poll.wait(10)
                return {"job_protocol": 2, "requests": [{"id": str(number)}], "acknowledgements": []}
            finally:
                with lock:
                    counts["active"] -= 1
    class Receipts:
        def __init__(self, *_args): pass
        def discard_other_activations(self, *_args): pass
        def pending(self, *_args): return []
        def acknowledge(self, *_args): pass
    def execute(_instance, jobs, **kwargs):
        assert jobs
        with lock:
            counts["executed"] += 1
        executions.wait(timeout=10)
        running.clear()
    monkeypatch.setattr(worker, "EnrollmentClient", lambda *_args: Client())
    monkeypatch.setattr(worker, "OperationReceipts", Receipts)
    monkeypatch.setattr(worker, "_execute_jobs", execute)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(worker._interactive_lane, tmp_path, {"agent_mainframe_url": "https://fixture"}, running.is_set, gate) for _ in range(3)]
        try:
            assert first_poll.wait(10)
            assert counts["calls"] == 1
        finally:
            release_poll.set()
        for future in futures:
            future.result(timeout=10)
    assert counts == {"calls": 3, "active": 0, "peak": 1, "executed": 3}


@pytest.mark.parametrize("values", [
    {"distributed_listener_connections": 1},
    {"distributed_listener_connections": 513},
    {"distributed_control_reserve": 0},
    {"distributed_control_reserve": 32},
    {"distributed_agent_long_polls": 9},
    {"distributed_listener_connections": True},
    {"distributed_control_reserve": 1.5},
    {"distributed_control_reserve": float("inf")},
])
def test_fleet_policy_rejects_invalid_capacity(tmp_path, values):
    with pytest.raises(ValueError):
        OperationalSettingsStore(str(tmp_path)).save(values)


def test_interactive_failure_pacing_is_shared_and_shutdown_releases_waiters(tmp_path, monkeypatch):
    gate = polling.InteractivePollGate()
    running = threading.Event()
    running.set()
    paused = threading.Event()
    release = threading.Event()
    started = threading.Barrier(3)
    calls = []
    delays = []
    class Client:
        def interactive(self, *_args, **_kwargs):
            calls.append(True)
            raise EnrollmentTransportError("fixture disconnected")
    class Receipts:
        def __init__(self, *_args): pass
        def discard_other_activations(self, *_args): pass
        def pending(self, *_args): return []
    def client_factory(*_args):
        started.wait(timeout=10)
        return Client()
    def waiting_pause(delay, _running):
        delays.append(delay)
        assert gate.lock.locked(), "another lane could bypass reconnect pacing"
        paused.set()
        assert release.wait(10)
    monkeypatch.setattr(worker, "EnrollmentClient", client_factory)
    monkeypatch.setattr(worker, "OperationReceipts", Receipts)
    monkeypatch.setattr(worker, "agent_activation", lambda _: {"activation_id": "11" * 16})
    monkeypatch.setattr(worker, "pause", waiting_pause)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(worker._interactive_lane, tmp_path, {"agent_mainframe_url": "https://fixture"}, running.is_set, gate) for _ in range(3)]
        try:
            assert paused.wait(10)
            assert calls == [True]
        finally:
            running.clear()
            release.set()
        for future in futures:
            future.result(timeout=10)
    assert len(delays) == 1
    assert 0.5 <= delays[0] <= 1
    assert not gate.lock.locked()
