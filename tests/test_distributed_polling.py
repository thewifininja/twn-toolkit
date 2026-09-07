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


def test_status_endpoint_never_claims_or_waits_and_acknowledges_results(tmp_path, monkeypatch):
    server = EnrollmentServer(tmp_path / "mainframe", "127.0.0.1", 0)
    server.enrollment_window.open(5)
    server.start()
    try:
        client, agent_id = enroll(server, tmp_path / "agent", "Agent")
        first = server.job_store.enqueue(
            agent_id=agent_id, requester_id="owner",
            capability_id="system.identity", capability_version="1",
        )
        owned = client.heartbeat([])["jobs"][0]
        assert owned["id"] == first["id"]
        assert client.job_control(owned, "start")["state"] == "running"
        queued = [
            server.job_store.enqueue(
                agent_id=agent_id, requester_id="owner",
                capability_id=capability, capability_version="1",
            )
            for capability in ("system.identity", "system.http.tunnel")
        ]
        def forbidden(*args, **kwargs):
            pytest.fail("status reporting entered the claiming/long-poll path")
        monkeypatch.setattr(server, "_poll_jobs", forbidden)
        result = client.heartbeat(
            [], control_only=True, wait_seconds=20,
            results=[{
                "id": owned["id"], "attempt_token": owned["attempt_token"],
                "state": "succeeded", "output": {"ok": True},
            }],
        )
        assert result["state"] == "approved"
        assert result["jobs"] == []
        assert result["retry_after_seconds"] == 5
        assert result["acknowledgements"][0]["status"] == "accepted"
        assert server.job_store.get(first["id"])["state"] == "succeeded"
        assert all(server.job_store.get(job["id"])["state"] == "queued" for job in queued)
        with pytest.raises(EnrollmentTransportError):
            client._request(
                "POST", "/v1/agent-status",
                {"protocol": 1, "job_protocol": 2}, authenticated=False,
            )
        server.agent_store.set_state(agent_id, "revoked")
        with pytest.raises(EnrollmentTransportError):
            client.heartbeat([], control_only=True)
    finally:
        server.stop()


def test_blocked_regular_execution_preserves_status_renewal_and_interactive_delivery(tmp_path, monkeypatch):
    from twn_toolkit.distributed_runtime import agent_activation

    root = tmp_path / "agent"
    server = EnrollmentServer(tmp_path / "mainframe", "127.0.0.1", 0)
    server.enrollment_window.open(5)
    server.start()
    started, release, renewed, stopped = (threading.Event() for _ in range(4))
    thread = None
    try:
        client, agent_id = enroll(server, root, "Agent")
        activation = agent_activation(root)["activation_id"]
        first = server.job_store.enqueue(
            agent_id=agent_id, requester_id="owner",
            capability_id="system.identity", capability_version="1",
        )
        second = server.job_store.enqueue(
            agent_id=agent_id, requester_id="owner",
            capability_id="system.identity", capability_version="1",
        )
        tunnel = server.job_store.enqueue(
            agent_id=agent_id, requester_id="owner",
            capability_id="system.http.tunnel", capability_version="1",
        )
        executions = []
        def execute(instance, capability, version, inputs):
            executions.append(capability)
            if capability == "system.identity":
                started.set()
                assert release.wait(15), "test did not release the blocked handler"
            return {"ok": True}
        monkeypatch.setattr(worker, "execute_capability", execute)
        original_control = server.job_control
        def control(*args, **kwargs):
            result = original_control(*args, **kwargs)
            payload = args[1]
            if payload["action"] == "renew":
                renewed.set()
            if result.get("state") == "running":
                result["lease_seconds"] = 0.15
            return result
        monkeypatch.setattr(server, "job_control", control)
        settings = {"agent_mainframe_url": f"https://127.0.0.1:{server.port}"}
        thread = threading.Thread(
            target=worker._regular_lane, args=(root, settings, lambda: not stopped.is_set()),
        )
        thread.start()
        assert started.wait(10)
        assert renewed.wait(10), "lease renewal stopped while the handler was blocked"
        for _ in range(3):
            status = worker._agent_tick(root, settings, control_only=True)
            assert status["state"] == "approved"
            assert server.job_store.get(second["id"])["state"] == "queued"
        interactive = client.interactive(wait_seconds=0, activation_id=activation)
        assert interactive["requests"][0]["id"] == tunnel["id"]
        worker._execute_jobs(root, interactive["requests"], client=client, lane="interactive")
        assert executions == ["system.identity", "system.http.tunnel"]
        # A background completion must not overwrite the control loop's newer status.
        marker = {"state": "disconnected", "last_connected_at": status["last_connected_at"]}
        worker._write_status(root / "distributed-status.json", marker)
        stopped.set()
        release.set()
        thread.join(10)
        assert not thread.is_alive()
        assert worker._read_status(root / "distributed-status.json") == marker
        assert server.job_store.get(first["id"])["state"] == "succeeded"
        assert server.job_store.get(second["id"])["state"] == "queued"
        assert executions.count("system.identity") == 1
        assert worker._agent_tick(root, settings, control_only=True)["state"] == "approved"
    finally:
        stopped.set()
        release.set()
        if thread is not None:
            thread.join(15)
        server.stop()


def test_regular_lane_leaves_enrollment_to_control_loop(tmp_path, monkeypatch):
    stopped = threading.Event()
    class Client:
        def __init__(self, *args):
            pass
        def enrolled(self):
            return False
    monkeypatch.setattr(worker, "EnrollmentClient", Client)
    monkeypatch.setattr(worker, "_agent_tick", lambda *args, **kwargs: pytest.fail("execution lane polled enrollment"))
    delays = []
    def pause(delay, running):
        delays.append(delay)
        stopped.set()
    monkeypatch.setattr(worker, "pause", pause)
    worker._regular_lane(tmp_path, {"agent_mainframe_url": "https://mainframe"}, lambda: not stopped.is_set())
    assert delays == [5]


def test_regular_claim_returned_during_shutdown_is_not_executed(tmp_path, monkeypatch):
    root = tmp_path / "agent"
    server = EnrollmentServer(tmp_path / "mainframe", "127.0.0.1", 0)
    server.enrollment_window.open(5)
    server.start()
    stopped = threading.Event()
    try:
        client, agent_id = enroll(server, root, "Agent")
        queued = server.job_store.enqueue(
            agent_id=agent_id, requester_id="owner",
            capability_id="system.identity", capability_version="1",
        )
        original = EnrollmentClient.heartbeat
        def heartbeat(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            stopped.set()
            return result
        monkeypatch.setattr(EnrollmentClient, "heartbeat", heartbeat)
        monkeypatch.setattr(worker, "execute_capability", lambda *args: pytest.fail("started during shutdown"))
        status = worker._agent_tick(
            root, {"agent_mainframe_url": f"https://127.0.0.1:{server.port}"},
            write_status=False, running=lambda: not stopped.is_set(),
        )
        assert status["state"] == "approved"
        assert server.job_store.get(queued["id"])["state"] == "claimed"
        assert not (root / "distributed-status.json").exists()
    finally:
        server.stop()


def test_old_mainframe_status_failure_does_not_fall_back_to_claiming(tmp_path, monkeypatch):
    import io
    import urllib.error
    import urllib.request

    root = tmp_path / "agent"
    server = EnrollmentServer(tmp_path / "mainframe", "127.0.0.1", 0)
    server.enrollment_window.open(5)
    server.start()
    try:
        enroll(server, root, "Agent")
        paths = []
        body = io.BytesIO(b'{"error":"Not found."}')
        def old_mainframe(request, **kwargs):
            paths.append(request.full_url)
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, body)
        monkeypatch.setattr(urllib.request, "urlopen", old_mainframe)
        status = worker._agent_tick(
            root, {"agent_mainframe_url": f"https://127.0.0.1:{server.port}"},
            control_only=True,
        )
        assert status["state"] == "disconnected"
        assert "Upgrade and restart the Mainframe" in status["error"]
        assert len(paths) == 1
        assert paths[0].endswith("/v1/agent-status")
        assert body.closed
    finally:
        server.stop()


@pytest.mark.parametrize("delivery_failure", [None, "before_commit", "lost_acknowledgement"])
def test_completed_gui_receipt_is_published_while_another_lane_is_long_polling(tmp_path, monkeypatch, delivery_failure):
    import time
    from twn_toolkit.distributed_operations import execute_owned

    server = EnrollmentServer(tmp_path / 'mainframe', '127.0.0.1', 0)
    server.enrollment_window.open(5)
    server.start()
    running = threading.Event()
    running.set()
    gate = polling.InteractivePollGate()
    executed = threading.Event()
    calls = []
    pool = ThreadPoolExecutor(max_workers=2)
    futures = []
    publications = []
    original_heartbeat = EnrollmentClient.heartbeat
    def publish(client, *args, **kwargs):
        publications.append(kwargs)
        first = len(publications) == 1
        if first and delivery_failure == "before_commit":
            raise EnrollmentTransportError("fixture: unavailable before delivery")
        result = original_heartbeat(client, *args, **kwargs)
        if first and delivery_failure == "lost_acknowledgement":
            raise EnrollmentTransportError("fixture: committed but acknowledgement lost")
        return result
    monkeypatch.setattr(EnrollmentClient, "heartbeat", publish)
    try:
        agent_path = tmp_path / 'agent'
        _, agent_id = enroll(server, agent_path, 'Receipt latency fixture')
        worker.agent_activation(agent_path)  # Production establishes one epoch before starting lanes.
        def execute(instance, jobs, *, client, lane):
            def effect(*args):
                calls.append(True)
                # Ensure the other lane has started its idle poll before finishing.
                end = time.monotonic() + 3
                while not gate.lock.locked() and time.monotonic() < end:
                    time.sleep(.01)
                assert gate.lock.locked()
                executed.set()
                return {'status': 200, 'body': 'b2s='}
            execute_owned(instance, jobs, client, lane, effect)
        monkeypatch.setattr(worker, '_execute_jobs', execute)
        settings = {'agent_mainframe_url': f'https://127.0.0.1:{server.port}'}
        futures = [pool.submit(worker._interactive_lane, agent_path, settings, running.is_set, gate) for _ in range(2)]
        end = time.monotonic() + 3
        while server.poll_budget.stats()['active'] == 0 and time.monotonic() < end:
            time.sleep(.01)
        assert server.poll_budget.stats()['active'] == 1
        queued = server.job_store.enqueue(agent_id=agent_id, requester_id='owner', capability_id='system.http.tunnel', capability_version='1')
        assert executed.wait(3)
        end = time.monotonic() + 3
        while time.monotonic() < end:
            result = server.job_store.get(queued['id'])
            if result['state'] == 'succeeded':
                break
            time.sleep(.01)
        assert result['state'] == 'succeeded', 'Completed GUI response waited behind the other lane’s 20-second idle poll'
        receipts = worker.OperationReceipts(agent_path)
        end = time.monotonic() + 3
        activation = worker.agent_activation(agent_path)["activation_id"]
        while receipts.pending("interactive", activation) and time.monotonic() < end:
            time.sleep(.01)
        assert not receipts.pending("interactive", activation)
        assert calls == [True]
        assert len(publications) >= (2 if delivery_failure else 1)
        assert all(item["control_only"] and item["wait_seconds"] == 0 for item in publications)
        assert server.poll_budget.stats()['active'] == 1
    finally:
        running.clear()
        server.stop()
        for future in futures:
            future.result(timeout=10)
        pool.shutdown()
