from __future__ import annotations

from contextlib import contextmanager
import multiprocessing
import sqlite3

import pytest

from twn_toolkit.distributed_jobs import DistributedJobStore as BaseStore
from twn_toolkit.distributed_job_epochs import DistributedJobStore as EpochStore


EPOCH = "11" * 16
NEXT_EPOCH = "22" * 16


def _store(instance, epoch):
    return (EpochStore if epoch else BaseStore)(instance)


def _enqueue(store, agent="agent_a", capability="system.identity", label=""):
    return store.enqueue(agent_id=agent, requester_id="user_a", capability_id=capability,
                         capability_version="1", inputs={"label": label})


def _claim_process(instance, epoch, ready, release, started, done, results):
    started.set()
    store = _store(instance, epoch)
    if ready is not None:
        connect = store._connect

        class Cursor:
            def __init__(self, cursor):
                self.cursor = cursor

            def fetchall(self):
                rows = self.cursor.fetchall()
                ready.set()
                if not release.wait(15):
                    raise TimeoutError("Paused claim was not released.")
                return rows

        class Connection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, sql, *args):
                cursor = self.connection.execute(sql, *args)
                if "SELECT * FROM distributed_jobs" in sql and "ORDER BY created_at" in sql:
                    return Cursor(cursor)
                return cursor

        @contextmanager
        def paused_connect(*args, **kwargs):
            with connect(*args, **kwargs) as connection:
                yield Connection(connection)

        store._connect = paused_connect
    options = {"activation_id": EPOCH} if epoch else {}
    results.put(store.claim("agent_a", limit=4, **options))
    done.set()


@pytest.mark.parametrize("epoch", [False, True], ids=["legacy-interface", "activation-interface"])
@pytest.mark.parametrize("count", [1, 8])
def test_simultaneous_claimers_receive_disjoint_jobs(tmp_path, epoch, count):
    store = _store(tmp_path, epoch)
    if epoch:
        store.activate_agent("agent_a", EPOCH)
    expected = {_enqueue(store, label=str(i))["id"] for i in range(count)}
    context = multiprocessing.get_context("spawn")
    ready, release, started_a, started_b, done_a, done_b = (context.Event() for _ in range(6))
    results = context.Queue()
    first = context.Process(target=_claim_process, args=(str(tmp_path), epoch, ready, release, started_a, done_a, results))
    second = context.Process(target=_claim_process, args=(str(tmp_path), epoch, None, release, started_b, done_b, results))
    first.start()
    try:
        assert ready.wait(15)
        second.start()
        assert started_b.wait(15)
        # The second constructor may also wait on the schema transaction. Either
        # way, it must not publish another claim while the first has a snapshot.
        blocked = not done_b.wait(0.5)
        release.set()
        claims = [results.get(timeout=15), results.get(timeout=15)]
        first.join(15)
        second.join(15)
        assert first.exitcode == second.exitcode == 0
        ids = [job["id"] for batch in claims for job in batch]
        assert len(ids) == len(set(ids)), "A job was delivered to both claimers."
        assert set(ids) == expected
        assert blocked
        assert all(store.get(job_id)["state"] == "running" for job_id in expected)
    finally:
        release.set()
        for process in (first, second):
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join(15)
        results.close()
        results.join_thread()


def test_expired_lease_can_be_reclaimed_without_resetting_start_time(tmp_path):
    store = EpochStore(tmp_path)
    store.activate_agent("agent_a", EPOCH)
    job = _enqueue(store)
    assert store.claim("agent_a", activation_id=EPOCH)[0]["id"] == job["id"]
    original_start = store.get(job["id"])["started_at"]
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE distributed_jobs SET lease_expires_at = 0 WHERE id = ?", (job["id"],))
    assert store.claim("agent_a", activation_id=EPOCH)[0]["id"] == job["id"]
    assert store.get(job["id"])["started_at"] == original_start
    assert store.claim("agent_a", activation_id=EPOCH) == []


def test_filters_isolate_agents_activations_and_interactive_lanes(tmp_path):
    store = EpochStore(tmp_path)
    store.activate_agent("agent_a", EPOCH)
    identity = _enqueue(store)
    interactive = _enqueue(store, capability="system.http.tunnel")
    other = _enqueue(store, agent="agent_b")
    assert store.claim("agent_a", activation_id=NEXT_EPOCH) == []
    assert [j["id"] for j in store.claim("agent_a", activation_id=EPOCH, exclude_capability_id="system.http.tunnel")] == [identity["id"]]
    assert [j["id"] for j in store.claim("agent_a", activation_id=EPOCH, capability_id="system.http.tunnel")] == [interactive["id"]]
    assert store.get(other["id"])["state"] == "queued"


def test_claim_rolls_back_the_entire_batch_on_write_failure(tmp_path):
    store = EpochStore(tmp_path)
    store.activate_agent("agent_a", EPOCH)
    jobs = [_enqueue(store) for _ in range(3)]
    connect = store._connect

    class Connection:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql, *args):
            cursor = self.connection.execute(sql, *args)
            if "SET state = 'running'" in sql:
                raise sqlite3.OperationalError("Injected interrupted claim")
            return cursor

    @contextmanager
    def failing_connect(*args, **kwargs):
        with connect(*args, **kwargs) as connection:
            yield Connection(connection)

    store._connect = failing_connect
    with pytest.raises(sqlite3.OperationalError, match="Injected interrupted claim"):
        store.claim("agent_a", activation_id=EPOCH)
    store._connect = connect
    assert [store.get(j["id"])["state"] for j in jobs] == ["queued"] * 3
    assert len(store.claim("agent_a", activation_id=EPOCH)) == 3


def test_enqueue_cannot_rebind_a_committed_job_to_a_later_activation(tmp_path):
    store = EpochStore(tmp_path)
    other = EpochStore(tmp_path)
    store.activate_agent("agent_a", EPOCH)
    connect = store._connect
    changed = False

    @contextmanager
    def change_epoch_after_commit(*args, **kwargs):
        nonlocal changed
        with connect(*args, **kwargs) as connection:
            yield connection
        if not changed:
            changed = True
            other.activate_agent("agent_a", NEXT_EPOCH)

    store._connect = change_epoch_after_commit
    job = _enqueue(store)
    retained = other.get(job["id"])
    assert retained["activation_id"] == EPOCH
    assert retained["state"] == "cancelled"
    assert other.claim("agent_a", activation_id=NEXT_EPOCH) == []
    assert _enqueue(other)["activation_id"] == NEXT_EPOCH
    # A late result must not undo cancellation, even through the legacy import.
    result = BaseStore(tmp_path).complete(job["id"], agent_id="agent_a", state="succeeded")
    assert result["state"] == "cancelled"


def test_concurrent_results_preserve_the_first_committed_terminal_state(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    store, other = EpochStore(tmp_path), EpochStore(tmp_path)
    job = _enqueue(store)
    store.claim("agent_a")
    ready, release, started, done = (Event() for _ in range(4))
    connect = store._connect
    paused = False

    class Cursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def fetchone(self):
            nonlocal paused
            row = self.cursor.fetchone()
            if not paused:
                paused = True
                ready.set()
                if not release.wait(15):
                    raise TimeoutError("Paused result was not released.")
            return row

    class Connection:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql, *args):
            cursor = self.connection.execute(sql, *args)
            return Cursor(cursor) if "SELECT" in sql else cursor

    @contextmanager
    def paused_connect(*args, **kwargs):
        with connect(*args, **kwargs) as connection:
            yield Connection(connection)

    store._connect = paused_connect

    def second_result():
        started.set()
        result = other.complete(job["id"], agent_id="agent_a", state="failed", error="duplicate result")
        done.set()
        return result

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(store.complete, job["id"], agent_id="agent_a", state="succeeded", output={"winner": True})
        try:
            assert ready.wait(15)
            second = pool.submit(second_result)
            assert started.wait(15)
            blocked = not done.wait(0.5)
        finally:
            release.set()
        assert first.result(timeout=15)["state"] == "succeeded"
        assert second.result(timeout=15)["state"] == "succeeded"
        assert blocked
    assert other.get(job["id"])["output"] == {"winner": True}


def _initialize_legacy_database(instance, start, results):
    if not start.wait(15):
        raise TimeoutError("Initialization did not start.")
    store = EpochStore(instance)
    results.put(store.get("legacy_job"))


def test_concurrent_initialization_migrates_a_legacy_database_without_losing_jobs(tmp_path):
    with sqlite3.connect(tmp_path / "distributed_jobs.sqlite3") as connection:
        connection.execute("""
            CREATE TABLE distributed_jobs (
                id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, requester_id TEXT NOT NULL,
                capability_id TEXT NOT NULL, capability_version TEXT NOT NULL,
                input_json TEXT NOT NULL, state TEXT NOT NULL, output_json TEXT,
                error TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL,
                started_at REAL, completed_at REAL, lease_expires_at REAL
            )
        """)
        connection.execute("""
            INSERT INTO distributed_jobs
                (id, agent_id, requester_id, capability_id, capability_version,
                 input_json, state, created_at)
            VALUES ('legacy_job', 'agent_a', 'user_a', 'system.identity', '1', '{}', 'queued', 1)
        """)
    context = multiprocessing.get_context("spawn")
    start, results = context.Event(), context.Queue()
    processes = [context.Process(target=_initialize_legacy_database, args=(str(tmp_path), start, results)) for _ in range(4)]
    for process in processes:
        process.start()
    try:
        start.set()
        for _ in processes:
            row = results.get(timeout=15)
            assert row["id"] == "legacy_job"
            assert row["activation_id"] == ""
            assert row["state"] == "queued"
        for process in processes:
            process.join(15)
            assert process.exitcode == 0
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(15)
        results.close()
        results.join_thread()
    store = EpochStore(tmp_path)
    store.activate_agent("agent_a", EPOCH)
    assert store.claim("agent_a", activation_id=EPOCH)[0]["id"] == "legacy_job"
