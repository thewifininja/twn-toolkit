from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager

import pytest

from twn_toolkit.distributed_jobs import DistributedJobStore


def enqueue(store, owner="owner"):
    return store.enqueue(
        agent_id="agent", requester_id=owner,
        capability_id="system.identity", capability_version="1",
        inputs={"keep": "until deadline"},
    )


def read(store, kind, job_id):
    if kind == "get":
        return store.get(job_id)
    if kind == "requester":
        return store.get_for_requester(job_id, "owner")
    if kind == "recent":
        return store.recent(requester_id="owner")[0]
    return store.latest(
        agent_id="agent", requester_id="owner",
        capability_id="system.identity", capability_version="1",
    )


def trace_connections(store, monkeypatch):
    modes, statements = [], []
    original = store._connect

    @contextmanager
    def traced(**kwargs):
        modes.append(bool(kwargs.get("write", False)))
        with original(**kwargs) as db:
            db.set_trace_callback(statements.append)
            yield db

    monkeypatch.setattr(store, "_connect", traced)
    return modes, statements


@pytest.mark.parametrize("kind", ["get", "requester", "recent", "latest"])
def test_fresh_reads_do_not_reserve_a_writer_even_while_another_writer_is_active(tmp_path, monkeypatch, kind):
    store = DistributedJobStore(tmp_path)
    job = enqueue(store)
    modes, statements = trace_connections(store, monkeypatch)
    # An IMMEDIATE writer reservation still permits readers of committed state.
    # An accidental second BEGIN IMMEDIATE would block and eventually fail.
    with sqlite3.connect(store.path) as writer:
        writer.execute("BEGIN IMMEDIATE")
        result = read(store, kind, job["id"])
    assert result["id"] == job["id"]
    assert result["inputs"] == {"keep": "until deadline"}
    assert modes == [False]
    assert not any(statement.startswith(("UPDATE", "DELETE", "INSERT")) for statement in statements)


@pytest.mark.parametrize("kind", ["get", "requester", "recent", "latest"])
@pytest.mark.parametrize("state,expected", [("claimed", "cancelled"), ("running", "unknown"), ("cancel_requested", "unknown")])
def test_due_reads_expire_selected_ownership_under_one_write_reservation(tmp_path, monkeypatch, kind, state, expected):
    store = DistributedJobStore(tmp_path)
    job = enqueue(store)
    other = enqueue(store, "other")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE distributed_jobs SET state = ?, lease_expires_at = 0", (state,))
    modes, _ = trace_connections(store, monkeypatch)
    result = read(store, kind, job["id"])
    assert result["state"] == expected
    assert result["lease_expires_at"] is None
    assert modes == [False, True]
    with sqlite3.connect(store.path) as db:
        # Reading one requester's history must not sweep another's work.
        assert db.execute("SELECT state FROM distributed_jobs WHERE id = ?", (other["id"],)).fetchone()[0] == state


@pytest.mark.parametrize("kind", ["get", "requester", "recent", "latest"])
def test_due_payload_is_removed_before_returning_a_history_record(tmp_path, kind):
    store = DistributedJobStore(tmp_path)
    job = enqueue(store)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE distributed_jobs SET payload_expires_at = 0")
    result = read(store, kind, job["id"])
    assert result["state"] == "cancelled"
    assert result["inputs"] == {}
    assert result["output"] is None
    assert "retention expired" in result["error"]


def test_expiry_rechecks_ownership_after_acquiring_write_reservation(tmp_path, monkeypatch):
    store = DistributedJobStore(tmp_path)
    job = enqueue(store)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE distributed_jobs SET state = 'running', lease_expires_at = 0")
    original = store._connect
    renewed_deadline = time.time() + 600

    @contextmanager
    def renew_between_snapshots(**kwargs):
        if kwargs.get("write"):
            with sqlite3.connect(store.path) as db:
                db.execute("UPDATE distributed_jobs SET lease_expires_at = ?", (renewed_deadline,))
        with original(**kwargs) as db:
            yield db

    monkeypatch.setattr(store, "_connect", renew_between_snapshots)
    result = store.get(job["id"])
    assert result["state"] == "running"
    assert result["lease_expires_at"] == renewed_deadline


def test_expiry_rechecks_the_selected_page_after_a_concurrent_insert(tmp_path, monkeypatch):
    store = DistributedJobStore(tmp_path)
    job = enqueue(store)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE distributed_jobs SET payload_expires_at = 0")
    original = store._connect
    inserted = []

    @contextmanager
    def insert_between_snapshots(**kwargs):
        if kwargs.get("write") and not inserted:
            # A separate store is an independent writer arriving before our lock.
            other = DistributedJobStore(tmp_path)
            new = enqueue(other)
            inserted.append(new["id"])
            with sqlite3.connect(store.path) as db:
                db.execute(
                    "UPDATE distributed_jobs SET payload_expires_at = 0, created_at = ? WHERE id = ?",
                    (job["created_at"] + 10, new["id"]),
                )
        with original(**kwargs) as db:
            yield db

    monkeypatch.setattr(store, "_connect", insert_between_snapshots)
    result = store.recent(requester_id="owner", limit=1)[0]
    assert result["id"] == inserted[0]
    assert result["state"] == "cancelled"
    assert result["inputs"] == {}


def test_inaccessible_and_missing_jobs_do_not_trigger_expiry(tmp_path, monkeypatch):
    store = DistributedJobStore(tmp_path)
    job = enqueue(store, "other")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE distributed_jobs SET payload_expires_at = 0")
    modes, _ = trace_connections(store, monkeypatch)
    assert store.get_for_requester(job["id"], "owner") is None
    assert store.get("missing") is None
    assert store.recent(requester_id="owner") == []
    assert store.latest(agent_id="agent", requester_id="owner", capability_id="system.identity", capability_version="1") is None
    assert not any(modes)
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT state FROM distributed_jobs").fetchone()[0] == "queued"


def test_retained_history_queries_use_ordered_indexes_and_bound_results(tmp_path):
    store = DistributedJobStore(tmp_path)
    with sqlite3.connect(store.path) as db:
        db.executemany(
            "INSERT INTO distributed_jobs(id, agent_id, requester_id, capability_id, capability_version, input_json, state, created_at) VALUES (?, ?, ?, ?, '1', '{}', 'succeeded', ?)",
            [(str(i), f"agent-{i % 10}", f"owner-{i % 100}", "system.identity", i) for i in range(20000)],
        )
        plans = [
            db.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM distributed_jobs WHERE requester_id = ? ORDER BY created_at DESC LIMIT 25",
                ("owner-1",),
            ).fetchall(),
            db.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM distributed_jobs WHERE agent_id = ? AND requester_id = ? AND capability_id = ? AND capability_version = ? ORDER BY created_at DESC LIMIT 1",
                ("agent-1", "owner-1", "system.identity", "1"),
            ).fetchall(),
        ]
    for plan, index in zip(plans, ("distributed_jobs_requester_history", "distributed_jobs_latest")):
        detail = " ".join(row[3] for row in plan)
        assert index in detail
        assert "TEMP B-TREE" not in detail
        assert "SCAN " not in detail
    rows = store.recent(requester_id="owner-1", limit=1000)
    assert len(rows) == 100
    assert all(row["requester_id"] == "owner-1" for row in rows)
    assert [row["created_at"] for row in rows] == sorted((row["created_at"] for row in rows), reverse=True)
    latest = store.latest(agent_id="agent-1", requester_id="owner-1", capability_id="system.identity", capability_version="1")
    assert latest["id"] == rows[0]["id"]
