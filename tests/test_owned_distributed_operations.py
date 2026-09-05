from __future__ import annotations

import sqlite3
import threading
import time

import pytest

from twn_toolkit.distributed_jobs import DistributedJobStore, JOB_PROTOCOL_VERSION
from twn_toolkit.distributed_operations import OperationReceipts, execute_owned
from twn_toolkit.operational import OperationalSettingsStore


EPOCH = "11" * 16
NEXT_EPOCH = "22" * 16


def enqueue(store, *, capability="system.identity"):
    return store.enqueue(
        agent_id="agent-a",
        requester_id="operator-a",
        capability_id=capability,
        capability_version="1",
        inputs={"target": "example"},
    )


def claim(store, *, activation=EPOCH):
    claimed = store.claim("agent-a", activation_id=activation)
    assert len(claimed) == 1
    job = claimed[0]
    assert job["job_protocol"] == JOB_PROTOCOL_VERSION
    assert len(job["attempt_token"]) == 64
    return job


def test_configured_lease_is_delivered_and_applies_to_subsequent_renewals(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({"distributed_job_lease_seconds": 5})
    store = DistributedJobStore(tmp_path)
    store.activate_agent("agent-a", EPOCH)
    queued = enqueue(store)
    job = claim(store)
    assert job["lease_seconds"] == 5

    assert store.control(
        queued["id"], agent_id="agent-a", activation_id=EPOCH,
        attempt_token=job["attempt_token"], action="start",
    )["lease_seconds"] == 5
    OperationalSettingsStore(str(tmp_path)).save({"distributed_job_lease_seconds": 6})
    assert store.control(
        queued["id"], agent_id="agent-a", activation_id=EPOCH,
        attempt_token=job["attempt_token"], action="renew",
    )["lease_seconds"] == 6


def test_claim_is_only_a_delivery_receipt_until_owned_start(tmp_path):
    store = DistributedJobStore(tmp_path)
    store.activate_agent("agent-a", EPOCH)
    queued = enqueue(store)
    job = claim(store)

    assert store.get(queued["id"])["state"] == "claimed"
    with pytest.raises(ValueError, match="unstarted"):
        store.complete(
            queued["id"],
            agent_id="agent-a",
            activation_id=EPOCH,
            attempt_token=job["attempt_token"],
            state="succeeded",
        )
    with pytest.raises(ValueError, match="ownership"):
        store.control(
            queued["id"],
            agent_id="agent-a",
            activation_id=EPOCH,
            attempt_token="not-the-owner",
            action="start",
        )

    started = store.control(
        queued["id"],
        agent_id="agent-a",
        activation_id=EPOCH,
        attempt_token=job["attempt_token"],
        action="start",
    )
    assert started["state"] == "running"
    assert store.get(queued["id"])["started_at"] is not None


def test_expired_claim_cannot_execute_or_be_redelivered(tmp_path):
    store = DistributedJobStore(tmp_path)
    store.activate_agent("agent-a", EPOCH)
    queued = enqueue(store)
    job = claim(store)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE distributed_jobs SET lease_expires_at = 0 WHERE id = ?",
            (queued["id"],),
        )

    assert store.get(queued["id"])["state"] == "cancelled"
    assert store.claim("agent-a", activation_id=EPOCH) == []
    assert store.control(
        queued["id"],
        agent_id="agent-a",
        activation_id=EPOCH,
        attempt_token=job["attempt_token"],
        action="start",
    )["state"] == "cancelled"


def test_expired_running_operation_is_unknown_until_same_attempt_resolves_it(tmp_path):
    store = DistributedJobStore(tmp_path)
    store.activate_agent("agent-a", EPOCH)
    queued = enqueue(store)
    job = claim(store)
    store.control(
        queued["id"], agent_id="agent-a", activation_id=EPOCH,
        attempt_token=job["attempt_token"], action="start",
    )
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE distributed_jobs SET lease_expires_at = 0 WHERE id = ?",
            (queued["id"],),
        )

    unknown = store.get(queued["id"])
    assert unknown["state"] == "unknown"
    assert "reconcile" in unknown["error"]
    assert store.claim("agent-a", activation_id=EPOCH) == []
    with pytest.raises(ValueError, match="ownership"):
        store.complete(
            queued["id"], agent_id="agent-a", activation_id=EPOCH,
            attempt_token="wrong", state="succeeded",
        )

    resolved = store.complete(
        queued["id"], agent_id="agent-a", activation_id=EPOCH,
        attempt_token=job["attempt_token"], state="succeeded", output={"ok": True},
    )
    assert resolved["state"] == "succeeded"
    assert resolved["output"] == {"ok": True}


def test_cancellation_is_atomic_before_start_and_honest_after_start(tmp_path):
    store = DistributedJobStore(tmp_path)
    store.activate_agent("agent-a", EPOCH)

    queued = enqueue(store)
    assert store.cancel(queued["id"], requester_id="operator-a")["state"] == "cancelled"
    assert store.claim("agent-a", activation_id=EPOCH) == []

    pending = enqueue(store)
    claimed = claim(store)
    assert claimed["id"] == pending["id"]
    assert store.cancel(pending["id"], requester_id="operator-a")["state"] == "cancelled"
    assert store.control(
        pending["id"], agent_id="agent-a", activation_id=EPOCH,
        attempt_token=claimed["attempt_token"], action="start",
    )["state"] == "cancelled"

    running = enqueue(store)
    claimed = claim(store)
    store.control(
        running["id"], agent_id="agent-a", activation_id=EPOCH,
        attempt_token=claimed["attempt_token"], action="start",
    )
    request = store.cancel(running["id"], requester_id="operator-a")
    assert request["state"] == "cancel_requested"
    assert "do not resubmit" in request["error"]
    assert store.control(
        running["id"], agent_id="agent-a", activation_id=EPOCH,
        attempt_token=claimed["attempt_token"], action="renew",
    )["state"] == "cancel_requested"
    assert store.complete(
        running["id"], agent_id="agent-a", activation_id=EPOCH,
        attempt_token=claimed["attempt_token"], state="succeeded",
    )["state"] == "succeeded"


def test_activation_change_cancels_unstarted_and_fences_started_attempt(tmp_path):
    store = DistributedJobStore(tmp_path)
    store.activate_agent("agent-a", EPOCH)
    unstarted = enqueue(store)
    running = enqueue(store)
    first = claim(store)
    second = claim(store)
    assert {first["id"], second["id"]} == {unstarted["id"], running["id"]}
    running_claim = first if first["id"] == running["id"] else second
    store.control(
        running["id"], agent_id="agent-a", activation_id=EPOCH,
        attempt_token=running_claim["attempt_token"], action="start",
    )

    assert store.activate_agent("agent-a", NEXT_EPOCH) == 2
    assert store.get(unstarted["id"])["state"] == "cancelled"
    assert store.get(running["id"])["state"] == "unknown"
    with pytest.raises(ValueError, match="ownership"):
        store.complete(
            running["id"], agent_id="agent-a", activation_id=EPOCH,
            attempt_token=running_claim["attempt_token"], state="succeeded",
        )


def test_migration_quarantines_unowned_legacy_running_work(tmp_path):
    path = tmp_path / "distributed_jobs.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE distributed_jobs ("
            "id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, requester_id TEXT NOT NULL, "
            "capability_id TEXT NOT NULL, capability_version TEXT NOT NULL, "
            "input_json TEXT NOT NULL, state TEXT NOT NULL, output_json TEXT, "
            "error TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, started_at REAL, "
            "completed_at REAL, lease_expires_at REAL)"
        )
        db.execute(
            "INSERT INTO distributed_jobs VALUES "
            "('legacy', 'agent-a', 'operator-a', 'system.identity', '1', '{}', "
            "'running', NULL, '', 1, 1, NULL, 9999999999)"
        )
    store = DistributedJobStore(tmp_path)
    migrated = store.get("legacy")
    assert migrated["state"] == "unknown"
    assert "Legacy execution outcome" in migrated["error"]
    assert store.claim("agent-a") == []


class FakeClient:
    def __init__(
        self, *, start_state="running", renew_state="running", lease_seconds=0.05
    ):
        self.start_state = start_state
        self.renew_state = renew_state
        self.lease_seconds = lease_seconds
        self.calls = []

    def job_control(self, _job, action):
        self.calls.append(action)
        state = self.start_state if action == "start" else self.renew_state
        return {"state": state, "lease_seconds": self.lease_seconds}


def owned_job():
    return {
        "id": "job_receipt",
        "attempt_token": "a" * 64,
        "activation_id": EPOCH,
        "job_protocol": JOB_PROTOCOL_VERSION,
        "capability_id": "system.identity",
        "capability_version": "1",
        "inputs": {},
    }


def test_agent_receipt_is_durable_before_execution_and_renews_lease(tmp_path):
    client = FakeClient()
    ran = []
    def execute(*_args):
        ran.append(True)
        time.sleep(0.12)
        return {"complete": True}

    execute_owned(tmp_path, [owned_job()], client, "regular", execute)
    results = OperationReceipts(tmp_path).pending("regular", EPOCH)
    assert results == [{
        "id": "job_receipt", "attempt_token": "a" * 64, "state": "succeeded",
        "output": {"complete": True}, "error": "",
    }]
    assert client.calls[0] == "start"
    assert client.calls.count("renew") >= 1


def test_agent_does_not_execute_when_start_is_cancelled(tmp_path):
    client = FakeClient(start_state="cancelled")
    execute_owned(
        tmp_path, [owned_job()], client, "regular",
        lambda *_args: pytest.fail("cancelled claim executed"),
    )
    result = OperationReceipts(tmp_path).pending("regular", EPOCH)[0]
    assert result["state"] == "failed"
    assert "not started" in result["error"]


def test_agent_restart_marks_accepted_but_unfinished_operation_unknown(tmp_path, monkeypatch):
    receipts = OperationReceipts(tmp_path)
    assert receipts.begin(owned_job(), "regular")
    monkeypatch.setattr("twn_toolkit.distributed_operations._BOOT_ID", "new-boot")
    recovered = OperationReceipts(tmp_path).pending("regular", EPOCH)[0]
    assert recovered["state"] == "unknown"
    assert "restarted" in recovered["error"]


def test_acked_receipts_are_evicted_before_unacknowledged_capacity(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({"distributed_receipt_limit": 2})
    receipts = OperationReceipts(tmp_path)
    for number in range(2):
        job = {**owned_job(), "id": f"job_{number}", "attempt_token": f"{number}" * 64}
        assert receipts.begin(job, "regular")
        receipts.finish(job, {"id": job["id"], "attempt_token": job["attempt_token"], "state": "failed", "output": {}, "error": ""})
        receipts.acknowledge([{"id": job["id"], "attempt_token": job["attempt_token"], "status": "accepted"}])
    fresh = {**owned_job(), "id": "job_fresh", "attempt_token": "f" * 64}
    assert receipts.begin(fresh, "regular")


def test_agent_stops_renewing_after_cancellation_is_requested(tmp_path):
    client = FakeClient(renew_state="cancel_requested", lease_seconds=0.05)

    def execute(*_args):
        time.sleep(0.12)
        return {"completed_after_cancellation": True}

    execute_owned(tmp_path, [owned_job()], client, "regular", execute)
    assert client.calls == ["start", "renew"]
    result = OperationReceipts(tmp_path).pending("regular", EPOCH)[0]
    assert result["state"] == "succeeded"
