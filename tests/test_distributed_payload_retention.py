from __future__ import annotations

import base64
import json
import sqlite3
import time

import pytest

from twn_toolkit.distributed_jobs import DistributedJobStore
from twn_toolkit.distributed_operations import OperationReceipts
from twn_toolkit.distributed_payloads import DistributedPayloadCipher
from twn_toolkit.operational import OperationalSettingsStore

SECRET = "payload-canary-NotForDisk-987654321"
BODY = base64.b64encode(SECRET.encode()).decode()


def enqueue(store, capability="system.http.tunnel"):
    return store.enqueue(
        agent_id="agent", requester_id="owner", capability_id=capability,
        capability_version="1", inputs={"body": BODY, "password": SECRET},
    )


def start(store):
    job = store.claim("agent")[0]
    store.control(job["id"], agent_id="agent", attempt_token=job["attempt_token"], action="start")
    return job


def complete(store, job, state="succeeded"):
    return store.complete(
        job["id"], agent_id="agent", attempt_token=job["attempt_token"],
        state=state, output={"body": BODY}, error=SECRET,
    )


def assert_no_plaintext(path):
    data = path.read_bytes()
    assert SECRET.encode() not in data
    assert BODY.encode() not in data


def test_queue_encryption_restart_and_early_tunnel_cleanup(tmp_path):
    store = DistributedJobStore(tmp_path)
    queued = enqueue(store)
    assert_no_plaintext(store.path)
    store = DistributedJobStore(tmp_path)
    assert store.get(queued["id"])["inputs"]["password"] == SECRET
    claimed = start(store)
    assert claimed["inputs"]["password"] == SECRET
    assert store.get(queued["id"])["inputs"] == {}
    complete(store, claimed)
    assert_no_plaintext(store.path)
    reopened = DistributedJobStore(tmp_path)
    assert reopened.get(queued["id"])["output"]["body"] == BODY
    assert reopened.get(queued["id"])["error"] == SECRET
    assert not reopened.discard_tunnel_output(queued["id"], requester_id="other")
    assert reopened.get(queued["id"])["output"]
    assert reopened.discard_tunnel_output(queued["id"], requester_id="owner")
    repeated = complete(reopened, claimed)
    assert repeated["state"] == "succeeded"
    assert repeated["output"] is None
    assert reopened.claim("agent") == []
    assert store.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("capability", ["system.http.tunnel", "tools.dns.lookup"])
def test_expired_queued_payload_is_cancelled_never_executed(tmp_path, capability):
    store = DistributedJobStore(tmp_path)
    queued = enqueue(store, capability)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE distributed_jobs SET payload_expires_at = 0")
    assert store.claim("agent") == []
    result = store.get(queued["id"])
    assert result["state"] == "cancelled"
    assert result["inputs"] == {}
    assert result["completed_at"] is not None


@pytest.mark.parametrize("state", ["succeeded", "failed", "unknown"])
def test_expiry_preserves_outcome_and_ownership_without_sensitive_details(tmp_path, state):
    store = DistributedJobStore(tmp_path)
    enqueue(store, "tools.dns.lookup")
    job = start(store)
    complete(store, job, state)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE distributed_jobs SET payload_expires_at = 0")
    store.prune_payloads()
    result = store.get(job["id"])
    assert result["state"] == state
    assert result["attempt_token"] == job["attempt_token"]
    assert result["inputs"] == {}
    assert result["output"] is None
    assert SECRET not in result["error"]
    assert "retention expired" in result["error"]
    assert store.claim("agent") == []
    if state == "unknown":
        assert not store.delete(job["id"], requester_id="owner")
        assert complete(store, job)["state"] == "succeeded"


def test_tunnel_cancellation_and_activation_change_scrub_inputs(tmp_path):
    store = DistributedJobStore(tmp_path)
    store.activate_agent("agent", "11" * 16)
    first = enqueue(store)
    assert store.cancel(first["id"], requester_id="owner")["inputs"] == {}
    second = enqueue(store)
    store.activate_agent("agent", "22" * 16)
    assert store.get(second["id"])["inputs"] == {}


def test_retention_policy_applies_to_new_payloads_without_rewriting_deadlines(tmp_path):
    policy = OperationalSettingsStore(str(tmp_path))
    policy.save({"distributed_receipt_retention_hours": 1})
    store = DistributedJobStore(tmp_path)
    first = enqueue(store)
    policy.save({"distributed_receipt_retention_hours": 2})
    second = enqueue(store)
    with sqlite3.connect(store.path) as db:
        deadlines = dict(db.execute("SELECT id, payload_expires_at - created_at FROM distributed_jobs"))
    assert deadlines[first["id"]] == 3600
    assert deadlines[second["id"]] == 7200


def test_cipher_rejects_wrong_instance_context_and_corruption(tmp_path, monkeypatch):
    monkeypatch.delenv("TWN_TOOLKIT_SECRET_KEY", raising=False)
    cipher = DistributedPayloadCipher(tmp_path / "one")
    sealed = cipher.seal(SECRET, "job:input")
    assert cipher.open(sealed, "job:input") == SECRET
    for other, value, context in [
        (DistributedPayloadCipher(tmp_path / "two"), sealed, "job:input"),
        (cipher, sealed, "other:input"),
        (cipher, sealed, "job:output"),
        (cipher, sealed[:-10] + "bad", "job:input"),
        (cipher, SECRET, "job:input"),
    ]:
        with pytest.raises(ValueError):
            other.open(value, context)


def test_corrupt_claim_rolls_back_instead_of_delivering_empty_inputs(tmp_path):
    store = DistributedJobStore(tmp_path)
    queued = enqueue(store)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE distributed_jobs SET input_json = 'twn-sealed-v1:bad'")
    with pytest.raises(ValueError, match="decrypted"):
        store.claim("agent")
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT state, attempt_token FROM distributed_jobs WHERE id = ?", (queued["id"],)).fetchone() == ("queued", "")


def receipt_job():
    return {"id": "receipt", "attempt_token": "a" * 64, "activation_id": "11" * 16}


def test_unacknowledged_receipt_expiry_preserves_dedup_and_outcome(tmp_path):
    receipts = OperationReceipts(tmp_path)
    job = receipt_job()
    assert receipts.begin(job, "interactive")
    result = {**job, "state": "succeeded", "output": {"body": BODY}, "error": SECRET}
    receipts.finish(job, result)
    assert_no_plaintext(receipts.path)
    assert OperationReceipts(tmp_path).pending("interactive", job["activation_id"]) == [result]
    with sqlite3.connect(receipts.path) as db:
        db.execute("UPDATE receipts SET payload_expires_at = 0")
    # The already-open interactive lane must clean up too.
    summary = receipts.pending("interactive", job["activation_id"])[0]
    assert summary["state"] == "succeeded"
    assert summary["output"] == {}
    assert SECRET not in summary["error"]
    assert summary["attempt_token"] == job["attempt_token"]
    assert not receipts.begin(job, "interactive")
    assert OperationReceipts(tmp_path).pending("interactive", job["activation_id"]) == [summary]
    receipts.acknowledge([{**job, "status": "accepted"}])
    assert receipts.pending("interactive", job["activation_id"]) == []
    assert not receipts.begin(job, "interactive")


def test_legacy_receipt_migrates_without_leaving_plaintext_or_resetting_age(tmp_path):
    path = tmp_path / "distributed-operation-receipts.sqlite3"
    job = receipt_job()
    result = {**job, "state": "unknown", "output": {"body": BODY}, "error": SECRET}
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE receipts (id TEXT PRIMARY KEY, token TEXT NOT NULL, activation TEXT NOT NULL, lane TEXT NOT NULL, boot TEXT NOT NULL, result TEXT, acknowledged INTEGER NOT NULL DEFAULT 0, updated REAL NOT NULL)")
        db.execute("INSERT INTO receipts VALUES (?, ?, ?, 'interactive', 'old', ?, 0, ?)",
                   (job["id"], job["attempt_token"], job["activation_id"], json.dumps(result), time.time()))
    receipts = OperationReceipts(tmp_path)
    assert receipts.pending("interactive", job["activation_id"]) == [result]
    assert_no_plaintext(path)


def test_legacy_queue_migration_encrypts_live_rows_and_expires_old_rows(tmp_path):
    path = tmp_path / "distributed_jobs.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE distributed_jobs (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, requester_id TEXT NOT NULL, capability_id TEXT NOT NULL, capability_version TEXT NOT NULL, input_json TEXT NOT NULL, state TEXT NOT NULL, output_json TEXT, error TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, started_at REAL, completed_at REAL, lease_expires_at REAL, activation_id TEXT NOT NULL DEFAULT '', attempt_token TEXT NOT NULL DEFAULT '')")
        for job_id, created in [("live", time.time()), ("old", 1)]:
            db.execute("INSERT INTO distributed_jobs (id,agent_id,requester_id,capability_id,capability_version,input_json,state,output_json,error,created_at) VALUES (?, 'agent', 'owner', 'system.identity', '1', ?, 'succeeded', ?, ?, ?)",
                       (job_id, json.dumps({"password": SECRET}), json.dumps({"body": BODY}), SECRET, created))
    store = DistributedJobStore(tmp_path)
    assert store.get("live")["inputs"]["password"] == SECRET
    assert store.get("live")["output"]["body"] == BODY
    assert store.get("live")["error"] == SECRET
    assert store.get("old")["state"] == "succeeded"
    assert store.get("old")["output"] is None
    assert_no_plaintext(path)
