"""Admission retries must never create a second mutation job."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.preview_binding import PREVIEW_MAX_AGE_SECONDS, PreviewSigner


def submit(store, key="review", owner="owner", tool="switch_order"):
    return store.enqueue(user_id=owner, tool=tool, config={"mode": "apply"}, request_key=key)


def test_concurrent_duplicate_admission_returns_one_original_job(tmp_path):
    store = DiagnosticJobStore(tmp_path)
    barrier = Barrier(8)

    def enqueue(_):
        barrier.wait(timeout=10)
        return submit(store)

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(enqueue, range(8)))
    assert len(set(ids)) == 1
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM diagnostic_jobs").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM diagnostic_receipts").fetchone()[0] == 1


@pytest.mark.parametrize("state", ["queued", "cancelled", "unknown", "succeeded"])
def test_retry_returns_original_even_at_capacity_and_after_restart(tmp_path, state):
    OperationalSettingsStore(str(tmp_path)).save({"diagnostic_history_limit": 1, "diagnostic_user_limit": 1})
    store = DiagnosticJobStore(tmp_path)
    first = submit(store)
    if state == "cancelled":
        store.cancel(first, "owner")
    elif state in {"unknown", "succeeded"}:
        job = store.claim()
        if state == "unknown":
            store.recover()
        else:
            store.finish(first, job["token"], [], {})
            store.release(first, job["token"])
    reopened = DiagnosticJobStore(tmp_path)
    assert submit(reopened) == first
    assert reopened.get(first, "owner")["state"] == state
    with pytest.raises(ValueError, match="already submitted"):
        submit(reopened, owner="intruder")


def test_receipt_cannot_redirect_another_tool_to_original_job(tmp_path):
    store = DiagnosticJobStore(tmp_path)
    submit(store)
    with pytest.raises(ValueError, match="already submitted"):
        submit(store, tool="tcp_scan")


def test_pruned_history_keeps_tombstone_and_full_receipts_roll_back_pruning(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({"diagnostic_history_limit": 1})
    store = DiagnosticJobStore(tmp_path)
    first = submit(store)
    store.cancel(first, "owner")
    with pytest.raises(ValueError, match="admission capacity"):
        submit(store, key="second")
    assert store.get(first, "owner") is not None
    replacement = store.enqueue(user_id="owner", config={})
    assert store.get(first, "owner") is None
    with pytest.raises(ValueError, match="already submitted"):
        submit(store)
    assert store.get(replacement, "owner")["state"] == "queued"


def test_receipt_outlives_last_valid_signed_second(tmp_path, monkeypatch):
    # itsdangerous timestamps are integer seconds and max_age is inclusive.
    now = [1000.1]
    monkeypatch.setattr("time.time", lambda: now[0])
    signer = PreviewSigner("secret", tmp_path, "owner")
    token = signer.issue("scope", {})
    store = DiagnosticJobStore(tmp_path)
    OperationalSettingsStore(str(tmp_path)).save({"diagnostic_history_limit": 1})
    first = submit(store)
    store.cancel(first, "owner")
    now[0] += PREVIEW_MAX_AGE_SECONDS + 0.1
    assert signer.valid(token, "scope", {})
    assert submit(store) == first
    now[0] += 1
    assert not signer.valid(token, "scope", {})
    assert submit(store, key="fresh") != first


def test_failed_admission_leaves_no_receipt(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({"diagnostic_queue_limit": 1})
    store = DiagnosticJobStore(tmp_path)
    occupied = store.enqueue(user_id="other", config={})
    with pytest.raises(ValueError, match="queue is full"):
        submit(store)
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM diagnostic_receipts").fetchone()[0] == 0
    store.cancel(occupied, "other")
    assert submit(store)
