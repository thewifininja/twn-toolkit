from __future__ import annotations

from twn_toolkit.distributed_job_epochs import DistributedJobStore
from twn_toolkit.distributed_jobs import DistributedJobStore as LegacyJobStore


def _enqueue(store: DistributedJobStore, agent_id: str, label: str):
    return store.enqueue(
        agent_id=agent_id,
        requester_id="administrator",
        capability_id="system.identity",
        capability_version="1",
        inputs={"label": label},
    )


def test_first_activation_adopts_legacy_pending_jobs(tmp_path):
    legacy = LegacyJobStore(tmp_path)
    job = legacy.enqueue(
        agent_id="agent_one",
        requester_id="administrator",
        capability_id="system.identity",
        capability_version="1",
        inputs={},
    )
    store = DistributedJobStore(tmp_path)

    assert store.activate_agent("agent_one", "11" * 16) == 0
    claimed = store.claim("agent_one", activation_id="11" * 16)

    assert [item["id"] for item in claimed] == [job["id"]]


def test_new_activation_cancels_work_from_before_standalone_interval(tmp_path):
    store = DistributedJobStore(tmp_path)
    first_epoch = "22" * 16
    second_epoch = "33" * 16
    store.activate_agent("agent_one", first_epoch)
    running = _enqueue(store, "agent_one", "running")
    queued = _enqueue(store, "agent_one", "queued")
    assert store.claim("agent_one", limit=1, activation_id=first_epoch)[0]["id"] == running["id"]

    assert store.activate_agent("agent_one", second_epoch) == 2

    assert store.get(running["id"])["state"] == "cancelled"
    assert store.get(queued["id"])["state"] == "cancelled"
    assert store.claim("agent_one", activation_id=second_epoch) == []
    fresh = _enqueue(store, "agent_one", "fresh")
    assert store.claim("agent_one", activation_id=second_epoch)[0]["id"] == fresh["id"]


def test_ordinary_reconnect_keeps_same_epoch_work_eligible(tmp_path):
    store = DistributedJobStore(tmp_path)
    activation_id = "44" * 16
    store.activate_agent("agent_one", activation_id)
    job = _enqueue(store, "agent_one", "survives restart")

    assert store.activate_agent("agent_one", activation_id) == 0
    assert store.claim("agent_one", activation_id=activation_id)[0]["id"] == job["id"]


def test_invalid_or_legacy_activation_uses_compatible_queue_behavior(tmp_path):
    store = DistributedJobStore(tmp_path)
    job = _enqueue(store, "legacy_agent", "legacy")

    assert store.activate_agent("legacy_agent", "") == 0
    assert store.claim("legacy_agent", activation_id="")[0]["id"] == job["id"]
