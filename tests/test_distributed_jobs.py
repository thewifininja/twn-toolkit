from __future__ import annotations

from twn_toolkit.distributed_jobs import DistributedJobStore


def test_job_delivery_is_leased_and_completion_is_idempotent(tmp_path):
    store = DistributedJobStore(tmp_path)
    queued = store.enqueue(
        agent_id="agent_a",
        requester_id="user_a",
        capability_id="system.identity",
        capability_version="1",
    )
    assert queued["state"] == "queued"

    claimed = store.claim("agent_a")
    assert claimed == [
        {
            "id": queued["id"],
            "capability_id": "system.identity",
            "capability_version": "1",
            "inputs": {},
        }
    ]
    assert store.claim("agent_a") == []

    completed = store.complete(
        queued["id"],
        agent_id="agent_a",
        state="succeeded",
        output={"toolkit": {"hostname": "agent-a"}},
    )
    assert completed["state"] == "succeeded"
    repeated = store.complete(
        queued["id"], agent_id="agent_a", state="failed", error="late duplicate"
    )
    assert repeated["state"] == "succeeded"
    assert store.recent(requester_id="user_a")[0]["output"]["toolkit"]["hostname"] == "agent-a"
    latest = store.latest(
        agent_id="agent_a",
        requester_id="user_a",
        capability_id="system.identity",
        capability_version="1",
    )
    assert latest is not None
    assert latest["id"] == queued["id"]
    assert store.latest(
        agent_id="agent_a",
        requester_id="another_user",
        capability_id="system.identity",
        capability_version="1",
    ) is None
