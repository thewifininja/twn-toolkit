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
    assert len(claimed) == 1
    delivery = claimed[0]
    assert {
        "id": delivery["id"],
        "capability_id": delivery["capability_id"],
        "capability_version": delivery["capability_version"],
        "inputs": delivery["inputs"],
    } == {
        "id": queued["id"],
        "capability_id": "system.identity",
        "capability_version": "1",
        "inputs": {},
    }
    assert delivery["attempt_token"]
    assert store.claim("agent_a") == []
    store.control(
        queued["id"], agent_id="agent_a", attempt_token=delivery["attempt_token"],
        activation_id="", action="start",
    )

    completed = store.complete(
        queued["id"],
        agent_id="agent_a",
        attempt_token=delivery["attempt_token"],
        activation_id="",
        state="succeeded",
        output={"toolkit": {"hostname": "agent-a"}},
    )
    assert completed["state"] == "succeeded"
    repeated = store.complete(
        queued["id"], agent_id="agent_a", attempt_token=delivery["attempt_token"],
        activation_id="", state="failed", error="late duplicate"
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
