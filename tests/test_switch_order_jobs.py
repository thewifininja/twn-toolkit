"""Failure boundaries for supervised mutations, using disposable local stores."""
from contextlib import contextmanager

import pytest

from twn_toolkit.auth import load_or_create_secret_key
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.fortigate import FortiGateError
from twn_toolkit.preview_binding import PreviewSigner, PREVIEW_MAX_AGE_SECONDS
from twn_toolkit.profiles import ProfileStore
from twn_toolkit import switch_order_jobs as operations

REAL_RECORD_OUTCOME = operations.record_switch_outcome


@pytest.fixture
def operation(tmp_path, monkeypatch):
    store = DiagnosticJobStore(tmp_path)
    profile = {"name": "Lab", "host": "https://fortigate.example", "api_key": "fixture-secret", "default_vdom": "root"}
    ProfileStore(str(tmp_path)).upsert(profile)
    config = dict(profile=profile, mode="apply", vdom="root", username="reviewer",
                  investigation_id="", original_ids=["a", "b", "c"], desired_ids=["c", "b", "a"])
    signer = PreviewSigner(load_or_create_secret_key(str(tmp_path)), store.instance, "owner")
    config["preview_token"] = signer.issue("switch-order-apply-v1", operations.review_context(config))
    job_id = store.enqueue(user_id="owner", config=config, tool="switch_order")
    job = store.claim()
    events = []

    class Appliance:
        def __init__(self):
            self.ids = ["a", "b", "c"]
            self.calls = []
            self.job_id = job_id

        @contextmanager
        def pooled(self):
            yield self

        def get_managed_switches(self, vdom):
            self.calls.append("read")
            return [{"switch-id": identifier, "name": "Switch " + identifier} for identifier in self.ids]

        def move_managed_switch_after(self, switch_id, after, vdom):
            saved = store.get(self.job_id, "owner")["summary"]
            assert saved["in_flight"] == {"switch_id": switch_id, "after": after}
            assert saved["attempted_moves"] == len(saved["completed_moves"]) + 1
            self.calls.append((switch_id, after))
            self.ids.remove(switch_id)
            self.ids.insert(self.ids.index(after) + 1, switch_id)

    appliance = Appliance()
    monkeypatch.setattr(operations.FortiGateClient, "from_profile", lambda _: appliance)
    monkeypatch.setattr(operations, "record_switch_outcome", lambda *args, **kwargs: events.append(args[2]))
    return store, job, config, appliance, events


def run(operation):
    store, job, config, _, _ = operation
    operations.execute_switch_order(store, job, config)
    return store.get(job["id"], "owner")


def test_verified_order_retains_encrypted_intent_ack_and_fresh_binding(operation):
    store, job, config, appliance, events = operation
    result = run(operation)
    assert result["state"] == "succeeded"
    summary = result["summary"]
    assert summary["phase"] == "verified"
    assert summary["attempted_moves"] == len(summary["completed_moves"]) == 2
    assert summary["in_flight"] is None
    assert appliance.ids == config["desired_ids"]
    assert events == ["succeeded"]
    signer = PreviewSigner(load_or_create_secret_key(str(store.instance)), store.instance, "owner")
    assert signer.valid(summary["load_token"], "switch-order-load-v1", {
        "profile": config["profile"], "vdom": "root", "original_ids": config["desired_ids"],
        "target_revision": job["id"]})
    assert b"fixture-secret" not in store.path.read_bytes()


@pytest.mark.parametrize("boundary", ["before_intent", "after_send", "after_ack", "before_finish"])
def test_cancel_preserves_last_durable_checkpoint(operation, monkeypatch, boundary):
    store, job, _, appliance, _ = operation
    original_progress = store.progress
    original_move = appliance.move_managed_switch_after

    def progress(job_id, token, summary):
        if boundary == "before_intent" and summary["in_flight"]:
            store.cancel(job_id, "owner")
        result = original_progress(job_id, token, summary)
        if boundary == "after_ack" and summary["completed_moves"]:
            store.cancel(job_id, "owner")
        if boundary == "before_finish" and summary["phase"] == "verified":
            store.cancel(job_id, "owner")
        return result

    def move(*args):
        original_move(*args)
        if boundary == "after_send":
            store.cancel(job["id"], "owner")

    monkeypatch.setattr(store, "progress", progress)
    monkeypatch.setattr(appliance, "move_managed_switch_after", move)
    result = run(operation)
    summary = result["summary"]
    if boundary == "before_intent":
        assert result["state"] == "cancelled"
        assert appliance.calls == ["read"]
        assert summary["attempted_moves"] == 0
    else:
        assert result["state"] == "unknown"
        if boundary == "after_send":
            assert summary["in_flight"] is not None
            assert summary["completed_moves"] == []
        elif boundary == "after_ack":
            assert summary["in_flight"] is None
            assert len(summary["completed_moves"]) == 1
    assert store.claim() is None


def test_response_loss_after_remote_change_is_unknown_without_replay(operation, monkeypatch):
    _, _, _, appliance, _ = operation
    original = appliance.move_managed_switch_after

    def lost_response(*args):
        original(*args)
        raise FortiGateError("lost fixture-secret response")

    monkeypatch.setattr(appliance, "move_managed_switch_after", lost_response)
    result = run(operation)
    assert result["state"] == "unknown"
    assert len(appliance.calls) == 2
    assert result["summary"]["completed_moves"] == []
    assert result["summary"]["in_flight"] is not None
    assert "fixture-secret" not in result["error"]


@pytest.mark.parametrize("change", ["profile", "actor", "expiry", "inventory", "invalid_order"])
def test_changed_review_rejects_before_mutation(operation, monkeypatch, change):
    store, job, config, appliance, _ = operation
    if change == "profile":
        ProfileStore(str(store.instance)).upsert({**config["profile"], "api_key": "replacement"})
    elif change == "actor":
        job["user_id"] = "other"
    elif change == "expiry":
        import time
        now = time.time()
        monkeypatch.setattr("time.time", lambda: now + PREVIEW_MAX_AGE_SECONDS + 2)
    elif change == "inventory":
        appliance.ids.reverse()
    else:
        config["desired_ids"] = ["c", "b", "a", "a"]
        signer = PreviewSigner(load_or_create_secret_key(str(store.instance)), store.instance, "owner")
        config["preview_token"] = signer.issue("switch-order-apply-v1", operations.review_context(config))
    result = run(operation)
    assert result["state"] == "failed"
    assert all(call == "read" for call in appliance.calls)


def test_profile_change_after_ack_stops_remaining_moves(operation, monkeypatch):
    store, _, config, appliance, _ = operation
    original = appliance.move_managed_switch_after

    def move(*args):
        original(*args)
        ProfileStore(str(store.instance)).upsert({**config["profile"], "api_key": "replacement"})

    monkeypatch.setattr(appliance, "move_managed_switch_after", move)
    result = run(operation)
    assert result["state"] == "unknown"
    assert len(result["summary"]["completed_moves"]) == 1
    assert len(appliance.calls) == 2


def test_token_loss_prevents_any_followup_mutation(operation, monkeypatch):
    store, job, _, appliance, _ = operation
    original = appliance.move_managed_switch_after

    def move(*args):
        original(*args)
        store.recover()

    monkeypatch.setattr(appliance, "move_managed_switch_after", move)
    result = run(operation)
    assert result["state"] == "unknown"
    assert result["summary"]["in_flight"] is not None
    assert len(appliance.calls) == 2
    assert not store.progress(job["id"], job["token"], {})
    assert store.claim() is None


@pytest.mark.parametrize("inventory", [
    [{"switch-id": "x" * 129}],
    [{"switch-id": str(i)} for i in range(501)],
])
def test_inventory_bounds_refuse_truncated_identifiers(inventory):
    with pytest.raises(ValueError, match="No truncated inventory"):
        operations.bounded_inventory(inventory)


@pytest.mark.parametrize("boundary", ["intent", "ack"])
def test_checkpoint_storage_failure_does_not_send_another_move(operation, monkeypatch, boundary):
    store, _, _, appliance, _ = operation
    original = store.progress

    def progress(job_id, token, summary):
        if boundary == "intent" and summary["in_flight"] or boundary == "ack" and summary["completed_moves"]:
            raise OSError("Injected disk failure")
        return original(job_id, token, summary)

    monkeypatch.setattr(store, "progress", progress)
    result = run(operation)
    assert result["state"] == ("failed" if boundary == "intent" else "unknown")
    assert len(appliance.calls) == (1 if boundary == "intent" else 2)
    assert result["summary"]["completed_moves"] == []
    assert bool(result["summary"]["in_flight"]) == (boundary == "ack")


@pytest.mark.parametrize("first,second", [
    ("https://FORTIGATE.example", "https://fortigate.example:443/path"),
    ("http://fortigate.example", "http://fortigate.example:80/"),
    ("https://[::1]", "https://[::1]:443"),
])
def test_origin_aliases_share_mutation_lock(first, second):
    assert operations.operation_target({"host": first}) == operations.operation_target({"host": second})
    assert operations.operation_target({"host": first}) != operations.operation_target({"host": "https://fortigate.example:8443"})


def test_cancel_while_waiting_for_target_does_not_contact_appliance(operation, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import hashlib
    from threading import Event
    from twn_toolkit.file_transactions import file_transaction

    store, job, config, appliance, _ = operation
    entered = Event()
    target = hashlib.sha256(operations.operation_target(config["profile"]).encode()).hexdigest()

    @contextmanager
    def waiting_transaction(path):
        entered.set()
        with file_transaction(path):
            yield

    monkeypatch.setattr(operations, "file_transaction", waiting_transaction)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with file_transaction(store.instance / "appliance-operation-locks" / target):
            future = pool.submit(run, operation)
            assert entered.wait(timeout=5)
            store.cancel(job["id"], "owner")
        result = future.result(timeout=10)
    assert result["state"] == "cancelled"
    assert appliance.calls == []


@pytest.mark.parametrize("state", ["succeeded", "failed", "cancelled", "unknown"])
def test_original_case_records_honest_mutation_outcome(operation, monkeypatch, state):
    from twn_toolkit.investigations import InvestigationStore
    from twn_toolkit.audit import AuditStore

    store, job, config, _, _ = operation
    cases = InvestigationStore(str(store.instance))
    case = cases.create(owner_user_id="owner", owner_username="reviewer", title="Original case")
    config["investigation_id"] = case["id"]
    audits = []
    monkeypatch.setattr(AuditStore, "record", lambda self, **values: audits.append(values))
    # Exercise the real recorder hidden by the appliance fixture.
    REAL_RECORD_OUTCOME(store, job, state, config=config)
    events = [event for event in cases.events_for_user(case["id"], "owner")
              if event["operation_id"] == "switch-order:" + job["id"]]
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == ("incomplete" if state == "unknown" else state)
    assert event["event_type"] == "external.action." + ("completed" if state == "succeeded" else state)
    assert audits[0]["user_id"] == "owner"
    assert audits[0]["username"] == "reviewer"
    assert audits[0]["details"]["outcome"] == state


def test_recording_failure_keeps_warning_with_retained_progress(operation, monkeypatch):
    from twn_toolkit.audit import AuditStore

    store, job, config, _, _ = operation
    result = run(operation)
    def failed_record(*args, **kwargs):
        raise OSError("Injected audit storage failure")
    monkeypatch.setattr(AuditStore, "record", failed_record)
    REAL_RECORD_OUTCOME(store, job, "succeeded", config=config)
    retained = store.get(job["id"], "owner")
    assert retained["state"] == "succeeded"
    assert retained["summary"]["completed_moves"] == result["summary"]["completed_moves"]
    assert "could not be fully confirmed" in retained["summary"]["recording_warning"]


def test_uncertain_predecessor_fences_old_reviews_even_after_history_pruning(operation, monkeypatch):
    from twn_toolkit.operational import OperationalSettingsStore

    store, job, config, appliance, _ = operation
    original_move = appliance.move_managed_switch_after
    def response_lost(*args):
        raise FortiGateError("No acknowledgement; appliance state is unknown")
    monkeypatch.setattr(appliance, "move_managed_switch_after", response_lost)
    assert run(operation)["state"] == "unknown"
    store.release(job["id"], job["token"])
    OperationalSettingsStore(str(store.instance)).save({"diagnostic_history_limit": 1})
    # The old inventory still matches. That alone cannot authorize a new attempt.
    old_id = store.enqueue(user_id="owner", tool="switch_order", config=config)
    old_job = store.claim()
    assert store.get(job["id"], "owner") is None
    appliance.calls.clear()
    operations.execute_switch_order(store, old_job, config)
    old_result = store.get(old_id, "owner")
    assert old_result["state"] == "failed"
    assert "Another operation attempted changes" in old_result["error"]
    assert appliance.calls == []
    store.release(old_id, old_job["token"])

    loaded_config = {**config, "mode": "load"}
    load_id = store.enqueue(user_id="owner", tool="switch_order", config=loaded_config)
    load_job = store.claim()
    operations.execute_switch_order(store, load_job, loaded_config)
    loaded = store.get(load_id, "owner")["summary"]
    assert loaded["target_revision"] == job["id"]
    signer = PreviewSigner(load_or_create_secret_key(str(store.instance)), store.instance, "owner")
    assert signer.valid(loaded["load_token"], "switch-order-load-v1", {
        "profile": config["profile"], "vdom": config["vdom"],
        "original_ids": config["original_ids"], "target_revision": job["id"]})
    store.release(load_id, load_job["token"])
    fresh_config = {**config, "target_revision": loaded["target_revision"]}
    fresh_config["preview_token"] = signer.issue("switch-order-apply-v1", operations.review_context(fresh_config))
    fresh_id = store.enqueue(user_id="owner", tool="switch_order", config=fresh_config)
    fresh_job = store.claim()
    appliance.job_id = fresh_id
    monkeypatch.setattr(appliance, "move_managed_switch_after", original_move)
    operations.execute_switch_order(store, fresh_job, fresh_config)
    assert store.get(fresh_id, "owner")["state"] == "succeeded"


def test_target_revision_cannot_be_substituted_in_review_token(operation):
    _, _, config, appliance, _ = operation
    config["target_revision"] = "forged"
    result = run(operation)
    assert result["state"] == "failed"
    assert appliance.calls == []


def test_ownership_loss_between_intent_and_origin_fence_prevents_send(operation, monkeypatch):
    store, _, _, appliance, _ = operation
    original = store.advance_mutation_revision
    def advance(*args):
        store.recover()
        return original(*args)
    monkeypatch.setattr(store, "advance_mutation_revision", advance)
    result = run(operation)
    assert result["state"] == "unknown"
    assert appliance.calls == ["read"]


@pytest.mark.parametrize('count', [3, 500])
def test_audit_retains_bounded_before_after_references(operation, count):
    from twn_toolkit.audit import AuditStore

    store, job, config, _, _ = operation
    rows = [{'id': str(i) + 'x' * 120, 'name': str(i) + 'n' * 250,
             'description': 'Do not copy this vendor field into the audit'} for i in range(count)]
    summary = {'original_switches': rows, 'switches': list(reversed(rows)),
               'completed_moves': [], 'attempted_moves': 0, 'phase': 'verified'}
    assert store.finish(job['id'], job['token'], [], summary)
    REAL_RECORD_OUTCOME(store, job, 'succeeded', config=config)
    details = AuditStore(str(store.instance)).recent(1)[0]['details']
    assert details['outcome'] == 'succeeded'
    assert details['changes']
    assert details['omitted switch references'] == max(0, count - 20)
    import json
    serialized = json.dumps(details)
    assert len(serialized.encode()) < 32768
    assert 'vendor field' not in serialized
