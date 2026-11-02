"""Metadata-only API admission; no sender, HTTP server, worker or replay."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import multiprocessing
import sqlite3
from unittest.mock import patch

import pytest

from twn_toolkit import api_request_receipts as receipts
from twn_toolkit.api_request_receipts import ApiRequestReceiptStore, ReceiptCapacityError


@pytest.fixture(autouse=True)
def no_execution():
    with ExitStack() as stack:
        mocks = [stack.enter_context(patch(target, side_effect=AssertionError("No execution in receipt tests: " + target))) for target in (
            "twn_toolkit.api_request_routes.send_api_request", "twn_toolkit.diagnostic_tools.send_api_request",
            "subprocess.Popen", "requests.request", "socket.create_connection", "socket.getaddrinfo",
        )]
        yield
        for mock in mocks:
            mock.assert_not_called()


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(receipts.time, "time", lambda: now[0])
    return now


def test_one_claim_cross_instances_and_threads(tmp_path):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("owner")
    assert len(token) == 64
    with ThreadPoolExecutor(max_workers=8) as pool:
        claimed = list(pool.map(lambda _: ApiRequestReceiptStore(tmp_path).claim("owner", token), range(16)))
    assert sum(claimed) == 1
    assert ApiRequestReceiptStore(tmp_path).get("owner", token)["state"] == "admitted"
    assert not store.claim("owner", token)


def _claim_in_process(path, token, output):
    # Only the metadata store is used in this independent interpreter.
    with patch("socket.create_connection", side_effect=AssertionError("No connections")), patch("socket.getaddrinfo", side_effect=AssertionError("No resolution")):
        output.put(ApiRequestReceiptStore(path).claim("owner", token))


def test_one_claim_across_processes(tmp_path):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("owner")
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [context.Process(target=_claim_in_process, args=(str(tmp_path), token, output)) for _ in range(3)]
    try:
        for process in processes:
            process.start()
        outcomes = [output.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            assert process.exitcode == 0
        assert sum(outcomes) == 1
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        output.close()
        output.join_thread()


def test_owner_scope_and_missing_tokens_never_create_rows(tmp_path, clock):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("owner")
    assert store.get("other", token) is None
    assert not store.claim("other", token)
    store.finish("other", token, confirmed=True, status=200)
    assert store.get("owner", token)["state"] == "issued"
    for invalid in (None, "", "x", "a" * 64, "g" * 64, "A" * 64, "a" * 64 + "\n"):
        assert not store.claim("owner", invalid)
        assert store.get("owner", invalid) is None
        store.finish("owner", invalid, confirmed=False)
    assert store.claim("owner", token)
    assert "owner_id" not in store.get("owner", token)


def test_expiry_and_pruning_never_readmit(tmp_path, clock):
    store = ApiRequestReceiptStore(tmp_path)
    expired = store.issue("owner")
    clock[0] += receipts.ISSUE_TTL
    assert not store.claim("owner", expired)
    assert store.get("owner", expired) is None
    terminal = store.issue("owner")
    assert store.claim("owner", terminal)
    store.finish("owner", terminal, confirmed=False)
    clock[0] += receipts.TERMINAL_RETENTION
    assert store.get("owner", terminal) is None
    assert not ApiRequestReceiptStore(tmp_path).claim("owner", terminal)
    assert not store.claim("owner", expired)
    fresh = store.issue("owner")
    assert fresh not in (expired, terminal)
    assert store.claim("owner", fresh)


def test_restart_stale_admission_is_unknown_not_requeued_and_cannot_finish_late(tmp_path, clock):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("owner")
    assert store.claim("owner", token)
    admitted = store.get("owner", token)["admitted"]
    clock[0] += receipts.STALE_AFTER - 0.01
    assert ApiRequestReceiptStore(tmp_path).get("owner", token)["state"] == "admitted"
    clock[0] += 0.01
    restarted = ApiRequestReceiptStore(tmp_path)
    result = restarted.get("owner", token)
    assert result["state"] == "unconfirmed"
    assert result["completed"] == admitted + receipts.STALE_AFTER
    restarted.finish("owner", token, confirmed=True, status=200, elapsed_ms=1, bytes=0, truncated=False)
    assert restarted.get("owner", token) == result
    assert not restarted.claim("owner", token)


def test_finish_only_admitted_and_first_completion_wins(tmp_path, clock):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("owner")
    store.finish("owner", token, confirmed=True, status=200)
    assert store.get("owner", token)["state"] == "issued"
    assert store.claim("owner", token)
    clock[0] += 2
    store.finish("owner", token, confirmed=True, status=503, elapsed_ms=2000.5, bytes=1024, truncated=False)
    result = store.get("owner", token)
    assert result["state"] == "confirmed" and result["status"] == 503
    assert result["truncated"] is False
    assert result["issued"] < result["completed"] and result["admitted"] == result["issued"]
    store.finish("owner", token, confirmed=False)
    assert store.get("owner", token) == result


def test_stale_finish_without_prior_get_cannot_upgrade(tmp_path, clock):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("owner")
    assert store.claim("owner", token)
    clock[0] += receipts.STALE_AFTER
    store.finish("owner", token, confirmed=True, status=200)
    assert store.get("owner", token)["state"] == "unconfirmed"


def test_capacity_is_bounded_and_expired_capacity_releases(tmp_path, clock, monkeypatch):
    monkeypatch.setattr(receipts, "OWNER_ISSUED_LIMIT", 2)
    monkeypatch.setattr(receipts, "GLOBAL_LIMIT", 3)
    store = ApiRequestReceiptStore(tmp_path)
    first = store.issue("owner")
    store.issue("owner")
    with pytest.raises(ReceiptCapacityError):
        store.issue("owner")
    store.issue("other")
    with pytest.raises(ReceiptCapacityError):
        store.issue("third")
    assert store.claim("owner", first)
    clock[0] += receipts.ISSUE_TTL
    assert store.issue("owner")
    assert not store.claim("owner", first)
    assert store.get("owner", first)["state"] == "unconfirmed"


@pytest.mark.parametrize("field,value", [
    ("confirmed", "yes"), ("status", "200"), ("status", True), ("status", 99), ("status", 600),
    ("elapsed_ms", "secret"), ("elapsed_ms", float("nan")), ("elapsed_ms", float("inf")), ("elapsed_ms", -1), ("elapsed_ms", 10 ** 1000),
    ("bytes", "body"), ("bytes", True), ("bytes", -1), ("bytes", 1024 * 1024 + 1), ("truncated", "secret"),
])
def test_metadata_types_reject_arbitrary_values_without_changing_admission(tmp_path, field, value):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("owner")
    assert store.claim("owner", token)
    with pytest.raises(ValueError):
        store.finish("owner", token, **{"confirmed": False, field: value})
    assert store.get("owner", token)["state"] == "admitted"


def test_schema_cannot_store_content_and_public_metadata_is_explicit(tmp_path):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("owner")
    assert store.claim("owner", token)
    with pytest.raises(TypeError):
        store.finish("owner", token, confirmed=True, body="SyntheticSecretBody")
    store.finish("owner", token, confirmed=True, status=200, elapsed_ms=1, bytes=20, truncated=True)
    public = store.get("owner", token)
    assert set(public) == {"token", "state", "issued", "expires", "admitted", "completed", "status", "elapsed_ms", "bytes", "truncated"}
    with sqlite3.connect(store.path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(api_request_receipts)")}
        assert columns == set(public) | {"owner_id"}
        assert "SyntheticSecretBody" not in str(db.execute("SELECT * FROM api_request_receipts").fetchall())
    for path in tmp_path.glob("api_request_receipts.sqlite3*"):
        assert b"SyntheticSecretBody" not in path.read_bytes()


@pytest.mark.parametrize("owner", [None, "", 1, True, [], {}])
def test_invalid_owner_cannot_issue_or_access(tmp_path, owner):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("1")
    with pytest.raises(ValueError):
        store.issue(owner)
    assert not store.claim(owner, token)
    assert store.get(owner, token) is None
    store.finish(owner, token, confirmed=True, status=200)
    assert store.get("1", token)["state"] == "issued"


def test_deleted_token_is_not_recreated(tmp_path):
    store = ApiRequestReceiptStore(tmp_path)
    token = store.issue("owner")
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM api_request_receipts WHERE token=?", (token,))
    assert not store.claim("owner", token)
    store.finish("owner", token, confirmed=True, status=200)
    assert store.get("owner", token) is None
