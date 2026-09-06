from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ProcessPoolExecutor
from contextlib import ExitStack
from multiprocessing import get_context
from unittest.mock import patch

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.login_throttle import LoginThrottle, LoginThrottled


def reserve_in_process(args):
    path, number = args
    limiter = LoginThrottle(path, "test-secret")
    try:
        limiter._reserve(f"192.0.2.{number + 1}", "SameUser")
        return True
    except LoginThrottled:
        return False


def attempt_in_process(path):
    limiter = LoginThrottle(path, "test-secret")
    try:
        with limiter.attempt("198.51.100.1", "another-user"):
            return True
    except LoginThrottled:
        return False


def test_username_limit_is_shared_across_sources_and_rejections_do_not_extend_it(tmp_path):
    limiter = LoginThrottle(tmp_path, "test-secret")
    with patch("twn_toolkit.login_throttle.USERNAME_ATTEMPTS", 2), patch(
        "twn_toolkit.login_throttle.time.time", return_value=100
    ):
        limiter._reserve("192.0.2.1", "Alice")
        limiter._reserve("192.0.2.2", "ALICE")
        with pytest.raises(LoginThrottled) as first:
            limiter._reserve("192.0.2.3", "alice")
        assert first.value.retry_after == 60
        assert first.value.audit
    with patch("twn_toolkit.login_throttle.USERNAME_ATTEMPTS", 2), patch(
        "twn_toolkit.login_throttle.time.time", return_value=110
    ), pytest.raises(LoginThrottled) as later:
        limiter._reserve("192.0.2.4", "alice")
    assert later.value.retry_after == 50
    assert not later.value.audit
    with patch("twn_toolkit.login_throttle.time.time", return_value=160):
        limiter._reserve("192.0.2.5", "alice")


def test_source_and_instance_limits_cover_rotating_usernames_and_addresses(tmp_path):
    limiter = LoginThrottle(tmp_path, "test-secret")
    with patch("twn_toolkit.login_throttle.SOURCE_ATTEMPTS", 2):
        for name in ("one", "two"):
            limiter._reserve("192.0.2.1", name)
        with pytest.raises(LoginThrottled):
            limiter._reserve("::ffff:192.0.2.1", "three")
    limiter.reset()
    with patch("twn_toolkit.login_throttle.INSTANCE_ATTEMPTS", 3):
        for i in range(3):
            limiter._reserve(f"192.0.2.{i + 1}", str(i))
        with pytest.raises(LoginThrottled):
            limiter._reserve("198.51.100.1", "different")


def test_ipv6_source_limit_groups_addresses_in_same_prefix(tmp_path):
    limiter = LoginThrottle(tmp_path, "test-secret")
    with patch("twn_toolkit.login_throttle.SOURCE_ATTEMPTS", 1):
        limiter._reserve("2001:db8::1", "one")
        with pytest.raises(LoginThrottled):
            limiter._reserve("2001:db8::2", "two")
        limiter._reserve("2001:db8:1::1", "three")


def test_bucket_capacity_does_not_evict_active_limits_and_expired_rows_are_reclaimed(tmp_path):
    limiter = LoginThrottle(tmp_path, "test-secret")
    with patch("twn_toolkit.login_throttle.MAX_BUCKETS", 3), patch(
        "twn_toolkit.login_throttle.time.time", return_value=100
    ):
        limiter._reserve("192.0.2.1", "alice")
        with pytest.raises(LoginThrottled):
            limiter._reserve("192.0.2.2", "bob")
        assert limiter.status()["active_buckets"] == 3
    with patch("twn_toolkit.login_throttle.MAX_BUCKETS", 3), patch(
        "twn_toolkit.login_throttle.time.time", return_value=161
    ):
        limiter._reserve("192.0.2.2", "bob")
        assert limiter.status()["active_buckets"] == 3


def test_shared_database_prevents_parallel_workers_exceeding_username_limit(tmp_path):
    LoginThrottle(tmp_path, "test-secret")
    with ProcessPoolExecutor(max_workers=4, mp_context=get_context("spawn")) as pool:
        admitted = list(pool.map(reserve_in_process, [(str(tmp_path), i) for i in range(24)]))
    assert sum(admitted) == 10


def test_password_slots_are_shared_across_processes_and_released_after_errors(tmp_path):
    limiter = LoginThrottle(tmp_path, "test-secret")
    with ProcessPoolExecutor(max_workers=1, mp_context=get_context("spawn")) as pool:
        with ExitStack() as stack:
            for i in range(4):
                stack.enter_context(limiter.attempt("192.0.2.1", str(i)))
            assert not pool.submit(attempt_in_process, str(tmp_path)).result(timeout=15)
        assert pool.submit(attempt_in_process, str(tmp_path)).result(timeout=15)
    with pytest.raises(RuntimeError):
        with limiter.attempt("192.0.2.1", "error"):
            raise RuntimeError("verifier failed")
    with ExitStack() as stack:
        for i in range(4):
            stack.enter_context(limiter.attempt("198.51.100.2", str(i)))


def test_state_omits_usernames_and_addresses_and_is_owner_only(tmp_path):
    limiter = LoginThrottle(tmp_path, "test-secret")
    limiter._reserve("192.0.2.123", "alice@example.test")
    with sqlite3.connect(limiter.path) as db:
        data = str(db.execute("SELECT * FROM buckets").fetchall())
    assert "alice" not in data and "192.0.2.123" not in data
    assert os.stat(limiter.path).st_mode & 0o777 == 0o600


def test_clock_rollback_does_not_create_an_indefinite_lockout(tmp_path):
    limiter = LoginThrottle(tmp_path, "test-secret")
    with patch("twn_toolkit.login_throttle.USERNAME_ATTEMPTS", 1):
        with patch("twn_toolkit.login_throttle.time.time", return_value=1000):
            limiter._reserve("192.0.2.1", "alice")
        with patch("twn_toolkit.login_throttle.time.time", return_value=900):
            limiter._reserve("192.0.2.1", "alice")


def configured_app(tmp_path):
    app = create_app(str(tmp_path))
    AuthStore(str(tmp_path)).create_initial_admin("admin", "correct horse battery staple")
    return app


def test_route_denies_before_password_check_ignores_forwarded_headers_and_bounds_audit(tmp_path):
    app = configured_app(tmp_path)
    client = app.test_client()
    with patch("twn_toolkit.login_throttle.SOURCE_ATTEMPTS", 2), patch(
        "twn_toolkit.app.AuthStore.authenticate", return_value=None
    ) as authenticate:
        for i in range(2):
            assert client.post("/login", data={"username": f"user{i}", "password": "secret"}).status_code == 200
        for i in range(4):
            response = client.post("/login", data={"username": f"other{i}", "password": "secret"},
                                   headers={"X-Forwarded-For": f"198.51.100.{i + 1}"})
            assert response.status_code == 429
            assert 1 <= int(response.headers["Retry-After"]) <= 60
            assert b"Try again" in response.data
        assert authenticate.call_count == 2
    events = AuditStore(str(tmp_path)).recent(20)
    assert sum(event["action"] == "authentication.login_throttled" for event in events) == 1
    assert b"secret" not in (tmp_path / "login_throttle.sqlite3").read_bytes()


def test_cli_reset_keeps_accounts_and_restores_admission(tmp_path):
    app = configured_app(tmp_path)
    client = app.test_client()
    with patch("twn_toolkit.login_throttle.USERNAME_ATTEMPTS", 1):
        assert client.post("/login", data={"username": "admin", "password": "wrong"}).status_code == 200
        assert client.post("/login", data={"username": "admin", "password": "correct horse battery staple"}).status_code == 429
        result = app.test_cli_runner().invoke(args=["login-throttle", "--reset"])
        assert result.exit_code == 0
        assert len(AuthStore(str(tmp_path)).users()) == 1
        assert client.post("/login", data={"username": "admin", "password": "correct horse battery staple"}).status_code == 302
    status = app.test_cli_runner().invoke(args=["login-throttle"])
    assert status.exit_code == 0 and "Rate-limited requests since reset: 0" in status.output


def test_storage_failure_fails_closed_and_oversized_body_never_checks_password(tmp_path):
    app = configured_app(tmp_path)
    client = app.test_client()
    with patch("twn_toolkit.app.AuthStore.authenticate") as authenticate, patch(
        "twn_toolkit.login_throttle.LoginThrottle._reserve", side_effect=sqlite3.OperationalError("busy")
    ):
        assert client.post("/login", data={"username": "admin", "password": "secret"}).status_code == 503
        authenticate.assert_not_called()
    with patch("twn_toolkit.app.AuthStore.authenticate") as authenticate:
        assert client.post("/login", data={"username": "admin", "password": "x" * 20000}).status_code == 413
        authenticate.assert_not_called()


def test_invalid_and_disabled_accounts_use_dummy_verification_and_bound_inputs(tmp_path):
    store = AuthStore(str(tmp_path))
    user = store.create_initial_admin("admin", "correct horse battery staple")
    with patch("twn_toolkit.auth._dummy_password_hash", return_value="dummy"), patch(
        "twn_toolkit.auth.check_password_hash", return_value=False
    ) as verify:
        assert store.authenticate("missing", "secret") is None
        verify.assert_called_once_with("dummy", "secret")
        verify.reset_mock()
        with patch.object(store, "get_user", return_value={**user, "enabled": False}):
            assert store.authenticate("admin", "secret") is None
        verify.assert_called_once_with("dummy", "secret")
        verify.reset_mock()
        assert store.authenticate("admin", "x" * 1025) is None
        assert store.authenticate("x" * 65, "secret") is None
        verify.assert_not_called()
