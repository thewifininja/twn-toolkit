from __future__ import annotations

import base64
import gc
import json
import threading
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
from flask import Flask, jsonify, request, session

from twn_toolkit import distributed_http as http
from twn_toolkit.distributed_dispatch_cache import DispatchCache, DispatchCacheBusy
from twn_toolkit.operational import OperationalSettingsStore


def policy(path, limit=2, idle=10):
    OperationalSettingsStore(str(path)).save({
        "distributed_http_client_limit": limit,
        "distributed_http_client_idle_seconds": idle,
    })


def inputs(owner, path="/probe"):
    return {"method": "GET", "path": path, "prefix": "/agents/agent/ui",
            "user": {"id": owner, "username": owner, "is_admin": owner == "admin"},
            "fabric": {"context_id": owner}}


def decoded(result):
    return json.loads(base64.b64decode(result["body"]))


def test_shared_app_keeps_owner_cookies_and_request_identity_separate(tmp_path, monkeypatch):
    cache = DispatchCache()
    monkeypatch.setattr(http, "_cache", cache)
    created = []
    overlap = threading.Barrier(2)
    def factory(instance):
        app = Flask(__name__)
        app.secret_key = "test-only-session-key"
        @app.get("/probe")
        def probe():
            session["count"] = session.get("count", 0) + 1
            return jsonify(count=session["count"], user=request.environ["twn.delegated_user"],
                           fabric=request.environ["twn.delegated_fabric"], prefix=request.environ["SCRIPT_NAME"])
        @app.get("/parallel")
        def parallel():
            owner = request.environ["twn.delegated_user"]["id"]
            session["marker"] = owner
            overlap.wait(timeout=10)
            return jsonify(owner=request.environ["twn.delegated_user"]["id"], marker=session["marker"])
        created.append(app)
        return app
    monkeypatch.setattr(http, "_create_dispatch_app", factory)
    assert decoded(http.dispatch_http_request(tmp_path, inputs("admin")))["count"] == 1
    other = decoded(http.dispatch_http_request(tmp_path, inputs("other")))
    assert other["count"] == 1
    assert other["user"] == {"id": "other", "username": "other", "is_admin": False}
    assert other["fabric"] == {"context_id": "other"}
    assert other["prefix"] == "/agents/agent/ui"
    assert decoded(http.dispatch_http_request(tmp_path, inputs("admin")))["count"] == 2
    assert len(created) == 1
    assert cache.stats() == {"instances": 1, "clients": 2, "borrowers": 0}
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(http.dispatch_http_request, tmp_path, inputs(owner, "/parallel")) for owner in ("admin", "other")]
        assert [decoded(result.result(timeout=10)) for result in results] == [
            {"owner": "admin", "marker": "admin"}, {"owner": "other", "marker": "other"},
        ]
    assert decoded(http.dispatch_http_request(tmp_path / "separate", inputs("admin")))["count"] == 1
    assert len(created) == 2


def test_actual_agent_application_is_initialized_once_for_multiple_users(tmp_path, monkeypatch):
    cache = DispatchCache()
    monkeypatch.setattr(http, "_cache", cache)
    from twn_toolkit import app as app_module
    original = app_module.create_app
    created = []
    def factory(instance):
        app = original(instance)
        created.append(app)
        return app
    monkeypatch.setattr(app_module, "create_app", factory)
    for owner in ("first", "second", "first"):
        assert http.dispatch_http_request(tmp_path, inputs(owner, "/health"))["status"] == 200
    assert len(created) == 1
    assert created[0].config["DISTRIBUTED_AGENT_DISPATCH"]
    from twn_toolkit.distributed_agents import DistributedSettingsStore
    DistributedSettingsStore(tmp_path).save({"role": "agent", "agent_mainframe_url": "https://mainframe.example:5051"})
    created[0].testing = True
    page = created[0].test_client().get("/settings?section=operations")
    assert page.status_code == 200
    assert b'name="distributed_http_client_limit"' in page.data
    assert b'name="distributed_http_client_idle_seconds"' in page.data
    assert cache.stats()["clients"] == 2


def test_lru_and_idle_expiry_release_clients_locks_and_application(tmp_path):
    now = [0.0]
    cache = DispatchCache(clock=lambda: now[0])
    policy(tmp_path)
    class App:
        pass
    refs = []
    with cache.borrow(tmp_path, "a", lambda _: App()) as (app, client):
        refs.append(weakref.ref(client))
        app_ref = weakref.ref(app)
    del app, client
    now[0] = 1
    with cache.borrow(tmp_path, "b", lambda _: App()):
        pass
    now[0] = 2
    with cache.borrow(tmp_path, "c", lambda _: App()):
        pass
    gc.collect()
    assert refs[0]() is None
    assert app_ref() is not None
    assert cache.stats()["clients"] == 2
    now[0] = 12
    cache.prune(tmp_path)
    gc.collect()
    assert app_ref() is None
    assert cache.stats() == {"instances": 0, "clients": 0, "borrowers": 0}


def test_active_and_waiting_requests_survive_expiry_and_capacity_pressure(tmp_path, monkeypatch):
    now = [0.0]
    pinned_waiter = threading.Event()
    entered = threading.Event()
    release = threading.Event()
    probes = []
    class ObservedCache(DispatchCache):
        @contextmanager
        def borrow(self, *args):
            with super().borrow(*args) as pair:
                if self.stats()["borrowers"] == 2:
                    pinned_waiter.set()
                yield pair
    cache = ObservedCache(clock=lambda: now[0])
    policy(tmp_path, limit=1)
    monkeypatch.setattr(http, "_cache", cache)
    app = Flask(__name__)
    @app.get("/slow")
    def slow():
        entered.set()
        assert release.wait(10)
        return "finished"
    @app.get("/probe")
    def probe():
        probes.append(True)
        return "probe"
    @app.get("/tools/remote-terminal/sessions/one/output")
    def output():
        return "terminal"
    monkeypatch.setattr(http, "_create_dispatch_app", lambda _: app)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(http.dispatch_http_request, tmp_path, inputs("owner", "/slow"))
        try:
            assert entered.wait(10)
            second = pool.submit(http.dispatch_http_request, tmp_path, inputs("owner"))
            assert pinned_waiter.wait(10)
            now[0] = 100
            cache.prune(tmp_path)
            assert cache.stats()["borrowers"] == 2
            refused = http.dispatch_http_request(tmp_path, inputs("other"))
            assert refused["status"] == 503
            assert ["Retry-After", "1"] in refused["headers"]
            terminal = http.dispatch_http_request(tmp_path, inputs("owner", "/tools/remote-terminal/sessions/one/output"))
            assert base64.b64decode(terminal["body"]) == b"terminal"
            assert probes == []
        finally:
            release.set()
        assert first.result(timeout=10)["status"] == 200
        assert second.result(timeout=10)["status"] == 200
    assert probes == [True]
    assert cache.stats()["clients"] == 1
    assert cache.stats()["borrowers"] == 0


def test_initialization_is_shared_without_blocking_another_instance(tmp_path):
    cache = DispatchCache()
    entered = threading.Event()
    release = threading.Event()
    calls = []
    first_path, other_path = tmp_path / "first", tmp_path / "other"
    def factory(key):
        calls.append(key)
        if key == str(first_path):
            entered.set()
            assert release.wait(10)
        return object()
    def borrow(path, owner):
        with cache.borrow(path, owner, factory) as (app, _):
            return app
    with ThreadPoolExecutor(max_workers=3) as pool:
        first = pool.submit(borrow, first_path, "a")
        try:
            assert entered.wait(10)
            second = pool.submit(borrow, first_path, "b")
            assert pool.submit(borrow, other_path, "a").result(timeout=10) is not None
        finally:
            release.set()
        assert first.result(timeout=10) is second.result(timeout=10)
    assert calls.count(str(first_path)) == 1
    assert cache.stats() == {"instances": 2, "clients": 3, "borrowers": 0}


def test_capacity_reduction_preserves_pins_then_trims_on_release(tmp_path):
    policy(tmp_path, limit=3)
    cache = DispatchCache()
    with cache.borrow(tmp_path, "a", lambda _: object()):
        with cache.borrow(tmp_path, "b", lambda _: object()):
            with cache.borrow(tmp_path, "c", lambda _: object()):
                policy(tmp_path, limit=1)
                cache.prune(tmp_path)
                assert cache.stats()["clients"] == 3
                with pytest.raises(DispatchCacheBusy):
                    with cache.borrow(tmp_path, "d", lambda _: object()):
                        pytest.fail("full cache admitted a new owner")
            assert cache.stats()["clients"] == 2
        assert cache.stats()["clients"] == 1


def test_process_instance_cap_evicts_only_inactive_apps(tmp_path, monkeypatch):
    from twn_toolkit import distributed_dispatch_cache as module
    monkeypatch.setattr(module, "MAX_CACHED_INSTANCES", 1)
    cache = DispatchCache()
    with cache.borrow(tmp_path / "a", "owner", lambda _: object()):
        with pytest.raises(DispatchCacheBusy):
            with cache.borrow(tmp_path / "b", "owner", lambda _: object()):
                pytest.fail("active app was evicted")
    with cache.borrow(tmp_path / "b", "owner", lambda _: object()):
        assert cache.stats()["instances"] == 1


def test_failed_initialization_releases_admission_and_can_retry(tmp_path):
    cache = DispatchCache()
    policy(tmp_path, limit=1)
    def fail(_):
        raise RuntimeError("fixture initialization failed")
    with pytest.raises(RuntimeError):
        with cache.borrow(tmp_path, "a", fail):
            pass
    assert cache.stats()["borrowers"] == 0
    with cache.borrow(tmp_path, "b", lambda _: object()):
        assert cache.stats()["clients"] == 1


@pytest.mark.parametrize("failure", ["none", "oversized", "read"])
def test_response_closes_and_cache_pin_releases_on_every_result(tmp_path, monkeypatch, failure):
    cache = DispatchCache()
    monkeypatch.setattr(http, "_cache", cache)
    closed = []
    class Response:
        status_code = 200
        headers = {}
        def iter_encoded(self):
            if failure == "read":
                raise OSError("fixture read failed")
            yield b"x" * (http.MAX_TUNNEL_BODY_BYTES + 1) if failure == "oversized" else b"ok"
        def close(self):
            closed.append(True)
    class Client:
        def open(self, *_args, **_kwargs):
            return Response()
    class App:
        def test_client(self):
            return Client()
    monkeypatch.setattr(http, "_create_dispatch_app", lambda _: App())
    if failure == "none":
        assert http.dispatch_http_request(tmp_path, inputs("a"))["status"] == 200
    else:
        with pytest.raises((ValueError, OSError)):
            http.dispatch_http_request(tmp_path, inputs("a"))
    assert closed == [True]
    assert cache.stats()["borrowers"] == 0


@pytest.mark.parametrize("value", [0, 257, True, 1.5, "1.5"])
def test_cache_capacity_rejects_invalid_policy(tmp_path, value):
    with pytest.raises(ValueError):
        OperationalSettingsStore(str(tmp_path)).save({"distributed_http_client_limit": value})


@pytest.mark.parametrize("value", [0, 86401, False, 1.5, "1.5"])
def test_cache_idle_rejects_invalid_policy(tmp_path, value):
    with pytest.raises(ValueError):
        OperationalSettingsStore(str(tmp_path)).save({"distributed_http_client_idle_seconds": value})
