from unittest.mock import patch

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore


@pytest.fixture
def signed_in(tmp_path):
    app = create_app(str(tmp_path))
    store = AuthStore(str(tmp_path))
    store.create_user("reviewer", "TemporaryReviewPassword123!", is_admin=True)
    store.set_idle_timeout_minutes(1)
    client = app.test_client()
    with patch("twn_toolkit.app.time.time", return_value=1000):
        client.post("/login", data={"username": "reviewer", "password": "TemporaryReviewPassword123!"})
    with patch("twn_toolkit.app.time.time", return_value=1000):
        yield app, client, store
    app.extensions["remote_session_manager"].close()


def test_background_polling_cannot_extend_idle_session(signed_in):
    app, client, _ = signed_in
    for now in (1020, 1040, 1059):
        with patch("twn_toolkit.app.time.time", return_value=now):
            assert client.get("/tools/live-sessions", headers={"Accept": "application/json"}).status_code == 200
    with patch("twn_toolkit.app.time.time", return_value=1061):
        assert client.get("/").status_code == 302


def test_activity_refreshes_only_before_expiry(signed_in):
    _, client, _ = signed_in
    with patch("twn_toolkit.app.time.time", return_value=1050):
        response = client.post("/session/activity", headers={"X-TWN-User-Activity": "1"})
        assert response.status_code == 200
        assert response.json["remaining_seconds"] == 60
    with patch("twn_toolkit.app.time.time", return_value=1100):
        assert client.get("/session/activity").json["remaining_seconds"] == 10
    with patch("twn_toolkit.app.time.time", return_value=1111):
        assert client.post("/session/activity", headers={"X-TWN-User-Activity": "1"}).status_code == 401
        assert client.get("/").status_code == 302


@pytest.mark.parametrize("headers", [{}, {"Origin": "https://other.example", "X-TWN-User-Activity": "1"}])
def test_activity_requires_explicit_same_origin_signal(signed_in, headers):
    _, client, _ = signed_in
    with patch("twn_toolkit.app.time.time", return_value=1050):
        assert client.post("/session/activity", headers=headers).status_code == 403
    with patch("twn_toolkit.app.time.time", return_value=1050), client.session_transaction() as state:
        assert state["last_seen"] == 1000


@pytest.mark.parametrize("headers, expected", [
    ({"Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1"}, 1050),
    ({"Sec-Fetch-Mode": "navigate"}, 1000),
    ({"Accept": "text/html"}, 1000),
])
def test_only_user_initiated_navigation_refreshes_activity(signed_in, headers, expected):
    _, client, _ = signed_in
    with patch("twn_toolkit.app.time.time", return_value=1050):
        assert client.get("/", headers=headers).status_code == 200
    with patch("twn_toolkit.app.time.time", return_value=1050), client.session_transaction() as state:
        assert state["last_seen"] == expected


def test_disabled_idle_timeout_and_logout(signed_in):
    _, client, store = signed_in
    store.set_idle_timeout_minutes(0)
    with patch("twn_toolkit.app.time.time", return_value=9999):
        assert client.get("/session/activity").json["remaining_seconds"] is None
        client.post("/logout")
        assert client.get("/session/activity").status_code == 401


def test_probe_does_not_set_cookie_or_refresh_activity(signed_in):
    _, client, _ = signed_in
    with patch("twn_toolkit.app.time.time", return_value=1045):
        response = client.get("/session/activity")
        assert response.json["remaining_seconds"] == 15
        assert response.headers["Cache-Control"] == "no-store"
        assert "Set-Cookie" not in response.headers


def test_password_revocation_cannot_be_refreshed(signed_in):
    _, client, store = signed_in
    user = store.users()[0]
    store.update_password(user["id"], "ReplacementPassword123!")
    with patch("twn_toolkit.app.time.time", return_value=1045):
        assert client.post("/session/activity", headers={"X-TWN-User-Activity": "1"}).status_code == 401


def test_multiple_tabs_share_activity_without_probe_renewal(signed_in):
    app, active, _ = signed_in
    passive = app.test_client()
    with patch("twn_toolkit.app.time.time", return_value=1050):
        active.post("/session/activity", headers={"X-TWN-User-Activity": "1"})
    # Browser tabs share the cookie jar; copy the renewed cookie to simulate it.
    passive.set_cookie(app.config["SESSION_COOKIE_NAME"], active.get_cookie(app.config["SESSION_COOKIE_NAME"]).value)
    with patch("twn_toolkit.app.time.time", return_value=1090):
        assert passive.get("/session/activity").json["remaining_seconds"] == 20
    with patch("twn_toolkit.app.time.time", return_value=1111):
        assert passive.get("/session/activity").status_code == 401


def test_delegated_page_activity_targets_login_host(tmp_path):
    app = create_app(str(tmp_path))
    app.config["DISTRIBUTED_AGENT_DISPATCH"] = True
    try:
        response = app.test_client().get("/", environ_overrides={
            "SCRIPT_NAME": "/agents/agent-1/ui",
            "twn.delegated_user": {"id": "coordinator-user", "username": "reviewer", "is_admin": True},
            "twn.delegated_fabric": {"session_activity_url": "/coordinator/session/activity", "session_login_url": "/coordinator/login"},
        })
        assert response.status_code == 200
        assert b'data-activity-url="/coordinator/session/activity"' in response.data
        assert b'href="/coordinator/login" target="_blank"' in response.data
    finally:
        app.extensions["remote_session_manager"].close()


def test_activity_refresh_does_not_flood_security_audit(signed_in):
    app, client, _ = signed_in
    from twn_toolkit.audit import AuditStore
    audit = AuditStore(app.instance_path)
    before = audit.recent(100)
    with patch("twn_toolkit.app.time.time", return_value=1040):
        for _ in range(3):
            assert client.post("/session/activity", headers={"X-TWN-User-Activity": "1"}).status_code == 200
    assert audit.recent(100) == before
