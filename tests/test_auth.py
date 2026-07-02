from __future__ import annotations

import json

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore


def _setup(client, username="admin", password="correct horse battery staple"):
    return client.post(
        "/setup",
        data={
            "username": username,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=False,
    )


def test_first_launch_requires_setup_and_creates_no_default_user(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()

    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/setup")
    assert AuthStore(str(tmp_path)).users() == []

    response = _setup(client)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
    users = AuthStore(str(tmp_path)).users()
    assert len(users) == 1
    assert users[0]["username"] == "admin"
    assert users[0]["is_admin"] is True
    assert users[0]["password_hash"] != "correct horse battery staple"


def test_login_logout_and_safe_next_redirect(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)
    client.post("/logout")

    assert client.get("/").status_code == 302
    login_page = client.get("/login")
    assert b"./twn adminreset" in login_page.data
    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "correct horse battery staple",
            "next": "//example.com/phishing",
        },
    )
    assert response.headers["Location"] == "/"
    assert client.get("/").status_code == 200


def test_admin_can_manage_users_timeout_and_passwords(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)

    response = client.post(
        "/settings/users",
        data={
            "username": "operator",
            "password": "a different long password",
            "confirm_password": "a different long password",
        },
    )
    assert response.status_code == 302
    store = AuthStore(str(tmp_path))
    operator = store.get_user("operator")
    assert operator is not None
    assert operator["is_admin"] is False

    client.post(
        "/settings/session",
        data={
            "idle_timeout_minutes": "45",
            "min_password_length": "16",
            "require_uppercase": "on",
            "require_number": "on",
            "require_special": "on",
        },
    )
    assert store.idle_timeout_minutes() == 45
    assert store.min_password_length() == 16
    assert store.password_policy()["require_uppercase"] is True
    assert store.password_policy()["require_lowercase"] is False
    assert store.password_policy()["require_number"] is True
    assert store.password_policy()["require_special"] is True

    client.post(
        f"/settings/users/{operator['id']}/password",
        data={
            "password": "Replacement password 2!",
            "confirm_password": "Replacement password 2!",
        },
    )
    assert store.authenticate("operator", "Replacement password 2!") is not None

    client.post(f"/settings/users/{operator['id']}/delete")
    assert store.get_user("operator") is None


def test_deleting_auth_file_returns_to_setup_without_touching_profiles(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)
    profiles = tmp_path / "profiles.json"
    profiles.write_text(json.dumps([{"name": "saved"}]), encoding="utf-8")

    (tmp_path / "auth.json").unlink()
    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/setup")
    assert profiles.exists()
