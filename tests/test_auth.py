from __future__ import annotations

import io
import json
from unittest.mock import patch

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

    setup_page = client.get("/setup")
    assert b'app-layout without-sidebar' in setup_page.data
    assert b'app-layout with-sidebar' not in setup_page.data

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
    assert b'app-layout without-sidebar' in login_page.data
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


def test_theme_preference_is_saved_per_user(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)

    response = client.post("/settings/theme", json={"theme": "dark"})
    assert response.status_code == 200
    assert response.get_json() == {"theme": "dark"}
    assert AuthStore(str(tmp_path)).get_user("admin")["theme"] == "dark"
    page = client.get("/")
    assert b'data-theme="dark"' in page.data
    assert b'id="theme-toggle"' in page.data

    assert client.post("/settings/theme", json={"theme": "sepia"}).status_code == 400
    client.post("/logout")
    client.post(
        "/login",
        data={"username": "admin", "password": "correct horse battery staple"},
    )
    assert b'data-theme="dark"' in client.get("/").data


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


def test_zero_idle_timeout_never_expires_session(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)
    store = AuthStore(str(tmp_path))

    store.set_policy(idle_timeout_minutes=0, min_password_length=8)
    with client.session_transaction() as user_session:
        user_session["last_seen"] = 1

    response = client.get("/")

    assert response.status_code == 200
    assert store.idle_timeout_minutes() == 0
    settings_page = client.get("/settings")
    assert b"Idle minutes (0 = never expire)" in settings_page.data
    assert b'min="0"' in settings_page.data


def test_admin_can_create_custom_access_profile_and_assign_to_user(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)

    response = client.post(
        "/settings/access-profiles",
        data={
            "name": "Ping only",
            "description": "Can run multi-host ping",
            "tool_id": ["tools.ping", "admin.settings", "not-a-real-tool"],
        },
    )
    assert response.status_code == 302
    store = AuthStore(str(tmp_path))
    profiles = store.access_profiles()
    assert len(profiles) == 1
    assert profiles[0]["name"] == "Ping only"
    assert profiles[0]["tool_ids"] == ["tools.ping"]

    client.post(
        "/settings/users",
        data={
            "username": "operator",
            "password": "a different long password",
            "confirm_password": "a different long password",
            "access_profile_id": profiles[0]["id"],
        },
    )
    operator = store.get_user("operator")
    assert operator is not None
    assert operator["is_admin"] is False
    assert operator["access_profile_ids"] == [profiles[0]["id"]]

    client.post("/logout")
    client.post(
        "/login",
        data={"username": "operator", "password": "a different long password"},
    )

    assert client.get("/tools/ping").status_code == 200
    assert client.get("/tools/dns-response").status_code == 403
    home = client.get("/")
    assert b"Multi-Host Ping" in home.data
    assert b"DNS Lookup Tester" not in home.data


def test_access_profile_can_grant_high_risk_tool_without_admin_status(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)
    store = AuthStore(str(tmp_path))
    profile = store.save_access_profile(name="Packet replay", tool_ids=["tools.packet_replay"])
    store.create_user(
        "packetuser",
        "a different long password",
        access_profile_ids=[profile["id"]],
    )

    client.post("/logout")
    client.post(
        "/login",
        data={"username": "packetuser", "password": "a different long password"},
    )

    assert client.get("/tools/packet-replay").status_code == 200
    assert client.get("/settings/backup").status_code == 403


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


def test_admin_can_save_server_access_and_trigger_restart(tmp_path):
    app = create_app(str(tmp_path))
    app.config["TESTING"] = True
    client = app.test_client()

    with patch("twn_toolkit.admin_routes.subprocess.Popen") as popen:
        response = client.post(
            "/settings/server",
            data={
                "listen_host": "0.0.0.0",
                "allowed_networks": "192.0.2.0/24",
            },
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )

    assert response.status_code == 200
    assert b"Restarting the toolkit" in response.data
    popen.assert_called_once()
    settings = json.loads((tmp_path / "server_settings.json").read_text())
    assert settings["listen_host"] == "0.0.0.0"
    assert settings["allowed_networks"] == ["192.0.2.0/24"]


def test_admin_can_export_and_import_selected_profile_backups(tmp_path):
    app = create_app(str(tmp_path))
    app.config["TESTING"] = True
    client = app.test_client()

    profiles = tmp_path / "profiles.json"
    ping_profiles = tmp_path / "ping_profiles.json"
    profiles.write_text(
        json.dumps(
            [
                {
                    "name": "Lab",
                    "host": "https://192.0.2.1",
                    "api_key": "secret-token",
                    "verify_tls": True,
                    "is_default": True,
                    "default_vdom": "root",
                }
            ]
        ),
        encoding="utf-8",
    )
    ping_profiles.write_text(json.dumps([{"name": "WAN", "targets": "1.1.1.1"}]), encoding="utf-8")

    page = client.get("/settings/backup")
    assert page.status_code == 200
    assert b"FortiGate profiles" in page.data
    assert b"Includes stored secrets/API keys." in page.data

    export = client.post(
        "/settings/backup/export",
        data={
            "item": ["fortigate_profiles", "ping_profiles"],
            "backup_password": "backup password",
            "confirm_backup_password": "backup password",
        },
    )
    assert export.status_code == 200
    backup = json.loads(export.data)
    assert backup["format"] == "twn-toolkit-encrypted-profile-backup"
    assert b"secret-token" not in export.data

    profiles.write_text(json.dumps([]), encoding="utf-8")
    ping_profiles.write_text(json.dumps([]), encoding="utf-8")

    imported = client.post(
        "/settings/backup/import",
        data={
            "backup_file": (io.BytesIO(export.data), "backup.json"),
            "item": ["fortigate_profiles"],
            "backup_password": "backup password",
            "import_mode": "replace",
        },
        content_type="multipart/form-data",
    )
    assert imported.status_code == 302
    assert json.loads(profiles.read_text(encoding="utf-8"))[0]["name"] == "Lab"
    assert json.loads(ping_profiles.read_text(encoding="utf-8")) == []


def test_sensitive_backup_requires_password_and_plain_backup_can_merge(tmp_path):
    app = create_app(str(tmp_path))
    app.config["TESTING"] = True
    client = app.test_client()

    profiles = tmp_path / "profiles.json"
    ping_profiles = tmp_path / "ping_profiles.json"
    profiles.write_text(
        json.dumps(
            [
                {
                    "name": "Lab",
                    "host": "https://192.0.2.1",
                    "api_key": "secret-token",
                    "verify_tls": True,
                    "is_default": True,
                    "default_vdom": "root",
                }
            ]
        ),
        encoding="utf-8",
    )
    ping_profiles.write_text(json.dumps([{"name": "WAN", "targets": "1.1.1.1"}]), encoding="utf-8")

    blocked = client.post(
        "/settings/backup/export",
        data={"item": ["fortigate_profiles"]},
        follow_redirects=True,
    )
    assert b"Enter an encryption password for this backup." in blocked.data

    export = client.post(
        "/settings/backup/export",
        data={"item": ["ping_profiles"]},
    )
    backup = json.loads(export.data)
    assert backup["format"] == "twn-toolkit-profile-backup"
    assert backup["items"]["ping_profiles"][0]["name"] == "WAN"

    ping_profiles.write_text(
        json.dumps(
            [
                {"name": "LAN", "targets": "192.0.2.10"},
                {"name": "WAN", "targets": "8.8.8.8"},
            ]
        ),
        encoding="utf-8",
    )
    imported = client.post(
        "/settings/backup/import",
        data={
            "backup_file": (io.BytesIO(export.data), "backup.json"),
            "item": ["ping_profiles"],
            "import_mode": "merge",
        },
        content_type="multipart/form-data",
    )
    assert imported.status_code == 302
    restored = {
        profile["name"]: profile["targets"]
        for profile in json.loads(ping_profiles.read_text(encoding="utf-8"))
    }
    assert restored == {"LAN": "192.0.2.10", "WAN": "1.1.1.1"}
