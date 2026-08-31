from __future__ import annotations

import io
import json
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.audit import AuditStore
from twn_toolkit.auth import AuthStore
from twn_toolkit.tls_tools import certificate_status, generate_self_signed_certificate


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
    event = AuditStore(str(tmp_path)).recent(1)[0]
    assert event["action"] == "authentication.setup_succeeded"
    assert event["resource_name"] == "admin"
    assert b"correct horse battery staple" not in (tmp_path / "audit.sqlite3").read_bytes()


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
    events = AuditStore(str(tmp_path)).recent(3)
    assert [event["action"] for event in events] == [
        "authentication.login_succeeded",
        "authentication.logout_succeeded",
        "authentication.setup_succeeded",
    ]
    assert b"correct horse battery staple" not in (tmp_path / "audit.sqlite3").read_bytes()

    client.post("/logout")
    failed = client.post(
        "/login",
        data={"username": "admin", "password": "definitely wrong"},
    )
    assert failed.status_code == 200
    failed_event = AuditStore(str(tmp_path)).recent(1)[0]
    assert failed_event["action"] == "authentication.login_failed"
    assert failed_event["details"]["outcome"] == "failed"
    assert b"definitely wrong" not in (tmp_path / "audit.sqlite3").read_bytes()


def test_appearance_preference_is_saved_per_user(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)

    response = client.post(
        "/settings/appearance",
        json={
            "palette": "flexoki-light",
            "density": "comfortable",
            "layout": "focus",
            "text_scale": "110",
        },
    )
    assert response.status_code == 200
    appearance = {
        "palette": "flexoki-light",
        "density": "comfortable",
        "layout": "focus",
        "text_scale": "110",
        "sidebar_width": "274",
    }
    assert response.get_json() == {"appearance": appearance}
    user = AuthStore(str(tmp_path)).get_user("admin")
    assert user["appearance"] == appearance
    assert user["theme"] == "light"
    page = client.get("/")
    assert b'data-theme="light"' in page.data
    assert b'data-palette="flexoki-light"' in page.data
    assert b'data-density="comfortable"' in page.data
    assert b'data-layout="focus"' in page.data
    assert b'data-text-scale="110"' in page.data
    assert b'id="appearance-menu"' in page.data
    assert b'aria-label="Appearance settings"' in page.data
    assert b"appearance.css" in page.data
    appearance_css = client.get("/static/appearance.css")
    assert appearance_css.status_code == 200
    assert b"--ui-radius: 0;" in appearance_css.data
    assert b".automation-workspace *::after" in appearance_css.data

    for invalid in (
        {"palette": "sepia"},
        {"density": "spacious"},
        {"layout": "floating"},
        {"text_scale": "200"},
        {"sidebar_width": "219"},
        {"sidebar_width": "401"},
        {"sidebar_width": "wide"},
    ):
        assert client.post("/settings/appearance", json=invalid).status_code == 400
    assert client.post("/settings/appearance", json=["tokyo-night"]).status_code == 400
    client.post("/logout")
    client.post(
        "/login",
        data={"username": "admin", "password": "correct horse battery staple"},
    )
    page = client.get("/")
    assert b'data-palette="flexoki-light"' in page.data
    assert b'data-layout="focus"' in page.data
    assert b'data-sidebar-width="274"' in page.data

    resized = client.post("/settings/appearance", json={"sidebar_width": "336"})
    assert resized.status_code == 200
    assert resized.get_json()["appearance"]["sidebar_width"] == "336"
    assert AuthStore(str(tmp_path)).get_user("admin")["appearance"]["sidebar_width"] == "336"


def test_osaka_jade_appearance_is_available_and_dark(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)

    response = client.post(
        "/settings/appearance",
        json={"palette": "osaka-jade"},
    )

    assert response.status_code == 200
    assert response.get_json()["appearance"]["palette"] == "osaka-jade"
    user = AuthStore(str(tmp_path)).get_user("admin")
    assert user["theme"] == "dark"
    page = client.get("/")
    assert b'data-theme="dark"' in page.data
    assert b'data-palette="osaka-jade"' in page.data
    assert b'data-appearance-value="osaka-jade"' in page.data
    assert b"Osaka Jade" in page.data


def test_legacy_theme_endpoint_maps_to_semantic_palette(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)

    response = client.post("/settings/theme", json={"theme": "light"})
    assert response.status_code == 200
    assert response.get_json() == {"theme": "light"}
    user = AuthStore(str(tmp_path)).get_user("admin")
    assert user["theme"] == "light"
    assert user["appearance"]["palette"] == "toolkit-classic"
    assert b'data-palette="toolkit-classic"' in client.get("/").data

    assert client.post("/settings/theme", json={"theme": "sepia"}).status_code == 400


def test_legacy_compact_workspace_migrates_to_tiled(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)

    auth_path = tmp_path / "auth.json"
    auth_data = json.loads(auth_path.read_text(encoding="utf-8"))
    auth_data["users"][0]["appearance"]["layout"] = "compact"
    auth_path.write_text(json.dumps(auth_data), encoding="utf-8")

    assert AuthStore(str(tmp_path)).get_user("admin")["appearance"]["layout"] == "compact"
    assert AuthStore(str(tmp_path)).user_appearance(auth_data["users"][0]["id"])["layout"] == "tiled"
    page = client.get("/")
    assert b'data-layout="tiled"' in page.data
    assert b'data-appearance-value="compact"' not in page.data.split(
        b"<legend>Workspace</legend>", 1
    )[1].split(b"</fieldset>", 1)[0]
    assert client.post(
        "/settings/appearance", json={"layout": "compact"}
    ).status_code == 400


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
    settings_page = client.get("/settings?section=accounts")
    assert b"Idle minutes (0 = never expire)" in settings_page.data
    assert b'min="0"' in settings_page.data


def test_admin_settings_categories_only_render_the_selected_section(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)

    system_page = client.get("/settings")
    assert b'id="server-access"' in system_page.data
    assert b'id="smtp-delivery"' not in system_page.data
    assert b'id="operational-limits"' not in system_page.data
    assert b'id="authentication-policy"' not in system_page.data

    email_page = client.get("/settings?section=email")
    assert b'id="smtp-delivery"' in email_page.data
    assert b'id="server-access"' not in email_page.data

    operations_page = client.get("/settings?section=operations")
    assert b'id="operational-limits"' in operations_page.data
    assert b'id="automation-retention"' in operations_page.data
    assert b'id="server-access"' not in operations_page.data

    accounts_page = client.get("/settings?section=accounts")
    assert b'id="authentication-policy"' in accounts_page.data
    assert b'id="access-profiles"' in accounts_page.data
    assert b'id="users"' in accounts_page.data
    assert b'id="server-access"' not in accounts_page.data

    invalid_page = client.get("/settings?section=unknown")
    assert b'id="server-access"' in invalid_page.data


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
    assert b">Ping</span>" in home.data
    assert b"DNS Tester" not in home.data


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


def test_cross_origin_mutations_are_blocked_before_route_execution(tmp_path):
    app = create_app(str(tmp_path))
    app.config["TESTING"] = True
    client = app.test_client()

    blocked = client.post(
        "/profiles",
        data={"name": "Injected"},
        headers={"Origin": "https://attacker.example"},
    )

    assert blocked.status_code == 403
    assert b"Cross-origin state-changing requests" in blocked.data
    assert not (tmp_path / "profiles.json").exists()


def test_cross_site_fetch_metadata_blocks_even_a_matching_origin(tmp_path):
    app = create_app(str(tmp_path))
    app.config["TESTING"] = True
    client = app.test_client()

    blocked = client.post(
        "/profiles",
        data={"name": "Injected"},
        headers={
            "Origin": "http://localhost",
            "Sec-Fetch-Site": "cross-site",
        },
    )

    assert blocked.status_code == 403
    assert not (tmp_path / "profiles.json").exists()


def test_same_origin_fetch_metadata_allows_login_through_a_host_alias(tmp_path):
    app = create_app(str(tmp_path))
    client = app.test_client()
    _setup(client)
    client.post("/logout")

    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "correct horse battery staple",
        },
        headers={
            "Host": "127.0.0.1:5050",
            "Origin": "https://toolkit.example:5050",
            "Sec-Fetch-Site": "same-origin",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_favorite_reordering_preserves_unsubmitted_favorites(tmp_path):
    store = AuthStore(str(tmp_path))
    user = store.create_user("admin", "correct horse battery staple")
    store.toggle_favorite_tool(user["id"], "tools.ping")
    store.toggle_favorite_tool(user["id"], "tools.dns_response")
    store.toggle_favorite_tool(user["id"], "tools.packet_capture")

    store.reorder_favorite_tools(
        user["id"], ["tools.packet_capture", "tools.ping"]
    )

    assert store.favorite_tool_ids(user["id"]) == [
        "tools.packet_capture",
        "tools.ping",
        "tools.dns_response",
    ]


def test_same_origin_mutations_and_security_headers_are_preserved(tmp_path):
    app = create_app(str(tmp_path))
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.post(
        "/profiles",
        data={
            "name": "Lab",
            "host": "https://fortigate.example",
            "api_key": "secret",
        },
        headers={"Origin": "http://localhost"},
    )
    page = client.get("/")

    assert response.status_code == 302
    assert page.headers["X-Content-Type-Options"] == "nosniff"
    assert page.headers["X-Frame-Options"] == "DENY"
    assert page.headers["Referrer-Policy"] == "no-referrer"
    assert page.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert page.headers["Cache-Control"] == "no-store"


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
                "instance_name": "branch-tools",
                "preferred_fqdn": "branch-tools.example.test",
            },
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )

    assert response.status_code == 200
    assert b"Restarting the toolkit" in response.data
    popen.assert_called_once()
    settings = json.loads((tmp_path / "server_settings.json").read_text())
    assert settings["listen_host"] == "0.0.0.0"
    assert settings["allowed_networks"] == ["192.0.2.0/24"]
    assert settings["instance_name"] == "branch-tools"
    assert settings["preferred_fqdn"] == "branch-tools.example.test"
    page = client.get("/settings")
    assert b"Settings \xc2\xb7 branch-tools \xc2\xb7 TWN Toolkit" in page.data


def test_admin_can_explicitly_regenerate_managed_certificate_for_fqdn(tmp_path):
    # Exercise real certificate generation without depending on resolution of a
    # transient CI runner hostname. GitHub's macOS images can spend minutes in
    # getaddrinfo() for names that are intentionally irrelevant to this route.
    with patch(
        "twn_toolkit.tls_tools.default_certificate_names",
        return_value=(["localhost"], []),
    ):
        generate_self_signed_certificate(tmp_path)
        app = create_app(str(tmp_path))
        app.config["TESTING"] = True
        client = app.test_client()
        with patch("twn_toolkit.admin_routes.subprocess.Popen"):
            response = client.post(
                "/settings/server",
                data={
                    "listen_host": "0.0.0.0",
                    "allowed_networks": "192.0.2.0/24",
                    "instance_name": "branch-tools",
                    "preferred_fqdn": "branch-tools.example.test",
                    "regenerate_tls": "on",
                },
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            )
    assert response.status_code == 200
    assert certificate_status(tmp_path, "branch-tools.example.test")["fqdn_covered"]


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
    assert b"Requires encrypted backup" not in page.data

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
    assert backup["format"] == "twn-toolkit-encrypted-configuration-backup"
    assert b"secret-token" not in export.data

    profiles.write_text(json.dumps([]), encoding="utf-8")
    ping_profiles.write_text(json.dumps([]), encoding="utf-8")

    inspected = client.post(
        "/settings/backup/inspect",
        data={
            "backup_file": (io.BytesIO(export.data), "backup.json"),
            "backup_password": "backup password",
            "import_mode": "replace",
        },
        content_type="multipart/form-data",
    )
    imported = client.post(
        "/settings/backup/import",
        data={
            "preview_token": inspected.location.rsplit("preview=", 1)[1],
            "item": ["fortigate_profiles"],
            "import_mode": "replace",
        },
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
    assert backup["format"] == "twn-toolkit-configuration-backup"
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
    inspected = client.post(
        "/settings/backup/inspect",
        data={
            "backup_file": (io.BytesIO(export.data), "backup.json"),
            "import_mode": "merge",
        },
        content_type="multipart/form-data",
    )
    imported = client.post(
        "/settings/backup/import",
        data={
            "preview_token": inspected.location.rsplit("preview=", 1)[1],
            "item": ["ping_profiles"],
            "import_mode": "merge",
        },
    )
    assert imported.status_code == 302
    restored = {
        profile["name"]: profile["targets"]
        for profile in json.loads(ping_profiles.read_text(encoding="utf-8"))
    }
    assert restored == {"LAN": "192.0.2.10", "WAN": "1.1.1.1"}
