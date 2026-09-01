from __future__ import annotations

import hashlib
import json
import stat
from unittest.mock import patch

import pytest

from twn_toolkit.app import create_app
from twn_toolkit.distributed_agents import (
    DistributedAgentStore,
    DistributedIdentityStore,
    DistributedSettingsStore,
    normalize_distributed_settings,
    pairing_code,
    normalize_capabilities,
)


def test_settings_default_to_standalone_and_save_privately(tmp_path):
    store = DistributedSettingsStore(tmp_path)
    assert store.get()["role"] == "standalone"

    saved = store.save(
        {
            "role": "mainframe",
            "mainframe_listen_interfaces": "192.0.2.10, ::",
            "mainframe_port": "5443",
            "agent_mainframe_url": "",
        }
    )

    assert saved["mainframe_listen_interfaces"] == ["192.0.2.10", "::"]
    assert saved["mainframe_port"] == 5443
    assert saved["mainframe_advertised_hosts"] == []
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_advertised_mainframe_hosts_are_normalized_and_validated():
    settings = normalize_distributed_settings(
        {
            "role": "mainframe",
            "mainframe_listen_interfaces": ["192.0.2.10"],
            "mainframe_port": 5051,
            "mainframe_advertised_hosts": "Mainframe.Example.Test.\n203.0.113.20",
        }
    )
    assert settings["mainframe_advertised_hosts"] == [
        "mainframe.example.test",
        "203.0.113.20",
    ]
    with pytest.raises(ValueError, match="advertised host"):
        normalize_distributed_settings(
            {**settings, "mainframe_advertised_hosts": ["bad host"]}
        )


def test_agent_role_requires_clean_https_mainframe_url():
    base = {
        "role": "agent",
        "mainframe_listen_interfaces": ["127.0.0.1"],
        "mainframe_port": 5051,
    }
    settings = normalize_distributed_settings(
        {**base, "agent_mainframe_url": "https://192.0.2.20:5051"}
    )
    assert settings["agent_mainframe_url"] == "https://192.0.2.20:5051"
    settings = normalize_distributed_settings(
        {
            **base,
            "agent_mainframe_url": "https://mainframe.example.test:5051/",
            "agent_mainframe_fallback_url": "https://192.0.2.20:5051/",
        }
    )
    assert settings["agent_mainframe_url"] == "https://mainframe.example.test:5051"
    assert settings["agent_mainframe_fallback_url"] == "https://192.0.2.20:5051"

    with pytest.raises(ValueError, match="must differ"):
        normalize_distributed_settings(
            {
                **base,
                "agent_mainframe_url": "https://mainframe.example.test:5051",
                "agent_mainframe_fallback_url": "https://mainframe.example.test:5051/",
            }
        )
    with pytest.raises(ValueError, match="fallback"):
        normalize_distributed_settings(
            {
                **base,
                "agent_mainframe_url": "https://mainframe.example.test:5051",
                "agent_mainframe_fallback_url": "http://192.0.2.20:5051",
            }
        )

    for invalid in ("", "http://192.0.2.20:5051", "https://user@host", "https://host/path"):
        with pytest.raises(ValueError):
            normalize_distributed_settings({**base, "agent_mainframe_url": invalid})


def test_identity_is_stable_private_and_contains_no_private_material(tmp_path):
    store = DistributedIdentityStore(tmp_path)
    first = store.load_or_create()
    second = store.load_or_create()

    assert first == second
    assert first["device_id"].startswith("twn_")
    assert len(bytes.fromhex(first["public_key"])) == 32
    assert "private" not in json.dumps(first).lower()
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_pairing_code_is_stable_bounded_and_transcript_dependent():
    first = pairing_code(b"canonical handshake transcript")
    assert first == pairing_code(b"canonical handshake transcript")
    assert first != pairing_code(b"different handshake transcript")
    assert len(first) == 6 and first.isdigit()


def test_enrollment_requires_matching_identity_and_explicit_approval(tmp_path):
    store = DistributedAgentStore(tmp_path)
    public_key = bytes(range(32))
    fingerprint = hashlib.sha256(public_key).hexdigest()

    pending = store.request_enrollment(
        public_key=public_key.hex(),
        fingerprint=fingerprint,
        name="Branch Pi",
        address="192.0.2.31",
    )
    assert pending["state"] == "pending"
    assert store.list("pending")[0]["id"] == pending["id"]

    approved = store.set_state(pending["id"], "approved")
    assert approved["state"] == "approved"
    assert approved["approved_at"] is not None
    with pytest.raises(ValueError):
        store.request_enrollment(
            public_key=public_key.hex(),
            fingerprint=fingerprint,
            name="Impostor",
        )

    revoked = store.set_state(pending["id"], "revoked")
    assert revoked["state"] == "revoked"
    assert revoked["revoked_at"] is not None


def test_enrollment_rejects_mismatched_fingerprint(tmp_path):
    with pytest.raises(ValueError, match="does not match"):
        DistributedAgentStore(tmp_path).request_enrollment(
            public_key=bytes(32).hex(),
            fingerprint=bytes(32).hex(),
            name="Untrusted",
        )


def test_denied_agent_can_make_a_fresh_pending_request(tmp_path):
    store = DistributedAgentStore(tmp_path)
    public_key = bytes(range(32))
    fingerprint = hashlib.sha256(public_key).hexdigest()
    first = store.request_enrollment(
        public_key=public_key.hex(), fingerprint=fingerprint, name="Lab Pi"
    )
    store.set_state(first["id"], "denied")

    retried = store.request_enrollment(
        public_key=public_key.hex(), fingerprint=fingerprint, name="Lab Pi"
    )

    assert retried["state"] == "pending"


def test_capabilities_are_bounded_normalized_and_deduplicated():
    assert normalize_capabilities(
        [
            {"id": "system.identity", "version": "1"},
            {"id": "system.identity", "version": "2"},
            {"id": "network.ping", "version": "1"},
        ]
    ) == [
        {"id": "system.identity", "version": "1"},
        {"id": "network.ping", "version": "1"},
    ]
    with pytest.raises(ValueError):
        normalize_capabilities([{"id": "x", "version": "1"}] * 257)


def test_agents_settings_page_exposes_roles_and_public_identity(tmp_path):
    app = create_app(str(tmp_path))
    app.config.update(TESTING=True)
    response = app.test_client().get("/mainframe")

    assert response.status_code == 200
    assert b'id="distributed-configuration"' in response.data
    assert b'id="distributed-identity"' in response.data
    assert b"Standalone" in response.data
    assert b"Mainframe" in response.data
    assert b"Agent" in response.data
    assert b"PRIVATE KEY" not in response.data
    assert b'data-role-fields="mainframe" hidden' in response.data
    assert b'data-role-fields="agent" hidden' in response.data


def test_mainframe_page_only_reveals_fields_for_the_saved_role(tmp_path):
    app = create_app(str(tmp_path))
    app.config.update(TESTING=True)
    store = DistributedSettingsStore(tmp_path)
    store.save(
        {
            "role": "agent",
            "mainframe_listen_interfaces": ["127.0.0.1"],
            "mainframe_port": 5051,
            "agent_mainframe_url": "https://192.0.2.20:5051",
        }
    )

    response = app.test_client().get("/mainframe")

    assert b'data-role-fields="mainframe" hidden' in response.data
    assert b'data-role-fields="agent" hidden' not in response.data
    assert b"mainframe.js" in response.data


def test_admin_can_save_distributed_configuration(tmp_path):
    app = create_app(str(tmp_path))
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/settings/agents/configuration",
        data={
            "role": "mainframe",
            "mainframe_listen_interfaces": "192.0.2.50\n::1",
            "mainframe_port": "5051",
            "agent_mainframe_url": "",
        },
    )

    assert response.status_code == 302
    assert response.location.endswith("/mainframe")
    assert DistributedSettingsStore(tmp_path).get()["role"] == "mainframe"
    assert app.extensions["distributed_pki_store"].ca_cert_path.exists()
    assert app.extensions["distributed_pki_store"].server_cert_path.exists()


def test_admin_can_save_distributed_configuration_and_restart(tmp_path):
    app = create_app(str(tmp_path))
    app.config.update(TESTING=True)
    with patch("twn_toolkit.admin_routes.subprocess.Popen") as popen:
        response = app.test_client().post(
            "/settings/agents/configuration",
            data={
                "role": "agent",
                "mainframe_listen_interfaces": "127.0.0.1",
                "mainframe_port": "5051",
                "agent_mainframe_url": "https://mainframe.example.test:5051",
                "apply_restart": "on",
            },
        )

    assert response.status_code == 200
    assert b"Restarting the toolkit" in response.data
    assert b"distributed role and listener settings are being applied" in response.data
    assert b'data-settings-url="/mainframe"' in response.data
    popen.assert_called_once()
    command = popen.call_args.args[0]
    assert command[-1] == "web-restart"


def test_admin_can_approve_and_revoke_pending_agent(tmp_path):
    app = create_app(str(tmp_path))
    app.config.update(TESTING=True)
    DistributedSettingsStore(tmp_path).save(
        {
            "role": "mainframe",
            "mainframe_listen_interfaces": ["127.0.0.1"],
            "mainframe_port": 5051,
            "agent_mainframe_url": "",
        }
    )
    store = app.extensions["distributed_agent_store"]
    public_key = bytes(range(32))
    pending = store.request_enrollment(
        public_key=public_key.hex(),
        fingerprint=hashlib.sha256(public_key).hexdigest(),
        name="Lab Pi",
    )
    client = app.test_client()

    page = client.get("/mainframe")
    assert b"Lab Pi" in page.data
    assert b"Approve" in page.data

    refused = client.post(f"/settings/agents/{pending['id']}/approve")
    assert refused.status_code == 302
    assert store.get(pending["id"])["state"] == "pending"

    approved = client.post(
        f"/settings/agents/{pending['id']}/approve",
        data={"pairing_code_confirmed": "on"},
    )
    assert approved.status_code == 302
    assert store.get(pending["id"])["state"] == "approved"

    refused_remove = client.post(f"/settings/agents/{pending['id']}/remove")
    assert refused_remove.status_code == 302
    assert store.get(pending["id"])["state"] == "approved"

    revoked = client.post(f"/settings/agents/{pending['id']}/revoke")
    assert revoked.status_code == 302
    assert store.get(pending["id"])["state"] == "revoked"
    assert b"Remove" in client.get("/mainframe").data

    removed = client.post(f"/settings/agents/{pending['id']}/remove")
    assert removed.status_code == 302
    assert store.get(pending["id"]) is None


def test_admin_can_open_and_close_agent_enrollment(tmp_path):
    app = create_app(str(tmp_path))
    app.config.update(TESTING=True)
    DistributedSettingsStore(tmp_path).save(
        {
            "role": "mainframe",
            "mainframe_listen_interfaces": ["127.0.0.1"],
            "mainframe_port": 5051,
            "agent_mainframe_url": "",
        }
    )
    client = app.test_client()
    page = client.get("/mainframe")
    assert b"Agent enrollment" in page.data
    assert b'<section class="panel server-access-panel" id="enrollment-window">' in page.data
    assert b"New enrollment requests are rejected" in page.data

    assert client.post(
        "/mainframe/enrollment-window", data={"action": "open", "minutes": "15"}
    ).status_code == 302
    assert b"Closes automatically" in client.get("/mainframe").data

    assert client.post(
        "/mainframe/enrollment-window", data={"action": "close"}
    ).status_code == 302
    assert b"New enrollment requests are rejected" in client.get("/mainframe").data
