"""Dependency metadata and CRUD gates with fail-closed transport boundaries."""
from __future__ import annotations

import time
from unittest.mock import Mock

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.network_profile_choices import FIELDS, choice, save_acknowledgment
from twn_toolkit.profiles import RadiusProfileStore, SNMPCredentialProfileStore
from twn_toolkit.tool_catalog import tool_id_for_endpoint

PROFILES = {
    ("snmp", "credentials"): {"name": "Synthetic credential", "version": "v2c", "community": "SyntheticCommunity"},
    ("snmp", "hosts"): {"name": "Synthetic host", "host": "192.0.2.44", "port": "161", "credential_name": "Synthetic credential"},
    ("snmp", "oids"): {"name": "Synthetic OIDs", "source": "Name = 1.3.6.1.2.1.1.5.0"},
    ("radius", "servers"): {"name": "Synthetic server", "host": "192.0.2.45", "port": "1812", "secret": "SyntheticRadiusSecret"},
    ("radius", "credentials"): {"name": "Synthetic login", "username": "synthetic-user", "password": "SyntheticRadiusPassword"},
    ("radius", "attributes"): {"name": "Synthetic attributes", "attributes": "NAS-Identifier = synthetic-fixture"},
}


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    blocked = []
    for target in (
        "twn_toolkit.snmp_routes.run_snmp_tests", "twn_toolkit.snmp_routes.discover_snmp_interfaces",
        "twn_toolkit.snmp_routes.poll_snmp_interface", "twn_toolkit.snmp_routes.poll_snmp_interfaces",
        "twn_toolkit.radius_routes.radius_authenticate", "socket.create_connection", "socket.getaddrinfo",
    ):
        mock = Mock(side_effect=AssertionError("Unexpected execution: " + target))
        monkeypatch.setattr(target, mock)
        blocked.append(mock)
    app = create_app(str(tmp_path))
    app.testing = True
    yield app, app.test_client(), tmp_path
    for mock in blocked:
        mock.assert_not_called()
    app.extensions["remote_session_manager"].close()


def save(client, tool, kind, data):
    return client.post(f"/tools/{tool}-test/profiles/{kind}", data=data)


def populate(client):
    for (tool, kind), data in PROFILES.items():
        response = save(client, tool, kind, data)
        assert response.status_code == 200, response.get_data(as_text=True)


@pytest.mark.parametrize("tool", ["snmp", "radius"])
def test_choices_allowlist_and_no_store(isolated, tool):
    app, client, path = isolated
    populate(client)
    response = client.get(f"/tools/{tool}-test/profile-choices")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert set(response.json) == set(FIELDS[tool])
    for kind, profiles in response.json.items():
        for profile in profiles:
            assert set(profile) == set(FIELDS[tool][kind])
    text = response.get_data(as_text=True)
    for secret in ("SyntheticCommunity", "SyntheticRadiusSecret", "SyntheticRadiusPassword", '"mso"', '"source"'):
        assert secret not in text


@pytest.mark.parametrize("tool,kind", PROFILES)
def test_duplicate_uses_persisted_canonical_metadata(isolated, tool, kind):
    app, client, path = isolated
    populate(client)
    original = PROFILES[tool, kind]["name"]
    url = f"/tools/{tool}-test/profiles/{kind}/duplicate"
    first = client.post(url, data={"name": original})
    second = client.post(url, data={"name": original})
    assert first.status_code == second.status_code == 200
    assert first.json["source_name"] == original
    assert set(first.json["profile"]) == set(FIELDS[tool][kind])
    assert first.json["profile"]["name"] != original
    assert first.json["profile"]["name"] != second.json["profile"]["name"]
    choices = client.get(f"/tools/{tool}-test/profile-choices").json[kind]
    assert first.json["profile"] in choices
    assert second.json["profile"] in choices
    assert client.post(url, data={"name": "missing"}).status_code == 404


@pytest.mark.parametrize("tool", ["snmp", "radius"])
@pytest.mark.parametrize("actor", ["admin", "granted", "denied"])
def test_actual_tool_gate_including_duplicate_and_choices(isolated, tool, actor):
    app, client, path = isolated
    populate(client)
    auth = AuthStore(str(path))
    admin = auth.create_user("fixture-admin", "FixturePassword123!", is_admin=True)
    grant = auth.save_access_profile(name="Fixture grant", tool_ids=[f"tools.{tool}_test"])
    user = auth.create_user("fixture-member", "FixturePassword123!", access_profile_ids=[grant["id"]] if actor == "granted" else [])
    if actor == "admin":
        user = admin
    app.testing = False
    with client.session_transaction() as session:
        session.update(user_id=user["id"], session_version=user["session_version"], last_seen=int(time.time()))
    assert client.get(f"/tools/{tool}-test/profile-choices").status_code == (403 if actor == "denied" else 200)
    kind = "credentials"
    name = PROFILES[tool, kind]["name"]
    assert client.post(f"/tools/{tool}-test/profiles/{kind}/duplicate", data={"name": name}).status_code == (403 if actor == "denied" else 200)
    data = {**PROFILES[tool, kind], "name": "Member synthetic profile"}
    assert save(client, tool, kind, data).status_code == (403 if actor == "denied" else 200)
    names = [p["name"] for p in (SNMPCredentialProfileStore(str(path)) if tool == "snmp" else RadiusProfileStore(str(path), kind)).all()]
    assert ("Member synthetic profile" in names) == (actor != "denied")


@pytest.mark.parametrize("tool", ["snmp", "radius"])
def test_invalid_kind_and_version_conflict_preserve_profile(isolated, tool):
    app, client, path = isolated
    data = dict(PROFILES[tool, "credentials"])
    response = save(client, tool, "credentials", data)
    assert response.status_code == 200
    metadata = response.json["profile"]["mso"]
    assert save(client, tool, "missing", data).status_code == 404
    assert client.post(f"/tools/{tool}-test/profiles/missing/duplicate", data={"name": data["name"]}).status_code == 404
    assert save(client, tool, "credentials", {**data, "mso_version": "invalid"}).status_code == 400
    assert save(client, tool, "credentials", {**data, "original_name": data["name"], "mso_id": metadata["id"], "mso_version": str(metadata["version"] - 1)}).status_code == 409
    assert save(client, tool, "credentials", {**data, "mso_kind": "radius.servers" if tool == "snmp" else "snmp.credentials"}).status_code == 400


@pytest.mark.parametrize("tool,kind,secret", [("snmp", "credentials", "community"), ("radius", "servers", "secret"), ("radius", "credentials", "password")])
def test_blank_secret_preserved_and_save_ack_safe(isolated, tool, kind, secret):
    app, client, path = isolated
    data = dict(PROFILES[tool, kind])
    assert save(client, tool, kind, data).status_code == 200
    response = save(client, tool, kind, {**data, "original_name": data["name"], secret: ""})
    assert response.status_code == 200
    assert secret not in response.json["profile"]
    store = SNMPCredentialProfileStore(str(path)) if tool == "snmp" else RadiusProfileStore(str(path), kind)
    assert store.get(data["name"])[secret] == data[secret]
    if tool == "radius":
        assert set(response.json["profile"]) == {*FIELDS[tool][kind], "mso"}


def test_helpers_drop_arbitrary_metadata_and_redact_compatibility_metadata():
    profile = {"name": "fixture", "username": "user", "password": "secret", "encrypted": "raw", "mso": {"id": "id", "conflict": {"password": "secret"}}}
    assert choice("radius", "credentials", profile) == {"name": "fixture", "username": "user"}
    assert save_acknowledgment("radius", "credentials", profile)["mso"]["conflict"]["password"] == "Stored secret"


def test_choice_endpoints_use_existing_tool_registry_gates():
    assert tool_id_for_endpoint("tools.snmp_profile_choices") == "tools.snmp_test"
    assert tool_id_for_endpoint("tools.radius_profile_choices") == "tools.radius_test"
