"""Exercise actual browser-fixture responses without binding a socket or running tools."""
from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import runpy
from unittest.mock import Mock, patch

import pytest

from twn_toolkit.profiles import SNMPCredentialProfileStore

FIXTURE = Path(__file__).parent / "fixtures" / "network_dependency_app.py"
BOUNDARIES = (
    "twn_toolkit.snmp_routes.run_snmp_tests",
    "twn_toolkit.snmp_routes.discover_snmp_interfaces",
    "twn_toolkit.snmp_routes.poll_snmp_interface",
    "twn_toolkit.snmp_routes.poll_snmp_interfaces",
    "twn_toolkit.radius_routes.radius_authenticate",
    "socket.create_connection",
    "socket.getaddrinfo",
)


@pytest.fixture
def browser_fixture(tmp_path, monkeypatch):
    instance = tmp_path / "instance"
    instance.mkdir()
    server = Mock()
    factory = Mock(return_value=server)
    with monkeypatch.context() as setup:
        setup.setattr("sys.argv", [str(FIXTURE), "--port", "5132"])
        setup.setattr("tempfile.mkdtemp", lambda **kwargs: str(instance))
        setup.setattr("werkzeug.serving.make_server", factory)
        state = runpy.run_path(str(FIXTURE))
    factory.assert_called_once()
    server.serve_forever.assert_called_once_with()
    server.server_close.assert_called_once_with()
    # The standalone fixture closes its own ExitStack on return. Cover every
    # test-client request with freshly installed fail-closed boundaries.
    with ExitStack() as stack:
        mocks = [stack.enter_context(patch(target, side_effect=AssertionError("Unexpected fixture execution: " + target))) for target in BOUNDARIES]
        yield state, state["app"].test_client(), instance
        for mock in mocks:
            mock.assert_not_called()
    assert all(value == 0 for value in state["counts"]["blocked_calls"].values())
    state["app"].extensions["remote_session_manager"].close()


@pytest.mark.parametrize("mode,status,mimetype,committed", [
    ("normal", 200, "application/json", True),
    ("validation", 400, "application/json", False),
    ("forbidden", 403, "text/html", False),
    ("html_after", 200, "text/html", True),
    ("json500_after", 500, "application/json", True),
    ("wrong_profile", 200, "application/json", True),
    ("wrong_metadata", 200, "application/json", True),
])
def test_fixture_fault_modes_are_actual_http_responses(browser_fixture, mode, status, mimetype, committed):
    state, client, instance = browser_fixture
    state["control_path"].write_text(json.dumps({"response": mode, "delay": 0}))
    data = {"name": "Synthetic fixture credential", "version": "v2c", "community": "SyntheticFixtureOnlySecret"}
    response = client.post("/tools/snmp-test/profiles/credentials", data=data)
    assert response.status_code == status
    assert response.mimetype == mimetype
    assert state["counts"]["profile_posts"] == 1
    assert state["counts"]["responses"] == [{"status": status, "mimetype": mimetype, "mode": mode, "committed": committed}]
    stored = SNMPCredentialProfileStore(str(instance)).get(data["name"])
    assert (stored is not None) == committed
    if committed:
        assert stored["version"] == "v2c"
        assert stored["community"] == data["community"]
    if mode == "normal":
        assert response.json["profile"]["name"] == data["name"]
    elif mode == "wrong_profile":
        assert response.json["profile"]["name"] == "Unrelated synthetic acknowledgment"
        assert SNMPCredentialProfileStore(str(instance)).get(response.json["profile"]["name"]) is None
    elif mode == "wrong_metadata":
        assert response.json["profile"]["version"] == "synthetic-wrong-metadata"
    elif mode == "validation":
        assert "preserve this draft" in response.json["error"]
    elif mode == "json500_after":
        assert "after committed save" in response.json["error"]
    elif mode == "html_after":
        assert b"lost JSON acknowledgment" in response.data
    if committed and response.is_json:
        assert data["community"] not in response.get_data(as_text=True)
    choices = client.get("/tools/snmp-test/profile-choices")
    assert choices.status_code == 200
    assert any(row["name"] == data["name"] for row in choices.json["credentials"]) == committed
    assert json.loads((instance / "counts.json").read_text())["responses"] == state["counts"]["responses"]


def test_wrong_metadata_selected_field_does_not_mutate_committed_profile(browser_fixture):
    state, client, instance = browser_fixture
    state["control_path"].write_text(json.dumps({"response": "wrong_metadata", "wrong_field": "username", "wrong_value": "wrong fixture user", "delay": 0}))
    response = client.post("/tools/radius-test/profiles/credentials", data={"name": "Fixture new login", "username": "true fixture user", "password": "SyntheticPassword"})
    assert response.status_code == 200 and response.json["profile"]["username"] == "wrong fixture user"
    choices = client.get("/tools/radius-test/profile-choices")
    assert next(row for row in choices.json["credentials"] if row["name"] == "Fixture new login")["username"] == "true fixture user"
    assert state["counts"]["responses"][0]["committed"] is True


def test_fixture_whitelist_rejects_valid_runs_and_sharing(browser_fixture):
    state, client, instance = browser_fixture
    # Both are valid-shaped requests, but the fixture must reject before a runner.
    assert client.post("/tools/snmp-test", data={"host_names": "any", "oid_profile_names": "System Identity"}).status_code == 403
    assert client.post("/tools/radius-test", data={"server_names": "Fixture initial server", "credential_name": "Fixture initial credential", "timeout": "3"}).status_code == 403
    assert client.post("/tools/snmp-test/profiles/credentials", data={"name": "Do not share", "version": "v2c", "community": "Synthetic", "mso_enabled": "true"}).status_code == 403
    assert state["counts"]["profile_posts"] == state["counts"]["invalid_runs"] == 0
    assert SNMPCredentialProfileStore(str(instance)).get("Do not share") is None


@pytest.mark.parametrize("tool,data,error", [
    ("snmp", {}, "Select between 1 and 20 valid SNMP hosts."),
    ("radius", {}, "Select at least one valid RADIUS server profile."),
    ("radius", {"server_names": "Fixture initial server", "credential_name": "Fixture initial credential", "timeout": ""}, "could not convert string to float"),
])
def test_fixture_only_allows_invalid_runs(browser_fixture, tool, data, error):
    state, client, instance = browser_fixture
    response = client.post(f"/tools/{tool}-test", data=data)
    assert response.status_code == 200
    assert error in response.get_data(as_text=True)
    assert state["counts"]["invalid_runs"] == 1
    assert state["counts"]["profile_posts"] == 0
