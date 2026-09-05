from __future__ import annotations

from unittest.mock import patch

from twn_toolkit.app import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.distributed_http import MAX_TUNNEL_BODY_BYTES
from twn_toolkit.operational import OperationalSettingsStore


def _mainframe(instance):
    DistributedSettingsStore(instance).save(
        {
            "role": "mainframe",
            "mainframe_listen_interfaces": ["127.0.0.1"],
            "mainframe_port": 5051,
            "agent_mainframe_url": "",
        }
    )


def _login(client, username: str) -> None:
    response = client.post(
        "/login",
        data={"username": username, "password": "correct horse battery staple"},
    )
    assert response.status_code == 302


def test_operation_status_is_requester_scoped_and_hides_tunnel_payload(tmp_path):
    _mainframe(tmp_path)
    app = create_app(str(tmp_path))
    app.testing = False
    auth = AuthStore(str(tmp_path))
    owner = auth.create_user("owner", "correct horse battery staple", is_admin=True)
    auth.create_user("other", "correct horse battery staple")
    job = app.extensions["distributed_job_store"].enqueue(
        agent_id="agent_status", requester_id=owner["id"],
        capability_id="system.http.tunnel", capability_version="1",
        inputs={"method": "POST", "body": "private browser request"},
    )

    owner_client = app.test_client()
    _login(owner_client, "owner")
    operations_settings = owner_client.get("/settings?section=operations")
    assert b"Operation lease" in operations_settings.data
    assert b"Receipt capacity" not in operations_settings.data
    page = owner_client.get(f"/operations/{job['id']}")
    assert page.status_code == 200
    assert b"Distributed operation" in page.data
    assert b"refreshes every five seconds" in page.data
    assert b"private browser request" not in page.data
    payload = owner_client.get(
        f"/operations/{job['id']}", headers={"Accept": "application/json"}
    ).get_json()
    assert payload == {
        "id": job["id"],
        "agent_id": "agent_status",
        "capability_id": "system.http.tunnel",
        "state": "queued",
        "created_at": job["created_at"],
        "started_at": None,
        "completed_at": None,
        "error": "",
    }

    other_client = app.test_client()
    _login(other_client, "other")
    assert other_client.get(f"/operations/{job['id']}").status_code == 404


def test_tunnel_timeout_cancels_unstarted_work_and_returns_a_status_location(tmp_path):
    _mainframe(tmp_path)
    OperationalSettingsStore(str(tmp_path)).save(
        {"distributed_tunnel_wait_seconds": 1}
    )
    app = create_app(str(tmp_path))
    app.testing = False
    auth = AuthStore(str(tmp_path))
    administrator = auth.create_user(
        "administrator", "correct horse battery staple", is_admin=True
    )
    agent_id = "agent_status"
    auth.set_execution_context(administrator["id"], agent_id)
    agent = {
        "id": agent_id,
        "name": "Status agent",
        "state": "approved",
        "online": True,
        "capabilities": [{"id": "system.http.tunnel", "version": "1"}],
    }
    agent_store = app.extensions["distributed_agent_store"]
    client = app.test_client()
    _login(client, "administrator")

    with (
        patch.object(agent_store, "get", return_value=agent),
        patch.object(agent_store, "list", return_value=[agent]),
        patch("twn_toolkit.app.time.monotonic", side_effect=[0, 2]),
    ):
        response = client.get(
            f"/agents/{agent_id}/ui/", headers={"Accept": "application/json"}
        )

    assert response.status_code == 202
    assert response.headers["Location"] == response.json["status_url"]
    assert response.json["state"] == "cancelled"
    operation = app.extensions["distributed_job_store"].get(response.json["operation_id"])
    assert operation["state"] == "cancelled"
    assert client.get(response.headers["Location"]).status_code == 200


def test_tunnel_request_body_limit_reserves_room_for_base64_and_metadata(tmp_path):
    _mainframe(tmp_path)
    app = create_app(str(tmp_path))
    app.testing = False
    auth = AuthStore(str(tmp_path))
    administrator = auth.create_user(
        "administrator", "correct horse battery staple", is_admin=True
    )
    agent_id = "agent_status"
    auth.set_execution_context(administrator["id"], agent_id)
    agent = {
        "id": agent_id,
        "name": "Status agent",
        "state": "approved",
        "online": True,
        "capabilities": [{"id": "system.http.tunnel", "version": "1"}],
    }
    agent_store = app.extensions["distributed_agent_store"]
    client = app.test_client()
    _login(client, "administrator")

    with (
        patch.object(agent_store, "get", return_value=agent),
        patch.object(agent_store, "list", return_value=[agent]),
    ):
        response = client.post(
            f"/agents/{agent_id}/ui/",
            data=b"x" * (MAX_TUNNEL_BODY_BYTES + 1),
            content_type="application/octet-stream",
        )

    assert response.status_code == 413
    assert app.extensions["distributed_job_store"].recent(
        requester_id=administrator["id"]
    ) == []
