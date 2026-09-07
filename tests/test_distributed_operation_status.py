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
    assert b'name="distributed_listener_connections"' in operations_settings.data
    assert b'name="distributed_control_reserve"' in operations_settings.data
    assert b'name="distributed_agent_long_polls"' in operations_settings.data
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
        "online": True, "job_protocol_version": 2, "gui_protocol_version": 2,
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
        "online": True, "job_protocol_version": 2, "gui_protocol_version": 2,
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


def test_tunnel_response_is_returned_but_not_retained_in_queue(tmp_path):
    import base64

    _mainframe(tmp_path)
    app = create_app(str(tmp_path))
    app.testing = False
    auth = AuthStore(str(tmp_path))
    owner = auth.create_user("owner", "correct horse battery staple", is_admin=True)
    agent_id = "agent_status"
    auth.set_execution_context(owner["id"], agent_id)
    agent = {
        "id": agent_id, "name": "Status agent", "state": "approved", "online": True, "job_protocol_version": 2, "gui_protocol_version": 2,
        "capabilities": [{"id": "system.http.tunnel", "version": "1"}],
    }
    agent_store = app.extensions["distributed_agent_store"]
    store = app.extensions["distributed_job_store"]
    client = app.test_client()
    _login(client, "owner")
    original_get = store.get
    completed = []

    def finish_during_poll(job_id):
        current = original_get(job_id)
        if current["state"] == "queued":
            job = store.claim(agent_id)[0]
            store.control(job_id, agent_id=agent_id, attempt_token=job["attempt_token"], action="start")
            store.complete(
                job_id, agent_id=agent_id, attempt_token=job["attempt_token"], state="succeeded",
                output={"body": base64.b64encode(b"private remote response").decode(), "status": 200, "headers": []},
            )
            completed.append(job_id)
        return original_get(job_id)

    with (
        patch.object(agent_store, "get", return_value=agent),
        patch.object(agent_store, "list", return_value=[agent]),
        patch.object(store, "get", side_effect=finish_during_poll),
    ):
        response = client.get(f"/agents/{agent_id}/ui/", headers={"Accept": "application/json"})

    assert response.status_code == 200
    assert response.data == b"private remote response"
    assert len(completed) == 1
    retained = original_get(completed[0])
    assert retained["state"] == "succeeded"
    assert retained["inputs"] == {}
    assert retained["output"] is None
    assert client.get(f"/operations/{completed[0]}").status_code == 200


def test_delayed_response_preserves_agent_url_and_never_replays(tmp_path):
    import base64
    import hashlib
    import sqlite3

    _mainframe(tmp_path)
    app = create_app(str(tmp_path))
    app.testing = False
    auth = AuthStore(str(tmp_path))
    owner = auth.create_user('owner', 'correct horse battery staple', is_admin=True)
    auth.create_user('other', 'correct horse battery staple', is_admin=True)
    agent_id = 'agent_retained'
    store = app.extensions['distributed_job_store']
    client = app.test_client()
    _login(client, 'owner')
    body = b'<html><form method="post"><button>Submit</button></form>' + b'x' * 200000 + b'</html>'
    queued = store.enqueue(agent_id=agent_id, requester_id=owner['id'], capability_id='system.http.tunnel', capability_version='1')
    job = store.claim(agent_id)[0]
    store.control(job['id'], agent_id=agent_id, attempt_token=job['attempt_token'], action='start')
    for position, offset in enumerate(range(0, len(body), 65536)):
        store.append_response_chunk(job['id'], agent_id=agent_id, attempt_token=job['attempt_token'],
                                    activation_id=job['activation_id'], position=position,
                                    body=base64.b64encode(body[offset:offset + 65536]).decode())
    store.complete(job['id'], agent_id=agent_id, attempt_token=job['attempt_token'], state='succeeded',
                   output=dict(status=200, headers=[['Content-Type', 'text/html']], request_path='/tools/fixture?name=a%20b',
                               body_transfer=1, body_size=len(body), body_sha256=hashlib.sha256(body).hexdigest()))
    url = f'/operations/{queued["id"]}/response'
    other = app.test_client()
    _login(other, 'other')
    assert other.get(url).status_code == 404
    assert client.get(url).status_code == 409  # Must choose original Agent.
    auth.set_execution_context(owner['id'], agent_id)
    assert client.head(url).status_code == 200
    assert store.get(job['id'])['output']
    page = client.get(f'/operations/{job["id"]}')
    assert b'View completed response' in page.data
    metadata = client.get(f'/operations/{job["id"]}', headers={'Accept': 'application/json'})
    assert 'body_sha256' not in metadata.get_data(as_text=True)
    response = client.get(url)
    assert response.status_code == 303
    location = response.headers['Location']
    assert location.startswith(f'/agents/{agent_id}/ui/tools/fixture?name=a+b&')
    assert f'_twn_response={job["id"]}' in location
    assert client.head(location).status_code == 200
    with patch.object(store, 'enqueue', side_effect=AssertionError('Recovered response replayed HTTP')):
        recovered = client.get(location)
        assert recovered.status_code == 200
        assert recovered.data == body
        recovered.close()
        assert client.get(location).status_code == 410
        assert client.get(url).status_code == 410
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT COUNT(*) FROM distributed_response_chunks').fetchone()[0] == 0
    assert store.get(job['id'])['state'] == 'succeeded'


def test_retained_response_requires_current_admin_and_original_owner(tmp_path):
    import base64

    _mainframe(tmp_path)
    app = create_app(str(tmp_path))
    app.testing = False
    auth = AuthStore(str(tmp_path))
    auth.create_user('administrator', 'correct horse battery staple', is_admin=True)
    owner = auth.create_user('owner', 'correct horse battery staple', is_admin=False)
    auth.set_execution_context(owner['id'], 'agent_fixture')
    store = app.extensions['distributed_job_store']
    store.enqueue(agent_id='agent_fixture', requester_id=owner['id'], capability_id='system.http.tunnel', capability_version='1')
    job = store.claim('agent_fixture')[0]
    store.control(job['id'], agent_id='agent_fixture', attempt_token=job['attempt_token'], action='start')
    store.complete(job['id'], agent_id='agent_fixture', attempt_token=job['attempt_token'], state='succeeded',
                   output={'status': 200, 'body': base64.b64encode(b'private').decode(), 'request_path': '/tools/fixture'})
    client = app.test_client()
    _login(client, 'owner')
    assert client.get(f'/operations/{job["id"]}/response').status_code == 403
    assert client.get(f'/agents/agent_fixture/ui/tools/fixture?_twn_response={job["id"]}').status_code == 403
    assert store.get(job['id'])['output']


def test_explicit_form_after_recovery_strips_only_retrieval_marker(tmp_path):
    _mainframe(tmp_path)
    OperationalSettingsStore(str(tmp_path)).save({'distributed_tunnel_wait_seconds': 1})
    app = create_app(str(tmp_path))
    app.testing = False
    auth = AuthStore(str(tmp_path))
    owner = auth.create_user('owner', 'correct horse battery staple', is_admin=True)
    auth.set_execution_context(owner['id'], 'agent_fixture')
    agent = dict(id='agent_fixture', name='Agent', state='approved', online=True,
                 job_protocol_version=2, gui_protocol_version=2,
                 capabilities=[{'id': 'system.http.tunnel', 'version': '1'}])
    client = app.test_client()
    _login(client, 'owner')
    agents = app.extensions['distributed_agent_store']
    store = app.extensions['distributed_job_store']
    enqueue = store.enqueue
    captured = []
    def capture(**kwargs):
        captured.append(kwargs)
        return enqueue(**kwargs)
    with patch.object(agents, 'get', return_value=agent), patch.object(agents, 'list', return_value=[agent]), \
         patch.object(store, 'enqueue', side_effect=capture), patch('twn_toolkit.app.time.monotonic', side_effect=[0, 2]):
        response = client.post('/agents/agent_fixture/ui/tools/fixture?name=a+b&_twn_response=old',
                               data={'action': 'explicit-new-work'}, headers={'Accept': 'application/json'})
    assert response.status_code == 202
    assert len(captured) == 1
    assert captured[0]['inputs']['path'] == '/tools/fixture?name=a+b'
    assert captured[0]['inputs']['method'] == 'POST'
