import hashlib
import sqlite3

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.distributed_agents import (
    DistributedAgentStore, DistributedSettingsStore, agent_gui_compatibility_error,
    selectable_gui_agents,
)

CAPS = [{'id': 'system.http.tunnel', 'version': '1'}]


def enroll(store):
    public = bytes(range(32))
    agent = store.request_enrollment(public_key=public.hex(), fingerprint=hashlib.sha256(public).hexdigest(), name='Mac fixture')
    return store.set_state(agent['id'], 'approved')['id']


def heartbeat(store, agent_id, **versions):
    return store.record_heartbeat(agent_id, capabilities=CAPS, address='127.0.0.1',
                                  toolkit_version='0.24.0', protocol_version=1, **versions)


@pytest.mark.parametrize('job,gui', [(0,0),(1,1),(2,0),(3,1),(2,2),(2,True),('2',1),(2,'1'),(-1,1)])
def test_missing_malformed_or_unsupported_protocols_never_enable_gui(tmp_path, job, gui):
    store = DistributedAgentStore(tmp_path); agent_id = enroll(store)
    agent = heartbeat(store, agent_id, job_protocol_version=job, gui_protocol_version=gui)
    assert agent['online'] and agent['state'] == 'approved'
    assert not agent['gui_compatible'] and 'Re-enrollment is not required' in agent['gui_compatibility_error']
    assert selectable_gui_agents([agent]) == []


def test_fresh_heartbeat_enables_same_release_and_legacy_heartbeat_removes_support(tmp_path):
    store = DistributedAgentStore(tmp_path); agent_id = enroll(store)
    old = heartbeat(store, agent_id)
    new = heartbeat(store, agent_id, job_protocol_version=2, gui_protocol_version=1)
    assert old['toolkit_version'] == new['toolkit_version']
    assert not old['gui_compatible'] and new['gui_compatible']
    assert selectable_gui_agents([new]) == [new]
    assert DistributedAgentStore(tmp_path).get(agent_id)['gui_compatible']
    assert not heartbeat(store, agent_id)['gui_compatible']


def test_legacy_store_migrates_to_unconfirmed_without_changing_identity(tmp_path):
    store = DistributedAgentStore(tmp_path); agent_id = enroll(store)
    with sqlite3.connect(store.path) as db:
        db.execute('ALTER TABLE distributed_agents DROP COLUMN job_protocol_version')
        db.execute('ALTER TABLE distributed_agents DROP COLUMN gui_protocol_version')
    migrated = DistributedAgentStore(tmp_path).get(agent_id)
    assert migrated['state'] == 'approved' and migrated['id'] == agent_id
    assert migrated['job_protocol_version'] == migrated['gui_protocol_version'] == 0
    assert not migrated['gui_compatible']


def test_selection_and_stale_context_block_before_queue_and_recover_after_heartbeat(tmp_path, monkeypatch):
    app = create_app(str(tmp_path)); app.testing = False
    DistributedSettingsStore(tmp_path).save({'role':'mainframe','mainframe_listen_interfaces':['127.0.0.1'], 'mainframe_port':5051})
    store = app.extensions['distributed_agent_store']; agent_id = enroll(store)
    heartbeat(store, agent_id)
    client = app.test_client(); auth = AuthStore(str(tmp_path))
    user_id = auth.create_user('owner', 'FixturePassword123!', is_admin=True)['id']
    assert client.post('/login', data={'username':'owner', 'password':'FixturePassword123!'}).status_code == 302
    monkeypatch.setattr('twn_toolkit.distributed_job_epochs.DistributedJobStore.enqueue',
                        lambda *a, **kw: pytest.fail('incompatible GUI request entered queue'))
    page = client.get('/mainframe')
    assert b'GUI update required' in page.data and b'Re-enrollment is not required' in page.data
    response = client.post('/execution-context', data={'context_id':agent_id, 'next':'/'})
    assert response.status_code == 302 and auth.execution_context(user_id) == 'local'
    auth.set_execution_context(user_id, agent_id)
    response = client.post(f'/agents/{agent_id}/ui/tools/dns-response', data={'hosts':'example.test'})
    assert response.status_code == 409 and b'GUI compatibility' in response.data
    assert auth.execution_context(user_id) == agent_id
    response = client.get(f'/agents/{agent_id}/ui/', headers={'Accept':'application/json'})
    assert response.status_code == 409
    response = client.get(f'/agents/{agent_id}/ui/', headers={'Accept':'text/html'})
    assert response.status_code == 302 and auth.execution_context(user_id) == 'local'
    heartbeat(store, agent_id, job_protocol_version=2, gui_protocol_version=1)
    response = client.post('/execution-context', data={'context_id':agent_id, 'next':'/'})
    assert response.status_code == 302 and auth.execution_context(user_id) == agent_id
