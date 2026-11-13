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


@pytest.mark.parametrize('job,gui', [(0,0),(1,1),(2,0),(2,1),(3,1),(2,3),(2,True),('2',1),(2,'1'),(-1,1)])
def test_missing_malformed_or_unsupported_protocols_never_enable_gui(tmp_path, job, gui):
    store = DistributedAgentStore(tmp_path); agent_id = enroll(store)
    agent = heartbeat(store, agent_id, job_protocol_version=job, gui_protocol_version=gui)
    assert agent['online'] and agent['state'] == 'approved'
    assert not agent['gui_compatible'] and 'does not diagnose certificate or connection problems' in agent['gui_compatibility_error']
    assert selectable_gui_agents([agent]) == []


def test_fresh_heartbeat_enables_same_release_and_legacy_heartbeat_removes_support(tmp_path):
    store = DistributedAgentStore(tmp_path); agent_id = enroll(store)
    old = heartbeat(store, agent_id)
    new = heartbeat(store, agent_id, job_protocol_version=2, gui_protocol_version=2)
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
    assert b'GUI compatibility unconfirmed' in page.data and b'Re-enrollment does not fix a protocol mismatch' in page.data
    response = client.post('/execution-context', data={'context_id':agent_id, 'next':'/'})
    assert response.status_code == 302 and auth.execution_context(user_id) == 'local'
    auth.set_execution_context(user_id, agent_id)
    response = client.post(f'/agents/{agent_id}/ui/tools/dns-response', data={'hosts':'example.test'})
    assert response.status_code == 409 and b'GUI compatibility' in response.data
    assert auth.execution_context(user_id) == agent_id
    response = client.get(f'/agents/{agent_id}/ui/', headers={'Accept':'application/json'})
    assert response.status_code == 409
    response = client.get(f'/agents/{agent_id}/ui/', headers={'Accept':'text/html'})
    assert response.status_code == 302 and auth.execution_context(user_id) == agent_id
    heartbeat(store, agent_id, job_protocol_version=2, gui_protocol_version=2)
    response = client.post('/execution-context', data={'context_id':agent_id, 'next':'/'})
    assert response.status_code == 302 and auth.execution_context(user_id) == agent_id



def test_concurrent_legacy_migration_preserves_approved_identity(tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    store = DistributedAgentStore(tmp_path); agent_id = enroll(store)
    with sqlite3.connect(store.path) as db:
        db.execute('ALTER TABLE distributed_agents DROP COLUMN job_protocol_version')
        db.execute('ALTER TABLE distributed_agents DROP COLUMN gui_protocol_version')
    barrier = threading.Barrier(8)
    def open_store(_):
        barrier.wait(timeout=5)
        return DistributedAgentStore(tmp_path).get(agent_id)
    with ThreadPoolExecutor(max_workers=8) as workers:
        records = list(workers.map(open_store, range(8)))
    assert all(r['state'] == 'approved' and not r['gui_compatible'] for r in records)


def test_approval_awaits_first_authenticated_report_without_claiming_upgrade(tmp_path):
    store = DistributedAgentStore(tmp_path)
    agent_id = enroll(store)
    before = store.get(agent_id)
    assert before['gui_compatibility_status'] == 'awaiting_report'
    assert before['gui_compatibility_label'] == 'Waiting for Agent status'
    assert not before['gui_compatible']
    assert 'No version mismatch has been established' in before['gui_compatibility_error']
    assert selectable_gui_agents([before]) == []
    after = heartbeat(store, agent_id, job_protocol_version=2, gui_protocol_version=2)
    assert after['gui_compatibility_status'] == 'ready' and after['gui_compatible']
    assert after['id'] == before['id'] and after['public_key'] == before['public_key']
    assert after['approved_at'] == before['approved_at']
    assert selectable_gui_agents([after]) == [after]


def test_reported_mismatch_is_distinct_from_missing_report(tmp_path):
    store = DistributedAgentStore(tmp_path); agent_id = enroll(store)
    old = heartbeat(store, agent_id, job_protocol_version=1, gui_protocol_version=1)
    assert old['gui_compatibility_status'] == 'mismatch'
    assert old['gui_compatibility_label'] == 'GUI protocol mismatch'
    assert 'reported job protocol 1 and GUI protocol 1' in old['gui_compatibility_error']
    assert 'Mainframe requires job protocol 2 and GUI protocol 2' in old['gui_compatibility_error']
    assert not old['gui_compatible'] and selectable_gui_agents([old]) == []
    legacy = heartbeat(store, agent_id)
    assert legacy['gui_compatibility_status'] == 'unconfirmed'
    assert 'missing or invalid protocol information' in legacy['gui_compatibility_error']


def test_mainframe_shows_pending_status_then_removes_note_after_compatible_report(tmp_path, monkeypatch):
    app = create_app(str(tmp_path)); app.testing = True
    DistributedSettingsStore(tmp_path).save({'role':'mainframe','mainframe_listen_interfaces':['127.0.0.1'], 'mainframe_port':5051})
    store = app.extensions['distributed_agent_store']; agent_id = enroll(store)
    monkeypatch.setattr('twn_toolkit.distributed_job_epochs.DistributedJobStore.enqueue',
                        lambda *a, **kw: pytest.fail('status display must not queue work'))
    client = app.test_client()
    before = client.get('/mainframe')
    assert before.status_code == 200
    assert b'Waiting for Agent status' in before.data and b'Awaiting heartbeat' in before.data
    assert b'GUI update required' not in before.data
    assert b'Re-enrollment is not required' not in before.data
    heartbeat(store, agent_id, job_protocol_version=2, gui_protocol_version=2)
    after = client.get('/mainframe')
    assert after.status_code == 200
    assert b'data-agent-compatibility' not in after.data
    assert b'Awaiting heartbeat' not in after.data


def test_known_mismatch_is_not_hidden_by_another_missing_protocol(tmp_path):
    store = DistributedAgentStore(tmp_path); agent_id = enroll(store)
    report = heartbeat(store, agent_id, job_protocol_version=3, gui_protocol_version=0)
    assert report['gui_compatibility_status'] == 'mismatch'
    assert 'job protocol 3 and GUI protocol not reported/invalid' in report['gui_compatibility_error']
    assert not report['gui_compatible'] and selectable_gui_agents([report]) == []
