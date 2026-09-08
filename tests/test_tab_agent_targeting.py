"""Targets belong to page/job URLs, independently of tabs sharing a login."""
import base64
import hashlib
import json

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.execution_context import switch_destination


@pytest.fixture
def fabric(tmp_path, monkeypatch):
    app = create_app(str(tmp_path))
    auth = AuthStore(str(tmp_path))
    owner = auth.create_user('owner', 'TemporaryPassword123!', is_admin=True)
    auth.create_user('other', 'TemporaryPassword123!', is_admin=True)
    auth.create_user('ordinary', 'TemporaryPassword123!', is_admin=False)
    DistributedSettingsStore(tmp_path).save({'role': 'mainframe', 'mainframe_listen_interfaces': ['127.0.0.1'], 'mainframe_port': 5051})
    agents = app.extensions['distributed_agent_store']
    ids = []
    for n in (1, 2):
        public = bytes([n]) * 32
        item = agents.request_enrollment(public_key=public.hex(), fingerprint=hashlib.sha256(public).hexdigest(), name=f'Agent {n}')
        agents.set_state(item['id'], 'approved')
        agents.record_heartbeat(item['id'], capabilities=[{'id': 'system.http.tunnel', 'version': '1'}, {'id':'system.identity','version':'1'}, {'id':'tools.dns.lookup','version':'1'}],
                               address='127.0.0.1', job_protocol_version=2, gui_protocol_version=2)
        ids.append(item['id'])
    calls = []
    jobs = app.extensions['distributed_job_store']
    enqueue = jobs.enqueue
    def complete_request(**values):
        calls.append(values)
        job = enqueue(**values)
        if values['capability_id'] != 'system.http.tunnel':
            return job
        claimed = jobs.claim(values['agent_id'])[0]
        jobs.control(job['id'], agent_id=values['agent_id'], attempt_token=claimed['attempt_token'], action='start')
        data = {'agent': values['agent_id'], 'method': values['inputs']['method'], 'path': values['inputs']['path']}
        jobs.complete(job['id'], agent_id=values['agent_id'], attempt_token=claimed['attempt_token'], state='succeeded',
                      output={'status':200, 'headers':[['Content-Type','application/json']], 'body':base64.b64encode(json.dumps(data).encode()).decode()})
        return job
    monkeypatch.setattr(jobs, 'enqueue', complete_request)
    def login(name='owner'):
        client = app.test_client()
        assert client.post('/login', data={'username':name,'password':'TemporaryPassword123!'}).status_code == 302
        return client
    yield app, auth, owner, ids, calls, login
    app.extensions['remote_session_manager'].close()


def test_two_devices_and_two_tabs_keep_explicit_targets(fabric):
    app, auth, owner, (a, b), calls, login = fabric
    ipad, laptop = login(), login()
    # An old account preference must not determine the new request target.
    auth.set_execution_context(owner['id'], b)
    for client, target in ((ipad, a), (laptop, b)):
        result = client.post('/execution-context', data={'context_id': target, 'next':'/tools/remote-terminal'})
        assert result.headers['Location'] == f'/agents/{target}/ui/tools/remote-terminal'
    for client, target in ((ipad,a), (laptop,b), (laptop,a), (ipad,b)):
        url = f'/agents/{target}/ui/tools/fixture'
        assert client.get(url).json['agent'] == target
        assert client.post(url, json={'action':'fixture'}).json == {'agent':target,'method':'POST','path':'/tools/fixture'}
        assert client.get('/').status_code == 200
        assert client.get('/session/activity').status_code == 200
    assert auth.execution_context(owner['id']) == b  # Selection never rewrites account state.
    assert all(call['inputs']['prefix'] == f"/agents/{call['agent_id']}/ui" for call in calls)


def test_switch_uses_source_tab_path_and_preserves_other_tab(fabric):
    app, auth, owner, (a,b), calls, login = fabric
    client = login()
    auth.set_execution_context(owner['id'], 'agent_unrelated')
    source = f'/agents/{a}/ui/tools/dns-response?folder=a%20b&_twn_response=old#results'
    changed = client.post('/execution-context', data={'context_id':b,'next':source})
    assert changed.headers['Location'] == f'/agents/{b}/ui/tools/dns-response?folder=a+b#results'
    local = client.post('/execution-context', data={'context_id':'local','next':source})
    assert local.headers['Location'] == '/tools/dns-response?folder=a+b#results'
    assert client.get(f'/agents/{a}/ui/tools/fixture').json['agent'] == a


@pytest.mark.parametrize('path', ['https://evil.invalid/', '//evil.invalid/', '/\\evil.invalid/', '/%2f%2fevil.invalid/', '/agents/agent_a/ui/../../settings', '/\n/evil.invalid/'])
def test_switch_never_redirects_outside_origin_or_traverses_target(path):
    assert switch_destination(path, 'agent_b')[1] == '/agents/agent_b/ui/'


def test_appearance_is_bound_to_explicit_agent_and_local_url(fabric):
    app, auth, owner, (a,b), calls, login = fabric
    client = login()
    auth.set_execution_context(owner['id'], b)
    assert client.post(f'/settings/appearance?agent_id={a}', json={'palette':'gruvbox'}).status_code == 200
    assert client.post(f'/settings/appearance?agent_id={b}', json={'palette':'tokyo-night'}).status_code == 200
    assert client.post('/settings/appearance', json={'palette':'osaka-jade'}).status_code == 200
    assert auth.user_appearance(owner['id'], a)['palette'] == 'gruvbox'
    assert auth.user_appearance(owner['id'], b)['palette'] == 'tokyo-night'
    assert auth.user_appearance(owner['id'])['palette'] == 'osaka-jade'
    client.get(f'/agents/{a}/ui/tools/fixture')
    assert calls[-1]['inputs']['fabric']['appearance_url'] == f'/settings/appearance?agent_id={a}'
    assert client.post('/settings/appearance?agent_id=agent_missing', json={'palette':'gruvbox'}).status_code == 404


def test_permissions_revocation_and_offline_failure_do_not_retarget(fabric, monkeypatch):
    app, auth, owner, (a,b), calls, login = fabric
    ordinary = login('ordinary')
    assert ordinary.post('/execution-context', data={'context_id':a,'next':'/'}).status_code == 403
    assert ordinary.post(f'/agents/{a}/ui/tools/fixture').status_code == 403
    assert ordinary.post(f'/settings/appearance?agent_id={a}', json={'palette':'gruvbox'}).status_code == 403
    client = login()
    approved = app.extensions['distributed_agent_store'].get(a)
    app.extensions['distributed_agent_store'].set_state(a, 'revoked')
    assert client.post(f'/agents/{a}/ui/tools/fixture').status_code == 404
    assert not calls
    agents = app.extensions['distributed_agent_store']
    original_get = agents.get
    monkeypatch.setattr(agents, 'get', lambda identifier: {**approved, 'online': False} if identifier == a else original_get(identifier))
    assert client.post(f'/agents/{a}/ui/tools/fixture').status_code == 503
    recovery = client.get(f'/agents/{a}/ui/tools/fixture', headers={'Accept':'text/html'})
    assert recovery.status_code == 302 and recovery.headers['Location'] == '/tools/fixture'
    assert not calls
    assert client.get(f'/agents/{b}/ui/tools/fixture').json['agent'] == b
    assert client.get('/').status_code == 200


def test_legacy_workspace_and_identity_actions_have_explicit_target(fabric):
    app, auth, owner, (a,b), calls, login = fabric
    client = login()
    auth.set_execution_context(owner['id'], b)
    page = client.get(f'/agents/{a}/')
    assert page.status_code == 200
    assert f'value="{a}" selected'.encode() in page.data
    assert client.post('/mainframe/system-identity', data={'agent_id':a}).status_code == 302
    assert calls[-1]['agent_id'] == a
    assert client.post(f'/agents/{b}/system-information/refresh').status_code == 302
    assert calls[-1]['agent_id'] == b
