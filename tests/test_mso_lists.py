"""Saved-list replication exercises real validators, migration and fleet behavior."""
import copy
import json
from unittest.mock import patch

import pytest

from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.mso import MsoStore, MsoConflict, validate
from twn_toolkit.mso_types import LIST_TYPES
from twn_toolkit.lldp_tools import default_persona


def payload(kind, name='Shared list'):
    result = {'name': name}
    if kind == 'ping.profile':
        result['targets'] = [{'host': '192.0.2.1', 'label': ''}]
    elif kind == 'dns.hosts':
        result['values'] = [{'host': 'example.org', 'label': 'Example'}]
    elif kind == 'dns.servers':
        result['values'] = [{'address': '192.0.2.53', 'label': 'Resolver'}]
    elif kind == 'tcp.ports':
        result['values'] = '443,8443'
    elif kind == 'wol.targets':
        result['values'] = '02:11:22:33:44:55'
    elif kind == 'snmp.credentials':
        result.update(version='v2c', community='fixture-community-secret')
    elif kind == 'snmp.oids':
        result['source'] = 'System Name = 1.3.6.1.2.1.1.5.0'
    elif kind == 'ssh.matrix':
        result.update(matrix='Host,Name\n192.0.2.1,Gateway',actions=[],created_at='2026-09-10T00:00:00+00:00',updated_at='2026-09-10T00:00:00+00:00')
    elif kind == 'fortigate.profile':
        result.update(host='https://192.0.2.10', api_key='fixture-api-key', verify_tls=True, default_vdom='root')
    elif kind == 'fortiauthenticator.profile':
        result.update(host='https://192.0.2.10', username='api', password='fixture-password', verify_tls=True, timeout=20)
    elif kind == 'radius.servers':
        result.update(host='192.0.2.10', port=1812, secret='fixture-radius-secret')
    elif kind == 'radius.credentials':
        result.update(username='tester', password='fixture-password')
    elif kind == 'radius.attributes':
        result['source'] = 'NAS-Identifier = audit'
    elif kind == 'lldp.persona':
        with patch('twn_toolkit.lldp_tools.interface_mac', return_value='02:11:22:33:44:55'):
            result = default_persona(interface='eth0')
        result['name'] = name
    else:
        result['values'] = 'Gateway = 192.0.2.1'
    return validate(kind, result)


def node(path, role, kind):
    settings = DistributedSettingsStore(path)
    settings.save({**settings.get(), 'role': role, 'agent_mainframe_url': 'https://main.example:7443'})
    return MsoStore(path, kind)


def sync(main, agent, types=None):
    for _ in range(8):
        req = agent.request(types)
        response = main.exchange(agent.node, req)
        agent.receive(response, req)
        if len(response['objects']) < 4 and not agent.request(types)['proposals']:
            break


def named(store, name):
    return next(p for p in store.profiles(metadata=True) if p['name'] == name)


@pytest.mark.parametrize('kind', [kind for kind in LIST_TYPES if kind != 'snmp.hosts' and not kind.startswith('terminal.')])
def test_all_list_types_bidirectional_conflicts_and_withdrawal(tmp_path, kind):
    main = node(tmp_path/'main', 'mainframe', kind)
    agent = node(tmp_path/'agent', 'agent', kind)
    created = main.save(payload(kind), enabled=True)
    sync(main, agent)
    assert named(agent, 'Shared list')['mso']['id'] == created['mso']['id']
    agent.save(payload(kind, 'Agent edit'), 'Shared list')
    sync(main, agent)
    assert named(main, 'Agent edit')['mso']['id'] == created['mso']['id']
    main.save(payload(kind, 'Main edit'), 'Agent edit')
    agent.save(payload(kind, 'Offline edit'), 'Agent edit')
    sync(main, agent)
    conflict = named(agent, 'Offline edit')['mso']
    assert conflict['state'] == 'Conflict'
    agent.resolve(conflict['id'], 'fleet', conflict['version'])
    current = named(agent, 'Main edit')
    local = agent.save(payload(kind, 'Main edit'), enabled=False, expected=current['mso']['version'])
    assert local['mso']['id'] != created['mso']['id']
    sync(main, agent)
    assert not any(p['name'] == 'Main edit' for p in main.profiles())
    assert named(agent, 'Main edit')['mso']['state'] == 'Local'


@pytest.mark.parametrize('kind', [kind for kind in LIST_TYPES if kind != 'snmp.hosts' and not kind.startswith('terminal.')])
def test_legacy_migration_is_local_stable_and_retains_source(tmp_path, kind):
    legacy = [payload(kind, 'Legacy')]
    source = tmp_path/LIST_TYPES[kind].filename
    source.write_text(json.dumps(legacy))
    first = MsoStore(tmp_path, kind).profiles(metadata=True)
    second = MsoStore(tmp_path, kind).profiles(metadata=True)
    assert first == second
    assert first[0]['mso']['state'] == 'Local'
    assert json.loads(source.read_text()) == legacy
    assert MsoStore(tmp_path, kind).request()['proposals'] == []


def test_old_clients_only_receive_ping_and_upgrade_rescans(tmp_path):
    main = node(tmp_path/'main', 'mainframe', 'dns.hosts')
    main.save(payload('dns.hosts'), enabled=True)
    ping = MsoStore(main.instance)
    ping.save(payload('ping.profile'), enabled=True)
    agent = node(tmp_path/'agent', 'agent', 'dns.hosts')
    old = agent.request(['ping.profile'])
    old.pop('types')  # Original pilot protocol had no capabilities.
    response = main.exchange(agent.node, old)
    assert [p['kind'] for p in response['objects']] == ['ping.profile']
    agent.receive(response, old)
    assert not agent.profiles()
    upgraded = agent.request()
    assert upgraded['cursor'] == 0
    assert upgraded['epoch'] != old['epoch']
    agent.receive(response, old)  # Late reply must not advance the new cursor.
    assert agent.request()['cursor'] == 0
    sync(main, agent)
    assert named(agent, 'Shared list')['mso']['state'] == 'Synced'


@pytest.mark.parametrize('kind', [kind for kind in LIST_TYPES if kind != 'snmp.hosts' and not kind.startswith('terminal.')])
def test_replace_failure_rolls_back_entire_library(tmp_path, kind):
    store = MsoStore(tmp_path, kind)
    store.replace_local([payload(kind)])
    before = store.backup_snapshot()
    with pytest.raises((ValueError, TypeError)):
        store.replace_local([payload(kind, 'Changed'), {'name': 'Broken', 'unsupported': object()}])
    assert store.backup_snapshot() == before


def test_lldp_sync_never_probes_hardware_or_retains_extra_fields():
    value = payload('lldp.persona')
    value.update(interface='origin-only', unrelated_secret='not-shared')
    with patch('twn_toolkit.lldp_tools.available_interfaces', side_effect=AssertionError('hardware access')), patch('twn_toolkit.lldp_tools.interface_mac', side_effect=AssertionError('hardware access')):
        shared = validate('lldp.persona', value)
    assert 'interface' not in shared and 'unrelated_secret' not in shared
    for key, bad in [('capabilities', None), ('ttl', True), ('quiet_lldpd', 'false')]:
        with pytest.raises(ValueError):
            validate('lldp.persona', {**value, key: bad})


def test_incoming_list_migrates_legacy_before_checking_name_collision(tmp_path):
    main = node(tmp_path/'main', 'mainframe', 'dns.hosts')
    shared = main.save(payload('dns.hosts'), enabled=True)
    agent = node(tmp_path/'agent', 'agent', 'ping.profile')
    legacy = payload('dns.hosts')
    (agent.instance/LIST_TYPES['dns.hosts'].filename).write_text(json.dumps([legacy]))
    sync(main, agent)
    lists = MsoStore(agent.instance, 'dns.hosts').profiles(metadata=True)
    assert len(lists) == 2
    assert next(p for p in lists if not p['mso']['enabled'])['values'] == legacy['values']
    assert next(p for p in lists if p['mso']['id'] == shared['mso']['id'])['mso']['conflict']


def test_migrating_one_list_does_not_read_unrelated_library(tmp_path):
    (tmp_path/LIST_TYPES['dns.hosts'].filename).write_text('broken unrelated JSON')
    assert MsoStore(tmp_path).profiles() == []
    with pytest.raises(ValueError):
        MsoStore(tmp_path, 'dns.hosts')


@pytest.mark.parametrize('kind,endpoint,data', [
    ('dns.hosts', '/dns-response/profiles/hosts', {'profile_name':'HTTP list','values':'example.org'}),
    ('dns.servers', '/dns-response/profiles/servers', {'profile_name':'HTTP list','values':'192.0.2.53'}),
    ('ntp.hosts', '/ntp-test/profiles', {'name':'HTTP list','values':'192.0.2.1'}),
    ('traceroute.hosts', '/traceroute/profiles', {'name':'HTTP list','values':'192.0.2.1'}),
    ('tcp.hosts', '/port-scanner/profiles/hosts', {'name':'HTTP list','values':'192.0.2.1'}),
    ('tcp.ports', '/port-scanner/profiles/ports', {'name':'HTTP list','values':'443'}),
    ('wol.targets', '/wake-on-lan/profiles', {'name':'HTTP list','values':'02:11:22:33:44:55'}),
    ('snmp.oids', '/snmp-test/profiles/oids', {'name':'HTTP list','source':'System Name = 1.3.6.1.2.1.1.5.0'}),
    ('radius.attributes', '/radius-test/profiles/attributes', {'name':'HTTP list','attributes':'NAS-Identifier = audit'}),
])
def test_http_list_sharing_guarded_edits_and_delete(tmp_path, kind, endpoint, data):
    from twn_toolkit.app import create_app
    from twn_toolkit.auth import AuthStore
    store = node(tmp_path, 'mainframe', kind)
    app = create_app(str(tmp_path))
    AuthStore(tmp_path).create_user('admin', 'Temporary admin password', is_admin=True)
    client = app.test_client()
    client.post('/login', data={'username':'admin', 'password':'Temporary admin password'})
    response = client.post('/tools'+endpoint, data={**data,'mso_kind':kind,'mso_enabled':'true'})
    assert response.status_code == 200, response.json
    info = response.json['profile']['mso']
    assert info['enabled'] and info['state'] == 'Synced'
    assert client.post('/tools'+endpoint, data=data).status_code == 409
    guard = {'mso_kind':kind,'mso_id':info['id'],'mso_version':str(info['version'])}
    assert client.post('/tools'+endpoint, data={**data,**guard}).status_code == 200
    assert client.post('/tools'+endpoint+'/delete', data={'name':'HTTP list',**guard}).status_code == 409
    latest = named(store,'HTTP list')['mso']
    assert client.post('/tools'+endpoint+'/delete', data={'name':'HTTP list',**guard,'mso_version':str(latest['version'])}).status_code == 200
    assert not any(p['name']=='HTTP list' for p in store.profiles())


def test_conflicts_are_filtered_and_resolution_cannot_cross_tool_permissions(tmp_path):
    from twn_toolkit.app import create_app
    from twn_toolkit.auth import AuthStore
    main=node(tmp_path/'main','mainframe','dns.hosts')
    agent=node(tmp_path/'agent','agent','dns.hosts')
    for kind in ['dns.hosts','ntp.hosts']:
        main_list=MsoStore(main.instance,kind);agent_list=MsoStore(agent.instance,kind)
        main_list.save(payload(kind, kind+' private'),enabled=True);sync(main,agent)
        main_list.save(payload(kind,kind+' main'),kind+' private')
        agent_list.save(payload(kind,kind+' draft'),kind+' private');sync(main,agent)
    auth=AuthStore(agent.instance);auth.create_user('admin','Temporary admin password',is_admin=True)
    access=auth.save_access_profile(name='DNS only',tool_ids=['tools.dns_response'])
    auth.create_user('dns','Temporary user password',access_profile_ids=[access['id']])
    app=create_app(str(agent.instance));client=app.test_client()
    client.post('/login',data={'username':'dns','password':'Temporary user password'})
    response=client.get('/tools/mso/conflicts');assert response.status_code==200
    assert b'dns.hosts draft' in response.data and b'ntp.hosts draft' not in response.data
    ntp=named(MsoStore(agent.instance,'ntp.hosts'),'ntp.hosts draft')['mso']
    for kind,code in [('ntp.hosts',403),('dns.hosts',404)]:
        assert client.post('/tools/mso/conflicts/resolve',data={'kind':kind,'object_id':ntp['id'],'version':ntp['version'],'choice':'fleet'}).status_code==code
    assert named(MsoStore(agent.instance,'ntp.hosts'),'ntp.hosts draft')['mso']['conflict']


@pytest.mark.parametrize('invalid', [{'name':'not a list'}, [None], [{'name':7}]])
def test_invalid_legacy_shape_does_not_mark_migration_complete(tmp_path, invalid):
    source=tmp_path/LIST_TYPES['dns.hosts'].filename
    source.write_text(json.dumps(invalid))
    with pytest.raises(ValueError,match='Repair it before migration'):
        MsoStore(tmp_path,'dns.hosts')
    source.write_text(json.dumps([payload('dns.hosts')]))
    assert len(MsoStore(tmp_path,'dns.hosts').profiles())==1



def test_new_capabilities_cannot_hide_rollback_below_last_seen_revision(tmp_path):
    main=node(tmp_path/'main','mainframe','ping.profile')
    agent=node(tmp_path/'agent','agent','ping.profile')
    main.save(payload('ping.profile'),enabled=True)
    sync(main,agent,['ping.profile'])
    previous=agent.request(['ping.profile'])
    upgraded=agent.request()
    assert upgraded['cursor']==0 and upgraded['history']==previous['cursor']>0
    with main._tx() as db:
        main._set(db,'sequence',0)
        db.execute('DELETE FROM mso_hub')
    with pytest.raises(ValueError,match='recovery requires explicit reconciliation'):
        main.exchange(agent.node,upgraded)
    # Losing capabilities also retains the recovery watermark.
    downgraded=agent.request(['ping.profile'])
    assert downgraded['history']==previous['cursor']
    with pytest.raises(ValueError,match='recovery requires explicit reconciliation'):
        main.exchange(agent.node,downgraded)
