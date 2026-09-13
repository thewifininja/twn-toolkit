import copy
import json
import pytest
from twn_toolkit.fortigate_loop import collect, STATUS, CONFIG
from twn_toolkit.fortigate import FortiGateError
from test_fortigate_dhcp import Client, ROOT, CHILD


def port(name,peer='',remote='',trunk=''):
    return dict(interface=name,status='up',isl_peer_device_name=peer,isl_peer_port_name=remote,isl_peer_trunk_name=trunk)


class SwitchClient(Client):
    api_key='private-token'
    def __init__(self):
        super().__init__()
        self.inventory=[{'switch-id':'A','serial':'HARDWARE1','status':'Connected','os_version':'7.6.6',
            'ports':[port('port1','B','port3','trunkB'),port('port2','B','port4','trunkB')]},
            {'switch-id':'B','serial':'HARDWARE2','status':'Connected','os_version':'3.6.12',
            'ports':[port('port3','A','port1','trunkA'),port('port4','A','port2','trunkA')]}]
        self.config_error=False;self.wrong_serial=False
    def request(self,method,endpoint,params):
        assert method=='GET'
        if endpoint.endswith('/csf'):return super().request(method,endpoint,params)
        self.calls.append((endpoint,params))
        if endpoint.endswith(STATUS):data=copy.deepcopy(self.inventory)
        elif endpoint.endswith(CONFIG):
            if self.config_error:raise FortiGateError('private-token unavailable')
            data=[{'switch-id':s['switch-id'],'password':'never retain', 'ports':[
                {'port-name':p['interface'],'stp-state':'enabled','loop-guard':'disabled','secret':'never retain'} for p in s['ports']]} for s in self.inventory]
        else:raise AssertionError(endpoint)
        return dict(serial=ROOT if self.wrong_serial or not endpoint.startswith('/csf/') else CHILD,status='success',vdom='root',results=data)


def test_trunks_are_topology_not_loop_findings_and_guard_state_is_unknown():
    c=SwitchClient();data=collect(c,fabric=True)
    assert data['switch_count']==4 and data['port_count']==8 and data['api_calls']==6
    assert data['review_count']==0 and not data['partial']
    for g in data['gates']:
        assert len(g['findings'])==2 and all(f['kind']=='Topology' for f in g['findings'])
        assert g['switches'][0]['id']!='HARDWARE1' and g['switches'][0]['serial']=='HARDWARE1'
        assert all(p['loop_state']=='Unavailable' and p['stp_state']=='Unavailable' for s in g['switches'] for p in s['ports'])
    assert 'never retain' not in json.dumps(data)
    assert any(path.startswith('/csf/') for path,_ in c.calls)


@pytest.mark.parametrize('change',['duplicate_remote','no_trunk','self','asymmetric'])
def test_suspicious_relationships_have_explanations_not_confirmed_loop_claims(change):
    c=SwitchClient();p=c.inventory[0]['ports'][0]
    if change=='duplicate_remote':p['isl_peer_port_name']='port4'
    elif change=='no_trunk':p['isl_peer_trunk_name']=''
    elif change=='self':p['isl_peer_device_name']='A'
    else:p['isl_peer_port_name']='missing'
    data=collect(c)
    assert data['review_count']>0
    assert all(f['message'] for f in data['gates'][0]['findings'])


def test_offline_inventory_is_not_an_active_topology_observation():
    c=SwitchClient()
    for s in c.inventory:s['status']='Disconnected'
    assert not collect(c)['gates'][0]['findings']


def test_configuration_failure_is_partial_and_does_not_expose_secrets():
    c=SwitchClient();c.config_error=True
    data=collect(c)
    assert data['partial'] and data['gates'][0]['switches'][0]['ports'][0]['loop_config']=='Unavailable'
    assert 'private-token' not in json.dumps(data)


def test_wrong_downstream_identity_is_unavailable_without_root_fallback():
    c=SwitchClient();c.wrong_serial=True;data=collect(c,fabric=True)
    assert data['partial'] and data['gates'][1]['errors'] and data['gates'][1]['switches']==[]
    assert len([p for p,_ in c.calls if p==STATUS])==1


@pytest.mark.parametrize('bad',['duplicate_switch','duplicate_port','limit','cancel'])
def test_ambiguous_or_unbounded_snapshots_are_rejected(monkeypatch,bad):
    c=SwitchClient()
    if bad=='duplicate_switch':c.inventory.append(copy.deepcopy(c.inventory[0]))
    if bad=='duplicate_port':c.inventory[0]['ports'].append(copy.deepcopy(c.inventory[0]['ports'][0]))
    if bad=='limit':monkeypatch.setattr('twn_toolkit.fortigate_loop.MAX_PORTS',1)
    def check():
        if bad=='cancel':raise ValueError('cancelled')
    with pytest.raises((FortiGateError,ValueError)):collect(c,check=check)


@pytest.fixture
def browser(tmp_path,monkeypatch):
    from twn_toolkit import create_app
    from twn_toolkit.profiles import ProfileStore
    from twn_toolkit.operational import OperationalSettingsStore
    app=create_app(str(tmp_path));app.testing=True
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib':0})
    ProfileStore(str(tmp_path)).upsert({'name':'Lab','host':'https://fixture.invalid','api_key':'private-token'})
    monkeypatch.setattr('twn_toolkit.fortigate.FortiGateClient.from_profile',lambda _:SwitchClient())
    yield app.test_client()
    app.extensions['remote_session_manager'].close()


def test_worker_retains_result_and_owner_scoped_pages(browser):
    from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
    from twn_toolkit.diagnostic_worker import execute_scan
    assert browser.get('/fortigate/loop-inspector').status_code==200
    response=browser.post('/fortigate/loop-inspector',data={'profile':'Lab','scope':'fabric'})
    assert response.status_code==303
    store=DiagnosticJobStore(browser.application.instance_path);job=store.claim()
    execute_scan(store,job['id'],job['token']);store.release(job['id'],job['token'])
    saved=store.get(job['id'],'test-user');assert saved['state']=='succeeded',saved['error']
    page=browser.get(response.location)
    assert page.status_code==200 and b'Experimental coverage' in page.data
    detail=browser.get(response.location+'&gate='+ROOT+'&switch=HARDWARE1')
    assert b'port1' in detail.data and b'Blocking state' in detail.data
    download=browser.get('/fortigate/loop-inspector/jobs/'+job['id']+'/download')
    assert download.status_code==200 and b'private-token' not in download.data
    other=store.enqueue(user_id='foreign',tool='appliance_read',config={'mode':'loop_inspector','tool_id':'fortigate.loop_inspector'})
    for suffix in ['status','download']:
        assert browser.get('/fortigate/loop-inspector/jobs/'+other+'/'+suffix).status_code==404
    assert browser.post('/fortigate/loop-inspector/jobs/'+other+'/cancel').status_code==404

STP='''Vdom: root
A:
Instance ID 0 (CST)
port1 1G 20000 128 DESIGNATED FORWARDING 2 EN ED
port2 - 200000000 128 DISABLED DISCARDING 2 ED
trunk1 2G 10000 128 ALTERNATIVE DISCARDING 2 EN
port3 1G 20000 128 DESIGNATED DISCARDING 2 EN BG
Instance ID 15
trunk1 2G 10000 128 ROOT FORWARDING 2 EN
'''
GUARD='''Vdom: root
port1 disabled - - - - -
port2 enabled blocked 45 0 1 2026-09-13
'''
LLDP='''Vdom: root
Managed Switch : A 0
port1 Up Branch Switch 120 B - port5
port2 Down - - - - -
'''


def test_diagnostic_parsing_preserves_instances_and_disabled_role():
    from twn_toolkit.fortigate_loop_ssh import parse_output
    rows=parse_output('stp',STP,'A')
    assert len(rows)==5 and rows[1]['role']=='DISABLED' and rows[-1]['instance']=='15'
    assert parse_output('guard',GUARD,'A')[1]['state']=='blocked'
    assert parse_output('lldp',LLDP,'A')[0]['detail'].startswith('Branch Switch')


@pytest.mark.parametrize('output',[STP+'--More--',STP.replace('Vdom: root','Vdom: other'),STP.replace('A:','B:'),'permission denied',''])
def test_incomplete_wrong_identity_and_unknown_cli_formats_are_unavailable(output):
    from twn_toolkit.fortigate_loop_ssh import parse_output
    with pytest.raises(ValueError):parse_output('stp',output,'A')


def test_ssh_identity_binding_protection_and_normal_stp_classification(monkeypatch):
    from twn_toolkit import fortigate_loop_ssh as ssh
    data=collect(SwitchClient())
    data['gates'][0]['switches']=data['gates'][0]['switches'][:1]
    calls=[]
    monkeypatch.setattr(ssh,'open_ssh_client',lambda **kw:object())
    monkeypatch.setattr(ssh,'close_ssh_client',lambda c:None)
    def read(client,command,*args):
        calls.append(command)
        if command.startswith('get system'):return 'Serial-Number: '+ROOT
        return GUARD if 'loop-guard' in command else LLDP if 'lldp' in command else STP
    monkeypatch.setattr(ssh,'read_command',read)
    ssh.supplement(data,{},lambda:None)
    assert data['protection_count']==2
    assert len(calls)==4 and all(c.startswith(('get system status | grep Serial','diagnose switch-controller switch-info ')) for c in calls)
    messages=[f['message'] for f in data['gates'][0]['findings']]
    assert any('normal redundancy' in m for m in messages)
    assert not any('port2' in f['ports'] and 'STP' in f['message'] for f in data['gates'][0]['findings'] if f['kind']=='Protection')
    calls.clear()
    monkeypatch.setattr(ssh,'read_command',lambda *a:'Serial-Number: WRONG')
    other=collect(SwitchClient());ssh.supplement(other,{},lambda:None)
    assert other['partial'] and not any('diagnostics' in s for s in other['gates'][0]['switches'])


def test_ssh_host_selection_rejects_missing_host(browser):
    response=browser.post('/fortigate/loop-inspector',data={'profile':'Lab','ssh_host':'missing'})
    assert response.status_code==400


def test_inspector_requires_its_own_tool_permission(tmp_path):
    from twn_toolkit import create_app
    from twn_toolkit.auth import AuthStore
    app=create_app(str(tmp_path));auth=AuthStore(str(tmp_path))
    auth.create_user('admin','TemporaryPassword123!',is_admin=True)
    grant=auth.save_access_profile(name='Ping',tool_ids=['tools.ping'])
    auth.create_user('reader','TemporaryPassword123!',access_profile_ids=[grant['id']])
    client=app.test_client();client.post('/login',data={'username':'reader','password':'TemporaryPassword123!'})
    for url in ['/fortigate/loop-inspector','/fortigate/loop-inspector/jobs/missing/status','/fortigate/loop-inspector/jobs/missing/download']:
        assert client.get(url).status_code==403
    assert client.post('/fortigate/loop-inspector').status_code==403
    assert client.post('/fortigate/loop-inspector/jobs/missing/cancel').status_code==403
    app.extensions['remote_session_manager'].close()
