from contextlib import contextmanager
from unittest.mock import Mock
import json
import pytest
from twn_toolkit.fortigate import FortiGateError
from twn_toolkit.fortigate_dhcp import FabricTarget, collect_inventory, discover, lease_duration

ROOT='FGROOT'; CHILD='FGCHILD'
class Client:
    def __init__(self, fail=None):
        self.calls=[]; self.fail=fail
    def test_connection(self):
        return {'serial':ROOT,'status':'success','results':{'hostname':'Home','model_number':'70F'}}
    @contextmanager
    def pooled(self):
        yield self
    def request(self, method, endpoint, params):
        assert method=='GET'
        self.calls.append((endpoint,params))
        sn=CHILD if endpoint.startswith('/csf/') else ROOT
        if self.fail and self.fail in endpoint:
            raise FortiGateError('secret-token raw device error')
        if endpoint.endswith('/csf'):
            result={'devices':{'fortigate':[
                {'serial':ROOT,'host_name':'Home','vdoms':['root','other']},
                {'serial':CHILD,'host_name':'Dad','proxy_path':ROOT+':'+CHILD,'vdoms':['root']}]}}
        elif endpoint.endswith('/server'):
            result=[{'id':1,'status':'disable','interface':'lan','netmask':'255.255.255.0',
                'default-gateway':'10.0.0.1','dns-service':'default','lease-time':3600,
                'ddns-key':'must-not-retain','ip-range':[{'id':1,'start-ip':'10.0.0.2','end-ip':'10.0.0.99'},
                {'id':2,'start-ip':'10.0.0.150','end-ip':'10.0.0.200'}],
                'reserved-address':[{'id':1,'type':'option82','circuit-id':'circuit','ip':'10.0.0.9'}]}]
        elif endpoint.endswith('/interface'):
            result=[{'name':'lan','alias':'LAN','ip':'10.0.0.1 255.255.255.0','password':'hidden'}]
        elif endpoint.endswith('/dns'):
            result={'primary':'1.1.1.1','secondary':'9.9.9.9'}
        else:
            result=[{'ip':'10.0.0.4','interface':'lan','server_mkey':1,'hostname':'=evil'}]
        return {'serial':sn,'vdom':params.get('vdom'),'status':'success','results':result}


def test_fabric_preserves_every_range_disabled_scopes_and_identity_without_secrets():
    c=Client(); data=collect_inventory(c,fabric=True,vdom='*')
    assert len(data['scopes'])==3
    assert {(s['serial'],s['vdom']) for s in data['scopes']}=={(ROOT,'root'),(ROOT,'other'),(CHILD,'root')}
    assert all(len(s['ip-range'])==2 and s['status']=='disable' for s in data['scopes'])
    assert data['scopes'][0]['system_dns']==['1.1.1.1','9.9.9.9']
    assert 'must-not-retain' not in json.dumps(data) and 'hidden' not in json.dumps(data)
    assert data['scopes'][0]['reserved-address'][0]['type']=='option82'
    assert data['api_calls']==len(c.calls)+1


def test_single_gate_does_not_require_fabric_permission():
    c=Client(fail='/csf'); data=collect_inventory(c)
    assert len(data['scopes'])==1
    assert not any('/csf' in p for p,_ in c.calls)


@pytest.mark.parametrize('field,value', [('serial',ROOT),('vdom','wrong'),('status','error')])
def test_target_rejects_root_fallback_wrong_vdom_and_failed_envelope(field,value):
    result={'serial':CHILD,'vdom':'root','status':'success','results':[]}
    result[field]=value
    c=Mock();c.request.return_value=result
    with pytest.raises(FortiGateError):
        FabricTarget(CHILD,'Dad',ROOT+':'+CHILD).get(c,'/api/v2/monitor/system/dhcp','root')
    assert c.request.call_count==1


@pytest.mark.parametrize('path', ['../bad','https://evil/FGCHILD',ROOT+':WRONG'])
def test_bad_paths_never_reach_network(path):
    c=Mock()
    with pytest.raises(FortiGateError):
        FabricTarget(CHILD,'Dad',path).get(c,'/api/v2/monitor/system/status')
    c.request.assert_not_called()


def test_partial_leases_preserve_pools_and_error_does_not_leak_appliance_text():
    data=collect_inventory(Client(fail='/monitor/system/dhcp'))
    assert data['partial'] and len(data['scopes'])==1 and not data['leases']
    assert 'secret-token' not in json.dumps(data)


def test_empty_and_unavailable_configuration_are_distinct():
    data=collect_inventory(Client(fail='/server'))
    assert data['partial'] and not data['scopes'] and data['devices'][0]['errors']


def test_cancel_stops_followup_requests():
    c=Client()
    def cancel():raise RuntimeError('cancelled')
    with pytest.raises(RuntimeError):collect_inventory(c,check=cancel)
    assert c.calls==[]


def test_discovery_rejects_duplicate_serials():
    c=Client(); original=c.request
    def request(*a,**kw):
        result=original(*a,**kw)
        result['results']['devices']['fortigate'][1]['serial']=ROOT
        return result
    c.request=request
    with pytest.raises(FortiGateError):discover(c,True)


def test_duration_preserves_zero_and_units():
    assert lease_duration(0)=='Unlimited (0 seconds)'
    assert lease_duration(604800)=='7d'
    assert lease_duration(3661)=='1h 1m 1s'
    assert lease_duration(None)=='Not reported'


def test_completed_cmdb_page_can_have_next_index():
    c=Mock();c.request.return_value={'serial':ROOT,'vdom':'root','status':'success',
        'results':[], 'next_idx':8,'limit_reached':False}
    assert FabricTarget(ROOT,'Home').get(c,'/api/v2/cmdb/system.dhcp/server','root')==[]
    c.request.return_value['limit_reached']=True
    with pytest.raises(FortiGateError):FabricTarget(ROOT,'Home').get(c,'/api/v2/cmdb/system.dhcp/server','root')


@pytest.fixture
def browser(tmp_path):
    from twn_toolkit import create_app
    from twn_toolkit.profiles import ProfileStore
    app=create_app(str(tmp_path));app.testing=True
    ProfileStore(str(tmp_path)).upsert({'name':'Lab','host':'https://lab.example','api_key':'private-token','default_vdom':'root'})
    return app.test_client()


def test_queue_snapshot_views_and_exports(browser,monkeypatch):
    from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
    from twn_toolkit.diagnostic_worker import execute_scan
    from twn_toolkit.profiles import ProfileStore
    lookup=Mock(side_effect=lambda *a,**kw:collect_inventory(Client(),fabric=True))
    monkeypatch.setattr('twn_toolkit.fortigate_dhcp.collect_inventory',lookup)
    assert browser.get('/fortigate/dhcp').status_code==200
    response=browser.post('/fortigate/dhcp',data={'profile':'Lab','scope':'fabric','vdom':'root'})
    assert response.status_code==303;lookup.assert_not_called()
    identifier=response.location.split('job=')[1]
    store=DiagnosticJobStore(browser.application.instance_path);job=store.claim()
    assert job['id']==identifier
    # Job uses original credentials even if the profile is subsequently edited.
    ProfileStore(browser.application.instance_path).upsert({'name':'Lab','host':'https://changed.example','api_key':'different-token','default_vdom':'root'})
    execute_scan(store,identifier,job['token'])
    result=store.get(identifier,'test-user')
    assert result['state']=='succeeded'
    assert lookup.call_args.args[0].api_key=='private-token'
    for view in ('pools','reservations','leases'):
        page=browser.get(response.location+'&view='+view)
        assert page.status_code==200
        assert b'private-token' not in page.data
        assert b'Dad' in page.data
    assert b'No matching pools' in browser.get(response.location+'&q=nonexistent').data
    for fmt in ('csv','json'):
        download=browser.get(f'/fortigate/dhcp/jobs/{identifier}/download?format={fmt}')
        assert download.status_code==200
        assert b'must-not-retain' not in download.data and b'private-token' not in download.data
    assert browser.get(f'/fortigate/dhcp/jobs/{identifier}/status').json=={'state':'succeeded'}
    assert b'private-token' not in store.path.read_bytes()


def test_foreign_job_and_cross_tool_results_rejected(browser):
    from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
    store=DiagnosticJobStore(browser.application.instance_path)
    for owner,tool_id in [('someone-else','fortigate.dhcp'),('test-user','fortigate.home')]:
        identifier=store.enqueue(user_id=owner,tool='appliance_read',config={'mode':'dhcp','tool_id':tool_id})
        assert browser.get('/fortigate/dhcp?job='+identifier).status_code==404
        assert browser.get(f'/fortigate/dhcp/jobs/{identifier}/download').status_code==404
        assert browser.post(f'/fortigate/dhcp/jobs/{identifier}/cancel').status_code==404


def test_current_tool_permission_required_for_all_job_routes(tmp_path):
    from twn_toolkit import create_app
    from twn_toolkit.auth import AuthStore
    app=create_app(str(tmp_path));auth=AuthStore(str(tmp_path))
    access=auth.save_access_profile(name='DHCP',tool_ids=['fortigate.dhcp'])
    auth.create_user('admin','TemporaryPassword123!',is_admin=True)
    auth.create_user('reader','TemporaryPassword123!',access_profile_ids=[access['id']])
    client=app.test_client();client.post('/login',data={'username':'reader','password':'TemporaryPassword123!'})
    assert client.get('/fortigate/dhcp').status_code==200
    auth.save_access_profile(profile_id=access['id'],name='DHCP',tool_ids=['tools.ping'])
    for url in ['/fortigate/dhcp','/fortigate/dhcp/jobs/fake/status','/fortigate/dhcp/jobs/fake/download']:
        assert client.get(url).status_code==403
    assert client.post('/fortigate/dhcp/jobs/fake/cancel').status_code==403
    assert client.post('/fortigate/dhcp').status_code==403
