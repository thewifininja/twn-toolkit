"""Exercise selected-gate workflows through the real scoped transport and workers."""
import re
import time
from dataclasses import asdict
import pytest
from werkzeug.datastructures import MultiDict
from twn_toolkit import create_app
from twn_toolkit.profiles import ProfileStore
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan
from twn_toolkit.fortigate import FortiGateClient, FortiGateError
from twn_toolkit.fortigate_fabric import FabricTarget
from twn_toolkit.fortigate_scoped_client import FabricScopedClient, BASE_AP, BASE_SWITCH, STATUS

ROOT, CHILD = 'FGROOT', 'FGCHILD'
TARGET = asdict(FabricTarget(CHILD, 'Branch', ROOT+':'+CHILD, '40F', ['root']))


@pytest.fixture
def appliance(monkeypatch):
    class Appliance:
        calls = []
        names = {'AP1':'Old AP', 'SW1':'Old switch', 'SW2':'Other switch'}
        order = ['SW1','SW2']
        fault = ''
        def request(self, client, method, endpoint, params=None, json=None, _budget=None):
            self.calls.append((method,endpoint,params,json,_budget))
            serial = CHILD if endpoint.startswith('/csf/') else ROOT
            data = {'serial':serial,'status':'success','vdom':(params or {}).get('vdom','root')}
            if endpoint.endswith(STATUS):
                data['results'] = {'hostname':'Root','model_number':'70F'}
                if self.fault=='preflight' and serial==CHILD:data['serial']=ROOT
            elif endpoint.endswith('/csf'):
                data['results']={'devices':{'fortigate':[
                    {'serial':ROOT,'host_name':'Root','vdoms':['root']},
                    {'serial':CHILD,'host_name':'Branch','proxy_path':ROOT+':'+CHILD,'vdoms':['root']}]}}
            elif endpoint.endswith(BASE_AP):
                data['results']=[{'wtp-id':'AP1','name':self.names['AP1']}]
            elif endpoint.endswith(BASE_SWITCH):
                data['results']=[{'switch-id':s,'name':self.names[s]} for s in self.order]
            elif '/event/wireless' in endpoint or '/monitor/wifi/client' in endpoint:
                data['results']=[]
            else:
                identifier=endpoint.rsplit('/',1)[-1]
                if method=='PUT':
                    if (params or {}).get('action')=='move':
                        self.order.remove(identifier);self.order.insert(self.order.index(params['after'])+1,identifier)
                    else:self.names[identifier]=next(iter(json.values()))
                    if self.fault=='ack':data['serial']=ROOT
                data['results']=[{'name':self.names[identifier]}]
            return data
    instance=Appliance()
    monkeypatch.setattr(FortiGateClient,'_request',lambda client,*args,**kw:instance.request(client,*args,**kw))
    return instance


@pytest.fixture
def browser(tmp_path, appliance):
    app=create_app(str(tmp_path));app.testing=True
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib':0})
    ProfileStore(str(tmp_path)).upsert({'name':'Lab','host':'https://fixture.invalid','api_key':'secret','default_vdom':'root'})
    yield app.test_client()
    app.extensions['remote_session_manager'].close()


def finish(browser,response):
    assert response.status_code in (202,303),response.data
    store=DiagnosticJobStore(browser.application.instance_path)
    job=store.claim();assert job
    execute_scan(store,job['id'],job['token']);store.release(job['id'],job['token'])
    return store.get(job['id'],'test-user')


def discover(browser,operation):
    url='/tasks/'+operation+'/fabric' if operation.startswith('rename-') else '/fortigate/fabric/'+operation
    response=browser.post(url,data={'profile':'Lab'})
    job=finish(browser,response)
    assert job['state']=='succeeded',job['error']
    assert browser.get(response.json['job_url']).status_code==200
    return {'profile':'Lab','fabric_discovery':job['id'],'fabric_serial':CHILD}


@pytest.mark.parametrize('operation,endpoint', [('rename-aps',BASE_AP),('rename-switches',BASE_SWITCH),('switch-order',BASE_SWITCH),('wireless-history','/api/v2/log/memory/event/wireless')])
def test_scoped_reads_use_proxy_and_keep_budget(appliance,operation,endpoint):
    client=FabricScopedClient('https://fixture.invalid','secret',target=TARGET,operation=operation)
    budget=object()
    assert client.request('GET',endpoint,params={'vdom':'root'},_budget=budget)['serial']==CHILD
    assert appliance.calls[-1][1]=='/csf/'+ROOT+':'+CHILD+endpoint
    assert appliance.calls[-1][-1] is budget


@pytest.mark.parametrize('field,value',[('serial',ROOT),('serial',None),('vdom','wrong'),('status','error'),('limit_reached',True)])
def test_wrong_or_incomplete_read_is_rejected(monkeypatch,field,value):
    result={'serial':CHILD,'status':'success','vdom':'root','results':[]};result[field]=value
    monkeypatch.setattr(FortiGateClient,'_request',lambda *a,**k:result)
    client=FabricScopedClient('https://fixture.invalid','secret',target=TARGET,operation='rename-aps')
    with pytest.raises(FortiGateError):client.request('GET',BASE_AP,params={'vdom':'root'})


@pytest.mark.parametrize('task,identifier,old',[('rename-aps','AP1','Old AP'),('rename-switches','SW1','Old switch')])
@pytest.mark.parametrize('fault',['','preflight','ack'])
def test_reviewed_rename_verifies_target_and_never_replays(browser,appliance,task,identifier,old,fault):
    selected=discover(browser,task)
    loaded=finish(browser,browser.post('/tasks/'+task+'/objects',data=selected))
    assert loaded['state']=='succeeded',loaded['error']
    assert 'Branch' in loaded['summary']['target_origin']
    form={**selected,'identifier':identifier,'current_name':old,'new_name':'Renamed','vdom':'root'}
    preview=browser.post('/tasks/'+task+'/rename',data={**form,'dry_run':'on'})
    assert preview.status_code==200 and b'Branch' in preview.data
    token=re.search(rb'name="preview_token" type="hidden" value="([^"]+)"',preview.data)[1].decode()
    assert b'name="fabric_serial" type="hidden" value="FGCHILD"' in preview.data
    apply={**form,'preview_token':token,'confirmed_live':'on'}
    for changed in ({'fabric_serial':ROOT},{'fabric_discovery':'','fabric_serial':''}):
        assert browser.post('/tasks/'+task+'/rename',data={**apply,**changed}).status_code==302
    appliance.calls.clear();appliance.fault=fault
    result=finish(browser,browser.post('/tasks/'+task+'/rename',data=apply))
    assert result['state']==('unknown' if fault else 'succeeded'),result['error']
    puts=[call for call in appliance.calls if call[0]=='PUT']
    assert len(puts)==(0 if fault=='preflight' else 1)
    assert all(call[1].startswith('/csf/'+ROOT+':'+CHILD+'/') for call in appliance.calls)
    assert browser.post('/tasks/'+task+'/rename',data=apply).status_code==303
    assert DiagnosticJobStore(browser.application.instance_path).claim() is None


def test_switch_order_load_review_apply_and_target_binding(browser,appliance):
    selected=discover(browser,'switch-order')
    loaded=finish(browser,browser.post('/fortigate/switch-order/objects',data=selected))
    assert loaded['state']=='succeeded',loaded['error']
    data=loaded['summary']
    form={**selected,'vdom':'root','original_switch_id':['SW1','SW2'],'switch_id':['SW2','SW1'],
          'load_token':data['load_token'],'target_revision':data['target_revision']}
    assert browser.post('/fortigate/switch-order/preview',data={**form,'fabric_serial':ROOT}).status_code==409
    preview=browser.post('/fortigate/switch-order/preview',data=form)
    assert preview.status_code==200,preview.data
    form['preview_token']=preview.json['preview_token']
    form['confirmed']='on'
    assert browser.post('/fortigate/switch-order/apply',data={**form,'fabric_serial':ROOT}).status_code==409
    appliance.calls.clear()
    result=finish(browser,browser.post('/fortigate/switch-order/apply',data=form))
    assert result['state']=='succeeded',result['error']
    assert appliance.order==['SW2','SW1']
    assert [c[0] for c in appliance.calls]==['GET','GET','PUT','GET']
    assert all('/csf/'+ROOT+':'+CHILD+'/' in c[1] for c in appliance.calls)


@pytest.mark.parametrize('operation', ['rename-aps','rename-switches','switch-order','wireless-history'])
def test_selection_admission_rejects_stale_foreign_multiple_and_endpoint_override(browser,operation):
    form=discover(browser,operation)
    url='/tasks/'+operation+'/objects' if operation.startswith('rename-') else ('/fortigate/switch-order/objects' if operation=='switch-order' else '/fortigate/fortiap/client-history')
    form.update(mac='aa:bb:cc:dd:ee:ff',hours='1')
    for changed in ({'fabric_serial':'invented'},{'fabric_serial':['FGROOT','FGCHILD']},{'fabric_discovery':'missing'}):
        assert browser.post(url,data={**form,**changed}).status_code==400
    if operation.startswith('rename-'):
        assert browser.post(url,data={**form,'endpoint_template':'/api/v2/cmdb/system/admin/{current_name}'}).status_code==400
    store=DiagnosticJobStore(browser.application.instance_path)
    with store.connect(write=True) as db:db.execute('UPDATE diagnostic_jobs SET completed=? WHERE id=?',(time.time()-901,form['fabric_discovery']))
    assert browser.post(url,data=form).status_code==400
    with store.connect(write=True) as db:db.execute('UPDATE diagnostic_jobs SET completed=?,user_id=? WHERE id=?',(time.time(),'foreign',form['fabric_discovery']))
    assert browser.post(url,data=form).status_code==400


@pytest.mark.parametrize('endpoint,method,payload',[(BASE_SWITCH+'/SW1','PUT',{'name':'X'}),(BASE_AP+'/../admin','GET',None),(BASE_AP+'/AP1','POST',{'name':'X'}),(BASE_AP+'/AP1','PUT',{'password':'x'}),(BASE_AP+'/AP1','PUT',{'name':'x','other':'y'})])
def test_unsupported_operations_never_contact_appliance(appliance,endpoint,method,payload):
    client=FabricScopedClient('https://fixture.invalid','secret',target=TARGET,operation='rename-aps')
    with pytest.raises(FortiGateError):client.request(method,endpoint,json=payload)
    assert appliance.calls==[]


def test_history_uses_only_selected_source_and_retains_identity(browser,appliance):
    form=discover(browser,'wireless-history')
    appliance.calls.clear()
    job=finish(browser,browser.post('/fortigate/fortiap/client-history',data={**form,'mac':'aa:bb:cc:dd:ee:ff','hours':'1'}))
    assert job['state']=='succeeded' and job['summary']['outcome']=='succeeded'
    assert job['config']['profile']['_fabric_target']['serial']==CHILD
    assert appliance.calls and all(c[0]=='GET' and c[1].startswith('/csf/'+ROOT+':'+CHILD+'/') for c in appliance.calls)
    assert browser.get('/fortigate/fortiap/client-history?job='+job['id']).status_code==200
    assert b'Run target: <strong>Branch</strong>' in browser.get('/fortigate/fortiap/client-history?job='+job['id']).data


@pytest.mark.parametrize('kind,grant', [('switch-order','fortigate.switch_order'),('wireless-history','fortigate.wireless_client_history')])
def test_discovery_routes_enforce_tool_permission_and_job_ownership(tmp_path,kind,grant):
    from twn_toolkit.auth import AuthStore
    app=create_app(str(tmp_path));auth=AuthStore(str(tmp_path))
    access=auth.save_access_profile(name='Scoped',tool_ids=[grant])
    auth.create_user('admin','TemporaryPassword123!',is_admin=True)
    user=auth.create_user('reader','TemporaryPassword123!',access_profile_ids=[access['id']])
    client=app.test_client();client.post('/login',data={'username':'reader','password':'TemporaryPassword123!'})
    path='/fortigate/fabric/'+kind
    assert client.post(path,data={'profile':'missing'}).status_code==400
    other='wireless-history' if kind=='switch-order' else 'switch-order'
    assert client.post('/fortigate/fabric/'+other).status_code==403
    store=DiagnosticJobStore(tmp_path)
    identifier=store.enqueue(user_id='foreign',tool='appliance_read',config={'tool_id':grant,'mode':'fabric_discovery'})
    assert client.get(path+'/jobs/'+identifier).status_code==404
    auth.save_access_profile(profile_id=access['id'],name='Scoped',tool_ids=['tools.ping'])
    assert client.post(path).status_code==403
    assert client.get(path+'/jobs/'+identifier+'/status').status_code==403
    assert client.post(path+'/jobs/'+identifier+'/cancel').status_code==403
    app.extensions['remote_session_manager'].close()


def test_empty_selection_keeps_existing_direct_rename_editor(browser,appliance):
    response=browser.post('/tasks/rename-aps/rename',data={'profile':'Lab','fabric_discovery':'','fabric_serial':'',
        'identifier':'AP1','current_name':'Old AP','new_name':'New AP','vdom':'root','dry_run':'on'})
    assert response.status_code==200
    assert b'name="preview_token"' in response.data and b'name="fabric_serial"' not in response.data
    assert not appliance.calls


def test_log_pagination_marker_is_preserved_for_existing_budget(monkeypatch):
    result={'serial':CHILD,'status':'success','vdom':'root','results':[],'limit_reached':True}
    monkeypatch.setattr(FortiGateClient,'_request',lambda *a,**k:result)
    client=FabricScopedClient('https://fixture.invalid','secret',target=TARGET,operation='wireless-history')
    assert client.request('GET','/api/v2/log/memory/event/wireless',params={'vdom':'root'})['limit_reached']
