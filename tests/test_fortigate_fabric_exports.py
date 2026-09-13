from dataclasses import asdict
import csv
import io
import json
import time
from unittest.mock import Mock
import pytest
from werkzeug.datastructures import MultiDict
from test_fortigate_dhcp import Client, ROOT, CHILD
from twn_toolkit.fortigate_fabric import discover
from twn_toolkit.fortigate_fabric_exports import read_exports, public_summary, write_export
from twn_toolkit.tasks import get_task
from twn_toolkit.fortigate import FortiGateError


@pytest.mark.parametrize('task_id', ['export-aps','export-switches','export-wireless-clients','export-fortiswitch-clients'])
def test_all_exports_route_each_saved_target_and_label_csv(task_id):
    client=Client(); targets=[asdict(t) for t in discover(client,True)]
    task=get_task(task_id)
    data=read_exports(client,task,targets,endpoint=task.endpoint_template,vdom='root',fields='ip,hostname',mode='export',check=lambda:None)
    output=io.StringIO();write_export(data,output)
    records=list(csv.DictReader(io.StringIO(output.getvalue())))
    assert {r['FortiGate serial'] for r in records}=={ROOT,CHILD}
    assert data['api_calls']==2 and not data['partial']
    assert any(path.startswith('/csf/'+ROOT+':'+CHILD+'/') for path,_ in client.calls)
    assert all('_rows' not in g and '_formatted' not in g for g in public_summary(data)['groups'])


def test_partial_error_is_safe_and_does_not_fall_back_to_root():
    client=Client(); targets=[asdict(t) for t in discover(client,True)]
    client.fail='/csf/'
    task=get_task('export-aps')
    data=public_summary(read_exports(client,task,targets,endpoint=task.endpoint_template,vdom='root',fields='ip',mode='preview',check=lambda:None))
    assert data['partial'] and data['successful_gates']==1
    assert data['groups'][1]['error'] and not data['groups'][1]['rows']
    assert 'secret-token' not in json.dumps(data)
    assert len([p for p,_ in client.calls if p==task.endpoint_template])==1


def test_empty_gate_success_differs_from_unavailable_and_identity_mismatch():
    client=Client();targets=[asdict(t) for t in discover(client,True)]
    client.request=Mock(return_value={'serial':ROOT,'status':'success','vdom':'root','results':[]})
    task=get_task('export-aps')
    data=public_summary(read_exports(client,task,targets,endpoint=task.endpoint_template,vdom='root',fields='',mode='preview',check=lambda:None))
    assert data['groups'][0]['row_count']==0 and not data['groups'][0]['error']
    assert data['groups'][1]['error'] and data['partial']


def test_cancellation_and_limits_do_not_publish_unbounded_results(monkeypatch):
    client=Client();targets=[asdict(t) for t in discover(client,False)]
    task=get_task('export-aps')
    def cancel():raise RuntimeError('cancelled')
    with pytest.raises(RuntimeError):
        read_exports(client,task,targets,endpoint=task.endpoint_template,vdom='root',fields='',mode='preview',check=cancel)
    monkeypatch.setattr('twn_toolkit.fortigate_fabric_exports.MAX_EXPORT_ROWS',0)
    data=public_summary(read_exports(client,task,targets,endpoint=task.endpoint_template,vdom='root',fields='',mode='preview',check=lambda:None))
    assert data['partial'] and data['row_count']==0


@pytest.fixture
def browser(tmp_path,monkeypatch):
    from twn_toolkit import create_app
    from twn_toolkit.profiles import ProfileStore
    from twn_toolkit.operational import OperationalSettingsStore
    app=create_app(str(tmp_path));app.testing=True
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib':0})
    ProfileStore(str(tmp_path)).upsert({'name':'Lab','host':'https://lab.example','api_key':'private-token','default_vdom':'root'})
    client=Client();client.for_display_export=lambda:client
    monkeypatch.setattr('twn_toolkit.appliance_read.FortiGateClient.from_profile',lambda p:client)
    return app.test_client()


def finish(browser,response):
    from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
    from twn_toolkit.diagnostic_worker import execute_scan
    store=DiagnosticJobStore(browser.application.instance_path);job=store.claim()
    identifier=(response.json['job_url'] if response.status_code==202 else response.location).split('/')[-2]
    assert job['id']==identifier
    execute_scan(store,identifier,job['token']);store.release(identifier,job['token'])
    return store.get(identifier,'test-user')


def selected(discovery,serials=(ROOT,CHILD)):
    return MultiDict([('profile','Lab'),('fabric_discovery',discovery['id']),('fields','ip,hostname')]+[('fabric_serial',s) for s in serials])


@pytest.mark.parametrize('mode', ['fields','preview','run'])
def test_discovery_selection_and_worker_views_exports(browser,mode):
    discovery=finish(browser,browser.post('/tasks/export-aps/fabric',data={'profile':'Lab'}))
    assert discovery['state']=='succeeded' and len(discovery['summary']['targets'])==2
    response=browser.post('/tasks/export-aps/'+mode,data=selected(discovery))
    assert response.status_code==(303 if mode=='run' else 202)
    result=finish(browser,response)
    assert result['state']=='succeeded' and len(result['summary']['groups'])==2
    assert [t['serial'] for t in result['config']['fabric_targets']]==[ROOT,CHILD]
    url='/tasks/export-aps/jobs/'+result['id']
    page=browser.get(url+'/job');assert page.status_code==200 and b'Dad' in page.data
    if mode=='run':
        download=browser.get(url+'/download');assert download.status_code==200
        assert ROOT.encode() in download.data and CHILD.encode() in download.data
        assert b'private-token' not in download.data
    assert b'private-token' not in browser.get(url+'/status').data


def test_selection_rejects_foreign_stale_tampered_and_changed_profile(browser):
    from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
    from twn_toolkit.profiles import ProfileStore
    discovery=finish(browser,browser.post('/tasks/export-aps/fabric',data={'profile':'Lab'}))
    for serials in [(),('invented',),(ROOT,ROOT)]:
        assert browser.post('/tasks/export-aps/preview',data=selected(discovery,serials)).status_code==400
    assert browser.post('/tasks/export-switches/preview',data=selected(discovery)).status_code==400
    bad=selected(discovery);bad['endpoint_template']='/api/v2/cmdb/system/admin'
    assert browser.post('/tasks/export-aps/preview',data=bad).status_code==400
    bad=selected(discovery);bad['fabric_discovery']='unknown'
    assert browser.post('/tasks/export-aps/preview',data=bad).status_code==400
    store=DiagnosticJobStore(browser.application.instance_path)
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET completed=? WHERE id=?',(time.time()-901,discovery['id']))
    assert browser.post('/tasks/export-aps/preview',data=selected(discovery)).status_code==400
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET completed=? WHERE id=?',(time.time(),discovery['id']))
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET user_id=? WHERE id=?',('someone-else',discovery['id']))
    assert browser.post('/tasks/export-aps/preview',data=selected(discovery)).status_code==400
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET user_id=? WHERE id=?',('test-user',discovery['id']))
    ProfileStore(browser.application.instance_path).upsert({'name':'Lab','host':'https://changed.example','api_key':'changed'})
    assert browser.post('/tasks/export-aps/preview',data=selected(discovery)).status_code==400


def test_queued_target_and_credentials_are_frozen(browser):
    from twn_toolkit.profiles import ProfileStore
    discovery=finish(browser,browser.post('/tasks/export-aps/fabric',data={'profile':'Lab'}))
    response=browser.post('/tasks/export-aps/preview',data=selected(discovery,(CHILD,)))
    ProfileStore(browser.application.instance_path).upsert({'name':'Lab','host':'https://changed.example','api_key':'changed'})
    result=finish(browser,response)
    assert result['state']=='succeeded'
    assert result['config']['profile']['api_key']=='private-token'
    assert [g['serial'] for g in result['summary']['groups']]==[CHILD]


def test_discovery_requires_current_export_tool_permission(tmp_path):
    from twn_toolkit import create_app
    from twn_toolkit.auth import AuthStore
    app=create_app(str(tmp_path));auth=AuthStore(str(tmp_path))
    access=auth.save_access_profile(name='Exports',tool_ids=['fortigate.export_aps'])
    auth.create_user('admin','TemporaryPassword123!',is_admin=True)
    auth.create_user('reader','TemporaryPassword123!',access_profile_ids=[access['id']])
    client=app.test_client();client.post('/login',data={'username':'reader','password':'TemporaryPassword123!'})
    assert client.post('/tasks/export-aps/fabric',data={'profile':'missing'}).status_code==400
    assert client.post('/tasks/export-switches/fabric').status_code==403
    auth.save_access_profile(profile_id=access['id'],name='Exports',tool_ids=['tools.ping'])
    assert client.post('/tasks/export-aps/fabric').status_code==403


@pytest.mark.parametrize('failure', ['/csf/', '/api/v2/'])
def test_partial_and_all_failed_exports_preserve_case_outcome(browser,monkeypatch,failure):
    from twn_toolkit.investigations import InvestigationStore
    discovery=finish(browser,browser.post('/tasks/export-aps/fabric',data={'profile':'Lab'}))
    browser.post('/investigations',data={'title':'Fabric investigation'})
    cases=InvestigationStore(browser.application.instance_path)
    case=cases.active_for_user('test-user')
    client=Client(fail=failure);client.for_display_export=lambda:client
    monkeypatch.setattr('twn_toolkit.appliance_read.FortiGateClient.from_profile',lambda p:client)
    result=finish(browser,browser.post('/tasks/export-aps/run',data=selected(discovery)))
    assert result['summary']['partial']
    assert 'recording_warning' not in result['summary']
    events=[event for event in cases.events_for_user(case['id'],'test-user') if event['operation_id']=='appliance-read:'+result['id']]
    assert len(events)==1 and events[0]['outcome']=='incomplete'
    download=browser.get('/tasks/export-aps/jobs/'+result['id']+'/download')
    assert download.status_code==(200 if failure=='/csf/' else 404)
    assert len(cases.artifacts_for_user(case['id'],'test-user'))==(1 if failure=='/csf/' else 0)
    assert b'secret-token' not in browser.get('/tasks/export-aps/jobs/'+result['id']+'/job').data


def test_malformed_rows_are_unavailable_instead_of_empty_success():
    client=Client();targets=[asdict(t) for t in discover(client,False)]
    client.request=Mock(return_value={'serial':ROOT,'status':'success','vdom':'root','results':['invalid row']})
    task=get_task('export-aps')
    data=public_summary(read_exports(client,task,targets,endpoint=task.endpoint_template,vdom='root',fields='',mode='preview',check=lambda:None))
    assert data['partial'] and data['successful_gates']==0
