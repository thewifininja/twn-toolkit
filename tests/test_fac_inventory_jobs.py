from __future__ import annotations

import csv
import io
import socket
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from twn_toolkit import create_app
from twn_toolkit.diagnostic_artifacts import artifact_directory
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import DiagnosticScheduler, execute_scan
from twn_toolkit.fac_inventory import KINDS, prepare_inventory_config
from twn_toolkit.investigations import InvestigationStore
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.profiles import FortiAuthenticatorProfileStore

PROFILE={'name':'Lab','host':'https://fac.example','username':'fixture-user','password':'fixture-password','timeout':20}


def config(kind='devices',mode='export'):
    return {**prepare_inventory_config(PROFILE,kind,mode,'spreadsheet'),'username':'operator','investigation_id':''}


def objects(kind,count=501):
    if kind=='devices':
        return [{'id':i,'name':f'=Row{i:04}','address':'aa:bb:cc:dd:ee:ff','description':'x'*600,'resource_uri':f'/api/v1/macdevices/{i}/'} for i in range(count)]
    return [{'id':i,'device':f'/api/v1/macdevices/{i}/','device_name':f'=Row{i:04}','group':'/api/v1/macgroups/3/','group_name':'Group','resource_uri':f'/api/v1/macgroup-memberships/{i}/'} for i in range(count)]


@pytest.mark.parametrize('kind',['devices','memberships'])
def test_nonblocking_export_retains_full_csv_original_case_and_scoped_pages(tmp_path,monkeypatch,kind):
    app=create_app(str(tmp_path));app.testing=True;client=app.test_client();profiles=FortiAuthenticatorProfileStore(str(tmp_path));profiles.upsert(PROFILE)
    spec=KINDS[kind];base='/fortiauthenticator/'+spec['path'];tool='fac_inventory_'+kind
    lookup=Mock(return_value=objects(kind));monkeypatch.setattr('twn_toolkit.fac_inventory.FortiAuthenticatorClient.'+spec['method'],lookup)
    client.post('/investigations',data={'title':'Original'});cases=InvestigationStore(str(tmp_path));case=cases.active_for_user('test-user')['id']
    submitted=client.post(base+'.csv',data={'profile':'Lab'})
    assert submitted.status_code==303;lookup.assert_not_called()
    client.post('/investigations',data={'title':'Different'})
    store=DiagnosticJobStore(tmp_path);job=store.claim();execute_scan(store,job['id'],job['token'])
    assert store.get(job['id'],'test-user')['summary']['total_count']==501
    page=client.get(submitted.location);assert page.status_code==200
    assert b'Row0099' in page.data and b'Row0100' not in page.data
    assert b'Row0499' in client.get(submitted.location+'&page=99').data
    assert b'Row0500' not in client.get(submitted.location+'&page=5').data
    response=client.get(base+'/jobs/'+job['id']+'/download')
    rows=list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert len(rows)==502 and any("'=Row0500" in cell for cell in rows[-1])
    assert response.headers['Cache-Control']=='private, no-store'
    assert client.get(base+'/jobs/'+job['id']+'/download',headers={'Range':'bytes=0-9'}).status_code==206
    client.get(submitted.location);lookup.assert_called_once()
    events=[e for e in cases.events_for_user(case,'test-user') if e['tool_id']==spec['tool_id']]
    assert len(events)==1 and events[0]['metrics']['record_count']==501
    artifacts=cases.artifacts_for_user(case,'test-user');raw=cases.datastore.file(artifacts[0]['relative_path']).read_text()
    assert '=Row0500' in raw and "'=Row0500" not in raw
    other=store.enqueue(user_id='other',tool=tool,config=config(kind))
    wrong=store.enqueue(user_id='test-user',tool='fac_inventory_'+('memberships' if kind=='devices' else 'devices'),config=config('memberships' if kind=='devices' else 'devices'))
    for identifier in (other,wrong):
        assert client.get(base+'?job='+identifier).status_code==404
        assert client.get(base+'/jobs/'+identifier+'/status').status_code==404
        assert client.get(base+'/jobs/'+identifier+'/download').status_code==404
        assert client.post(base+'/jobs/'+identifier+'/cancel').status_code==404
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET completed=? WHERE id=?',(time.time()-48*3600,job['id']))
    assert client.get(base+'/jobs/'+job['id']+'/download').status_code==410
    directory=artifact_directory(store,job['id'],tool)
    store.cleanup();assert directory.exists() # token fences case/worker completion
    store.release(job['id'],job['token']);store.cleanup();assert not directory.exists()
    assert b'fixture-password' not in store.path.read_bytes()


def test_quota_snapshot_and_partial_artifact_cleanup(tmp_path,monkeypatch):
    policy=OperationalSettingsStore(str(tmp_path));policy.save({'diagnostic_artifact_max_mib':1})
    store=DiagnosticJobStore(tmp_path);tool='fac_inventory_devices';identifier=store.enqueue(user_id='owner',tool=tool,config=config())
    policy.save({'diagnostic_artifact_max_mib':2})
    assert store.get(identifier,'owner')['config']['artifact_bytes']==1024**2
    monkeypatch.setattr('twn_toolkit.fac_inventory.FortiAuthenticatorClient.get_all_mac_devices',Mock(return_value=[{'name':'x'*(1024**2+1)}]))
    job=store.claim();execute_scan(store,identifier,job['token']);failed=store.get(identifier,'owner')
    assert failed['state']=='failed' and 'configured export file limit' in failed['error']
    assert store.page(identifier,'owner')==([],0)
    directory=artifact_directory(store,identifier,tool);assert directory.exists()
    store.cleanup();assert directory.exists()
    store.release(identifier,job['token']);store.cleanup();assert not directory.exists()
    monkeypatch.setattr('twn_toolkit.diagnostic_jobs.shutil.disk_usage',lambda _:SimpleNamespace(free=policy.get()['minimum_free_gib']*1024**3+37*1024**2))
    with pytest.raises(ValueError,match='free-disk reserve'):
        store.enqueue(user_id='owner',tool=tool,config=config()) #32MiB result+6MiB export reserve


@pytest.mark.parametrize('cancel',[False,True])
def test_stalled_inventory_fetch_is_reaped(tmp_path,cancel):
    OperationalSettingsStore(str(tmp_path)).save({'diagnostic_timeout_seconds':5});scheduler=DiagnosticScheduler(tmp_path)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(10)
        settings=config();settings['profile']={**PROFILE,'host':f'http://127.0.0.1:{listener.getsockname()[1]}'}
        identifier=scheduler.store.enqueue(user_id='owner',tool='fac_inventory_devices',config=settings)
        try:
            scheduler.tick();process=scheduler.active[identifier]['process'];connection,_=listener.accept()
            with connection:
                if cancel:scheduler.store.cancel(identifier,'owner')
                end=time.monotonic()+12
                while scheduler.active and time.monotonic()<end:
                    scheduler.tick();time.sleep(.03)
                assert not scheduler.active and process.poll() is not None
                assert scheduler.store.get(identifier,'owner')['state']==('cancelled' if cancel else 'failed')
                assert scheduler.store.page(identifier,'owner')==([],0)
        finally:scheduler.close()


def test_inventory_endpoints_require_matching_tool_permission(tmp_path):
    from twn_toolkit.auth import AuthStore
    app=create_app(str(tmp_path));auth=AuthStore(str(tmp_path));auth.create_user('admin','TemporaryPassword123!',is_admin=True)
    user=auth.create_user('restricted','TemporaryPassword123!');client=app.test_client();client.post('/login',data={'username':'restricted','password':'TemporaryPassword123!'})
    store=DiagnosticJobStore(tmp_path)
    for kind in KINDS:
        identifier=store.enqueue(user_id=user['id'],tool='fac_inventory_'+kind,config=config(kind));base='/fortiauthenticator/'+KINDS[kind]['path']
        assert client.get(base+'?job='+identifier).status_code==403
        for suffix in ('status','download'):assert client.get(base+'/jobs/'+identifier+'/'+suffix).status_code==403
        assert client.post(base+'/jobs/'+identifier+'/cancel').status_code==403


def test_queued_cancel_never_contacts_appliance(tmp_path, monkeypatch):
    lookup = Mock()
    monkeypatch.setattr('twn_toolkit.fac_inventory.FortiAuthenticatorClient.get_all_mac_devices', lookup)
    app = create_app(str(tmp_path))
    app.testing = True
    client = app.test_client()
    FortiAuthenticatorProfileStore(str(tmp_path)).upsert(PROFILE)
    response = client.post('/fortiauthenticator/mac-devices.csv', data={'profile': 'Lab'})
    identifier = response.location.split('job=')[1]
    cancelled = client.post('/fortiauthenticator/mac-devices/jobs/' + identifier + '/cancel')
    assert cancelled.status_code == 303
    store = DiagnosticJobStore(tmp_path)
    assert store.get(identifier, 'test-user')['state'] == 'cancelled'
    assert store.claim() is None
    assert not artifact_directory(store, identifier, 'fac_inventory_devices').exists()
    lookup.assert_not_called()


def test_profile_snapshot_and_failure_redaction(tmp_path, monkeypatch):
    from twn_toolkit.fortiauthenticator import FortiAuthenticatorError
    app = create_app(str(tmp_path))
    app.testing = True
    client = app.test_client()
    profiles = FortiAuthenticatorProfileStore(str(tmp_path))
    profiles.upsert(PROFILE)
    response = client.post('/fortiauthenticator/mac-devices', data={'profile': 'Lab'})
    profiles.upsert({**PROFILE, 'host': 'https://changed.example', 'password': 'changed-secret'})
    factory = Mock(return_value=SimpleNamespace(get_all_mac_devices=Mock(
        side_effect=FortiAuthenticatorError('Rejected fixture-password'))))
    monkeypatch.setattr('twn_toolkit.fac_inventory.FortiAuthenticatorClient.from_profile', factory)
    store = DiagnosticJobStore(tmp_path)
    job = store.claim()
    execute_scan(store, job['id'], job['token'])
    used = factory.call_args.args[0]
    assert used['host'] == PROFILE['host'] and used['password'] == PROFILE['password']
    result = store.get(job['id'], 'test-user')
    assert result['state'] == 'failed' and result['error'] == 'Rejected [redacted]'
    page = client.get(response.location)
    assert b'fixture-password' not in page.data and b'changed-secret' not in page.data
    assert store.page(job['id'], 'test-user') == ([], 0)


def test_inventory_limit_is_editable_in_operations(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    client = app.test_client()
    page = client.get('/settings?section=operations')
    assert page.status_code == 200
    assert b'name="diagnostic_artifact_max_mib"' in page.data

    policy = OperationalSettingsStore(str(tmp_path))
    response = client.post('/settings/operations', data={**policy.get(), 'diagnostic_artifact_max_mib': '64'})
    assert response.status_code == 302
    assert policy.get()['diagnostic_artifact_max_mib'] == 64


def test_export_reservation_survives_result_publication(tmp_path, monkeypatch):
    policy = OperationalSettingsStore(str(tmp_path))
    policy.save({'diagnostic_artifact_max_mib': 1})
    store = DiagnosticJobStore(tmp_path)
    identifier = store.enqueue(user_id='owner', tool='fac_inventory_devices', config=config())
    job = store.claim()
    assert store.finish(identifier, job['token'], [], {'archive': True})
    # The result can be visible while its worker still copies case evidence.
    # Keep that worker's three-file reservation until it releases ownership.
    monkeypatch.setattr('twn_toolkit.diagnostic_jobs.shutil.disk_usage', lambda _: SimpleNamespace(
        free=policy.get()['minimum_free_gib'] * 1024**3 + 34 * 1024**2))
    with pytest.raises(ValueError, match='free-disk reserve'):
        store.enqueue(user_id='owner', tool='fac_inventory_devices', config=config(mode='preview'))
    store.release(identifier, job['token'])
    assert store.enqueue(user_id='owner', tool='fac_inventory_devices', config=config(mode='preview'))
