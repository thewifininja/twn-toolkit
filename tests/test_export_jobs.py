"""Exports remain private and finite across cancellation and uncertain attachment."""
import json
import time
import subprocess
from unittest.mock import Mock

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.automation import AutomationStore
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan, DiagnosticScheduler
from twn_toolkit.diagnostic_artifacts import artifact_directory
from twn_toolkit.export_jobs import mark_case_attachment
from twn_toolkit.investigations import InvestigationStore
from twn_toolkit.operational import OperationalSettingsStore


@pytest.fixture
def env(tmp_path):
    app=create_app(str(tmp_path)); app.testing=True
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib':0})
    return app,app.test_client(),DiagnosticJobStore(tmp_path)


def queue(client, encrypted=False):
    data={'item':['ping_profiles']}
    if encrypted:
        data.update(encrypt_backup='on',backup_password='Private export passphrase!',confirm_backup_password='Private export passphrase!')
    response=client.post('/settings/backup/export',data=data)
    assert response.status_code==303
    return response.location.split('job=')[1]


def execute(store):
    job=store.claim(); assert job
    execute_scan(store,job['id'],job['token'])
    store.release(job['id'],job['token'])
    return store.get(job['id'],job['user_id'])


def test_queue_does_not_build_and_cancel_scrubs_secret(env,monkeypatch):
    app,client,store=env
    builder=Mock(side_effect=AssertionError('request built export'))
    monkeypatch.setattr('twn_toolkit.export_jobs.configuration_payload',builder)
    identifier=queue(client,True)
    secret=b'Private export passphrase!'
    assert secret not in store.path.read_bytes()
    for url in ('/settings/backup/exports?job='+identifier,'/settings/backup/exports/'+identifier+'/status'):
        assert secret not in client.get(url).data
    assert client.post('/settings/backup/exports/'+identifier+'/cancel').status_code==303
    job=store.get(identifier,'test-user')
    assert job['state']=='cancelled' and 'password' not in job['config']
    assert store.claim() is None
    builder.assert_not_called()


@pytest.mark.parametrize('interrupt',['cancel','recover','error'])
def test_password_scrub_and_partial_cleanup(env,monkeypatch,interrupt):
    _,client,store=env; identifier=queue(client,True)
    def builder(*args):
        if interrupt=='cancel': store.cancel(identifier,'test-user')
        elif interrupt=='recover': store.recover()
        else: raise ValueError('Private export passphrase!')
        return b'private bytes','backup.json',{}
    monkeypatch.setattr('twn_toolkit.export_jobs.configuration_payload',builder)
    result=execute(store)
    assert result['state']=={'cancel':'cancelled','recover':'unknown','error':'failed'}[interrupt]
    assert 'password' not in result['config'] and 'passphrase' not in result['error']
    assert store.claim() is None
    store.cleanup()
    assert not artifact_directory(store,identifier,'configuration_export').exists()
    assert not list((store.instance/'.upload-reservations').glob('*/data'))


def test_completed_download_is_retained_and_password_scrubbed(env):
    _,client,store=env; identifier=queue(client,True); result=execute(store)
    assert result['state']=='succeeded' and 'password' not in result['config']
    url='/settings/backup/exports/'+identifier+'/download'
    response=client.get(url)
    assert response.status_code==200 and response.headers['Cache-Control']=='private, no-store'
    from twn_toolkit.profile_backup import decrypt_backup
    assert decrypt_backup(json.loads(response.data),'Private export passphrase!')
    response.close()
    assert client.get(url,headers={'Range':'bytes=0-3'}).status_code==206
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET completed=? WHERE id=?',(time.time()-48*3600,identifier))
    assert client.get(url).status_code==410
    store.cleanup(); assert not artifact_directory(store,identifier,'configuration_export').exists()


@pytest.mark.parametrize('when',['before','publication','download'])
def test_current_admin_and_owner_required(env,monkeypatch,when):
    app,_,store=env; app.testing=False; auth=AuthStore(str(store.instance))
    owner=auth.create_user('owner','TemporaryPassword123!',is_admin=True)
    auth.create_user('other','TemporaryPassword123!',is_admin=True)
    client=app.test_client(); client.post('/login',data={'username':'owner','password':'TemporaryPassword123!'})
    other=app.test_client(); other.post('/login',data={'username':'other','password':'TemporaryPassword123!'})
    identifier=queue(client)
    assert other.get('/settings/backup/exports?job='+identifier).status_code==404
    assert other.post('/settings/backup/exports/'+identifier+'/cancel').status_code==404
    def revoke(): auth.update_user_access(owner['id'],is_admin=False,access_profile_ids=[])
    if when=='before': revoke()
    if when=='publication':
        from twn_toolkit.export_jobs import configuration_payload
        def build(*args):
            payload=configuration_payload(*args); revoke(); return payload
        monkeypatch.setattr('twn_toolkit.export_jobs.configuration_payload',build)
    result=execute(store)
    assert result['state']==('succeeded' if when=='download' else 'failed')
    if when=='download': revoke()
    assert client.get('/settings/backup/exports/'+identifier+'/download').status_code!=200


@pytest.fixture
def run_env(env,monkeypatch):
    app,client,store=env
    run=dict(id='run',automation_id='automation',automation_name='Collection',started_at=1,finished_at=2,
             status='success',trigger_summary='Manual',results=[])
    monkeypatch.setattr(AutomationStore,'get_run',lambda self,*a,**kw:run)
    cases=InvestigationStore(str(store.instance))
    case=cases.create(owner_user_id='test-user',owner_username='test-user',title='Original')
    return app,client,store,cases,case


def test_automation_admission_only_reads_metadata(run_env,monkeypatch):
    _,client,store,_,_=run_env
    def read(self,identifier,**kwargs):
        assert kwargs.get('metadata_only'); return {'id':identifier}
    monkeypatch.setattr(AutomationStore,'get_run',read)
    builder=Mock(side_effect=AssertionError('request built archive'))
    monkeypatch.setattr('twn_toolkit.export_jobs._automation_run_archive',builder)
    for method,suffix in ((client.get,'download'),(client.post,'case')):
        response=method('/automations/runs/run/'+suffix)
        assert response.status_code==303
        identifier=response.location.split('job=')[1]; store.cancel(identifier,'test-user')
    builder.assert_not_called()


def test_attachment_keeps_original_case_deduplicates_and_survives_run_deletion(run_env,monkeypatch):
    _,client,store,cases,case=run_env
    response=client.post('/automations/runs/run/case'); assert response.status_code==303
    different=cases.create(owner_user_id='other',owner_username='other',title='Different active case')
    monkeypatch.setattr(InvestigationStore,'active_for_user',lambda *a:different)
    first=execute(store); assert first['state']=='succeeded'
    assert first['summary']['case_id']==case['id']
    store.enqueue(user_id='test-user',tool='automation_export',config={'run_id':'run','username':'test-user','investigation_id':case['id']})
    second=execute(store); assert second['state']=='succeeded'
    assert second['summary']['case_artifact_id']==first['summary']['case_artifact_id']
    assert not artifact_directory(store,first['id'],'automation_export').exists()
    monkeypatch.setattr(AutomationStore,'get_run',lambda *a,**kw:None)
    page=client.get('/automations/exports?job='+first['id'])
    assert page.status_code==200 and b'Download case evidence' in page.data
    assert client.get('/automations/exports/'+first['id']+'/download').status_code==404


@pytest.mark.parametrize('interruption',['abort','restart','publish_cancel'])
def test_case_intent_is_unknown_and_never_replayed(run_env,monkeypatch,interruption):
    _,client,store,cases,case=run_env
    response=client.post('/automations/runs/run/case'); identifier=response.location.split('job=')[1]
    if interruption=='publish_cancel':
        original=InvestigationStore.add_generated_evidence_event
        def publish(self,**kwargs):
            callback=kwargs['before_publish']
            def cancel(): store.cancel(identifier,'test-user'); callback()
            kwargs['before_publish']=cancel
            return original(self,**kwargs)
        monkeypatch.setattr(InvestigationStore,'add_generated_evidence_event',publish)
        result=execute(store)
        assert not [event for event in cases.events_for_user(case['id'],'test-user') if event['event_type']=='automation.run.attached']
    else:
        job=store.claim(); mark_case_attachment(store,job,case['id'])
        if interruption=='abort': store.abort(identifier,job['token'],'failed','Stopped'); store.release(identifier,job['token'])
        else: store.recover()
        result=store.get(identifier,'test-user')
    assert result['state']=='unknown' and store.claim() is None
    assert b'Inspect the original case' in client.get('/automations/exports?job='+identifier).data
    store.cleanup(); assert not list((store.instance/'.upload-reservations').glob('*/data'))


@pytest.mark.parametrize('cancel',[False,True])
def test_stalled_configuration_export_is_terminated_and_reaped(tmp_path, monkeypatch, cancel):
    OperationalSettingsStore(str(tmp_path)).save({'diagnostic_timeout_seconds':5})
    
    scheduler=DiagnosticScheduler(tmp_path);identifier=scheduler.store.enqueue(user_id='test-user',tool='configuration_export',config={'selected_ids':['ping_profiles'],'encrypted':False})
    marker=tmp_path/'builder-started'; original_popen=subprocess.Popen
    script="import runpy,time;from pathlib import Path;import twn_toolkit.export_jobs as ex;ex.configuration_payload=lambda *a:(Path("+repr(str(marker))+").write_text('started'),time.sleep(60))[1];runpy.run_module('twn_toolkit.diagnostic_worker',run_name='__main__')"
    def popen(args,**kwargs):return original_popen([args[0],'-c',script,*args[3:]],**kwargs)
    monkeypatch.setattr('twn_toolkit.diagnostic_worker.subprocess.Popen',popen)
    try:
        scheduler.tick();process=scheduler.active[identifier]['process'];end=time.monotonic()+12
        while not marker.exists() and time.monotonic()<end:time.sleep(.03)
        assert marker.exists()
        if cancel:scheduler.store.cancel(identifier,'test-user')
        while scheduler.active and time.monotonic()<end:scheduler.tick();time.sleep(.03)
        assert not scheduler.active and process.poll() is not None
        assert scheduler.store.get(identifier,'test-user')['state']==('cancelled' if cancel else 'failed')
        scheduler.store.cleanup();assert not artifact_directory(scheduler.store,identifier,'configuration_export').exists()
        assert not [path for path in (tmp_path/'.upload-reservations').iterdir() if path.is_dir()]
    finally:scheduler.close()

