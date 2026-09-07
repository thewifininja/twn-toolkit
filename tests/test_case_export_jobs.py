from __future__ import annotations

import json
import sqlite3
import shutil
import subprocess
import time
from unittest.mock import Mock

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.case_export import ExportCaseStore
from twn_toolkit.diagnostic_artifacts import artifact_directory
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import DiagnosticScheduler, execute_scan
from twn_toolkit.investigations import InvestigationStore
from twn_toolkit.operational import OperationalSettingsStore


def settings(case_id, kind='pdf', username='owner'):
    return {'kind':kind, 'investigation_id':case_id, 'username':username}


def test_export_queues_without_building_and_retains_completed_snapshot(tmp_path, monkeypatch):
    app=create_app(str(tmp_path)); app.testing=True; client=app.test_client()
    cases=InvestigationStore(str(tmp_path)); case=cases.create(owner_user_id='test-user',owner_username='test-user',title='Original')
    builder=Mock(return_value=b'%PDF-1.4\nfixture')
    monkeypatch.setattr('twn_toolkit.case_export.build_case_report_pdf',builder)
    queued=client.get('/investigations/'+case['id']+'/report.pdf')
    assert queued.status_code==303; builder.assert_not_called()
    store=DiagnosticJobStore(tmp_path); job=store.claim(); execute_scan(store,job['id'],job['token'])
    assert store.get(job['id'],'test-user')['state']=='succeeded'
    url='/investigations/exports/'+job['id']+'/download'
    response=client.get(url)
    assert response.data==b'%PDF-1.4\nfixture' and response.headers['Cache-Control']=='private, no-store'
    assert client.get(url,headers={'Range':'bytes=0-3'}).status_code==206
    cases.set_report_contents(case['id'],'test-user',event_ids=[],artifact_ids=[])
    assert client.get(url).data==response.data; builder.assert_called_once()
    with store.connect(write=True) as db:db.execute('UPDATE diagnostic_jobs SET completed=? WHERE id=?',(time.time()-48*3600,job['id']))
    assert client.get(url).status_code==410
    directory=artifact_directory(store,job['id'],'case_export')
    store.cleanup(); assert directory.exists()
    store.release(job['id'],job['token']); store.cleanup(); assert not directory.exists()


def test_export_snapshot_is_consistent_during_a_concurrent_change(tmp_path, monkeypatch):
    cases=InvestigationStore(str(tmp_path)); case=cases.create(owner_user_id='owner',owner_username='owner',title='Snapshot')
    before=cases.events_for_user(case['id'],'owner')
    original=ExportCaseStore.events_for_user
    def read_after_change(self,*args,**kwargs):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE investigation_events SET summary='changed while reading' WHERE investigation_id=?",(case['id'],))
        return original(self,*args,**kwargs)
    monkeypatch.setattr(ExportCaseStore,'events_for_user',read_after_change)
    exported=ExportCaseStore(str(tmp_path)).snapshot(case['id'],'owner','pdf',1024**2)
    assert exported['events'][0]['summary']==before[0]['summary']
    assert cases.events_for_user(case['id'],'owner')[0]['summary']=='changed while reading'


@pytest.mark.parametrize('limit',['input','output','cells'])
def test_export_limits_fail_without_publishing_partial_files(tmp_path, monkeypatch, limit):
    policy=OperationalSettingsStore(str(tmp_path)); policy.save({'diagnostic_case_export_input_mib':1,'diagnostic_case_export_max_mib':1,'diagnostic_case_export_pdf_cells':1000})
    cases=InvestigationStore(str(tmp_path));case=cases.create(owner_user_id='owner',owner_username='owner',title='Limits')
    if limit in {'input','cells'}:
        details={'large':'x'*(2*1024**2)} if limit=='input' else {'results':[{'host':'192.0.2.1','port':443,'status':'open'}]*1200}
        with sqlite3.connect(cases.path) as db:
            db.execute("UPDATE investigation_events SET tool_id='tools.port_scanner',details_json=? WHERE investigation_id=?",(json.dumps(details),case['id']))
    if limit=='output':monkeypatch.setattr('twn_toolkit.case_export.build_case_report_pdf',lambda *_:b'x'*(2*1024**2))
    if limit=='input':
        reader=Mock(side_effect=AssertionError('Oversized payload was deserialized'))
        monkeypatch.setattr(ExportCaseStore,'events_for_user',reader)
    store=DiagnosticJobStore(tmp_path);identifier=store.enqueue(user_id='owner',tool='case_export',config=settings(case['id']))
    policy.save({'diagnostic_case_export_max_mib':2})
    assert store.get(identifier,'owner')['config']['artifact_bytes']==1024**2
    job=store.claim();execute_scan(store,identifier,job['token']);result=store.get(identifier,'owner')
    assert result['state']=='failed' and 'limit' in result['error']
    if limit=='input':reader.assert_not_called()
    assert not (artifact_directory(store,identifier,'case_export')/'export.bin').exists()
    store.release(identifier,job['token']);store.cleanup()
    assert not artifact_directory(store,identifier,'case_export').exists()


def test_export_ownership_and_revoked_case_membership(tmp_path, monkeypatch):
    app=create_app(str(tmp_path));auth=AuthStore(str(tmp_path))
    owner=auth.create_user('owner','TemporaryPassword123!',is_admin=True)
    collaborator=auth.create_user('collaborator','TemporaryPassword123!',is_admin=True)
    cases=InvestigationStore(str(tmp_path));case=cases.create(owner_user_id=owner['id'],owner_username='owner',title='Shared')
    cases.add_participant(case['id'],owner['id'],'owner',collaborator['id'],'collaborator')
    client=app.test_client();client.post('/login',data={'username':'collaborator','password':'TemporaryPassword123!'})
    monkeypatch.setattr('twn_toolkit.case_export.build_case_report_pdf',lambda *_:b'%PDF fixture')
    assert client.get('/investigations/'+case['id']+'/report.pdf').status_code==303
    store=DiagnosticJobStore(tmp_path);job=store.claim();execute_scan(store,job['id'],job['token'])
    url='/investigations/exports/'+job['id']+'/download'
    assert client.get(url).status_code==200
    other=app.test_client();other.post('/login',data={'username':'owner','password':'TemporaryPassword123!'})
    assert other.get(url).status_code==404
    cases.remove_participant(case['id'],owner['id'],'owner',collaborator['id'])
    assert client.get(url).status_code==404
    assert client.get('/investigations/exports?job='+job['id']).status_code==404


@pytest.mark.parametrize('cancel',[False,True])
def test_stalled_export_builder_is_terminated_and_reaped(tmp_path, monkeypatch, cancel):
    OperationalSettingsStore(str(tmp_path)).save({'diagnostic_timeout_seconds':5})
    cases=InvestigationStore(str(tmp_path));case=cases.create(owner_user_id='owner',owner_username='owner',title='Stalled')
    scheduler=DiagnosticScheduler(tmp_path);identifier=scheduler.store.enqueue(user_id='owner',tool='case_export',config=settings(case['id']))
    marker=tmp_path/'builder-started'; original_popen=subprocess.Popen
    script="import runpy,time;from pathlib import Path;import twn_toolkit.case_export as ex;ex.build_case_report_pdf=lambda *a:(Path("+repr(str(marker))+").write_text('started'),time.sleep(60))[1];runpy.run_module('twn_toolkit.diagnostic_worker',run_name='__main__')"
    def popen(args,**kwargs):return original_popen([args[0],'-c',script,*args[3:]],**kwargs)
    monkeypatch.setattr('twn_toolkit.diagnostic_worker.subprocess.Popen',popen)
    try:
        scheduler.tick();process=scheduler.active[identifier]['process'];end=time.monotonic()+12
        while not marker.exists() and time.monotonic()<end:time.sleep(.03)
        assert marker.exists()
        if cancel:scheduler.store.cancel(identifier,'owner')
        while scheduler.active and time.monotonic()<end:scheduler.tick();time.sleep(.03)
        assert not scheduler.active and process.poll() is not None
        assert scheduler.store.get(identifier,'owner')['state']==('cancelled' if cancel else 'failed')
        scheduler.store.cleanup();assert not artifact_directory(scheduler.store,identifier,'case_export').exists()
        assert not [path for path in (tmp_path/'.upload-reservations').iterdir() if path.is_dir()]
    finally:scheduler.close()


def test_queued_export_cancellation_does_not_build(tmp_path, monkeypatch):
    app=create_app(str(tmp_path));app.testing=True;client=app.test_client()
    cases=InvestigationStore(str(tmp_path));case=cases.create(owner_user_id='test-user',owner_username='test-user',title='Cancel')
    builder=Mock();monkeypatch.setattr('twn_toolkit.case_export.build_case_report_pdf',builder)
    queued=client.get('/investigations/'+case['id']+'/report.pdf')
    identifier=queued.location.split('job=')[1]
    assert client.post('/investigations/exports/'+identifier+'/cancel').status_code==303
    store=DiagnosticJobStore(tmp_path)
    assert store.get(identifier,'test-user')['state']=='cancelled' and store.claim() is None
    builder.assert_not_called()


def test_export_reservations_and_operations_controls(tmp_path, monkeypatch):
    from types import SimpleNamespace
    app=create_app(str(tmp_path));app.testing=True;client=app.test_client()
    policy=OperationalSettingsStore(str(tmp_path));policy.save({'diagnostic_case_export_max_mib':1})
    store=DiagnosticJobStore(tmp_path);identifier=store.enqueue(user_id='owner',tool='case_export',config=settings('fixture'))
    job=store.claim();assert store.finish(identifier,job['token'],[],{})
    original_disk_usage = shutil.disk_usage
    monkeypatch.setattr('twn_toolkit.diagnostic_jobs.shutil.disk_usage',lambda _:SimpleNamespace(free=policy.get()['minimum_free_gib']*1024**3+35*1024**2))
    with pytest.raises(ValueError,match='free-disk reserve'):
        store.enqueue(user_id='owner',tool='case_export',config=settings('fixture'))
    store.release(identifier,job['token'])
    assert store.enqueue(user_id='owner',tool='case_export',config=settings('fixture'))
    monkeypatch.setattr('twn_toolkit.diagnostic_jobs.shutil.disk_usage', original_disk_usage)
    page=client.get('/settings?section=operations')
    for key in ('diagnostic_case_export_max_mib','diagnostic_case_export_input_mib','diagnostic_case_export_pdf_cells'):
        assert ('name="'+key+'"').encode() in page.data
    client.post('/settings/operations',data={**policy.get(),'diagnostic_case_export_max_mib':'32','diagnostic_case_export_input_mib':'8','diagnostic_case_export_pdf_cells':'2000'})
    assert policy.get()['diagnostic_case_export_max_mib']==32
    assert policy.get()['diagnostic_case_export_input_mib']==8
    assert policy.get()['diagnostic_case_export_pdf_cells']==2000
