import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from twn_toolkit.case_export import ExportCaseStore, CaseExportLimitError
from twn_toolkit.case_export_source import selected_case_snapshot
from twn_toolkit.investigations import InvestigationStore, InvestigationError


@pytest.fixture
def case(tmp_path):
    store = InvestigationStore(tmp_path)
    case = store.create(owner_user_id='owner', owner_username='owner', title='Selected case 中文😀')
    return store, case


@pytest.mark.parametrize('column', ['description', 'title'])
def test_case_header_is_gated_before_store_projection(case, column):
    store, item = case
    with sqlite3.connect(store.path) as db:
        db.execute(f'UPDATE investigations SET {column}=zeroblob(?) WHERE id=?', (65*1024**2, item['id']))
    with patch.object(ExportCaseStore, 'get_for_user', side_effect=AssertionError('projected before gate')):
        with pytest.raises(CaseExportLimitError, match='limit'):
            ExportCaseStore(store.instance_path).snapshot(item['id'], 'owner', 'pdf', 1024**2)


def test_excluded_payload_is_never_copied_and_other_cases_are_ignored(case):
    store, item = case
    other = store.create(owner_user_id='other', owner_username='other', title='Other case')
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE investigation_events SET details_json=zeroblob(?),report_placement='excluded',created_by_username='prior operator' WHERE investigation_id=?", (65*1024**2,item['id']))
        db.execute('UPDATE investigations SET description=zeroblob(?) WHERE id=?', (65*1024**2,other['id']))
    exported = ExportCaseStore(store.instance_path).snapshot(item['id'], 'owner', 'pdf', 1024**2)
    assert exported['events'] == []
    assert exported['investigation']['event_count'] == 1
    assert exported['investigation']['operator_names'] == 'owner, prior operator'
    with pytest.raises(CaseExportLimitError, match='limit'):
        ExportCaseStore(store.instance_path).snapshot(item['id'], 'owner', 'portable', 1024**2)


@pytest.mark.parametrize('raw', ['['*66+']'*66, '['+'0,'*500_001+'0]'])
def test_case_json_complexity_is_checked_before_deserialization(case, raw):
    store, item = case
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE investigation_events SET details_json=?', (raw,))
    with patch.object(ExportCaseStore, 'events_for_user', side_effect=AssertionError('decoded complex data')):
        with pytest.raises(CaseExportLimitError, match='limit'):
            ExportCaseStore(store.instance_path).snapshot(item['id'],'owner','portable',4*1024**2)


def test_case_snapshot_access_closure_and_readonly(case):
    store, item = case
    with pytest.raises(InvestigationError, match='not found'):
        with selected_case_snapshot(store.path,item['id'],'stranger','pdf',1024**2):
            raise AssertionError('unauthorized')
    with selected_case_snapshot(store.path,item['id'],'owner','pdf',1024**2) as (db,counts,names):
        assert db.execute('SELECT title FROM investigations').fetchone()[0] == item['title']
        with pytest.raises(sqlite3.OperationalError):
            db.execute('DELETE FROM investigations')
    with pytest.raises(sqlite3.ProgrammingError):
        db.execute('SELECT 1')


def test_case_source_rejects_large_cell_without_native_full_copy(case):
    store, item = case
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE investigation_events SET details_json=zeroblob(?)', (65*1024**2,))
    if not Path('/proc/self/status').exists():
        with pytest.raises(CaseExportLimitError):
            ExportCaseStore(store.instance_path).snapshot(item['id'],'owner','portable',1024**2)
        return
    program = '''from pathlib import Path
import sys,json
from twn_toolkit.case_export import ExportCaseStore,CaseExportLimitError
def hwm():return int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('VmHWM:')))
store=ExportCaseStore(sys.argv[1]);before=hwm()
try:store.snapshot(sys.argv[2],'owner','portable',1024**2)
except CaseExportLimitError:pass
else:raise AssertionError('oversized accepted')
print(json.dumps({'increase_kib':hwm()-before}))
'''
    result = subprocess.run([sys.executable,'-c',program,str(store.instance_path),item['id']],capture_output=True,text=True,timeout=20,check=True)
    assert json.loads(result.stdout)['increase_kib'] < 12*1024


def test_report_preserves_import_and_evidence_origins_when_event_is_excluded(case):
    import io
    store, item = case
    event = store.events_for_user(item['id'],'owner')[0]
    artifact = store.add_evidence(investigation_id=item['id'],user_id='owner',username='owner',filename='fixture.txt',content_type='text/plain',stream=io.BytesIO(b'fixture'))
    with sqlite3.connect(store.path) as db:
        db.execute("INSERT INTO investigation_imports VALUES (?, 'source-case','0.24.0','source-owner',?,'digest','owner','owner',1)",(item['id'],json.dumps([{'user_id':'source-user','username':'source-operator','role':'owner'}])))
        db.execute('INSERT INTO investigation_event_origins VALUES (?,?,?,?)',(item['id'],event['id'],'source-case','source-event'))
        db.execute('INSERT INTO investigation_artifact_origins VALUES (?,?,?,?)',(item['id'],artifact['id'],'source-case','source-artifact'))
        db.execute("UPDATE investigation_events SET report_placement='excluded' WHERE id=?",(event['id'],))
        db.execute('UPDATE investigation_artifacts SET event_id=? WHERE id=?',(event['id'],artifact['id']))
    exported = ExportCaseStore(store.instance_path).snapshot(item['id'],'owner','pdf',1024**2)
    assert exported['investigation']['source_operators'][0]['username']=='source-operator'
    evidence = next(row for row in exported['artifacts'] if row['id']==artifact['id'])
    assert evidence['origin_case_id']=='source-case'
    assert evidence['origin_artifact_id']=='source-artifact'
    assert evidence['event_origin_id']=='source-event'
    assert not any(row['id']==event['id'] for row in exported['events'])


def test_export_routes_authorize_large_case_without_loading_its_header(tmp_path):
    from twn_toolkit import create_app
    from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
    from twn_toolkit.diagnostic_worker import execute_scan
    app=create_app(str(tmp_path));app.testing=True
    store=InvestigationStore(tmp_path)
    item=store.create(owner_user_id='test-user',owner_username='test-user',title='Large header')
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE investigations SET description=zeroblob(?)',(65*1024**2,))
    client=app.test_client()
    with patch.object(InvestigationStore,'get_for_user',side_effect=AssertionError('authorization loaded header')):
        response=client.get('/investigations/'+item['id']+'/report.pdf')
        assert response.status_code==303
        jobs=DiagnosticJobStore(tmp_path);job=jobs.claim()
        execute_scan(jobs,job['id'],job['token'])
        response=client.get('/investigations/exports/'+job['id']+'/status')
        assert response.status_code==200 and response.json['state']=='failed'
        assert 'limit' in response.json['error']
