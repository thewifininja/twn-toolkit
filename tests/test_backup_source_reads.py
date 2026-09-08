from export_job_helpers import run_export
import json
import os
import sqlite3
from unittest.mock import patch

import pytest

from twn_toolkit.auth import AuthStore, load_or_create_secret_key
from twn_toolkit.automation import AutomationStore, AutomationBackupStore
from twn_toolkit.backup_source_reads import (
    SourceReadLimit, bounded_source_reads, read_json_file, source_json_loads,
    configuration_snapshot, bounded_backup_store, current_source_budget,
)
from twn_toolkit.profile_backup import build_profile_backup, build_backup_catalog
from twn_toolkit.sqlite_incremental import ReadSnapshot


def test_file_gate_precedes_read_and_decoder(tmp_path):
    path = tmp_path/'large.json'
    with path.open('wb') as source:
        source.truncate(65*1024*1024)
    with bounded_source_reads(64*1024*1024), patch('twn_toolkit.backup_source_reads.json.loads',side_effect=AssertionError('decoded oversized source')):
        with pytest.raises(SourceReadLimit,match='read limit'):
            read_json_file(path)
    assert path.stat().st_size == 65*1024*1024


def test_file_bytes_and_json_nodes_are_shared_and_context_resets(tmp_path):
    first=tmp_path/'first.json';second=tmp_path/'second.json'
    first.write_text('["中文😀"]');second.write_text('[1,2]')
    with bounded_source_reads(first.stat().st_size):
        assert read_json_file(first)==['中文😀']
        with pytest.raises(SourceReadLimit):read_json_file(second)
    assert current_source_budget() is None
    with bounded_source_reads(100):
        current_source_budget()[1]=3
        assert source_json_loads('[1,2]')==[1,2]
        with pytest.raises(SourceReadLimit,match='complex'):
            source_json_loads('[3,4]')


@pytest.mark.parametrize('raw',[b'['*66+b']'*66,b'not JSON',b'"\xff"'])
def test_invalid_source_cannot_silently_become_defaults(tmp_path,raw):
    path=tmp_path/'source.json';path.write_bytes(raw)
    with bounded_source_reads(1000):
        with pytest.raises(SourceReadLimit):read_json_file(path)
    assert path.read_bytes()==raw


def test_source_fifo_is_rejected_without_blocking(tmp_path):
    path=tmp_path/'source.json';os.mkfifo(path)
    with bounded_source_reads(1000):
        with pytest.raises(SourceReadLimit,match='regular file'):
            read_json_file(path)


@pytest.fixture
def automation(tmp_path):
    store=AutomationStore(str(tmp_path),'fixture')
    aid=store.save(name='fixture',interval_seconds=30,trigger_after=1,recover_after=1,cooldown_seconds=0,condition={'type':'manual.trigger','config':{}},actions=[{'type':'ssh.collect','config':{'hosts':'192.0.2.1','username':'u','password':'secret','commands':'show clock','port':22,'command_timeout':300,'allow_unknown_hosts':False,'send_ctrl_y':False}}],created_by='fixture')
    return store,aid


def test_snapshot_preserves_configuration_and_excludes_large_history(automation):
    store,aid=automation
    expected=AutomationBackupStore(store).all()
    with store._connect() as writer:
        writer.execute("INSERT INTO automation_runs (id,automation_id,started_at,finished_at,status,trigger_summary,results_json) VALUES ('run',?,1,1,'success','fixture',zeroblob(?))",(aid,65*1024*1024))
    with bounded_source_reads(64*1024*1024), bounded_backup_store(AutomationBackupStore(store)) as bounded:
        assert bounded.all()==expected
        with bounded.store._connect() as connection:
            with pytest.raises(sqlite3.OperationalError):
                connection.execute('DELETE FROM automations')
    with pytest.raises(sqlite3.ProgrammingError):connection.execute('SELECT 1')
    assert AutomationBackupStore(store).all()==expected


def test_oversized_sqlite_cell_is_rejected_before_copy(automation):
    store,_=automation
    with store._connect() as writer:
        writer.execute('UPDATE automation_conditions SET config_json=zeroblob(?)',(65*1024*1024,))
    original=ReadSnapshot.read_blob
    def checked(self,table,column,rowid,**kwargs):
        raw,size=original(self,table,column,rowid,**kwargs)
        if column=='config_json':assert raw is None
        return raw,size
    with bounded_source_reads(64*1024*1024),patch.object(ReadSnapshot,'read_blob',checked):
        with pytest.raises(ValueError,match='read limit'):
            with bounded_backup_store(AutomationBackupStore(store)):
                raise AssertionError('oversized snapshot accepted')
    with store._connect() as db:
        assert db.execute('SELECT count(*) FROM automation_conditions').fetchone()[0]==1


def test_export_rejects_deep_encrypted_action_before_decoding(automation):
    store,_=automation
    encrypted=store._cipher.encrypt(b'['*66+b']'*66).decode()
    with store._connect() as db:
        db.execute('UPDATE automation_actions SET config_encrypted=?',(encrypted,))
    adapter=AutomationBackupStore(store)
    item=dict(id='automation_definitions',label='Automation',category='Automation',sensitive=True,store=adapter)
    with pytest.raises(ValueError,match='nesting'):
        build_profile_backup([item])


def test_actual_catalog_all_groups_export_without_mutating_sources(tmp_path):
    secret=load_or_create_secret_key(str(tmp_path))
    auth=AuthStore(str(tmp_path));auth.create_user('owner','TemporaryPassword123!',is_admin=True)
    catalog=build_backup_catalog(str(tmp_path))
    expected={item['id']:item['store'].all() for item in catalog}
    exported=build_profile_backup(catalog)
    assert exported['items']==expected
    assert {item['id']:item['store'].all() for item in catalog}==expected


def test_selected_time_source_errors_do_not_export_default_timezone(tmp_path):
    from twn_toolkit.time_settings import TimeSettingsStore
    store=TimeSettingsStore(tmp_path)
    store.path.write_bytes(b'['*66+b']'*66)
    with bounded_source_reads(1000):
        with pytest.raises(SourceReadLimit,match='nesting'):
            store.get()
    # Existing non-export fallback remains available outside the bounded context.
    assert 'timezone' in store.get()


def test_snapshot_isolated_from_later_source_changes(automation):
    store,_=automation
    expected=AutomationBackupStore(store).all()
    with bounded_source_reads(64*1024*1024),bounded_backup_store(AutomationBackupStore(store)) as bounded:
        with store._connect() as writer:
            writer.execute("UPDATE automation_conditions SET name='changed source'")
        assert bounded.all()==expected
    assert AutomationBackupStore(store).all()!=expected


def test_snapshot_table_row_cap_preserves_source(tmp_path):
    from types import SimpleNamespace
    path=tmp_path/'source.db'
    with sqlite3.connect(path) as writer:
        writer.execute('CREATE TABLE sample (id INTEGER PRIMARY KEY, payload TEXT)')
        writer.executemany('INSERT INTO sample VALUES (?,?)',((i,'fixture') for i in range(10001)))
    with bounded_source_reads(64*1024*1024):
        with pytest.raises(ValueError,match='10000 records'):
            with configuration_snapshot(SimpleNamespace(path=path),('sample',)):
                raise AssertionError('oversized table accepted')
    with sqlite3.connect(path) as read:
        assert read.execute('SELECT count(*) FROM sample').fetchone()[0]==10001


def test_populated_remote_and_pki_export_preserves_secrets_and_omits_versions(tmp_path):
    from twn_toolkit.remote_connections import RemoteConnectionStore
    from twn_toolkit.certificate_automation import CertificateAutomationStore,EnrollmentResult
    secret=load_or_create_secret_key(str(tmp_path))
    auth=AuthStore(str(tmp_path));owner=auth.create_user('owner','TemporaryPassword123!',is_admin=True)
    remote=RemoteConnectionStore(str(tmp_path),secret)
    credential=remote.save_credential(user_id=owner['id'],name='SSH credential',remote_username='operator',password='SSH-secret')
    remote.save_host(user_id=owner['id'],name='fixture',host='192.0.2.1',port=22,protocol='ssh',folder_id='',credential_id=credential['id'],allow_unknown_hosts=False,allow_legacy_algorithms=False)
    pki=CertificateAutomationStore(str(tmp_path),secret)
    credential=pki.save_credential(credential_id='',name='PKI credential',username='operator',password='PKI-secret')
    server=pki.save_server(dict(name='Fixture CA',provider='adcs_web_enrollment',enrollment_url='https://ca.example.test/certsrv/',credential_id=credential['id'],ca_bundle_pem='',verify_tls=True,retrieval_strategy='same_endpoint',timeout=15))
    template=pki.save_template(dict(name='Web server',server_id=server['id'],template_identifier='WebServer',key_size=2048,renewal_days=30))
    pki.save_enrollment(managed_id='',name='Fixture',server_id=server['id'],template_id=template['id'],common_name='fixture.example.test',dns_names=['fixture.example.test'],private_key_pem=b'PRIVATE KEY MATERIAL',result=EnrollmentResult(status='pending',request_id='42',message='private issued history'))
    catalog=[item for item in build_backup_catalog(str(tmp_path)) if item['id'] in {'remote_connection_library','certificate_automation_profiles'}]
    expected={item['id']:item['store'].all() for item in catalog}
    original=ReadSnapshot.read_blob
    def checked(self,table,*args,**kwargs):
        assert table!='certificate_versions'
        return original(self,table,*args,**kwargs)
    with patch.object(ReadSnapshot,'read_blob',checked):
        exported=build_profile_backup(catalog)
    assert exported['items']==expected
    encoded=json.dumps(exported)
    assert 'SSH-secret' in encoded and 'PKI-secret' in encoded
    assert 'PRIVATE KEY MATERIAL' not in encoded and 'private issued history' not in encoded


def test_large_source_export_error_can_render_backup_page(tmp_path):
    from twn_toolkit import create_app
    app=create_app(str(tmp_path));app.testing=True
    item=next(item for item in build_backup_catalog(str(tmp_path)) if item['id']=='ping_profiles')
    with item['store'].path.open('wb') as file:
        file.write(b'[]');file.truncate(65*1024*1024)
    client=app.test_client()
    with patch('twn_toolkit.export_jobs.encrypt_backup') as encrypt:
        result=run_export(client,client.post('/settings/backup/export',data={'item':'ping_profiles'}))
    assert result['state']=='failed' and 'Export fewer groups' in result['error']
    response=client.get('/settings/backup')
    assert response.status_code==200 and b'Count unavailable' in response.data
    assert item['store'].path.stat().st_size==65*1024*1024
    encrypt.assert_not_called()
