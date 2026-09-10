import json
import sqlite3
from unittest.mock import Mock, patch

import pytest

from twn_toolkit.profile_backup import build_backup_catalog, import_backup_items, preview_import_items
from twn_toolkit.backup_source_reads import bounded_source_reads, bounded_backup_store
from twn_toolkit.profiles import JsonListStore


def group(identifier, store):
    return {'id':identifier,'label':identifier,'category':'Fixture','supports_merge':True,'supports_replace':True,'store':store}


@pytest.mark.parametrize('operation', ['preview','import'])
def test_oversized_later_file_is_rejected_before_any_write(tmp_path, operation):
    first=JsonListStore(str(tmp_path),'first.json');second=JsonListStore(str(tmp_path),'second.json')
    first.replace_all([{'name':'original'}])
    with second.path.open('wb') as source:source.truncate(65*1024**2)
    selected=[group('first',first),group('second',second)]
    incoming={'first':[{'name':'new'}],'second':[{'name':'new'}]}
    with patch.object(first,'replace_all',side_effect=AssertionError('must not mutate before all sources pass')):
        with pytest.raises(ValueError,match='read limit'):
            (preview_import_items if operation=='preview' else import_backup_items)(incoming,selected,'replace')
    assert first.all()==[{'name':'original'}]
    assert second.path.stat().st_size==65*1024**2


def test_import_source_budget_is_aggregate(tmp_path):
    stores=[JsonListStore(str(tmp_path),f'{i}.json') for i in range(2)]
    for store in stores:store.replace_all([{'name':'fixture','data':'x'*300}])
    selected=[group(str(i),store) for i,store in enumerate(stores)]
    with patch('twn_toolkit.profile_backup.MAX_BACKUP_WIRE_BYTES',500):
        with patch.object(stores[0],'replace_all',side_effect=AssertionError('preflight must precede mutation')):
            with pytest.raises(ValueError,match='read limit'):
                import_backup_items({str(i):[{'name':'new'}] for i in range(2)},selected,'replace')
    assert all(store.all()[0]['name']=='fixture' for store in stores)


def test_automation_rollback_includes_runtime_event_state_without_run_history(tmp_path):
    item=next(item for item in build_backup_catalog(str(tmp_path)) if item['id']=='automation_definitions')
    store=item['store'].store
    aid=store.save(name='fixture',interval_seconds=30,trigger_after=1,recover_after=1,cooldown_seconds=0,condition={'type':'manual.trigger','config':{}},actions=[{'type':'ssh.collect','config':{'hosts':'192.0.2.1','username':'fixture','password':'fixture','commands':'show clock','port':22,'command_timeout':30,'allow_unknown_hosts':False,'send_ctrl_y':False}}],created_by='fixture')
    with store._connect() as db:
        db.execute("INSERT INTO automation_event_state VALUES (?, 'manual.trigger','original',1,1)",(aid,))
        db.execute("INSERT INTO automation_runs (id,automation_id,started_at,finished_at,status,trigger_summary,results_json) VALUES ('run',?,1,1,'success','fixture',zeroblob(?))",(aid,65*1024**2))
    with bounded_source_reads(64*1024**2),bounded_backup_store(item['store'],rollback=True) as source:
        snapshot=source.backup_snapshot()
    assert snapshot['automation_event_state'][0]['event_key']=='original'
    assert 'automation_runs' not in snapshot
    with store._connect() as db:db.execute('UPDATE automation_event_state SET event_key=zeroblob(?)',(65*1024**2,))
    with patch.object(item['store'],'import_records',side_effect=AssertionError('must reject before mutation')):
        with pytest.raises(ValueError,match='read limit'):
            import_backup_items({item['id']:[{'name':'incoming'}]},[item],'merge')


def test_import_merge_reuses_preflight_records_and_rolls_back_later_failure(tmp_path):
    first=JsonListStore(str(tmp_path),'first.json');first.replace_all([{'name':'original','credential':'fixture-secret'}])
    class FailingStore:
        def all(self):return [{'name':'old'}]
        def import_records(self, *_):raise ValueError('fixture rejected')
        def replace_all(self, records):assert records==[{'name':'old'}]
    read=Mock(wraps=first.all)
    selected=[group('first',first),group('second',FailingStore())]
    with patch.object(first,'all',read):
        with pytest.raises(ValueError,match='fixture rejected'):
            import_backup_items({'first':[{'name':'new'}],'second':[{'name':'new'}]},selected,'merge')
    assert read.call_count==1
    assert first.all()==[{'name':'original','credential':'fixture-secret'}]


@pytest.mark.parametrize("identifier", ["ping_profiles", "dns_host_profiles"])
def test_large_destination_preview_renders_actionable_error_without_import_controls(tmp_path, identifier):
    from twn_toolkit import create_app
    from twn_toolkit.profile_backup import build_profile_backup, ConfigurationImportStore
    from twn_toolkit.auth import load_or_create_secret_key
    app=create_app(str(tmp_path));app.testing=True
    item=next(item for item in build_backup_catalog(str(tmp_path)) if item['id']==identifier)
    backup=build_profile_backup([item])
    previews=ConfigurationImportStore(str(tmp_path),load_or_create_secret_key(str(tmp_path)))
    token=previews.create(backup,user_id='test-user',encrypted_input=False,import_mode='merge')
    store = item['store'].mso_store()
    store.save({'name':'large'})
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE mso_objects SET payload=zeroblob(?) WHERE kind=?', (65*1024**2, store.kind))
    response=app.test_client().get('/settings/backup?view=import&preview='+token)
    assert response.status_code==200
    assert b'Backup preview could not be prepared' in response.data
    assert b'Export fewer groups' in response.data
    assert b'configuration-preview-form' not in response.data
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT length(payload) FROM mso_objects WHERE kind=?', (store.kind,)).fetchone()[0] == 65*1024**2


def test_private_rollback_preflight_checks_json_before_first_group_mutation(tmp_path):
    item=next(item for item in build_backup_catalog(str(tmp_path)) if item['id']=='automation_definitions')
    store=item['store'].store
    store.save(name='fixture',interval_seconds=30,trigger_after=1,recover_after=1,cooldown_seconds=0,
               condition={'type':'manual.trigger','config':{}},
               actions=[{'type':'ssh.collect','config':{'hosts':'192.0.2.1','username':'fixture','password':'fixture',
                         'commands':'show clock','port':22,'command_timeout':30,'allow_unknown_hosts':False,'send_ctrl_y':False}}],
               created_by='fixture')
    with store._connect() as db:
        db.execute('UPDATE automation_conditions SET config_json=?',('['*66+']'*66,))
    first=JsonListStore(str(tmp_path),'first.json');first.replace_all([{'name':'original'}])
    with patch.object(first,'replace_all',side_effect=AssertionError('decoded source must pass before any write')):
        with pytest.raises(ValueError,match='nesting'):
            import_backup_items({'first':[{'name':'new'}],item['id']:[{'name':'incoming'}]},
                                [group('first',first),item],'merge')
    assert first.all()==[{'name':'original'}]
