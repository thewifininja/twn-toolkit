import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from twn_toolkit.artifact_storage import ArtifactStore, checked_automation_source, staging_directory
from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.uploads import reap_abandoned_uploads

GIB = 1024**3


@pytest.fixture
def storage(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib': 0, 'automation_artifact_quota_gib': 1})
    return ArtifactStore(tmp_path, 'packet_captures', 1024**2)


def test_capture_reservation_blocks_competing_datastore_write(storage):
    with patch('twn_toolkit.uploads.shutil.disk_usage', return_value=SimpleNamespace(free=10)):
        with storage.begin_upload('', 'capture', max_bytes=8) as capture:
            path, _ = capture.external_writer()
            with pytest.raises(DatastoreError, match='free-disk'):
                LocalDatastore(str(storage.instance)).begin_upload('', 'competing', expected_bytes=4)
            path.write_bytes(b'pcap')
            assert not capture.destination.exists()
            assert capture.commit() == (capture.destination, 4)
    assert capture.destination.read_bytes() == b'pcap'
    assert capture.destination.stat().st_mode & 0o777 == 0o600


def test_artifact_quota_includes_other_areas_and_pending_writes(storage):
    baseline = storage.root / 'baseline'
    with baseline.open('wb') as stream: stream.truncate(GIB - 8)
    other = ArtifactStore(storage.instance, 'automation_staging', 8)
    with other.begin_upload('', 'first', expected_bytes=6) as first:
        with pytest.raises(DatastoreError, match='quota'):
            storage.begin_upload('', 'second', expected_bytes=4)
        first.write(b'123456');first.commit()
    with pytest.raises(DatastoreError, match='quota'):
        storage.begin_upload('', 'second', expected_bytes=4)


@pytest.mark.parametrize('change', ['oversize', 'replacement', 'symlink'])
def test_external_output_identity_and_size_are_checked_before_publication(storage, change):
    with storage.begin_upload('', 'capture', max_bytes=8) as capture:
        path, _ = capture.external_writer()
        if change == 'oversize': path.write_bytes(b'x' * 9)
        else:
            path.unlink()
            if change == 'replacement': path.write_bytes(b'new')
            else:
                target = storage.instance / 'untouched';target.write_bytes(b'original');path.symlink_to(target)
        with pytest.raises(DatastoreError, match='External output'):
            capture.commit()
    assert not capture.destination.exists()
    if change == 'symlink': assert target.read_bytes() == b'original'


def test_external_child_keeps_reservation_after_parent_exit(storage):
    program = r'''
import json, os, subprocess, sys
from twn_toolkit.artifact_storage import ArtifactStore
store = ArtifactStore(sys.argv[1], 'packet_captures', 8)
upload = store.begin_upload('', 'orphan', max_bytes=8)
path, lease = upload.external_writer()
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], pass_fds=(lease,),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(json.dumps({'pid': child.pid, 'directory': str(upload.directory)}), flush=True)
os._exit(0)
'''
    result = subprocess.run([sys.executable, '-c', program, str(storage.instance)], capture_output=True, text=True, timeout=10, check=True)
    child = json.loads(result.stdout)
    directory = Path(child['directory'])
    try:
        reap_abandoned_uploads(storage.instance)
        assert directory.exists()
        with patch('twn_toolkit.uploads.shutil.disk_usage', return_value=SimpleNamespace(free=10)):
            with pytest.raises(DatastoreError, match='free-disk'):
                LocalDatastore(str(storage.instance)).begin_upload('', 'competing', expected_bytes=4)
    finally:
        os.kill(child['pid'], signal.SIGKILL)
    deadline = time.monotonic()+5
    while directory.exists() and time.monotonic()<deadline:
        reap_abandoned_uploads(storage.instance)
        time.sleep(.02)
    assert not directory.exists()
    assert not (storage.root/'orphan').exists()


def test_automation_staging_is_private_and_not_diagnostic_history(storage):
    from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
    store, stage = staging_directory(storage.instance, 100)
    store.save_upload(store.relative(stage), 'collected', io.BytesIO(b'private'))
    source = stage/'collected'
    assert checked_automation_source(storage.instance, source) == source
    assert stage.stat().st_mode & 0o777 == 0o700
    DiagnosticJobStore(storage.instance).cleanup()
    assert source.read_bytes() == b'private'
    assert LocalDatastore(str(storage.instance)).list()['entries'] == []


def test_automation_source_rejects_unrelated_files_and_symlinks(storage):
    unrelated = storage.instance/'keep';unrelated.write_bytes(b'keep')
    with pytest.raises(ValueError, match='outside'):
        checked_automation_source(storage.instance, unrelated)
    _, stage = staging_directory(storage.instance, 100)
    alias = stage/'alias';alias.symlink_to(unrelated)
    with pytest.raises(ValueError, match='unavailable'):
        checked_automation_source(storage.instance, alias)
    assert unrelated.read_bytes() == b'keep'


def automation_store(instance):
    from twn_toolkit.automation import AutomationStore
    from twn_toolkit.auth import load_or_create_secret_key
    store = AutomationStore(str(instance), load_or_create_secret_key(str(instance)))
    identifier = store.save(name='Artifact regression', interval_seconds=30, trigger_after=1, recover_after=1,
        cooldown_seconds=0, condition={'type':'manual.trigger','config':{}}, created_by='owner',
        actions=[{'type':'ssh.collect', 'config':{'hosts':'192.0.2.1', 'username':'api', 'password':'fixture',
            'commands':'show clock', 'port':22, 'command_timeout':30, 'allow_unknown_hosts':False, 'send_ctrl_y':False}}])
    return store, identifier


@pytest.mark.parametrize('state', ['waiting', 'failed'])
def test_staging_cleanup_preserves_delayed_and_retryable_inputs(storage, state):
    from twn_toolkit.artifact_storage import cleanup_staging
    from twn_toolkit.automation_registry import ConditionResult
    store, automation_id = automation_store(storage.instance)
    _, retained = staging_directory(storage.instance, 100)
    _, abandoned = staging_directory(storage.instance, 100)
    _, fresh = staging_directory(storage.instance, 100)
    (retained/'source').write_bytes(b'retained')
    (abandoned/'source').write_bytes(b'abandoned')
    job_id = store.enqueue_manual_job(automation_id, ConditionResult(True,'met','manual',{}))
    store.claim_job(job_id)
    progress = {'action_results':[{'output':{'_artifact_sources':[{'source_path':str(retained/'source')}]}}]}
    store.defer_job_for_stage(job_id, 60, progress)
    if state == 'failed':
        with store._connect() as db: db.execute("UPDATE automation_jobs SET status='failed' WHERE id=?",(job_id,))
    old = time.time()-90000
    os.utime(retained, (old,old));os.utime(abandoned,(old,old))
    assert cleanup_staging(store) == 1
    assert (retained/'source').read_bytes() == b'retained'
    assert fresh.exists()
    assert not abandoned.exists()


def test_failed_publication_preserves_all_sources_for_retry(storage, monkeypatch):
    from twn_toolkit.automation_registry import ActionResult, ConditionResult
    store, automation_id = automation_store(storage.instance)
    output, stage = staging_directory(storage.instance, 100)
    for name in ('one','two'): output.save_upload(output.relative(stage), name, io.BytesIO(name.encode()))
    result = ActionResult('success','collected',{'_artifact_sources':[{'source_path':str(stage/name), 'filename':name} for name in ('one','two')]})
    original = ArtifactStore.begin_upload
    calls = []
    def upload(target, *args, **kwargs):
        calls.append(args)
        if len(calls) == 2: raise DatastoreError('fixture publication failure')
        return original(target,*args,**kwargs)
    with monkeypatch.context() as scoped:
        scoped.setattr(ArtifactStore,'begin_upload',upload)
        with pytest.raises(DatastoreError, match='publication failure'):
            store.record_run(automation_id,ConditionResult(True,'met','manual',{}),[result])
    assert (stage/'one').read_bytes() == b'one'
    assert (stage/'two').read_bytes() == b'two'
    assert not list(store.artifact_root.iterdir())
    run_id = store.record_run(automation_id,ConditionResult(True,'met','manual',{}),[result])
    assert store.run_artifact(run_id,'action-1/one').read_bytes() == b'one'
    assert not stage.exists()


def test_capture_exec_retains_reserved_lease_and_publishes_only_after_exit(storage, monkeypatch):
    from twn_toolkit.packet_capture import run_packet_capture
    from tests.test_packet_capture import VALID_CONFIG
    executable = storage.instance/'capture-fixture'
    executable.write_text('#!'+sys.executable+'\n'+'''import os, pathlib, sys
os.fstat(int(os.environ['TWN_FIXTURE_LEASE']))
pathlib.Path(sys.argv[sys.argv.index('-w')+1]).write_bytes(b'\\xd4\\xc3\\xb2\\xa1'+b'\\0'*28)
print('1 packets captured',file=sys.stderr)
''')
    executable.chmod(0o700)
    actual = subprocess.Popen
    destination = storage.root/'result.pcap'
    def launch(command, **kwargs):
        assert not destination.exists()
        kwargs['env'] = {**os.environ, 'TWN_FIXTURE_LEASE':str(kwargs['pass_fds'][0])}
        return actual(command, **kwargs)
    monkeypatch.setattr('twn_toolkit.packet_capture.subprocess.Popen', launch)
    monkeypatch.setattr('twn_toolkit.packet_capture.validate_capture_config', lambda *args, **kwargs: {**VALID_CONFIG,'max_size_mib':1})
    monkeypatch.setattr('twn_toolkit.packet_capture.capture_capability', lambda: {'available':True,'executable':str(executable)})
    result = run_packet_capture(VALID_CONFIG, instance_path=storage.instance, output_path=destination)
    assert result['size_bytes'] == 32
    assert result['packet_count_captured'] == 1
    assert destination.read_bytes() == b'\xd4\xc3\xb2\xa1'+b'\0'*28


def test_capture_refuses_capacity_before_starting_process(storage, monkeypatch):
    from twn_toolkit.packet_capture import run_packet_capture
    from twn_toolkit.network_tools import ToolInputError
    from tests.test_packet_capture import VALID_CONFIG
    monkeypatch.setattr('twn_toolkit.packet_capture.validate_capture_config', lambda *args, **kwargs: {**VALID_CONFIG,'max_size_mib':1})
    with patch('twn_toolkit.uploads.shutil.disk_usage', return_value=SimpleNamespace(free=512)), patch('twn_toolkit.packet_capture.subprocess.Popen') as launch:
        with pytest.raises(ToolInputError, match='free-disk'):
            run_packet_capture(VALID_CONFIG, instance_path=storage.instance, output_path=storage.root/'refused.pcap')
        launch.assert_not_called()


def test_orphan_cleanup_waits_for_in_progress_publication(storage, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from twn_toolkit.automation_registry import ActionResult, ConditionResult
    store, automation_id = automation_store(storage.instance)
    output, stage = staging_directory(storage.instance, 100)
    output.save_upload(output.relative(stage),'source',io.BytesIO(b'collected'))
    result = ActionResult('success','collected',{'_artifact_sources':[{'source_path':str(stage/'source'),'filename':'source'}]})
    entered, release, cleanup_started = threading.Event(), threading.Event(), threading.Event()
    original = ArtifactStore.begin_upload
    def upload(target, *args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(target,*args,**kwargs)
    monkeypatch.setattr(ArtifactStore,'begin_upload',upload)
    def clean():
        cleanup_started.set()
        return store.cleanup_orphan_artifacts()
    with ThreadPoolExecutor(max_workers=2) as executor:
        writing = executor.submit(store.record_run,automation_id,ConditionResult(True,'met','manual',{}),[result])
        try:
            assert entered.wait(5)
            cleaning = executor.submit(clean)
            assert cleanup_started.wait(5)
            time.sleep(.05)
            assert not cleaning.done()
        finally:
            release.set()
        run_id = writing.result(timeout=5)
        assert cleaning.result(timeout=5)['count'] == 0
    assert store.run_artifact(run_id,'action-1/source').read_bytes() == b'collected'
