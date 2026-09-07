from __future__ import annotations

import io
import socket
import time
import zipfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from twn_toolkit import create_app
from twn_toolkit.datastore import LocalDatastore
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import DiagnosticScheduler, execute_scan
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.transfer_diagnostic import artifact_directory, prepare_transfer_config

FORM = {'hosts': '127.0.0.1', 'username': 'remote', 'port': '22', 'remote_paths': '/config',
        'allow_unknown_hosts': True, 'allow_legacy_algorithms': False, 'destination': '',
        'output_mode': 'download', 'filename_pattern': '{filename}', 'protocol': 'sftp'}


def config(**changes):
    return {**prepare_transfer_config({**FORM, **changes}, 'fixture-password'),
            'username': 'operator', 'investigation_id': ''}


def fetch(**kwargs):
    rows = []
    for index in range(2):
        name = f'config-{index}.txt'
        (kwargs['output_dir'] / name).write_bytes(b'configuration')
        rows.append({'host': '127.0.0.1', 'host_label': '', 'remote_path': '/config',
                     'filename': name, 'size': 13, 'status': 'success', 'error': ''})
    return rows


def test_post_never_fetches_and_all_job_routes_require_owner(tmp_path, monkeypatch):
    app = create_app(str(tmp_path)); app.testing = True
    client = app.test_client()
    blocked = Mock(side_effect=AssertionError('Network work reached the web process'))
    monkeypatch.setattr('twn_toolkit.transfer_diagnostic.fetch_transfer_files', blocked)
    response = client.post('/tools/multi-transfer', data={**FORM, 'password': 'fixture-password'})
    assert response.status_code == 303
    assert client.get(response.location).status_code == 200
    assert b'fixture-password' not in client.get(response.location).data
    assert client.get('/').status_code == 200
    blocked.assert_not_called()
    store = DiagnosticJobStore(tmp_path)
    other = store.enqueue(user_id='different-owner', tool='transfer', config=config())
    for suffix in ('status', 'download'):
        assert client.get(f'/tools/multi-transfer/jobs/{other}/{suffix}').status_code == 404
    assert client.post(f'/tools/multi-transfer/jobs/{other}/cancel').status_code == 404
    assert client.get('/tools/multi-transfer', query_string={'job': other}).status_code == 404
    assert b'fixture-password' not in store.path.read_bytes()


def test_archive_range_download_and_retention_cleanup(tmp_path, monkeypatch):
    app = create_app(str(tmp_path)); app.testing = True
    client = app.test_client()
    response = client.post('/tools/multi-transfer', data={**FORM, 'password': 'fixture-password'})
    store = DiagnosticJobStore(tmp_path); job = store.claim()
    monkeypatch.setattr('twn_toolkit.transfer_diagnostic.fetch_transfer_files', fetch)
    execute_scan(store, job['id'], job['token']); store.release(job['id'], job['token'])
    path = artifact_directory(store, job['id']) / 'download.zip'
    assert path.exists() and path.stat().st_mode & 0o777 == 0o600
    assert not (path.parent / 'files').exists()
    assert b'Download ZIP' in client.get(response.location).data
    url = f"/tools/multi-transfer/jobs/{job['id']}/download"
    downloaded = client.get(url)
    assert downloaded.headers['Cache-Control'] == 'private, no-store'
    with zipfile.ZipFile(io.BytesIO(downloaded.data)) as archive:
        assert archive.read('config-0.txt') == b'configuration'
        assert 'multi-transfer-report.txt' in archive.namelist()
    part = client.get(url, headers={'Range': 'bytes=0-3'})
    assert part.status_code == 206 and part.data == downloaded.data[:4]
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET completed=? WHERE id=?', (time.time()-31*86400, job['id']))
    assert client.get(url).status_code == 410
    store.cleanup()
    assert not path.parent.exists()
    assert client.get(url).status_code == 404


def test_cancel_during_datastore_publication_retains_progress_without_replay(tmp_path, monkeypatch):
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id='owner', tool='transfer', config=config(output_mode='datastore'))
    job = store.claim(); original = store.progress
    calls = []

    def cancel_after_publish(job_id, token, summary):
        result = original(job_id, token, summary)
        if result and summary['published_paths']:
            calls.append(list(summary['published_paths']))
            store.cancel(job_id, 'owner')
        return result

    monkeypatch.setattr(store, 'progress', cancel_after_publish)
    monkeypatch.setattr('twn_toolkit.transfer_diagnostic.fetch_transfer_files', fetch)
    with pytest.raises(InterruptedError):
        execute_scan(store, job_id, job['token'])
    assert calls == [['config-0.txt']]
    assert LocalDatastore(str(tmp_path)).file('config-0.txt').read_bytes() == b'configuration'
    assert store.get(job_id, 'owner')['summary']['published_paths'] == ['config-0.txt']
    store.recover()
    assert store.get(job_id, 'owner')['state'] == 'unknown'
    assert store.claim() is None
    store.cleanup()
    assert not artifact_directory(store, job_id).exists()
    assert LocalDatastore(str(tmp_path)).file('config-0.txt').exists()


def test_queue_reserves_peak_transfer_disk_budget(tmp_path, monkeypatch):
    store = DiagnosticJobStore(tmp_path)
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib': 0, 'transfer_run_mib': 8})
    # 32MiB result envelope + two 8MiB copies; second job cannot reserve the same headroom.
    monkeypatch.setattr('twn_toolkit.diagnostic_jobs.shutil.disk_usage', lambda path: type('Usage', (), {'free': 70*1024**2})())
    store.enqueue(user_id='owner', tool='transfer', config=config())
    with pytest.raises(ValueError, match='free-disk reserve'):
        store.enqueue(user_id='owner', tool='transfer', config=config())


@pytest.mark.parametrize('cancel', [False, True])
def test_real_subprocess_releases_stalled_ssh_on_deadline_or_cancel(tmp_path, cancel):
    OperationalSettingsStore(str(tmp_path)).save({'diagnostic_timeout_seconds': 5, 'transfer_deadline_seconds': 60})
    scheduler = DiagnosticScheduler(tmp_path)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(10)
        job_id = scheduler.store.enqueue(user_id='owner', tool='transfer', config=config(port=str(listener.getsockname()[1])))
        try:
            scheduler.tick()
            connection, _ = listener.accept()
            with connection:
                if cancel:
                    scheduler.store.cancel(job_id, 'owner')
                end = time.monotonic()+12
                while time.monotonic() < end:
                    scheduler.tick()
                    job = scheduler.store.get(job_id, 'owner')
                    if job['state'] in {'failed', 'cancelled'}:
                        break
                    time.sleep(.03)
                assert job['state'] == ('cancelled' if cancel else 'failed')
                assert not scheduler.active
                scheduler.store.cleanup()
                assert not artifact_directory(scheduler.store, job_id).exists()
        finally:
            scheduler.close()


def test_queued_cancel_does_not_claim_or_create_artifacts(tmp_path):
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id='owner', tool='transfer', config=config())
    assert store.cancel(job_id, 'owner')
    assert store.claim() is None
    assert not artifact_directory(store, job_id).exists()


def test_case_is_captured_at_submission_and_refresh_does_not_duplicate(tmp_path, monkeypatch):
    from twn_toolkit.investigations import InvestigationStore
    app = create_app(str(tmp_path)); app.testing = True
    client = app.test_client(); client.post('/investigations', data={'title': 'Original'})
    cases = InvestigationStore(str(tmp_path)); original = cases.active_for_user('test-user')['id']
    submitted = client.post('/tools/multi-transfer', data={**FORM, 'password': 'fixture-password'})
    client.post('/investigations', data={'title': 'Different'})
    store = DiagnosticJobStore(tmp_path); job = store.claim()
    monkeypatch.setattr('twn_toolkit.transfer_diagnostic.fetch_transfer_files', fetch)
    execute_scan(store, job['id'], job['token'])
    for _ in range(2):
        assert client.get(submitted.location).status_code == 200
    events = [event for event in cases.events_for_user(original, 'test-user') if event['tool_id'] == 'tools.multi_sftp']
    assert len(events) == 1
    assert len(events[0]['details']['results']) == 2
    assert events[0]['metrics']['successful_transfers'] == 2
    assert events[0]['metrics']['transferred_bytes'] == 26
    assert events[0]['parameters']['remote_paths'] == ['/config']
    assert store.get(job['id'], 'test-user')['summary']['journal_event']['investigation_id'] == original
    assert len(cases.artifacts_for_user(original, 'test-user')) == 1


def test_status_cancel_and_download_require_transfer_permission(tmp_path):
    from twn_toolkit.auth import AuthStore
    app = create_app(str(tmp_path)); auth = AuthStore(str(tmp_path))
    auth.create_user('admin', 'TemporaryPassword123!', is_admin=True)
    user = auth.create_user('restricted', 'TemporaryPassword123!')
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id=user['id'], tool='transfer', config=config())
    client = app.test_client(); client.post('/login', data={'username': 'restricted', 'password': 'TemporaryPassword123!'})
    assert client.get(f'/tools/multi-transfer?job={job_id}').status_code == 403
    for suffix in ('status', 'download'):
        assert client.get(f'/tools/multi-transfer/jobs/{job_id}/{suffix}').status_code == 403
    assert client.post(f'/tools/multi-transfer/jobs/{job_id}/cancel').status_code == 403
