from __future__ import annotations

import csv
import io
import subprocess
import time
from unittest.mock import Mock

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.appliance_read import TOOL
from twn_toolkit.diagnostic_artifacts import artifact_directory
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import DiagnosticScheduler, execute_scan
from twn_toolkit.investigations import InvestigationStore
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.profiles import ProfileStore, FortiAuthenticatorProfileStore

PROFILE = {'name': 'Lab', 'host': 'https://fortigate.example', 'api_key': 'private-key', 'default_vdom': 'root'}


@pytest.fixture
def browser(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    ProfileStore(str(tmp_path)).upsert(PROFILE)
    return app.test_client()


def finish(client, response):
    url = response.get_json()['job_url'] if response.status_code == 202 else response.location
    identifier = url.split('/')[-2]
    store = DiagnosticJobStore(client.application.instance_path)
    job = store.claim(); assert job['id'] == identifier
    execute_scan(store, identifier, job['token'])
    return store, job, url


@pytest.mark.parametrize('mode', ['fields', 'preview', 'export'])
def test_reads_queue_without_network_and_preserve_original_profile_case(browser, tmp_path, monkeypatch, mode):
    rows = [{'serial': str(i), 'name': '=Name' + str(i), 'notes': 'x' * 600} for i in range(501)]
    lookup = Mock(return_value={'results': rows})
    monkeypatch.setattr('twn_toolkit.appliance_read.FortiGateClient.export_data', lookup)
    browser.post('/investigations', data={'title': 'Original'})
    cases = InvestigationStore(str(tmp_path)); original = cases.active_for_user('test-user')['id']
    endpoint = 'run' if mode == 'export' else mode
    queued = browser.post('/tasks/export-switches/' + endpoint, data={'profile': 'Lab', 'fields': 'serial,name,notes'})
    assert queued.status_code == (303 if mode == 'export' else 202)
    lookup.assert_not_called()
    assert browser.get(queued.location if mode == 'export' else queued.json['job_url']).status_code == 200
    ProfileStore(str(tmp_path)).upsert({**PROFILE, 'host': 'https://changed.example', 'api_key': 'new-key'})
    browser.post('/investigations', data={'title': 'Different'})
    store, job, url = finish(browser, queued)
    result = store.get(job['id'], 'test-user')
    assert result['state'] == 'succeeded'
    assert result['config']['profile']['host'] == PROFILE['host']
    assert browser.get(url).status_code == 200
    status = browser.get(url.rsplit('/', 1)[0] + '/status')
    assert status.headers['Cache-Control'] == 'no-store'
    assert b'private-key' not in store.path.read_bytes()
    if mode == 'preview':
        assert len(status.json['data']['rows']) == 100 and status.json['data']['row_count'] == 501
        assert status.json['data']['fields_clipped'] and len(status.json['data']['rows'][0]['notes']) == 512
    elif mode == 'fields':
        assert {field['name'] for field in status.json['data']['fields']} >= {'serial', 'name', 'notes'}
    else:
        download = browser.get(url.rsplit('/', 1)[0] + '/download')
        parsed = list(csv.reader(io.StringIO(download.get_data(as_text=True))))
        assert len(parsed) == 502 and parsed[-1][1] == "'=Name500" and len(parsed[-1][2]) == 600
        assert download.headers['Cache-Control'] == 'private, no-store'
        assert browser.get(url.rsplit('/', 1)[0] + '/download', headers={'Range': 'bytes=0-3'}).status_code == 206
        artifacts = cases.artifacts_for_user(original, 'test-user')
        assert len(artifacts) == 1
        raw = cases.datastore.file(artifacts[0]['relative_path']).read_text()
        assert '=Name500' in raw and "'=Name500" not in raw
    lookup.assert_called_once()
    events = [event for event in cases.events_for_user(original, 'test-user') if event['operation_id'] == 'appliance-read:' + job['id']]
    assert len(events) == 1
    store.release(job['id'], job['token'])


def test_object_identity_is_never_silently_truncated(browser, monkeypatch):
    lookup = Mock(return_value=[{'identifier': str(i), 'current_name': 'A', 'vdom': 'root'} for i in range(501)])
    monkeypatch.setattr('twn_toolkit.appliance_read.RenameTask.discover_objects', lookup)
    queued = browser.post('/tasks/rename-aps/objects', data={'profile': 'Lab'})
    lookup.assert_not_called()
    store, job, url = finish(browser, queued)
    assert store.get(job['id'], 'test-user')['state'] == 'failed'
    assert b'500 devices' in browser.get(url).data
    assert browser.get(url.replace('rename-aps', 'rename-switches')).status_code == 404
    assert browser.post(url.replace('/job', '/cancel').replace('rename-aps', 'rename-switches')).status_code == 404


def test_file_limit_retention_and_ownership_fences(browser, tmp_path, monkeypatch):
    OperationalSettingsStore(str(tmp_path)).save({'diagnostic_artifact_max_mib': 1})
    def export(*args, **kwargs): kwargs['output'].write('x' * (1024**2 + 1))
    monkeypatch.setattr('twn_toolkit.appliance_read.ExportTask.run', export)
    queued = browser.post('/tasks/export-switches/run', data={'profile': 'Lab'})
    store, job, url = finish(browser, queued)
    assert store.get(job['id'], 'test-user')['state'] == 'failed'
    assert browser.get(url.rsplit('/', 1)[0] + '/download').status_code == 404
    directory = artifact_directory(store, job['id'], TOOL)
    store.cleanup(); assert directory.exists()
    store.release(job['id'], job['token']); store.cleanup(); assert not directory.exists()
    assert not list((tmp_path / '.upload-reservations').glob('*/data'))


@pytest.mark.parametrize('cancel', [False, True])
def test_stalled_appliance_process_is_killed_and_not_replayed(browser, tmp_path, monkeypatch, cancel):
    OperationalSettingsStore(str(tmp_path)).save({'diagnostic_timeout_seconds': 5})
    queued = browser.post('/profiles/Lab/test')
    identifier = queued.location.split('/')[-2]
    marker = tmp_path / 'appliance-started'
    script = "import runpy,time;from pathlib import Path;from twn_toolkit.fortigate import FortiGateClient;FortiGateClient.test_connection=lambda *a:(Path(" + repr(str(marker)) + ").write_text('started'),time.sleep(60))[1];runpy.run_module('twn_toolkit.diagnostic_worker',run_name='__main__')"
    original = subprocess.Popen
    monkeypatch.setattr('twn_toolkit.diagnostic_worker.subprocess.Popen', lambda args, **kwargs: original([args[0], '-c', script, *args[3:]], **kwargs))
    scheduler = DiagnosticScheduler(tmp_path)
    try:
        scheduler.tick(); process = scheduler.active[identifier]['process']; end = time.monotonic() + 15
        while not marker.exists() and time.monotonic() < end: time.sleep(.03)
        assert marker.exists()
        if cancel: scheduler.store.cancel(identifier, 'test-user')
        while scheduler.active and time.monotonic() < end: scheduler.tick(); time.sleep(.03)
        assert not scheduler.active and process.poll() is not None
        assert scheduler.store.get(identifier, 'test-user')['state'] == ('cancelled' if cancel else 'failed')
        assert scheduler.store.claim() is None
    finally: scheduler.close()


def test_job_requires_original_owner_and_current_task_permission(tmp_path, monkeypatch):
    app = create_app(str(tmp_path)); auth = AuthStore(str(tmp_path))
    access = auth.save_access_profile(name='Exports', tool_ids=['fortigate.export_switches'])
    auth.create_user('admin', 'TemporaryPassword123!', is_admin=True)
    user = auth.create_user('reader', 'TemporaryPassword123!', access_profile_ids=[access['id']])
    ProfileStore(str(tmp_path)).upsert(PROFILE)
    client = app.test_client(); client.post('/login', data={'username': 'reader', 'password': 'TemporaryPassword123!'})
    monkeypatch.setattr('twn_toolkit.appliance_read.FortiGateClient.export_data', lambda *a, **kw: {'results': []})
    queued = client.post('/tasks/export-switches/run', data={'profile': 'Lab'})
    assert queued.status_code == 303
    store, job, url = finish(client, queued)
    assert client.get(url).status_code == 200
    other = app.test_client(); other.post('/login', data={'username': 'admin', 'password': 'TemporaryPassword123!'})
    assert other.get(url).status_code == 404
    auth.save_access_profile(profile_id=access['id'], name='Exports', tool_ids=['tools.ping'])
    for suffix in ('job', 'status', 'download'):
        assert client.get(url.rsplit('/', 1)[0] + '/' + suffix).status_code == 403
    assert client.post(url.rsplit('/', 1)[0] + '/cancel').status_code == 403


def test_completed_export_expires_and_cannot_cross_provider(browser, tmp_path, monkeypatch):
    monkeypatch.setattr('twn_toolkit.appliance_read.FortiGateClient.export_data', lambda *a, **kw: {'results': []})
    queued = browser.post('/tasks/export-switches/run', data={'profile': 'Lab'})
    store, job, url = finish(browser, queued)
    assert browser.get('/fortigate/connection-jobs/' + job['id'] + '/job').status_code == 404
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET completed=? WHERE id=?', (time.time() - 48 * 3600, job['id']))
    assert browser.get(url.rsplit('/', 1)[0] + '/download').status_code == 410
    directory = artifact_directory(store, job['id'], TOOL)
    store.cleanup(); assert directory.exists()
    store.release(job['id'], job['token']); store.cleanup(); assert not directory.exists()


def test_queued_cancel_never_calls_appliance(browser, monkeypatch):
    lookup = Mock(); monkeypatch.setattr('twn_toolkit.appliance_read.FortiGateClient.test_connection', lookup)
    queued = browser.post('/profiles/Lab/test')
    assert browser.post(queued.location.rsplit('/', 1)[0] + '/cancel').status_code == 303
    store = DiagnosticJobStore(browser.application.instance_path)
    assert store.claim() is None
    assert b'Run cancelled' in browser.get(queued.location).data
    lookup.assert_not_called()


def test_case_recording_failure_is_visible_without_exposing_evidence(browser, monkeypatch):
    browser.post('/investigations', data={'title': 'Recording failure'})
    monkeypatch.setattr('twn_toolkit.appliance_read.FortiGateClient.export_data', lambda *a, **kw: {'results': []})
    monkeypatch.setattr(InvestigationStore, 'add_generated_evidence_event', Mock(side_effect=RuntimeError('private evidence detail')))
    queued = browser.post('/tasks/export-switches/run', data={'profile': 'Lab'})
    store, job, url = finish(browser, queued)
    page = browser.get(url)
    assert b'recording could not be fully confirmed' in page.data
    assert b'private evidence detail' not in page.data
    assert store.get(job['id'], 'test-user')['state'] == 'succeeded'
    assert url.encode() in browser.get('/tasks/export-switches').data


@pytest.mark.parametrize('mode',['fields','preview','export'])
def test_wireless_bad_text_is_retained_with_visible_warning(browser,monkeypatch,mode):
    response=Mock(status_code=200)
    response.iter_content.side_effect=lambda **kw:[b'{"results":[{"host":"client\xff","ip":"192.0.2.10"}]}']
    monkeypatch.setattr('twn_toolkit.fortigate.requests.Session.request',lambda *a,**kw:response)
    queued=browser.post('/tasks/export-wireless-clients/'+('run' if mode=='export' else mode),data={'profile':'Lab','fields':'host,ip'})
    store,job,url=finish(browser,queued)
    result=store.get(job['id'],'test-user')
    assert result['state']=='succeeded'
    assert 'invalid UTF-8' in result['summary']['response_warnings'][0]
    assert b'invalid UTF-8' in browser.get(url).data
    status=browser.get(url.rsplit('/',1)[0]+'/status').json
    assert status['data']['response_warnings']==result['summary']['response_warnings']
    if mode=='export':
        download=browser.get(url.rsplit('/',1)[0]+'/download')
        assert br'client\xff' in download.data
    elif mode=='preview':assert result['summary']['rows'][0]['host']==r'client\xff'
    store.release(job['id'],job['token'])
    page=browser.get('/tasks/export-wireless-clients').data
    assert b'data-recent-runs' in page
    assert b'Lab' in page and b'class="field-note"' in page
