"""Automation ZIPs stream through reservations and release every owned spool."""
from export_job_helpers import complete_export, run_export

import io
import json
import os
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

import pytest

from twn_toolkit import create_app
from twn_toolkit.automation import AutomationStore
from twn_toolkit.automation_routes import _automation_run_archive
from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.operational import OperationalSettingsStore


@pytest.fixture
def setup(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    from twn_toolkit.investigations import InvestigationStore
    InvestigationStore(tmp_path).create(owner_user_id='test-user',owner_username='test-user',title='Original case')
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib': 0})
    source = tmp_path / 'retained.bin'
    source.write_bytes(os.urandom(128 * 1024))
    run = dict(id='run-test', automation_id='auto-test', automation_name='Collection',
               started_at=1, finished_at=2, status='success', trigger_summary='Manual',
               results=[dict(status='success', summary='Collected', output={
                   'hosts': [{'host': '192.0.2.1', 'host_label': 'Core', 'output': 'clock output'}],
                   'destinations': [{'name': 'destination'}], 'endpoints': [{'name': 'endpoint'}],
                   'artifacts': [{'artifact_path': 'retained.bin', 'filename': 'retained.bin'}],
               })])
    with patch.object(AutomationStore, 'get_run', return_value=run), patch.object(
        AutomationStore, 'run_artifact', return_value=source
    ):
        yield app, run, source


def stages(app):
    from pathlib import Path
    return list((Path(app.instance_path) / '.upload-reservations').glob('*/data'))


def download(app):
    client=app.test_client()
    return complete_export(client,client.get('/automations/runs/run-test/download'))


def queued_result(app, route='download'):
    client=app.test_client()
    response=(client.get if route=='download' else client.post)(f'/automations/runs/run-test/{route}')
    return run_export(client,response)


def build(app, run):
    return _automation_run_archive(AutomationStore(app.instance_path,app.secret_key),run)


def test_download_matches_source_after_reserved_job_publication(setup):
    from pathlib import Path
    app, run, source = setup
    response = download(app)
    assert response.status_code == 200
    assert not stages(app)
    published=list((Path(app.instance_path)/'automation_export_job_artifacts').glob('*/export.bin'))
    assert len(published)==1 and published[0].stat().st_mode&0o777==0o600
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read('action-1/files/retained.bin') == source.read_bytes()
        assert json.loads(archive.read('summary.json'))['automation'] == run['automation_name']
        host=next(name for name in archive.namelist() if name.endswith('.txt'))
        assert archive.read(host)==b'Friendly name: Core\nTarget: 192.0.2.1\n\nclock output'
        assert 'action-1-endpoints.json' in archive.namelist()
        assert 'action-1-destinations.json' in archive.namelist()
    response.close()
    assert published[0].exists() and source.exists()


def test_disconnect_preserves_the_completed_download(setup):
    from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
    app, _, _ = setup
    response=download(app);assert response.status_code==200;response.close()
    job=DiagnosticJobStore(app.instance_path).recent('test-user','automation_export')[0]
    retried=app.test_client().get('/automations/exports/'+job['id']+'/download')
    assert retried.status_code==200 and retried.data.startswith(b'PK')
    retried.close();assert not stages(app)


@pytest.mark.parametrize('route',['download','case'])
def test_output_limit_cleans_archive_and_preserves_source(setup,route):
    app,_,source=setup;original=source.read_bytes()
    with patch.object(LocalDatastore,'upload_limit',return_value=100):
        assert queued_result(app,route)['state']=='failed'
    assert not stages(app) and source.read_bytes()==original


def test_compressible_source_obeys_expanded_limit(setup):
    app,run,source=setup;source.write_bytes(b'0'*256*1024)
    with patch.object(LocalDatastore,'upload_limit',return_value=128*1024):
        with pytest.raises(DatastoreError,match='expanded content'):build(app,run)
    assert not stages(app)


def test_member_limit_cleans_archive(setup):
    app,run,_=setup
    with patch('twn_toolkit.automation_routes.MAX_RUN_ARCHIVE_MEMBERS',2):
        with pytest.raises(DatastoreError,match='10,000 members'):build(app,run)
    assert not stages(app)


def test_shared_upload_reservation_blocks_export(setup):
    app,run,_=setup;datastore=LocalDatastore(app.instance_path)
    with patch('twn_toolkit.uploads.shutil.disk_usage',return_value=SimpleNamespace(free=1000)):
        with datastore.begin_upload('','in-flight',expected_bytes=950):
            with pytest.raises(DatastoreError):build(app,run)
            assert len(stages(app))==1
    assert not stages(app)


@pytest.mark.parametrize('failure',[OSError('read failed'),KeyboardInterrupt()])
def test_failed_or_interrupted_build_releases_staging(setup,failure):
    app,run,_=setup
    with patch('twn_toolkit.automation_routes.zipfile.ZipFile.open',side_effect=failure):
        with pytest.raises(type(failure)):build(app,run)
    assert not stages(app)


def test_response_setup_failure_preserves_completed_artifact(setup):
    from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
    app,_,_=setup
    with patch('twn_toolkit.export_routes.send_file',side_effect=RuntimeError('fixture')):
        with pytest.raises(RuntimeError,match='fixture'):download(app)
    assert not stages(app)
    job=DiagnosticJobStore(app.instance_path).recent('test-user','automation_export')[0]
    response=app.test_client().get('/automations/exports/'+job['id']+'/download')
    assert response.status_code==200;response.close()


@pytest.mark.parametrize('failure',[False,True])
def test_case_attachment_passes_stream_and_always_releases(setup,failure):
    from twn_toolkit.investigations import InvestigationStore
    app,_,source=setup;original=InvestigationStore.add_generated_evidence_event
    def attach(self,**event):
        assert 'content' not in event and stages(app)
        stream=event['stream']
        with zipfile.ZipFile(io.BytesIO(stream.read())) as archive:
            assert archive.read('action-1/files/retained.bin')==source.read_bytes()
        assert event['metrics']['archive_bytes']==stream.upload.total
        stream.seek(0)
        if failure:raise RuntimeError('fixture')
        return original(self,**event)
    with patch.object(InvestigationStore,'add_generated_evidence_event',attach):
        result=queued_result(app,'case')
    assert result['state']==('unknown' if failure else 'succeeded')
    assert not stages(app)


def test_large_artifact_does_not_materialize_archive_in_memory(setup):
    import tracemalloc
    app, run, source = setup
    with source.open('wb') as target:
        for _ in range(128):
            target.write(os.urandom(64 * 1024))
    store = AutomationStore(app.instance_path, app.secret_key)
    tracemalloc.start()
    try:
        output, _ = _automation_run_archive(store, run)
        try:
            _, peak = tracemalloc.get_traced_memory()
            assert output.upload.total > 8 * 1024 * 1024
            assert peak < 3 * 1024 * 1024
        finally:
            output.close()
    finally:
        tracemalloc.stop()
    assert not stages(app)


def test_large_metadata_streams_without_whole_scalar_allocation(setup):
    import tracemalloc
    app, run, _ = setup
    # Allocate input before measuring the serializer, including JSON escaping.
    value = '\x00😀"\\' * (1024 * 1024)
    run['results'][0]['summary'] = value
    store = AutomationStore(app.instance_path, app.secret_key)
    tracemalloc.start()
    try:
        output, _ = _automation_run_archive(store, run)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    try:
        assert peak < 3 * 1024 * 1024
        with zipfile.ZipFile(io.BytesIO(output.read())) as archive:
            assert archive.read('action-1-summary.json') == json.dumps(
                {'status': 'success', 'summary': value}, indent=2).encode()
    finally:
        output.close()
    assert not stages(app)


@pytest.mark.parametrize('route', ['download', 'case'])
@pytest.mark.parametrize('kind', ['scalar', 'key', 'deep', 'cycle'])
def test_bad_or_oversized_metadata_releases_archive_and_preserves_source(setup, route, kind):
    app, run, source = setup
    original = source.read_bytes()
    if kind == 'scalar':
        run['trigger_summary'] = '\x00' * 100_000
    elif kind == 'key':
        run['results'][0]['\x00' * 100_000] = 'value'
    else:
        value = []
        if kind == 'deep':
            for _ in range(66):
                value = [value]
        else:
            value.append(value)
        run['results'][0]['summary'] = value
    with patch.object(LocalDatastore, 'upload_limit', return_value=256 * 1024):
        assert queued_result(app,route)['state']=='failed'
    assert not stages(app)
    assert source.read_bytes() == original


def test_metadata_limit_stops_before_reading_later_artifacts(setup):
    app, run, _ = setup
    run['results'][0]['summary'] = '\x00' * 100_000
    with patch.object(LocalDatastore, 'upload_limit', return_value=256 * 1024), patch.object(
            AutomationStore, 'run_artifact', side_effect=AssertionError('must stop before artifact')):
        with pytest.raises(DatastoreError):build(app,run)
    assert not stages(app)


def test_metadata_members_share_the_expanded_budget(setup):
    app, run, _ = setup
    run['results'][0]['summary'] = 'a' * 150_000
    run['results'][0]['output'] = {'endpoints': [{'detail': 'b' * 150_000}]}
    with patch.object(LocalDatastore, 'upload_limit', return_value=256 * 1024):
        with pytest.raises(DatastoreError,match='expanded content'):build(app,run)
    assert not stages(app)
