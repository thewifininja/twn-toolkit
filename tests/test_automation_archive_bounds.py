"""Automation ZIPs stream through reservations and release every owned spool."""
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
    return app.test_client().get('/automations/runs/run-test/download')


def test_download_matches_source_and_retains_reservation_until_close(setup):
    app, run, source = setup
    response = download(app)
    assert response.status_code == 200
    assert len(stages(app)) == 1
    stage = stages(app)[0]
    assert stage.stat().st_mode & 0o777 == 0o600
    record = json.loads((stage.parent / 'record.json').read_text())
    assert record['staging_only'] and record['capacity'] >= stage.stat().st_size
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read('action-1/files/retained.bin') == source.read_bytes()
        assert json.loads(archive.read('summary.json'))['automation'] == run['automation_name']
        host = next(name for name in archive.namelist() if name.endswith('.txt'))
        assert archive.read(host) == b'Friendly name: Core\nTarget: 192.0.2.1\n\nclock output'
        assert 'action-1-endpoints.json' in archive.namelist()
        assert 'action-1-destinations.json' in archive.namelist()
    response.close()
    assert not stages(app)
    assert source.exists()


def test_disconnect_releases_spool(setup):
    app, _, _ = setup
    response = download(app)
    assert response.status_code == 200
    assert stages(app)
    response.close()
    assert not stages(app)


@pytest.mark.parametrize('route', ['download', 'case'])
def test_output_limit_cleans_archive_and_preserves_source(setup, route):
    app, _, source = setup
    original = source.read_bytes()
    with patch.object(LocalDatastore, 'upload_limit', return_value=100):
        client = app.test_client()
        response = (client.get if route == 'download' else client.post)(
            f'/automations/runs/run-test/{route}')
    assert response.status_code == 400
    assert not stages(app)
    assert source.read_bytes() == original


def test_compressible_source_obeys_expanded_limit(setup):
    app, _, source = setup
    source.write_bytes(b'0' * 256 * 1024)
    with patch.object(LocalDatastore, 'upload_limit', return_value=128 * 1024):
        response = download(app)
    assert response.status_code == 400
    assert b'expanded content' in response.data
    assert not stages(app)


def test_member_limit_cleans_archive(setup):
    app, _, _ = setup
    with patch('twn_toolkit.automation_routes.MAX_RUN_ARCHIVE_MEMBERS', 2):
        response = download(app)
    assert response.status_code == 400
    assert b'10,000 members' in response.data
    assert not stages(app)


def test_shared_upload_reservation_blocks_export(setup):
    app, _, _ = setup
    datastore = LocalDatastore(app.instance_path)
    with patch('twn_toolkit.uploads.shutil.disk_usage', return_value=SimpleNamespace(free=1000)):
        with datastore.begin_upload('', 'in-flight', expected_bytes=950):
            response = download(app)
            assert response.status_code == 400
            assert len(stages(app)) == 1
    assert not stages(app)


@pytest.mark.parametrize('failure', [OSError('read failed'), KeyboardInterrupt()])
def test_failed_or_interrupted_build_releases_staging(setup, failure):
    app, _, _ = setup
    with patch('twn_toolkit.automation_routes.zipfile.ZipFile.open', side_effect=failure):
        if isinstance(failure, OSError):
            assert download(app).status_code == 400
        else:
            with pytest.raises(KeyboardInterrupt):
                download(app)
    assert not stages(app)


def test_response_setup_failure_releases_staging(setup):
    app, _, _ = setup
    with patch('twn_toolkit.automation_routes.send_file', side_effect=RuntimeError('fixture')):
        with pytest.raises(RuntimeError, match='fixture'):
            download(app)
    assert not stages(app)


@pytest.mark.parametrize('failure', [False, True])
def test_case_attachment_passes_stream_and_always_releases(setup, failure):
    app, _, source = setup
    def attach(**event):
        assert 'content' not in event
        assert stages(app)
        stream = event['stream']
        with zipfile.ZipFile(io.BytesIO(stream.read())) as archive:
            assert archive.read('action-1/files/retained.bin') == source.read_bytes()
        assert event['metrics']['archive_bytes'] == stream.upload.total
        if failure:
            raise RuntimeError('fixture')
        return None
    with patch('twn_toolkit.automation_routes.add_current_investigation_generated_evidence_event', side_effect=attach):
        if failure:
            with pytest.raises(RuntimeError, match='fixture'):
                app.test_client().post('/automations/runs/run-test/case')
        else:
            assert app.test_client().post('/automations/runs/run-test/case').status_code == 302
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
        client = app.test_client()
        response = (client.get if route == 'download' else client.post)(
            f'/automations/runs/run-test/{route}')
    assert response.status_code == 400
    assert not stages(app)
    assert source.read_bytes() == original


def test_metadata_limit_stops_before_reading_later_artifacts(setup):
    app, run, _ = setup
    run['results'][0]['summary'] = '\x00' * 100_000
    with patch.object(LocalDatastore, 'upload_limit', return_value=256 * 1024), patch.object(
            AutomationStore, 'run_artifact', side_effect=AssertionError('must stop before artifact')):
        assert download(app).status_code == 400
    assert not stages(app)


def test_metadata_members_share_the_expanded_budget(setup):
    app, run, _ = setup
    run['results'][0]['summary'] = 'a' * 150_000
    run['results'][0]['output'] = {'endpoints': [{'detail': 'b' * 150_000}]}
    with patch.object(LocalDatastore, 'upload_limit', return_value=256 * 1024):
        response = download(app)
    assert response.status_code == 400
    assert b'expanded content' in response.data
    assert not stages(app)
