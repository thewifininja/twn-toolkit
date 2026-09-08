"""Datastore ZIPs retain accounted private staging until response close."""
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

import pytest

from twn_toolkit import create_app
from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.operational import OperationalSettingsStore


@pytest.fixture
def setup(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib': 0})
    store = LocalDatastore(str(tmp_path))
    (store.root / 'source.bin').write_bytes(os.urandom(32 * 1024))
    return app, store


def stages(store):
    root = store.instance / '.upload-reservations'
    return list(root.glob('*/data')) if root.exists() else []


def download(app):
    return app.test_client().post('/local/datastore/bulk-download', data={
        'paths_json': json.dumps(['source.bin']), 'path': ''})


def test_stream_retains_private_lease_and_removes_on_disconnect(setup):
    app, store = setup
    response = download(app)
    assert response.status_code == 200
    paths = stages(store)
    assert len(paths) == 1
    assert paths[0].stat().st_mode & 0o777 == 0o600
    with (paths[0].parent / 'record.json').open() as stream:
        record = json.load(stream)
    assert record['staging_only'] is True
    assert record['capacity'] >= paths[0].stat().st_size
    # Close before consuming the complete response, as a disconnected client does.
    response.close()
    assert stages(store) == []
    assert [p.name for p in store.root.iterdir()] == ['source.bin']


def test_archive_bytes_match_and_release_after_complete_download(setup):
    app, store = setup
    response = download(app)
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read('source.bin') == (store.root / 'source.bin').read_bytes()
    response.close()
    assert stages(store) == []


@pytest.mark.parametrize('free', [0, 100])
def test_disk_pressure_rejects_archive_and_cleans_partial_output(setup, free):
    app, store = setup
    with patch('twn_toolkit.uploads.shutil.disk_usage', return_value=SimpleNamespace(free=free)):
        response = download(app)
    assert response.status_code == 400
    assert stages(store) == []
    assert (store.root / 'source.bin').stat().st_size == 32 * 1024


def test_archive_obeys_configured_output_limit(setup):
    app, store = setup
    with patch.object(LocalDatastore, 'upload_limit', return_value=100):
        response = download(app)
    assert response.status_code == 400
    assert stages(store) == []


def test_upload_reservation_blocks_archive_growth(setup):
    app, store = setup
    with patch('twn_toolkit.uploads.shutil.disk_usage', return_value=SimpleNamespace(free=1000)):
        with store.begin_upload('', 'in-flight', expected_bytes=950):
            response = download(app)
            assert response.status_code == 400
            assert len(stages(store)) == 1  # Only the original upload survives.
    assert stages(store) == []


def test_response_setup_failure_releases_archive(setup):
    app, store = setup
    with patch('twn_toolkit.datastore_routes.send_file', side_effect=RuntimeError('fixture')):
        with pytest.raises(RuntimeError, match='fixture'):
            download(app)
    assert stages(store) == []


def test_archive_member_limit_counts_directories_and_files(setup):
    _app, store = setup
    folder = store.create_folder('', 'folder')
    (folder / 'a').write_bytes(b'a')
    (folder / 'b').write_bytes(b'b')
    with patch('twn_toolkit.datastore.MAX_ARCHIVE_MEMBERS', 3):
        assert len(store.archive_members(['folder'])) == 3
    with patch('twn_toolkit.datastore.MAX_ARCHIVE_MEMBERS', 2):
        with pytest.raises(DatastoreError, match='10,000'):
            store.archive_members(['folder'])


def test_interrupted_archive_build_releases_staging(setup):
    app, store = setup
    with patch('twn_toolkit.datastore_routes.zipfile.ZipFile.write', side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            download(app)
    assert stages(store) == []
