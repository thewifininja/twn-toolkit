from __future__ import annotations

import io
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from twn_toolkit.datastore import LocalDatastore, DatastoreError
from twn_toolkit.diagnostic_artifacts import PrivateArtifactStore, artifact_directory
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.sftp_tools import fetch_ssh_files
from twn_toolkit.transfer_deadlines import TransferPolicy
from tests.test_transfer_jobs import config, fetch


class ScpChannel:
    def __init__(self):
        self.buffer = bytearray(b'C0644 5 config.cfg\nhello\x00')
    def settimeout(self, value): pass
    def exec_command(self, command): pass
    def sendall(self, value): pass
    def recv(self, size):
        value = bytes(self.buffer[:size]); del self.buffer[:size]; return value
    def close(self): pass


@pytest.mark.parametrize('protocol', ['sftp', 'scp', 'ftp'])
def test_transfer_staging_competes_with_uploads_and_releases_on_failure(tmp_path, monkeypatch, protocol):
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib': 0})
    incoming = LocalDatastore(str(tmp_path))
    private = PrivateArtifactStore(tmp_path, 'transfer', 1024)
    directory = private.create_folder('', 'a' * 32)
    output = directory / 'files'; output.mkdir()
    ssh = MagicMock()
    ssh.open_sftp.return_value.stat.return_value.st_size = 5
    ssh.open_sftp.return_value.open.side_effect = lambda *a: io.BytesIO(b'hello')
    ssh.get_transport.return_value.open_session.side_effect = lambda *a, **kw: ScpChannel()
    monkeypatch.setattr('paramiko.SSHClient', lambda: ssh)
    ftp = MagicMock(); ftp.size.return_value = 5
    ftp.retrbinary.side_effect = lambda command, callback, **kw: callback(b'hello')
    monkeypatch.setattr('twn_toolkit.sftp_tools.ftplib.FTP', lambda: ftp)
    monkeypatch.setattr('twn_toolkit.uploads.shutil.disk_usage', lambda path: SimpleNamespace(free=32))
    args = dict(hosts=[{'host': '192.0.2.1', 'label': 'Lab'}], remote_paths=['/config.cfg'],
                username='user', password='fixture-password', port=21 if protocol == 'ftp' else 22,
                allow_unknown_hosts=True, output_dir=output, output_store=private,
                protocol=protocol, filename_pattern='{filename}',
                policy=TransferPolicy(file_bytes=16, run_bytes=32))
    with incoming.begin_upload('', 'incoming', expected_bytes=32):
        result = fetch_ssh_files(**args)
        assert result[0]['status'] == 'error' and 'free-disk' in result[0]['error']
        assert list(output.iterdir()) == []
        assert len(list((tmp_path / '.upload-reservations').glob('*/data'))) == 1  # incoming owner remains live
    result = fetch_ssh_files(**args)
    assert result[0]['status'] == 'success'
    saved = output / result[0]['filename']
    assert saved.read_bytes() == b'hello' and saved.stat().st_mode & 0o777 == 0o600
    assert incoming.list()['entries'] == []
    assert not list((tmp_path / '.upload-reservations').glob('*/data'))


def test_unknown_ftp_length_reserves_growth_and_aborts_partial_file(tmp_path, monkeypatch):
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib': 0})
    private = PrivateArtifactStore(tmp_path, 'transfer', 1024)
    output = private.create_folder('', 'b' * 32)
    ftp = MagicMock(); ftp.size.return_value = None
    ftp.retrbinary.side_effect = lambda command, callback, **kw: (callback(b'hello'), callback(b'world'))
    monkeypatch.setattr('twn_toolkit.sftp_tools.ftplib.FTP', lambda: ftp)
    monkeypatch.setattr('twn_toolkit.uploads.shutil.disk_usage', lambda path: SimpleNamespace(free=6))
    result = fetch_ssh_files(hosts=[{'host': '192.0.2.1'}], remote_paths=['/config.cfg'], username='u', password='p',
        port=21, allow_unknown_hosts=False, output_dir=output, output_store=private, protocol='ftp',
        policy=TransferPolicy(file_bytes=16, run_bytes=32))
    assert result[0]['status'] == 'error' and 'free-disk' in result[0]['error']
    assert list(output.iterdir()) == []
    assert not list((tmp_path / '.upload-reservations').glob('*/data'))


def test_zip_assembly_respects_incoming_reservation_and_leaves_no_partial_download(tmp_path, monkeypatch):
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib': 0})
    store = DiagnosticJobStore(tmp_path)
    identifier = store.enqueue(user_id='owner', tool='transfer', config=config())
    job = store.claim()
    monkeypatch.setattr('twn_toolkit.transfer_diagnostic.fetch_transfer_files', fetch)
    incoming = LocalDatastore(str(tmp_path))
    monkeypatch.setattr('twn_toolkit.uploads.shutil.disk_usage', lambda path: SimpleNamespace(free=1024**2))
    with incoming.begin_upload('', 'incoming', expected_bytes=1024**2):
        with pytest.raises(DatastoreError):
            execute_scan(store, identifier, job['token'])
        assert not (artifact_directory(store, identifier) / 'download.zip').exists()
        assert not (artifact_directory(store, identifier) / 'files').exists()
    store.abort(identifier, job['token'], 'failed', 'Storage rejected output')
    store.release(identifier, job['token']); store.cleanup()
    assert not artifact_directory(store, identifier).exists()
    assert not list((tmp_path / '.upload-reservations').glob('*/data'))
