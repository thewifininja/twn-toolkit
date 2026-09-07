import os
import stat
import subprocess
import sys
from unittest.mock import Mock

import pytest

from twn_toolkit import log_retention as logs


def test_open_append_descriptor_survives_rotation_and_child_output(tmp_path):
    path = tmp_path / 'twn-supervisor.log'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, b'old-prefix-newest')
        inode = path.stat().st_ino
        assert logs.rotate_log(path, logs.LogPolicy(max_bytes=6, backups=2))
        assert path.stat().st_ino == inode
        assert path.read_bytes() == b''
        assert path.with_suffix('.log.1').read_bytes() == b'newest'
        subprocess.run([sys.executable, '-c', 'import os; os.write(1, b"child-output")'],
                       stdout=fd, check=True)
        os.write(fd, b'-parent')
        assert path.read_bytes() == b'child-output-parent'
        assert stat.S_IMODE(path.with_suffix('.log.1').stat().st_mode) == 0o600
    finally:
        os.close(fd)


def test_repeated_rotation_retains_only_configured_newest_archives(tmp_path):
    path = tmp_path / 'twn-toolkit-error.log'
    for value in (b'aaaa', b'bbbb', b'cccc', b'dddd'):
        path.write_bytes(value)
        logs.rotate_log(path, logs.LogPolicy(max_bytes=4, backups=2))
    assert path.with_suffix('.log.1').read_bytes() == b'dddd'
    assert path.with_suffix('.log.2').read_bytes() == b'cccc'
    assert not path.with_suffix('.log.3').exists()
    assert not list(tmp_path.glob('*.rotation'))
    # Reduced retention removes old numbered archives even below threshold.
    assert not logs.rotate_log(path, logs.LogPolicy(max_bytes=4, backups=1))
    assert not path.with_suffix('.log.2').exists()


@pytest.mark.parametrize('operation', ['read', 'fsync', 'replace'])
def test_archive_failure_preserves_live_output_and_cleans_staging(tmp_path, monkeypatch, operation):
    path = tmp_path / 'twn-toolkit-error.log'
    path.write_bytes(b'precious-output')
    monkeypatch.setattr(logs.os, operation, Mock(side_effect=OSError('disk failure')))
    with pytest.raises(OSError, match='disk failure'):
        logs.rotate_log(path, logs.LogPolicy(max_bytes=4, backups=2))
    assert path.read_bytes() == b'precious-output'
    assert not (tmp_path / f'.{path.name}.rotation').exists()


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo', 'directory'])
def test_non_regular_or_linked_logs_never_modify_target(tmp_path, kind):
    original = tmp_path / 'other-file'
    original.write_bytes(b'untouched')
    path = tmp_path / 'twn-automation.log'
    if kind == 'symlink':
        path.symlink_to(original)
    elif kind == 'hardlink':
        os.link(original, path)
    elif kind == 'fifo':
        os.mkfifo(path)
    else:
        path.mkdir()
    with pytest.raises(OSError):
        logs.rotate_log(path, logs.LogPolicy(max_bytes=4))
    assert original.read_bytes() == b'untouched'


def test_interrupted_staging_is_reclaimed_without_following_links(tmp_path):
    path = tmp_path / 'twn-automation.log'
    path.write_bytes(b'new-record')
    original = tmp_path / 'other-file'
    original.write_bytes(b'untouched')
    staging = tmp_path / f'.{path.name}.rotation'
    staging.symlink_to(original)
    assert logs.rotate_log(path, logs.LogPolicy(max_bytes=6))
    assert original.read_bytes() == b'untouched'
    assert not staging.exists()
    assert path.with_suffix('.log.1').read_bytes() == b'record'


def test_missing_logs_are_not_created(tmp_path):
    maintenance = logs.LogRetention(tmp_path, logs.LogPolicy(max_bytes=4))
    for _ in logs.LOG_NAMES:
        assert not maintenance.maintain_next()
    assert list(tmp_path.iterdir()) == []


def test_one_file_per_sweep_and_failure_does_not_starve_other_logs(tmp_path, monkeypatch, capsys):
    rotate = Mock(side_effect=[OSError('denied')] + [True] * len(logs.LOG_NAMES))
    monkeypatch.setattr(logs, 'rotate_log', rotate)
    maintenance = logs.LogRetention(tmp_path)
    for index in range(len(logs.LOG_NAMES) + 1):
        maintenance.maintain_next()
        assert rotate.call_count == index + 1
        assert rotate.call_args.args[0].name == logs.LOG_NAMES[index % len(logs.LOG_NAMES)]
    assert 'Could not retain twn-toolkit-access.log' in capsys.readouterr().out


def test_policy_overrides_and_invalid_values_fall_back(monkeypatch, capsys):
    monkeypatch.setenv('TWN_LOG_MAX_BYTES', '1048576')
    monkeypatch.setenv('TWN_LOG_BACKUPS', '7')
    assert logs.LogPolicy.from_environment() == logs.LogPolicy(1048576, 7)
    monkeypatch.setenv('TWN_LOG_MAX_BYTES', '-1')
    monkeypatch.setenv('TWN_LOG_BACKUPS', 'broken')
    assert logs.LogPolicy.from_environment() == logs.LogPolicy()
    assert capsys.readouterr().out.count('using default') == 2


def test_large_existing_log_copies_only_bounded_tail(tmp_path, monkeypatch):
    path = tmp_path / 'twn-toolkit-error.log'
    with path.open('wb') as output:
        output.seek(100 * 1024 * 1024)
        output.write(b'last-record')
    read = Mock(wraps=os.read)
    monkeypatch.setattr(logs.os, 'read', read)
    assert logs.rotate_log(path, logs.LogPolicy(max_bytes=128 * 1024))
    assert read.call_count == 2
    assert all(call.args[1] <= logs.COPY_CHUNK_BYTES for call in read.call_args_list)
    archive = path.with_suffix('.log.1').read_bytes()
    assert len(archive) == 128 * 1024
    assert archive.endswith(b'last-record')


def test_upgrade_logs_included_but_audit_and_unrelated_files_untouched(tmp_path):
    instance = tmp_path / 'instance'
    instance.mkdir()
    workspace = tmp_path / '.twn-upgrades'
    workspace.mkdir()
    for name in ('upgrade.log', 'service-reload.log', 'unrelated.log'):
        (workspace / name).write_bytes(b'old-new')
    audit = instance / 'audit.sqlite3'
    audit.write_bytes(b'not-an-operational-log')
    maintenance = logs.LogRetention(instance, logs.LogPolicy(max_bytes=3), root=tmp_path)
    for _ in range(len(logs.LOG_NAMES) + 2):
        maintenance.maintain_next()
    for name in ('upgrade.log', 'service-reload.log'):
        assert (workspace / name).read_bytes() == b''
        assert (workspace / (name + '.1')).read_bytes() == b'new'
    assert (workspace / 'unrelated.log').read_bytes() == b'old-new'
    assert audit.read_bytes() == b'not-an-operational-log'
