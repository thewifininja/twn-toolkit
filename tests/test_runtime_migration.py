from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest

from twn_toolkit import runtime_migration as migration
from twn_toolkit import upgrade_manager as manager
from twn_toolkit.release_bundle import build_release_bundle, UpgradeError


def installed(tmp_path):
    root = tmp_path / 'installed'
    (root / '.venv/bin').mkdir(parents=True)
    (root / '.venv/bin/python').symlink_to(sys.executable)
    (root / '.venv/preserved-package').write_bytes(b'original-runtime')
    (root / 'instance').mkdir()
    (root / 'instance/key').write_bytes(b'original-key')
    (root / 'twn_toolkit').mkdir()
    (root / 'twn_toolkit/version.py').write_text('APP_VERSION = "0.27.0"\n')
    script = root / 'twn'
    script.write_text('#!/bin/sh\nexit 0\n')
    script.chmod(0o755)
    return root


def make_bundle(tmp_path):
    source = tmp_path / 'release'
    (source / 'twn_toolkit').mkdir(parents=True)
    (source / 'twn_toolkit/version.py').write_text('APP_VERSION = "0.28.0"\n')
    (source / 'requirements.txt').write_text('')
    (source / 'twn').write_text('#!/bin/sh\nexit 0\n')
    (source / 'twn').chmod(0o755)
    bundle = tmp_path / 'release.zip'
    build_release_bundle(source, bundle, version='0.28.0')
    return bundle, hashlib.sha256(bundle.read_bytes()).hexdigest()


def prepare(tmp_path, monkeypatch):
    root = installed(tmp_path)
    bundle, checksum = make_bundle(tmp_path)
    identifier = 'a' * 32
    workspace = root / '.twn-upgrades'
    workspace.mkdir()
    (workspace / 'operation.lock').write_text(identifier + '\n')

    def staged_command(command, **kwargs):
        if '-m' in command and 'venv' in command:
            venv = Path(command[-1])
            (venv / 'bin').mkdir(parents=True)
            (venv / 'bin/python').symlink_to(sys.executable)
        return subprocess.CompletedProcess(command, 0, '', '')

    with monkeypatch.context() as context:
        context.setattr(migration, 'run', staged_command)
        context.setattr(migration, 'python_version', lambda path: (3, 12))
        journal = migration.stage(root, bundle, checksum, Path(sys.executable), identifier)
    return root, journal


def test_staging_failure_keeps_old_code_environment_and_instance(tmp_path, monkeypatch):
    root = installed(tmp_path)
    bundle, checksum = make_bundle(tmp_path)
    old = migration.snapshot(root / '.venv')
    stop = Mock()

    def failed(command, **kwargs):
        if '-m' in command and 'venv' in command:
            venv = Path(command[-1]); (venv / 'bin').mkdir(parents=True)
        if command[0] == root / 'twn':
            stop()
        return subprocess.CompletedProcess(command, 1 if 'pip' in command else 0, '', '')

    monkeypatch.setattr(migration, 'run', failed)
    monkeypatch.setattr(migration, 'python_version', lambda path: (3, 12))
    with migration.migration_lock(root, 'b' * 32):
        with pytest.raises(UpgradeError, match='Staged dependency'):
            migration.stage(root, bundle, checksum, Path(sys.executable), 'b' * 32)
    assert migration.snapshot(root / '.venv') == old
    assert (root / 'instance/key').read_bytes() == b'original-key'
    assert '0.27.0' in (root / 'twn_toolkit/version.py').read_text()
    assert not (root / '.twn-upgrades/operation.lock').exists()
    stop.assert_not_called()


def test_checksum_and_missing_python_fail_before_any_stop(tmp_path, monkeypatch):
    root = installed(tmp_path)
    bundle, _ = make_bundle(tmp_path)
    with pytest.raises(UpgradeError, match='checksum'):
        migration.verify_checksum(bundle, '0' * 64)
    monkeypatch.setattr(migration, 'python_version', lambda path: (3, 10))
    with pytest.raises(UpgradeError, match='Install Python 3.11'):
        migration.choose_python(sys.executable)
    assert not (root / '.twn-upgrades').exists()


def test_success_preserves_old_environment_and_normal_rollback_restores_it(tmp_path, monkeypatch):
    root, journal = prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(migration, 'ensure_idle', lambda root: None)
    monkeypatch.setattr(manager, '_prepare_service_reload', lambda *args: False)
    health = Mock()
    monkeypatch.setattr(manager, '_install_and_validate', health)
    migration.perform(journal)
    _, plan = migration.load_plan(journal)
    assert plan['state'] == 'succeeded'
    assert (root / '.venv').is_symlink()
    assert (root / '.venv').resolve() == journal / 'venv'
    assert (journal / 'previous-venv/preserved-package').read_bytes() == b'original-runtime'
    assert '0.28.0' in (root / 'twn_toolkit/version.py').read_text()
    backup = Path(plan['backup'])
    manager._verify_backup(backup)
    manager._restore_backup(root, root / 'instance', backup)
    assert not (root / '.venv').is_symlink()
    assert (root / '.venv/preserved-package').read_bytes() == b'original-runtime'
    assert '0.27.0' in (root / 'twn_toolkit/version.py').read_text()
    # A recovery point remains reusable: restoration does not consume its runtime.
    assert (journal / 'previous-venv').is_dir()
    manager._restore_backup(root, root / 'instance', backup)
    assert (root / 'instance/key').read_bytes() == b'original-key'


def test_failed_target_health_restores_matching_code_data_and_runtime(tmp_path, monkeypatch):
    root, journal = prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(migration, 'ensure_idle', lambda root: None)
    monkeypatch.setattr(manager, '_prepare_service_reload', lambda *args: False)
    versions = []

    def health(root, instance, version, **kwargs):
        versions.append(version)
        if version == '0.28.0':
            (instance / 'key').write_bytes(b'changed-by-target')
            raise UpgradeError('Injected target health failure')

    monkeypatch.setattr(manager, '_install_and_validate', health)
    with pytest.raises(UpgradeError, match='Injected target health'):
        migration.perform(journal)
    assert versions == ['0.28.0', '0.27.0']
    assert migration.load_plan(journal)[1]['state'] == 'rolled_back'
    assert (root / '.venv/preserved-package').read_bytes() == b'original-runtime'
    assert (root / 'instance/key').read_bytes() == b'original-key'
    assert '0.27.0' in (root / 'twn_toolkit/version.py').read_text()


def test_interrupted_cutover_recovers_when_dot_venv_is_missing(tmp_path, monkeypatch):
    root, journal = prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(migration, 'ensure_idle', lambda root: None)
    monkeypatch.setattr(manager, '_prepare_service_reload', lambda *args: False)
    monkeypatch.setattr(manager, '_install_and_validate', Mock())
    replace = os.replace

    def interrupted(source, destination):
        if Path(destination) == root / '.venv' and Path(source).name.startswith('.venv-next-'):
            raise KeyboardInterrupt('Injected interruption after old environment moved')
        return replace(source, destination)

    with monkeypatch.context() as context:
        context.setattr(migration.os, 'replace', interrupted)
        with pytest.raises(KeyboardInterrupt):
            migration.perform(journal)
    assert not (root / '.venv').exists()
    assert migration.load_plan(journal)[1]['state'] == 'switching_runtime'
    migration.perform(journal, recover=True)
    assert migration.load_plan(journal)[1]['state'] == 'rolled_back'
    assert (root / '.venv/preserved-package').read_bytes() == b'original-runtime'
    assert (root / 'instance/key').read_bytes() == b'original-key'


def test_runtime_tampering_blocks_rollback_before_replacing_code(tmp_path, monkeypatch):
    root, journal = prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(migration, 'ensure_idle', lambda root: None)
    monkeypatch.setattr(manager, '_prepare_service_reload', lambda *args: False)
    monkeypatch.setattr(manager, '_install_and_validate', Mock())
    migration.perform(journal)
    backup = Path(migration.load_plan(journal)[1]['backup'])
    (journal / 'previous-venv/preserved-package').write_bytes(b'tampered')
    with pytest.raises(UpgradeError, match='runtime integrity'):
        manager._restore_backup(root, root / 'instance', backup)
    assert '0.28.0' in (root / 'twn_toolkit/version.py').read_text()
    assert (root / '.venv').is_symlink()


def test_operation_lock_and_live_recovery_are_not_stolen(tmp_path, monkeypatch):
    root, journal = prepare(tmp_path, monkeypatch)
    with pytest.raises(UpgradeError, match='Another upgrade'):
        with migration.migration_lock(root, 'c' * 32):
            pass
    assert migration.main(['--recover', str(journal)]) == 1
    assert (root / '.twn-upgrades/operation.lock').read_text().strip() == 'a' * 32


def test_busy_installation_fails_closed_without_cutover(tmp_path, monkeypatch):
    root, journal = prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(migration, 'ensure_idle', Mock(side_effect=UpgradeError('Active jobs')))
    stop = Mock()
    monkeypatch.setattr(migration, 'run', stop)
    with pytest.raises(UpgradeError, match='Active jobs'):
        migration.perform(journal)
    stop.assert_not_called()
    assert migration.load_plan(journal)[1]['state'] == 'failed'
    assert (root / '.venv/preserved-package').exists()


def test_interrupted_staging_can_release_its_lock_without_a_staged_python(tmp_path, monkeypatch):
    root = installed(tmp_path)
    bundle, checksum = make_bundle(tmp_path)
    monkeypatch.setattr(migration, 'python_version', lambda path: (3, 12))
    identifier = 'd' * 32
    (root / '.twn-upgrades').mkdir()
    journal = migration.stage(root, bundle, checksum, Path(sys.executable), identifier, initialize_only=True)
    (root / '.twn-upgrades/operation.lock').write_text(identifier + '\n')
    plan = migration.load_plan(journal)[1]
    plan['pid'] = 999999999
    migration.write_json(journal / 'plan.json', plan)
    assert not (journal / 'venv').exists()
    assert migration.main(['--recover', str(journal)]) == 0
    assert migration.load_plan(journal)[1]['state'] == 'failed'
    assert not (root / '.twn-upgrades/operation.lock').exists()
    assert (root / '.venv/preserved-package').exists()


def test_updater_does_not_steal_an_interrupted_runtime_lock_after_timeout(tmp_path, monkeypatch):
    root, journal = prepare(tmp_path, monkeypatch)
    lock = root / '.twn-upgrades/operation.lock'
    os.utime(lock, (1, 1))
    updater = manager.UpgradeManager(root, root / 'instance', '0.27.0')
    with pytest.raises(UpgradeError, match='interrupted runtime migration'):
        updater.launch_backup({'username': 'test'})
    assert lock.read_text().strip() == 'a' * 32


def test_private_recovery_metadata_is_integrity_checked(tmp_path, monkeypatch):
    root, journal = prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(migration, 'ensure_idle', lambda root: None)
    monkeypatch.setattr(manager, '_prepare_service_reload', lambda *args: True)
    health = Mock()
    monkeypatch.setattr(manager, '_install_and_validate', health)
    migration.perform(journal)
    assert health.call_args.kwargs['suppress_start_event'] is True
    backup = Path(migration.load_plan(journal)[1]['backup'])
    (backup / 'runtime.json').write_text('{}')
    with pytest.raises(UpgradeError, match='integrity verification'):
        manager._restore_backup(root, root / 'instance', backup)
    assert (root / '.venv').is_symlink()
