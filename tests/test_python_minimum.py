from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import patch
import zipfile

import pytest

from twn_toolkit import release_bundle as bundles
from twn_toolkit.upgrade_manager import UpgradeManager

ROOT = Path(__file__).resolve().parents[1]


def executable(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    path.chmod(0o755)
    return path


@pytest.mark.parametrize('old_venv', [False, True], ids=['old-bootstrap', 'old-venv'])
def test_installer_refuses_old_python_without_changing_existing_files(tmp_path, old_venv):
    shutil.copy2(ROOT / 'install.sh', tmp_path / 'install.sh')
    instance = tmp_path / 'instance'
    instance.mkdir()
    (instance / 'key').write_bytes(b'preserve-key')
    (instance / 'requirements.sha256').write_bytes(b'preserve-stamp')
    old = executable(tmp_path / 'old-python', '#!/bin/sh\nexit 1\n')
    if old_venv:
        executable(tmp_path / '.venv/bin/python', '#!/bin/sh\nexit 1\n')
    executable(tmp_path / 'twn', '#!/bin/sh\necho unexpected > "$(dirname "$0")/called"\n')
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    result = subprocess.run(['sh', str(tmp_path / 'install.sh'), '--non-interactive'],
                            env={**os.environ, 'TWN_TOOLKIT_PYTHON': sys.executable if old_venv else str(old)},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert 'docs/python-upgrade.md' in result.stderr
    assert 'Installing toolkit requirements' not in result.stdout
    assert before == {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    if not old_venv:
        assert not (tmp_path / '.venv').exists()


@pytest.mark.parametrize('command', ['start', 'restart', 'recover', 'upgrade'])
def test_launcher_rejects_old_environment_before_mutation(tmp_path, command):
    shutil.copy2(ROOT / 'twn', tmp_path / 'twn')
    executable(tmp_path / '.venv/bin/python', '#!/bin/sh\nexit 1\n')
    result = subprocess.run(['sh', str(tmp_path / 'twn'), command], capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert 'Python 3.11' in result.stderr
    assert not (tmp_path / 'instance').exists()


def bundle(tmp_path):
    source = tmp_path / 'release'
    source.mkdir()
    (source / 'README.md').write_text('test release')
    target = tmp_path / 'release.zip'
    manifest = bundles.build_release_bundle(source, target, version='0.28.0')
    return target, manifest


def rewrite_manifest(target, manifest):
    with zipfile.ZipFile(target) as archive:
        payload = [(info, archive.read(info.filename)) for info in archive.infolist() if info.filename != 'manifest.json']
    with zipfile.ZipFile(target, 'w') as archive:
        archive.writestr('manifest.json', json.dumps(manifest))
        for info, content in payload:
            archive.writestr(info, content)


def test_python_requirement_blocks_upgrade_before_launch(tmp_path):
    target, manifest = bundle(tmp_path)
    assert manifest['format'] == 2
    assert manifest['minimum_python'] == '3.11'
    manager = UpgradeManager(tmp_path / 'installed', tmp_path / 'instance', current_version='0.27.0')
    with patch.object(bundles.sys, 'version_info', (3, 10, 22)), patch.object(manager, '_launch') as launch:
        with pytest.raises(bundles.UpgradeError, match='requires Python 3.11'):
            manager.launch_upgrade(target, {'id': 'test', 'username': 'test'})
        launch.assert_not_called()
    assert not (tmp_path / 'installed').exists()
    assert not (tmp_path / 'instance').exists()


@pytest.mark.parametrize('minimum', [None, '3.10', '3.11junk', ['3', '11']])
def test_format_two_requires_valid_supported_python_metadata(tmp_path, minimum):
    target, manifest = bundle(tmp_path)
    manifest['minimum_python'] = minimum
    rewrite_manifest(target, manifest)
    with pytest.raises(bundles.UpgradeError, match='Python'):
        bundles.validate_release_bundle(target)


def test_minimum_python_acceptance_and_legacy_bundle_compatibility(tmp_path):
    target, manifest = bundle(tmp_path)
    with patch.object(bundles.sys, 'version_info', (3, 11, 0)):
        assert bundles.validate_release_bundle(target)['minimum_python'] == '3.11'
    manifest['format'] = 1
    manifest.pop('minimum_python')
    rewrite_manifest(target, manifest)
    assert bundles.validate_release_bundle(target)['format'] == 1
