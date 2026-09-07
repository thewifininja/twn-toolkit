from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from packaging.markers import default_environment
from packaging.requirements import Requirement
from scripts import lock_dependencies as locks
from twn_toolkit.release_bundle import build_release_bundle, validate_release_bundle
from twn_toolkit.upgrade_manager import _create_backup, _restore_backup

ROOT = Path(__file__).resolve().parent.parent


def copy_locks(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name in (*locks.FILES, locks.MANIFEST):
        shutil.copy2(ROOT / name, root / name)


def active_pins(path: Path, environment: dict[str, str]) -> dict[str, str]:
    result = {}
    for line in path.read_text().splitlines():
        if not line or line[0].isspace() or line.startswith("#"):
            continue
        requirement = Requirement(line.removesuffix("\\").strip())
        if not requirement.marker or requirement.marker.evaluate(environment):
            result[requirement.name] = str(requirement.specifier)
    return result


class DependencyLockTests(unittest.TestCase):
    def test_committed_provenance_and_every_file_mutation(self):
        locks.check(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in locks.FILES:
                with self.subTest(name=name):
                    copy_locks(root)
                    with (root / name).open("a") as output:
                        output.write("\n# unreviewed change\n")
                    with self.assertRaisesRegex(ValueError, "Regenerate"):
                        locks.check(root)
            copy_locks(root)
            (root / locks.MANIFEST).unlink()
            with self.assertRaisesRegex(ValueError, "missing/unreadable"):
                locks.check(root)

    def test_development_preserves_runtime_versions_across_supported_markers(self):
        for version in ("3.10", "3.13", "3.14"):
            for system, platform in (("Linux", "linux"), ("Darwin", "darwin")):
                with self.subTest(version=version, system=system):
                    environment = {**default_environment(), "python_version": version,
                                   "python_full_version": version + ".0", "sys_platform": platform,
                                   "platform_system": system, "platform_python_implementation": "CPython",
                                   "implementation_name": "cpython"}
                    runtime = active_pins(ROOT / "requirements.txt", environment)
                    development = active_pins(ROOT / "requirements-dev.txt", environment)
                    self.assertTrue(runtime)
                    self.assertEqual(runtime, {name: development.get(name) for name in runtime})
                    self.assertEqual("pyasyncore" in runtime, version != "3.10")
                    self.assertNotIn("pywin32", runtime)

    def test_failed_generation_does_not_publish_matching_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_locks(root)
            original = (root / locks.MANIFEST).read_bytes()
            calls = []

            def resolve(command, **kwargs):
                calls.append(command)
                if len(calls) == 1:
                    (root / "requirements.txt").write_text("partial==1\n")
                else:
                    raise subprocess.CalledProcessError(1, command)

            with patch.object(locks.subprocess, "check_output", return_value=f"uv {locks.RESOLVER_VERSION}\n"), patch.object(locks.subprocess, "run", side_effect=resolve):
                with self.assertRaises(subprocess.CalledProcessError):
                    locks.generate(root, "uv")
            self.assertEqual((root / locks.MANIFEST).read_bytes(), original)
            self.assertIn("--constraint", calls[1])
            with self.assertRaises(ValueError):
                locks.check(root)

    def test_incorrect_resolver_is_rejected_before_writing(self):
        with patch.object(locks.subprocess, "check_output", return_value="uv 0.0.0\n"), patch.object(locks.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "Install uv=="):
                locks.generate(ROOT, "uv")
            run.assert_not_called()

    def test_stale_lock_stops_installer_before_package_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_locks(root)
            (root / "scripts").mkdir()
            shutil.copy2(ROOT / "scripts/lock_dependencies.py", root / "scripts/lock_dependencies.py")
            shutil.copy2(ROOT / "install.sh", root / "install.sh")
            (root / ".venv/bin").mkdir(parents=True)
            (root / ".venv/bin/python").symlink_to(sys.executable)
            (root / "twn").write_text("#!/bin/sh\nexit 1\n")
            (root / "twn").chmod(0o755)
            (root / "requirements.in").write_text("changed==1\n")
            status = root / "status"
            result = subprocess.run(["sh", str(root / "install.sh")], text=True,
                                    capture_output=True, timeout=10,
                                    env={**os.environ, "TWN_TOOLKIT_INSTALL_STATUS_FILE": str(status)})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Dependency lock error", result.stderr)
            self.assertEqual(status.read_text().strip(), "failed:dependency-lock:1")
            self.assertNotIn("Updating packaging tools", result.stdout)

    def test_bundle_and_recovery_restore_matching_lock_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "toolkit"
            copy_locks(root)
            instance = root / "instance"
            instance.mkdir()
            backups = root / ".twn-upgrades/backups"
            backups.mkdir(parents=True)
            archive = Path(directory) / "release.zip"
            build_release_bundle(root, archive, version="0.24.0", minimum_upgrade_version="0.9.0")
            manifest = validate_release_bundle(archive)
            self.assertTrue(set((*locks.FILES, locks.MANIFEST)) <= set(manifest["files"]))
            backup = _create_backup(root, instance, backups, {"from_version": "0.24.0"})
            for name in locks.FILES:
                (root / name).write_text("changed\n")
            _restore_backup(root, instance, backup)
            locks.check(root)
