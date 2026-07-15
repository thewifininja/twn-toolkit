from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.upgrade_manager import (
    ReleaseClient,
    UpgradeError,
    UpgradeManager,
    _create_backup,
    _restore_backup,
    _verify_backup,
    build_release_bundle,
    bundle_name,
    execute_request,
    parse_version,
    validate_release_bundle,
)
from twn_toolkit.upgrade_cli import _wait


def release_root(path: Path, version: str, marker: str) -> None:
    (path / "twn_toolkit").mkdir(parents=True)
    (path / "twn_toolkit" / "__init__.py").write_text("", encoding="utf-8")
    (path / "twn_toolkit" / "version.py").write_text(
        f'APP_VERSION = "{version}"\nMARKER = "{marker}"\n', encoding="utf-8"
    )
    (path / "requirements.txt").write_text("", encoding="utf-8")
    (path / "install.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (path / "twn").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(path / "install.sh", 0o755)
    os.chmod(path / "twn", 0o755)


class UpgradeBundleTests(unittest.TestCase):
    def test_build_and_validate_verified_release_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "release"
            root.mkdir(); release_root(root, "0.10.3", "new")
            output = Path(temporary) / bundle_name("0.10.3")
            manifest = build_release_bundle(root, output, version="0.10.3")
            validated = validate_release_bundle(output, current_version="0.10.2")

            self.assertEqual(manifest, validated)
            self.assertEqual(validated["version"], "0.10.3")
            self.assertIn("twn_toolkit/version.py", validated["files"])
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(
                    hashlib.sha256(archive.read("payload/twn_toolkit/version.py")).hexdigest(),
                    validated["files"]["twn_toolkit/version.py"]["sha256"],
                )

    def test_bundle_rejects_tampering_traversal_and_downgrades(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "release"
            root.mkdir(); release_root(root, "0.10.3", "new")
            output = Path(temporary) / "release.zip"
            build_release_bundle(root, output, version="0.10.3")
            with self.assertRaisesRegex(UpgradeError, "newer"):
                validate_release_bundle(output, current_version="0.10.3")

            unsafe = Path(temporary) / "unsafe.zip"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("manifest.json", json.dumps({
                    "format": 1, "product": "twn-toolkit", "version": "0.10.3",
                    "minimum_upgrade_version": "0.9.0", "files": {"../escape": {}},
                }))
                archive.writestr("payload/../escape", b"bad")
            with self.assertRaisesRegex(UpgradeError, "unsafe path"):
                validate_release_bundle(unsafe, current_version="0.10.2")

    def test_release_discovery_requires_stable_verified_assets(self) -> None:
        client = ReleaseClient()
        good_name = bundle_name("0.10.3")
        with patch.object(client, "releases", return_value=[
            {"tag_name": "v0.10.4", "draft": False, "prerelease": True, "assets": []},
            {"tag_name": "v0.10.3", "draft": False, "prerelease": False, "name": "Next", "assets": [
                {"name": good_name, "browser_download_url": "https://github.com/bundle"},
                {"name": f"{good_name}.sha256", "browser_download_url": "https://github.com/checksum"},
            ]},
        ]):
            release = client.release("0.10.2")
        self.assertEqual(release["version"], "0.10.3")
        self.assertEqual(parse_version(release["version"]), (0, 10, 3))


class UpgradeRecoveryTests(unittest.TestCase):
    def test_backup_and_restore_keep_code_and_instance_as_a_matched_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "toolkit"; root.mkdir()
            instance = root / "instance"; instance.mkdir()
            backups = root / ".twn-upgrades" / "backups"; backups.mkdir(parents=True)
            release_root(root, "0.10.2", "old")
            (instance / "saved.txt").write_text("before", encoding="utf-8")
            request = {"from_version": "0.10.2", "target_version": "0.10.3", "operation": "upgrade"}

            backup = _create_backup(root, instance, backups, request)
            (root / "twn_toolkit" / "version.py").write_text("new", encoding="utf-8")
            (instance / "saved.txt").write_text("after", encoding="utf-8")
            _restore_backup(root, instance, backup)

            self.assertIn("0.10.2", (root / "twn_toolkit" / "version.py").read_text())
            self.assertEqual((instance / "saved.txt").read_text(), "before")

            (backup / "instance" / "saved.txt").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(UpgradeError, "integrity verification"):
                _verify_backup(backup)

    def test_upgrade_request_applies_bundle_and_recovery_request_restores_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "toolkit"; root.mkdir()
            instance = root / "instance"; instance.mkdir()
            release_root(root, "0.10.2", "old")
            (instance / "saved.txt").write_text("before", encoding="utf-8")
            target = Path(temporary) / "target"; target.mkdir()
            release_root(target, "0.10.3", "new")
            bundle = Path(temporary) / bundle_name("0.10.3")
            build_release_bundle(target, bundle, version="0.10.3")
            workspace = root / ".twn-upgrades"; workspace.mkdir()
            upgrade_request = workspace / "upgrade.json"
            upgrade_request.write_text(json.dumps({
                "id": "upgrade-1", "operation": "upgrade", "root": str(root),
                "instance": str(instance), "from_version": "0.10.2",
                "target_version": "0.10.3", "bundle": str(bundle), "actor": {},
            }), encoding="utf-8")
            with patch("twn_toolkit.upgrade_manager._install_and_validate"):
                execute_request(upgrade_request, delay=0)
            status = json.loads((workspace / "status.json").read_text())
            self.assertEqual(status["state"], "succeeded")
            self.assertIn("new", (root / "twn_toolkit" / "version.py").read_text())
            backup_id = status["backup_id"]

            (instance / "saved.txt").write_text("after", encoding="utf-8")
            rollback_request = workspace / "rollback.json"
            rollback_request.write_text(json.dumps({
                "id": "rollback-1", "operation": "rollback", "root": str(root),
                "instance": str(instance), "from_version": "0.10.3",
                "target_version": "0.10.2", "backup_id": backup_id, "actor": {},
            }), encoding="utf-8")
            with patch("twn_toolkit.upgrade_manager._install_and_validate"):
                execute_request(rollback_request, delay=0)
            status = json.loads((workspace / "status.json").read_text())
            self.assertEqual(status["state"], "rolled_back")
            self.assertIn("old", (root / "twn_toolkit" / "version.py").read_text())
            self.assertEqual((instance / "saved.txt").read_text(), "before")

    def test_manager_upload_is_bounded_and_launch_is_external(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); instance = root / "instance"; instance.mkdir()
            manager = UpgradeManager(root, instance, "0.10.2")
            saved = manager.save_upload(io.BytesIO(b"bundle"))
            self.assertEqual(saved.read_bytes(), b"bundle")
            with patch("twn_toolkit.upgrade_manager.subprocess.Popen") as process:
                request = manager.launch_backup({"id": "1", "username": "admin", "remote_ip": "127.0.0.1"})
            process.assert_called_once()
            self.assertEqual(manager.status()["state"], "starting")
            self.assertEqual(request["operation"], "backup")

    def test_failed_upgrade_restores_automatic_recovery_point(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "toolkit"; root.mkdir()
            instance = root / "instance"; instance.mkdir()
            release_root(root, "0.10.2", "old")
            (instance / "saved.txt").write_text("before", encoding="utf-8")
            target = Path(temporary) / "target"; target.mkdir()
            release_root(target, "0.10.3", "new")
            bundle = Path(temporary) / bundle_name("0.10.3")
            build_release_bundle(target, bundle, version="0.10.3")
            workspace = root / ".twn-upgrades"; workspace.mkdir()
            request = workspace / "upgrade.json"
            request.write_text(json.dumps({
                "id": "upgrade-failure", "operation": "upgrade", "root": str(root),
                "instance": str(instance), "from_version": "0.10.2",
                "target_version": "0.10.3", "bundle": str(bundle), "actor": {},
            }), encoding="utf-8")
            calls = []
            def fail_then_validate(*args, **kwargs):
                calls.append((args, kwargs))
                if len(calls) == 1:
                    raise UpgradeError("simulated startup failure")
            with patch(
                "twn_toolkit.upgrade_manager._install_and_validate",
                side_effect=fail_then_validate,
            ):
                execute_request(request, delay=0)
            status = json.loads((workspace / "status.json").read_text())
            self.assertEqual(status["state"], "rolled_back")
            self.assertIn("simulated startup failure", status["error"])
            self.assertIn("old", (root / "twn_toolkit" / "version.py").read_text())
            self.assertEqual((instance / "saved.txt").read_text(), "before")

    def test_failed_backup_restarts_untouched_installation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "toolkit"; root.mkdir()
            instance = root / "instance"; instance.mkdir()
            release_root(root, "0.10.2", "old")
            workspace = root / ".twn-upgrades"; workspace.mkdir()
            request = workspace / "backup.json"
            request.write_text(json.dumps({
                "id": "backup-failure", "operation": "backup", "root": str(root),
                "instance": str(instance), "from_version": "0.10.2",
                "target_version": "0.10.2", "actor": {},
            }), encoding="utf-8")
            with patch(
                "twn_toolkit.upgrade_manager._create_backup",
                side_effect=UpgradeError("simulated backup failure"),
            ), patch("twn_toolkit.upgrade_manager._install_and_validate") as restart:
                execute_request(request, delay=0)
            restart.assert_called_once_with(
                root.resolve(), instance.resolve(), "0.10.2", install_dependencies=False,
            )
            status = json.loads((workspace / "status.json").read_text())
            self.assertEqual(status["state"], "failed")

    def test_upgrade_backup_failure_restarts_untouched_installation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "toolkit"; root.mkdir()
            instance = root / "instance"; instance.mkdir()
            release_root(root, "0.10.2", "old")
            workspace = root / ".twn-upgrades"; workspace.mkdir()
            request = workspace / "upgrade.json"
            request.write_text(json.dumps({
                "id": "upgrade-backup-failure", "operation": "upgrade",
                "root": str(root), "instance": str(instance),
                "from_version": "0.10.2", "target_version": "0.10.3",
                "bundle": str(root / "unused.zip"), "actor": {},
            }), encoding="utf-8")
            with patch(
                "twn_toolkit.upgrade_manager._create_backup",
                side_effect=UpgradeError("simulated backup failure"),
            ), patch("twn_toolkit.upgrade_manager._install_and_validate") as restart:
                execute_request(request, delay=0)
            restart.assert_called_once_with(
                root.resolve(), instance.resolve(), "0.10.2",
                install_dependencies=False,
            )
            status = json.loads((workspace / "status.json").read_text())
            self.assertEqual(status["state"], "failed")

    def test_automatic_rollback_is_not_reported_as_cli_success(self) -> None:
        manager = unittest.mock.Mock()
        manager.status.return_value = {
            "id": "operation", "state": "rolled_back",
            "message": "Upgrade failed and was restored.", "error": "startup failed",
        }
        self.assertEqual(_wait(manager, "operation"), 1)


class UpgradeRouteTests(unittest.TestCase):
    def test_admin_updates_page_and_confirmations_are_available(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            page = client.get("/settings/updates")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Updates &amp; recovery", page.data)
            self.assertIn(b"Manual release bundle", page.data)
            self.assertIn(b"Create a recovery point now", page.data)

            rejected = client.post("/settings/updates/backup", data={})
            self.assertEqual(rejected.status_code, 302)
            with patch(
                "twn_toolkit.admin_routes.UpgradeManager.launch_backup",
                return_value={"id": "test-operation", "operation": "backup", "target_version": "0.10.2"},
            ):
                accepted = client.post(
                    "/settings/updates/backup", data={"confirm_backup": "on"}
                )
            self.assertEqual(accepted.status_code, 200)
            self.assertIn(b"Creating a recovery point", accepted.data)


if __name__ == "__main__":
    unittest.main()
