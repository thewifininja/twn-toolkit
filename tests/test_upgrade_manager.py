from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
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
    _install_and_validate,
    _prepare_service_reload,
    _preserve_prepared_service_reload,
    _run,
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
    def test_installer_execution_does_not_create_captured_output_pipes(self) -> None:
        completed = subprocess.CompletedProcess(["installer"], 0)
        with patch(
            "twn_toolkit.upgrade_manager.subprocess.run", return_value=completed,
        ) as run:
            result = _run(
                ["installer"], cwd=Path("/srv/twn"), timeout=1200,
                retain_output=False,
            )

        self.assertIs(result, completed)
        run.assert_called_once_with(
            ["installer"], cwd=Path("/srv/twn"), text=True, timeout=1200,
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def test_install_passes_upgrade_context_without_capturing_installer_output(self) -> None:
        completed = [
            subprocess.CompletedProcess(["install"], 0, "", ""),
            subprocess.CompletedProcess(["version"], 0, "0.10.3\n", ""),
            subprocess.CompletedProcess(
                ["status"], 0,
                "Toolkit is running\nAutomation scheduler is running\nWorker supervisor is running\n",
                "",
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary, patch(
            "twn_toolkit.upgrade_manager._run", side_effect=completed,
        ) as run:
            root = Path(temporary)
            instance = root / "instance"
            instance.mkdir()
            _install_and_validate(
                root,
                instance,
                "0.10.3",
                upgrade_request_id="upgrade-1",
                suppress_start_event=True,
            )

        installer_call = run.call_args_list[0]
        self.assertEqual(installer_call.args[0], [str(root / "install.sh")])
        self.assertFalse(installer_call.kwargs["retain_output"])
        self.assertEqual(
            installer_call.kwargs["environment"]["TWN_TOOLKIT_UPGRADE_REQUEST_ID"],
            "upgrade-1",
        )
        self.assertEqual(
            installer_call.kwargs["environment"]["TWN_TOOLKIT_SUPPRESS_START_EVENT"],
            "1",
        )

    def test_service_reload_preparation_is_request_scoped_and_optional(self) -> None:
        root = Path("/srv/twn")
        with patch(
            "twn_toolkit.upgrade_manager._run",
            return_value=subprocess.CompletedProcess(["prepare"], 0, "prepared", ""),
        ) as run:
            self.assertTrue(_prepare_service_reload(root, "upgrade-1"))
        self.assertEqual(
            run.call_args.kwargs["environment"]["TWN_TOOLKIT_UPGRADE_REQUEST_ID"],
            "upgrade-1",
        )
        self.assertEqual(
            run.call_args.args[0],
            ["/srv/twn/twn", "prepare-upgrade-service-reload"],
        )

        with patch(
            "twn_toolkit.upgrade_manager._run",
            return_value=subprocess.CompletedProcess(["prepare"], 3, "not managed", ""),
        ):
            self.assertFalse(_prepare_service_reload(root, "upgrade-2"))

    def test_restored_instance_cannot_rediscover_prepared_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = Path(temporary)
            (instance / "twn-service-launcher.pid").write_text("123\n")
            (instance / "twn-service-resume").touch()
            launchd_markers = (
                "twn-launchd-direct-enabled",
                "twn-tftp.launchd-enabled",
                "twn-ssh-transfer.launchd-enabled",
                "twn-ftp.launchd-enabled",
            )
            for marker in launchd_markers:
                (instance / marker).touch()

            _preserve_prepared_service_reload(instance, True)

            self.assertTrue((instance / "twn-service-paused").is_file())
            self.assertFalse((instance / "twn-service-launcher.pid").exists())
            self.assertFalse((instance / "twn-service-resume").exists())
            self.assertTrue(all(not (instance / marker).exists() for marker in launchd_markers))

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
            with patch(
                "twn_toolkit.upgrade_manager._prepare_service_reload",
                return_value=True,
            ), patch("twn_toolkit.upgrade_manager._install_and_validate") as install:
                execute_request(upgrade_request, delay=0)
            install.assert_called_once_with(
                root.resolve(), instance.resolve(), "0.10.3",
                upgrade_request_id="upgrade-1",
                suppress_start_event=True,
            )
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
            with patch(
                "twn_toolkit.upgrade_manager._prepare_service_reload",
                return_value=True,
            ), patch("twn_toolkit.upgrade_manager._install_and_validate") as install:
                execute_request(rollback_request, delay=0)
            install.assert_called_once_with(
                root.resolve(), instance.resolve(), "0.10.2",
                upgrade_request_id="rollback-1",
                suppress_start_event=True,
            )
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
            self.assertEqual(process.call_args.kwargs["cwd"], root.resolve())
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
            ), patch(
                "twn_toolkit.upgrade_manager._prepare_service_reload",
                return_value=True,
            ):
                execute_request(request, delay=0)
            status = json.loads((workspace / "status.json").read_text())
            self.assertEqual(status["state"], "rolled_back")
            self.assertIn("simulated startup failure", status["error"])
            self.assertIn("old", (root / "twn_toolkit" / "version.py").read_text())
            self.assertEqual((instance / "saved.txt").read_text(), "before")
            self.assertEqual(
                [kwargs["upgrade_request_id"] for _, kwargs in calls],
                ["upgrade-failure", "upgrade-failure"],
            )
            self.assertEqual(
                [kwargs["suppress_start_event"] for _, kwargs in calls],
                [True, True],
            )

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
                root.resolve(), instance.resolve(), "0.10.2",
                install_dependencies=False,
                suppress_start_event=False,
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
                suppress_start_event=False,
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
            with patch(
                "twn_toolkit.upgrade_manager.UpgradeManager.backups",
                return_value=[],
            ), patch(
                "twn_toolkit.upgrade_manager.UpgradeManager.status",
                return_value=None,
            ):
                page = client.get("/settings/updates")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Updates &amp; recovery", page.data)
            self.assertIn(b"Install from a local bundle", page.data)
            self.assertIn(b"Profile backups", page.data)
            self.assertNotIn(b"Create a recovery point now", page.data)

            with patch(
                "twn_toolkit.upgrade_manager.UpgradeManager.backups",
                return_value=[],
            ), patch(
                "twn_toolkit.upgrade_manager.UpgradeManager.status",
                return_value=None,
            ):
                recovery_page = client.get("/settings/updates?section=recovery")
            self.assertEqual(recovery_page.status_code, 200)
            self.assertIn(b"Create a recovery point now", recovery_page.data)
            self.assertIn(b"recovery-point-form", recovery_page.data)
            self.assertIn(b"updates-recovery-empty", recovery_page.data)
            self.assertNotIn(b"Install from a local bundle", recovery_page.data)

            backup_page = client.get("/settings/backup")
            self.assertEqual(backup_page.status_code, 200)
            self.assertIn(b"Profile backup and restore", backup_page.data)
            self.assertIn(b"Export backup", backup_page.data)
            self.assertIn(b"Import backup", backup_page.data)

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
