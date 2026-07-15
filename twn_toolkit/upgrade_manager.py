from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlparse

from .audit import AuditStore
from .release_bundle import (
    MAX_BUNDLE_BYTES,
    RELEASE_MANIFEST,
    ROOT_DIRECTORIES,
    ROOT_FILES,
    UpgradeError,
    build_release_bundle,
    bundle_name,
    parse_version,
    safe_relative_path,
    validate_release_bundle,
)


GITHUB_RELEASES_URL = "https://api.github.com/repos/thewifininja/twn-toolkit/releases"
BACKUP_RETENTION = 5
TERMINAL_STATES = {"succeeded", "rolled_back", "failed", "backup_created"}
ACTIVE_STATES = {"starting", "stopping", "backing_up", "installing", "validating", "rolling_back"}


class ReleaseClient:
    def __init__(self, api_url: str = GITHUB_RELEASES_URL, timeout: int = 15) -> None:
        self.api_url = api_url
        self.timeout = timeout

    def releases(self) -> list[dict[str, Any]]:
        request = urllib.request.Request(
            self.api_url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "twn-toolkit-updater"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read(2 * 1024 * 1024))
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise UpgradeError(f"Release information could not be retrieved: {exc}") from exc
        if not isinstance(payload, list):
            raise UpgradeError("Release service returned an unexpected response.")
        return [item for item in payload if isinstance(item, dict)]

    def compatible_releases(self, current_version: str) -> list[dict[str, Any]]:
        current = parse_version(current_version)
        releases = []
        for release in self.releases():
            if release.get("draft") or release.get("prerelease"):
                continue
            version = str(release.get("tag_name", "")).removeprefix("v")
            try:
                if parse_version(version) <= current:
                    continue
            except UpgradeError:
                continue
            assets = {
                str(asset.get("name", "")): str(asset.get("browser_download_url", ""))
                for asset in release.get("assets", [])
                if isinstance(asset, dict)
            }
            name = bundle_name(version)
            if name not in assets or f"{name}.sha256" not in assets:
                continue
            releases.append({
                "version": version,
                "name": str(release.get("name") or f"v{version}"),
                "published_at": str(release.get("published_at", "")),
                "notes": str(release.get("body", ""))[:20_000],
                "bundle_url": assets[name],
                "checksum_url": assets[f"{name}.sha256"],
            })
        return sorted(releases, key=lambda item: parse_version(item["version"]), reverse=True)

    def release(self, current_version: str, version: str | None = None) -> dict[str, Any]:
        releases = self.compatible_releases(current_version)
        if not releases:
            raise UpgradeError("No newer stable release with a verified upgrade bundle is available.")
        if not version:
            return releases[0]
        normalized = str(version).removeprefix("v")
        for release in releases:
            if release["version"] == normalized:
                return release
        raise UpgradeError(f"v{normalized} is not an available compatible upgrade.")

    def download(self, release: dict[str, Any], destination: Path) -> Path:
        destination.mkdir(parents=True, exist_ok=True)
        name = bundle_name(str(release["version"]))
        checksum = self._download_bytes(str(release["checksum_url"]), 4096).decode("ascii", errors="strict")
        expected = checksum.strip().split()[0].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise UpgradeError("Release checksum file is invalid.")
        target = destination / name
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        self._download_file(str(release["bundle_url"]), temporary)
        actual = hashlib.sha256(temporary.read_bytes()).hexdigest()
        if actual != expected:
            temporary.unlink(missing_ok=True)
            raise UpgradeError("Downloaded release bundle failed its SHA-256 check.")
        os.replace(temporary, target)
        return target

    def _open(self, url: str):
        parsed = urlparse(url)
        if parsed.scheme != "https" or not (
            parsed.hostname == "github.com"
            or parsed.hostname == "api.github.com"
            or str(parsed.hostname).endswith(".githubusercontent.com")
        ):
            raise UpgradeError("Release download URL is not an approved GitHub HTTPS address.")
        request = urllib.request.Request(url, headers={"User-Agent": "twn-toolkit-updater"})
        response = urllib.request.urlopen(request, timeout=self.timeout)
        final = urlparse(response.geturl())
        if final.scheme != "https" or not (
            final.hostname == "github.com"
            or str(final.hostname).endswith(".githubusercontent.com")
        ):
            response.close()
            raise UpgradeError("Release download redirected outside approved GitHub storage.")
        return response

    def _download_bytes(self, url: str, limit: int) -> bytes:
        try:
            with self._open(url) as response:
                content = response.read(limit + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise UpgradeError(f"Release asset could not be downloaded: {exc}") from exc
        if len(content) > limit:
            raise UpgradeError("Release checksum response exceeded its limit.")
        return content

    def _download_file(self, url: str, destination: Path) -> None:
        total = 0
        try:
            with self._open(url) as response, destination.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_BUNDLE_BYTES:
                        raise UpgradeError("Release bundle exceeds the 256 MiB limit.")
                    output.write(chunk)
        except Exception:
            destination.unlink(missing_ok=True)
            raise


class UpgradeManager:
    def __init__(self, root: Path, instance: Path, current_version: str) -> None:
        self.root = root.resolve()
        self.instance = instance.resolve()
        self.current_version = current_version
        self.workspace = self.root / ".twn-upgrades"
        self.status_path = self.workspace / "status.json"
        self.backup_root = self.workspace / "backups"
        self.incoming = self.workspace / "incoming"

    def _ensure_workspace(self) -> None:
        for directory in (self.workspace, self.backup_root, self.incoming):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)

    def status(self) -> dict[str, Any]:
        try:
            value = json.loads(self.status_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def backups(self) -> list[dict[str, Any]]:
        backups = []
        if not self.backup_root.is_dir():
            return backups
        for path in self.backup_root.iterdir():
            try:
                metadata = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(metadata, dict) and (path / "instance").is_dir() and (path / "code").is_dir():
                backups.append({**metadata, "id": path.name})
        return sorted(backups, key=lambda item: float(item.get("created_at", 0)), reverse=True)

    def save_upload(self, source: BinaryIO) -> Path:
        self._ensure_workspace()
        target = self.incoming / f"uploaded-{uuid.uuid4().hex}.zip"
        total = 0
        with target.open("wb") as output:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BUNDLE_BYTES:
                    target.unlink(missing_ok=True)
                    raise UpgradeError("Uploaded release bundle exceeds the 256 MiB limit.")
                output.write(chunk)
        if not total:
            target.unlink(missing_ok=True)
            raise UpgradeError("Choose a release bundle to upload.")
        return target

    def download_release(
        self,
        release: dict[str, Any],
        client: ReleaseClient | None = None,
    ) -> Path:
        self._ensure_workspace()
        return (client or ReleaseClient()).download(release, self.incoming)

    def launch_upgrade(self, bundle: Path, actor: dict[str, str]) -> dict[str, Any]:
        try:
            manifest = validate_release_bundle(
                bundle, current_version=self.current_version, require_newer=True
            )
            return self._launch(
                "upgrade", actor, bundle=bundle,
                target_version=manifest["version"],
            )
        except Exception:
            try:
                if bundle.resolve().parent == self.incoming.resolve():
                    bundle.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def launch_backup(self, actor: dict[str, str]) -> dict[str, Any]:
        return self._launch("backup", actor, target_version=self.current_version)

    def launch_rollback(self, backup_id: str, actor: dict[str, str]) -> dict[str, Any]:
        backup = next((item for item in self.backups() if item["id"] == backup_id), None)
        if not backup:
            raise UpgradeError("Choose an available recovery point.")
        return self._launch(
            "rollback", actor, backup_id=backup_id,
            target_version=str(backup.get("from_version", "")),
        )

    def _launch(self, operation: str, actor: dict[str, str], **values: Any) -> dict[str, Any]:
        self._ensure_workspace()
        status = self.status()
        try:
            recent_active = (
                status.get("state") in ACTIVE_STATES
                and time.time() - float(status.get("updated_at", 0)) < 7200
            )
        except (TypeError, ValueError):
            recent_active = False
        if recent_active:
            raise UpgradeError("Another upgrade or recovery operation is already running.")
        request_id = uuid.uuid4().hex
        lock_path = self.workspace / "operation.lock"
        try:
            lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            try:
                stale = time.time() - lock_path.stat().st_mtime >= 7200
            except OSError:
                stale = False
            if not stale:
                raise UpgradeError("Another upgrade or recovery operation is already running.") from exc
            lock_path.unlink(missing_ok=True)
            try:
                lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError as race:
                raise UpgradeError("Another upgrade or recovery operation is already running.") from race
            except OSError as lock_error:
                raise UpgradeError("The upgrade operation lock could not be created.") from lock_error
        except OSError as exc:
            raise UpgradeError("The upgrade operation lock could not be created.") from exc
        request_data = {
            "id": request_id, "operation": operation, "created_at": time.time(),
            "root": str(self.root), "instance": str(self.instance),
            "from_version": self.current_version, "actor": actor,
            **{key: str(value) for key, value in values.items()},
        }
        request_path = self.workspace / f"request-{request_id}.json"
        try:
            try:
                os.write(lock_fd, f"{request_id}\n".encode("ascii"))
            finally:
                os.close(lock_fd)
            _atomic_json(request_path, request_data)
            _atomic_json(self.status_path, {
                "id": request_id, "operation": operation, "state": "starting",
                "message": "Preparing the requested operation.",
                "from_version": self.current_version,
                "target_version": request_data.get("target_version", ""),
                "updated_at": time.time(),
            })
            log_path = self.workspace / "upgrade.log"
            with log_path.open("ab") as log:
                subprocess.Popen(
                    [sys.executable, "-m", "twn_toolkit.upgrade_worker", "--request", str(request_path)],
                    cwd=self.root, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
        except Exception as exc:
            lock_path.unlink(missing_ok=True)
            request_path.unlink(missing_ok=True)
            _atomic_json(self.status_path, {
                "id": request_id, "operation": operation, "state": "failed",
                "message": "The updater worker could not be started.",
                "from_version": self.current_version,
                "target_version": request_data.get("target_version", ""),
                "error": "The updater worker could not be started.",
                "updated_at": time.time(),
            })
            raise UpgradeError("The updater worker could not be started.") from exc
        return request_data


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _tree_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return total
    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            pass
    return total


def _copy_code(root: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for name in ROOT_FILES + (RELEASE_MANIFEST,):
        source = root / name
        if source.is_file():
            shutil.copy2(source, destination / name)
    for name in ROOT_DIRECTORIES:
        source = root / name
        if source.is_dir():
            shutil.copytree(source, destination / name, symlinks=True)


def _integrity_manifest(root: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for base_name in ("code", "instance"):
        base = root / base_name
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                values[relative] = f"link:{os.readlink(path)}"
            elif path.is_file():
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                values[relative] = digest.hexdigest()
    return values


def _verify_backup(backup: Path) -> None:
    try:
        expected = json.loads((backup / "integrity.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise UpgradeError("Recovery point integrity manifest is missing or invalid.") from exc
    if not isinstance(expected, dict) or expected != _integrity_manifest(backup):
        raise UpgradeError("Recovery point integrity verification failed.")


def _create_backup(root: Path, instance: Path, backup_root: Path, request: dict[str, Any]) -> Path:
    identifier = time.strftime("%Y%m%d-%H%M%S") + f"-{uuid.uuid4().hex[:8]}"
    destination = backup_root / identifier
    required = _tree_size(instance) + sum(_tree_size(root / name) for name in ROOT_DIRECTORIES) + 256 * 1024 * 1024
    if shutil.disk_usage(root).free < required:
        raise UpgradeError("Not enough free disk space for a complete recovery point and upgrade staging.")
    destination.mkdir(parents=True, mode=0o700)
    try:
        _copy_code(root, destination / "code")
        shutil.copytree(instance, destination / "instance", symlinks=True)
        _atomic_json(destination / "integrity.json", _integrity_manifest(destination))
        metadata = {
            "id": identifier, "created_at": time.time(),
            "from_version": str(request.get("from_version", "")),
            "target_version": str(request.get("target_version", "")),
            "operation": str(request.get("operation", "")),
        }
        _atomic_json(destination / "metadata.json", metadata)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return destination


def _extract_and_apply(root: Path, bundle: Path, manifest: dict[str, Any], workspace: Path) -> None:
    staging = Path(tempfile.mkdtemp(prefix="release-", dir=workspace))
    try:
        with zipfile.ZipFile(bundle) as archive:
            for relative, metadata in manifest["files"].items():
                destination = staging / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(f"payload/{relative}"))
                os.chmod(destination, int(metadata.get("mode", 0o644)) & 0o755)
        previous_files: set[str] = set()
        try:
            previous = json.loads((root / RELEASE_MANIFEST).read_text(encoding="utf-8"))
            previous_files = set(previous.get("files", {}))
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        new_files = set(manifest["files"])
        for relative in sorted(previous_files - new_files, reverse=True):
            target = root / safe_relative_path(relative)
            if target.is_file() or target.is_symlink():
                target.unlink()
        for relative, metadata in manifest["files"].items():
            source = staging / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.upgrade-{uuid.uuid4().hex}.tmp")
            shutil.copy2(source, temporary)
            os.chmod(temporary, int(metadata.get("mode", 0o644)) & 0o755)
            os.replace(temporary, target)
        _atomic_json(root / RELEASE_MANIFEST, manifest)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _restore_backup(root: Path, instance: Path, backup: Path) -> None:
    _verify_backup(backup)
    workspace = root / ".twn-upgrades"
    staging = Path(tempfile.mkdtemp(prefix="restore-", dir=workspace))
    staged_code = staging / "code"
    staged_instance = staging / "instance"
    try:
        shutil.copytree(backup / "code", staged_code, symlinks=True)
        shutil.copytree(backup / "instance", staged_instance, symlinks=True)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    displaced = backup / f"displaced-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    displaced.mkdir(mode=0o700)
    try:
        for path in staged_code.iterdir():
            target = root / path.name
            if target.exists() or target.is_symlink():
                os.replace(target, displaced / path.name)
            os.replace(path, target)
        if instance.exists() or instance.is_symlink():
            os.replace(instance, displaced / "instance")
        os.replace(staged_instance, instance)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _run(command: list[str], *, cwd: Path, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)


def _install_and_validate(
    root: Path, instance: Path, expected_version: str, *, install_dependencies: bool = True
) -> None:
    command = [str(root / "install.sh")] if install_dependencies else [str(root / "twn"), "start"]
    install = _run(command, cwd=root, timeout=1200)
    if install.returncode:
        raise UpgradeError(
            f"Installer exited with status {install.returncode}; output was not retained because package-manager logs may contain repository credentials."
        )
    version = _run([
        str(root / ".venv/bin/python"), "-c",
        "from twn_toolkit import __version__; print(__version__)",
    ], cwd=root, timeout=30)
    if version.returncode or version.stdout.strip() != expected_version:
        raise UpgradeError("The restarted toolkit does not report the expected version.")
    status = _run([str(root / "twn"), "status"], cwd=root, timeout=30)
    combined = f"{status.stdout}\n{status.stderr}".lower()
    if status.returncode or "not running" in combined or "enabled but not running" in combined:
        raise UpgradeError(f"Post-upgrade process health check failed: {combined[-2000:]}")
    for database in instance.glob("*.sqlite3"):
        connection = sqlite3.connect(database, timeout=5)
        try:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise UpgradeError(f"Database integrity check failed: {database.name}")
        finally:
            connection.close()


def _record_result(
    instance: Path,
    request: dict[str, Any],
    state: str,
    message: str,
    backup_id: str = "",
    *,
    failed_operation: bool = False,
) -> None:
    actor = request.get("actor") if isinstance(request.get("actor"), dict) else {}
    try:
        AuditStore(str(instance)).record(
            user_id=str(actor.get("id", "")), username=str(actor.get("username", "system-updater")),
            remote_ip=str(actor.get("remote_ip", "local")), method="SYSTEM",
            endpoint="upgrade_worker", path="/settings/updates",
            status_code=500 if state == "failed" or failed_operation else 200,
            category="Administration",
            action="upgrade.failed_recovered" if failed_operation else f"upgrade.{state}",
            summary=message, resource_type="toolkit_release",
            resource_id=str(request.get("target_version", "")),
            resource_name=f"Toolkit v{request.get('target_version', '')}",
            details={"operation": request.get("operation", ""), "recovery point": backup_id},
        )
    except Exception:
        pass


def execute_request(request_path: Path, *, delay: float = 2.0) -> None:
    request = json.loads(request_path.read_text(encoding="utf-8"))
    root = Path(request["root"]).resolve()
    instance = Path(request["instance"]).resolve()
    workspace = root / ".twn-upgrades"
    status_path = workspace / "status.json"
    backup_root = workspace / "backups"
    backup: Path | None = None
    manifest: dict[str, Any] | None = None
    lock_path = workspace / "operation.lock"
    services_stopped = False

    def status(state: str, message: str, **extra: Any) -> None:
        _atomic_json(status_path, {
            "id": request["id"], "operation": request["operation"], "state": state,
            "message": message, "from_version": request.get("from_version", ""),
            "target_version": request.get("target_version", ""),
            "updated_at": time.time(), **extra,
        })

    def finish() -> None:
        lock_path.unlink(missing_ok=True)
        request_path.unlink(missing_ok=True)
        bundle_value = request.get("bundle")
        if not bundle_value:
            return
        try:
            bundle_path = Path(str(bundle_value)).resolve()
            if bundle_path.parent == (workspace / "incoming").resolve():
                bundle_path.unlink(missing_ok=True)
        except OSError:
            pass

    time.sleep(max(0, delay))
    try:
        if request["operation"] == "rollback":
            backup = backup_root / str(request["backup_id"])
            _verify_backup(backup)
            status("stopping", "Stopping services before restoring the recovery point.")
            stopped = _run([str(root / "twn"), "stop"], cwd=root, timeout=120)
            if stopped.returncode:
                raise UpgradeError(f"Toolkit services could not be stopped: {(stopped.stderr or stopped.stdout)[-2000:]}")
            services_stopped = True
            status("rolling_back", "Restoring the matched toolkit code and instance data.")
            _restore_backup(root, instance, backup)
            _install_and_validate(root, instance, str(request["target_version"]))
            message = f"Restored recovery point for v{request['target_version']}."
            status("rolled_back", message, backup_id=backup.name)
            _record_result(instance, request, "rolled_back", message, backup.name)
            finish()
            return

        status("stopping", "Stopping toolkit services for a consistent backup.")
        stopped = _run([str(root / "twn"), "stop"], cwd=root, timeout=120)
        if stopped.returncode:
            raise UpgradeError(f"Toolkit services could not be stopped: {(stopped.stderr or stopped.stdout)[-2000:]}")
        services_stopped = True
        status("backing_up", "Creating a complete code and instance recovery point.")
        backup = _create_backup(root, instance, backup_root, request)
        if request["operation"] == "backup":
            _install_and_validate(
                root, instance, str(request["from_version"]), install_dependencies=False
            )
            message = f"Created recovery point for v{request['from_version']}."
            status("backup_created", message, backup_id=backup.name)
            _record_result(instance, request, "backup_created", message, backup.name)
            finish()
            return

        bundle = Path(request["bundle"])
        manifest = validate_release_bundle(
            bundle, current_version=str(request["from_version"]), require_newer=True
        )
        status("installing", f"Installing toolkit v{manifest['version']}.", backup_id=backup.name)
        _extract_and_apply(root, bundle, manifest, workspace)
        status("validating", "Restarting and validating processes, version, and databases.", backup_id=backup.name)
        _install_and_validate(root, instance, str(manifest["version"]))
        message = f"Toolkit upgraded successfully to v{manifest['version']}."
        status("succeeded", message, backup_id=backup.name)
        _record_result(instance, request, "succeeded", message, backup.name)
        backups = sorted(
            (path for path in backup_root.iterdir() if (path / "metadata.json").is_file()),
            key=lambda path: path.stat().st_mtime, reverse=True,
        )
        for old in backups[BACKUP_RETENTION:]:
            shutil.rmtree(old, ignore_errors=True)
        finish()
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
        if backup and backup.is_dir() and request.get("operation") == "upgrade":
            try:
                status(
                    "rolling_back",
                    "Upgrade failed; restoring the automatic recovery point.",
                    error=failure,
                    backup_id=backup.name,
                )
                _run([str(root / "twn"), "stop"], cwd=root, timeout=120)
                _restore_backup(root, instance, backup)
                _install_and_validate(root, instance, str(request["from_version"]))
                message = "Upgrade failed and the previous version was restored automatically."
                status("rolled_back", message, error=failure, backup_id=backup.name)
                _record_result(
                    instance, request, "rolled_back", message, backup.name,
                    failed_operation=True,
                )
                finish()
                return
            except Exception as rollback_exc:
                failure = f"{failure}; rollback failed: {type(rollback_exc).__name__}: {rollback_exc}"
        elif services_stopped and request.get("operation") in {"backup", "upgrade"}:
            try:
                _install_and_validate(
                    root, instance, str(request["from_version"]),
                    install_dependencies=False,
                )
            except Exception as restart_exc:
                failure = f"{failure}; restart failed: {type(restart_exc).__name__}: {restart_exc}"
        status("failed", "The operation failed. Preserve the recovery files and inspect the upgrade log.", error=failure, backup_id=backup.name if backup else "")
        _record_result(instance, request, "failed", "Toolkit upgrade or recovery failed.", backup.name if backup else "")
        finish()
