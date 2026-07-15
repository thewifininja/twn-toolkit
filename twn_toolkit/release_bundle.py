from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


UPGRADE_FORMAT = 1
PRODUCT_ID = "twn-toolkit"
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_FILES = 10_000
ROOT_DIRECTORIES = (".github", "docs", "scripts", "tests", "twn_toolkit")
ROOT_FILES = (
    ".gitignore", "CONTRIBUTING.md", "LICENSE", "QUICKSTART.md", "README.md",
    "install.sh", "requirements-dev.txt", "requirements.txt", "twn",
)
RELEASE_MANIFEST = ".twn-release-manifest.json"


class UpgradeError(RuntimeError):
    pass


def parse_version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(
        r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)",
        str(value).strip(),
    )
    if not match:
        raise UpgradeError(f"Unsupported release version: {value}")
    return tuple(int(part) for part in match.groups())


def bundle_name(version: str) -> str:
    normalized = str(version).removeprefix("v")
    parse_version(normalized)
    return f"twn-toolkit-v{normalized}.zip"


def safe_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise UpgradeError("Release bundle contains an unsafe path.")
    normalized = path.as_posix()
    if normalized.startswith(".") and not (
        normalized in {RELEASE_MANIFEST, ".gitignore"}
        or normalized.startswith(".github/")
    ):
        raise UpgradeError(f"Release bundle contains unsupported path: {normalized}")
    return normalized


def _release_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for name in ROOT_FILES:
        path = root / name
        if path.is_file() and not path.is_symlink():
            files.append(path)
    for name in ROOT_DIRECTORIES:
        directory = root / name
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if (
                path.is_file()
                and not path.is_symlink()
                and "__pycache__" not in path.parts
                and path.name != ".DS_Store"
                and not path.name.endswith((".pyc", ".pyo"))
            ):
                files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def build_release_bundle(
    root: Path,
    output: Path,
    *,
    version: str,
    minimum_upgrade_version: str = "0.9.0",
) -> dict[str, Any]:
    version = str(version).removeprefix("v")
    parse_version(version)
    parse_version(minimum_upgrade_version)
    entries: dict[str, dict[str, Any]] = {}
    files = _release_files(root)
    if not files:
        raise UpgradeError("No toolkit files were found for the release bundle.")
    for path in files:
        relative = safe_relative_path(path.relative_to(root).as_posix())
        content = path.read_bytes()
        entries[relative] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
            "mode": 0o755 if os.access(path, os.X_OK) else 0o644,
        }
    manifest = {
        "format": UPGRADE_FORMAT,
        "product": PRODUCT_ID,
        "version": version,
        "minimum_upgrade_version": minimum_upgrade_version,
        "files": entries,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
    with zipfile.ZipFile(
        temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9,
    ) as archive:
        archive.writestr(
            "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        )
        for path in files:
            relative = path.relative_to(root).as_posix()
            archive.write(path, f"payload/{relative}")
    os.replace(temporary, output)
    return manifest


def validate_release_bundle(
    path: Path,
    *,
    current_version: str | None = None,
    require_newer: bool = True,
) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > MAX_BUNDLE_BYTES:
        raise UpgradeError("Release bundle is missing or exceeds the 256 MiB limit.")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_BUNDLE_FILES:
                raise UpgradeError("Release bundle contains too many files.")
            if sum(info.file_size for info in infos) > MAX_EXPANDED_BYTES:
                raise UpgradeError("Release bundle expands beyond the 512 MiB limit.")
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or "manifest.json" not in names:
                raise UpgradeError("Release bundle has a missing or duplicate manifest.")
            for info in infos:
                safe_relative_path(info.filename)
                file_type = (info.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    raise UpgradeError("Release bundles may not contain symbolic links.")
            manifest = json.loads(archive.read("manifest.json"))
            if not isinstance(manifest, dict):
                raise UpgradeError("Release manifest is invalid.")
            if (
                manifest.get("format") != UPGRADE_FORMAT
                or manifest.get("product") != PRODUCT_ID
            ):
                raise UpgradeError("Release bundle is not compatible with this toolkit.")
            version = str(manifest.get("version", ""))
            minimum = str(manifest.get("minimum_upgrade_version", ""))
            parse_version(version)
            parse_version(minimum)
            if current_version:
                current = parse_version(current_version)
                if current < parse_version(minimum):
                    raise UpgradeError(
                        f"This bundle requires v{minimum} or newer; "
                        f"this installation is v{current_version}."
                    )
                if require_newer and parse_version(version) <= current:
                    raise UpgradeError("Choose a release newer than the installed version.")
            files = manifest.get("files")
            if not isinstance(files, dict) or not files:
                raise UpgradeError("Release manifest does not contain toolkit files.")
            expected_names = {
                f"payload/{safe_relative_path(str(name))}" for name in files
            }
            actual_names = {
                name for name in names
                if name != "manifest.json" and not name.endswith("/")
            }
            if expected_names != actual_names:
                raise UpgradeError("Release bundle contents do not match its manifest.")
            for relative, expected in files.items():
                if not isinstance(expected, dict):
                    raise UpgradeError("Release file metadata is invalid.")
                content = archive.read(f"payload/{relative}")
                if len(content) != int(expected.get("size", -1)):
                    raise UpgradeError(f"Release file size check failed: {relative}")
                if hashlib.sha256(content).hexdigest() != str(expected.get("sha256", "")):
                    raise UpgradeError(f"Release file integrity check failed: {relative}")
            return manifest
    except (KeyError, OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        if isinstance(exc, UpgradeError):
            raise
        raise UpgradeError(f"Release bundle could not be validated: {exc}") from exc
