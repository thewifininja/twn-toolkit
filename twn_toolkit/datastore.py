from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import BinaryIO


MAX_UPLOAD_BYTES = 1024 * 1024 * 1024


class DatastoreError(ValueError):
    pass


class LocalDatastore:
    """Owner-only file storage strictly contained beneath the toolkit instance."""

    def __init__(self, instance_path: str, root_name: str = "datastore") -> None:
        if root_name not in {"datastore", "tftp_runtime", "ssh_transfer_runtime", "ftp_runtime"}:
            raise ValueError("Unsupported local datastore root.")
        root = Path(instance_path) / root_name
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = root.resolve()
        os.chmod(self.root, 0o700)

    def list(self, relative_path: str = "") -> dict[str, object]:
        folder = self._resolve(relative_path, must_exist=True)
        if not folder.is_dir():
            raise DatastoreError("The requested datastore path is not a folder.")
        entries = []
        visible_entries = [entry for entry in folder.iterdir() if not entry.is_symlink()]
        for entry in sorted(visible_entries, key=lambda item: (not item.is_dir(), item.name.casefold())):
            stat = entry.stat()
            entries.append(
                {
                    "name": entry.name,
                    "path": self.relative(entry),
                    "is_dir": entry.is_dir(),
                    "size": 0 if entry.is_dir() else stat.st_size,
                    "modified_at": stat.st_mtime,
                }
            )
        return {
            "path": self.relative(folder),
            "entries": entries,
            "breadcrumbs": self.breadcrumbs(folder),
        }

    def folder(self, relative_path: str = "") -> Path:
        """Return a contained, existing directory through the public datastore API."""
        folder = self._resolve(relative_path, must_exist=True)
        if not folder.is_dir() or folder.is_symlink():
            raise DatastoreError("The requested datastore path is not a folder.")
        return folder

    def describe(self, relative_path: str) -> dict[str, object]:
        """Return bounded metadata for one contained file or folder."""
        path = self._resolve(relative_path, must_exist=True, allow_root=False)
        if path.is_symlink():
            raise DatastoreError("Symbolic links are not supported in the datastore.")
        is_dir = path.is_dir()
        return {
            "name": path.name,
            "path": self.relative(path),
            "kind": "folder" if is_dir else "file",
            "bytes": 0 if is_dir else path.stat().st_size,
        }

    def create_folder(self, relative_path: str, name: str) -> Path:
        parent = self._resolve(relative_path, must_exist=True)
        if not parent.is_dir():
            raise DatastoreError("The destination is not a folder.")
        destination = parent / self._validate_name(name)
        self._ensure_available(destination)
        destination.mkdir(mode=0o700)
        return destination

    def save_upload(
        self,
        relative_path: str,
        filename: str,
        stream: BinaryIO,
        *,
        max_bytes: int = MAX_UPLOAD_BYTES,
        overwrite: bool = False,
    ) -> tuple[Path, int]:
        parent = self._resolve(relative_path, must_exist=True)
        if not parent.is_dir():
            raise DatastoreError("The upload destination is not a folder.")
        destination = parent / self._validate_name(filename)
        if destination.exists() and destination.is_dir():
            raise DatastoreError(f"{destination.name} is an existing folder.")
        if not overwrite:
            self._ensure_available(destination)
        temporary_name = ""
        total = 0
        existing_bytes = destination.stat().st_size if overwrite and destination.is_file() else 0
        baseline_bytes = None
        if self.root.name == "datastore":
            from .operational import directory_bytes
            baseline_bytes = directory_bytes(self.root) - existing_bytes
        try:
            with tempfile.NamedTemporaryFile(dir=parent, prefix=".upload-", delete=False) as target:
                temporary_name = target.name
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise DatastoreError(
                            f"Uploads may not exceed {max_bytes // (1024 * 1024)} MiB per file."
                        )
                    if baseline_bytes is not None:
                        from .operational import OperationalSettingsStore
                        settings = OperationalSettingsStore(str(self.root.parent)).get()
                        if baseline_bytes + total > int(settings["datastore_quota_gib"]) * 1024**3:
                            raise DatastoreError("The configured datastore quota would be exceeded.")
                        if shutil.disk_usage(self.root).free - total < int(settings["minimum_free_gib"]) * 1024**3:
                            raise DatastoreError("The upload would cross the configured minimum free-disk reserve.")
                    target.write(chunk)
            os.chmod(temporary_name, 0o600)
            if not overwrite:
                self._ensure_available(destination)
            os.replace(temporary_name, destination)
            return destination, total
        finally:
            if temporary_name and os.path.exists(temporary_name):
                os.unlink(temporary_name)

    def file(self, relative_path: str) -> Path:
        path = self._resolve(relative_path, must_exist=True)
        if not path.is_file() or path.is_symlink():
            raise DatastoreError("The requested datastore file was not found.")
        return path

    def rename(self, relative_path: str, new_name: str) -> Path:
        source = self._resolve(relative_path, must_exist=True, allow_root=False)
        destination = source.parent / self._validate_name(new_name)
        if destination == source:
            return source
        self._ensure_available(destination)
        source.rename(destination)
        return destination

    def delete(self, relative_path: str) -> None:
        target = self._resolve(relative_path, must_exist=True, allow_root=False)
        if target.is_symlink():
            raise DatastoreError("Symbolic links are not supported in the datastore.")
        if target.is_dir():
            try:
                target.rmdir()
            except OSError as exc:
                raise DatastoreError("Folders must be empty before they can be deleted.") from exc
        else:
            target.unlink()

    def delete_files(self, relative_paths: list[str]) -> int:
        paths = self._unique_entries(relative_paths)
        for path in paths:
            if path.is_dir():
                try:
                    next(path.iterdir())
                except StopIteration:
                    continue
                raise DatastoreError(
                    f"{path.name} is not empty. Empty folders before bulk deletion."
                )
        for path in paths:
            path.rmdir() if path.is_dir() else path.unlink()
        return len(paths)

    def move_files(self, relative_paths: list[str], destination_path: str) -> int:
        sources = self._unique_entries(relative_paths)
        destination = self._resolve(destination_path, must_exist=True)
        if not destination.is_dir():
            raise DatastoreError("Choose an existing destination folder.")
        moves: list[tuple[Path, Path]] = []
        destinations: set[Path] = set()
        for source in sources:
            if source.is_dir():
                try:
                    destination.relative_to(source)
                except ValueError:
                    pass
                else:
                    raise DatastoreError(
                        f"{source.name} cannot be moved into itself or one of its subfolders."
                    )
            target = destination / source.name
            if target == source:
                raise DatastoreError(f"{source.name} is already in that folder.")
            if target in destinations or target.exists() or target.is_symlink():
                raise DatastoreError(f"{source.name} already exists in the destination folder.")
            destinations.add(target)
            moves.append((source, target))
        completed: list[tuple[Path, Path]] = []
        try:
            for source, target in moves:
                source.rename(target)
                completed.append((source, target))
        except OSError as exc:
            for source, target in reversed(completed):
                try:
                    target.rename(source)
                except OSError:
                    pass
            raise DatastoreError(f"The selected items could not be moved: {exc}") from exc
        return len(moves)

    def archive_members(
        self, relative_paths: list[str], base_path: str = ""
    ) -> list[tuple[Path, str, bool]]:
        """Return contained files/directories and their ZIP-relative names."""
        base = self._resolve(base_path, must_exist=True)
        if not base.is_dir():
            raise DatastoreError("The current datastore path is not a folder.")
        sources = sorted(self._unique_entries(relative_paths), key=lambda item: len(item.parts))
        roots: list[Path] = []
        for source in sources:
            try:
                source.relative_to(base)
            except ValueError as exc:
                raise DatastoreError("Selected items must be inside the current folder.") from exc
            if any(parent.is_dir() and source.is_relative_to(parent) for parent in roots):
                continue
            roots.append(source)

        members: list[tuple[Path, str, bool]] = []
        for source in roots:
            relative = source.relative_to(base).as_posix()
            if source.is_file():
                members.append((source, relative, False))
                continue
            members.append((source, relative, True))
            for folder, directory_names, file_names in os.walk(source, followlinks=False):
                folder_path = Path(folder)
                directory_names[:] = sorted(
                    name for name in directory_names
                    if not (folder_path / name).is_symlink()
                )
                if folder_path != source:
                    members.append((folder_path, folder_path.relative_to(base).as_posix(), True))
                for name in sorted(file_names, key=str.casefold):
                    file_path = folder_path / name
                    if file_path.is_file() and not file_path.is_symlink():
                        members.append((file_path, file_path.relative_to(base).as_posix(), False))
        return members

    def usage(self) -> dict[str, int]:
        files = 0
        folders = 0
        total = 0
        for folder, directory_names, file_names in os.walk(self.root, followlinks=False):
            directory_names[:] = [
                name for name in directory_names if not (Path(folder) / name).is_symlink()
            ]
            folders += len(directory_names)
            for name in file_names:
                path = Path(folder) / name
                if not path.is_symlink():
                    files += 1
                    total += path.stat().st_size
        return {"files": files, "folders": folders, "bytes": total}

    def folders(self) -> list[dict[str, str]]:
        folders = [{"name": "Datastore root", "path": ""}]
        for folder, directory_names, _file_names in os.walk(self.root, followlinks=False):
            directory_names[:] = sorted(
                [name for name in directory_names if not (Path(folder) / name).is_symlink()],
                key=str.casefold,
            )
            for name in directory_names:
                path = Path(folder) / name
                relative = self.relative(path)
                folders.append({"name": relative, "path": relative})
        return folders

    def clear(self) -> None:
        for entry in self.root.iterdir():
            if entry.is_symlink() or entry.is_file():
                entry.unlink()
            elif entry.is_dir():
                shutil.rmtree(entry)

    def relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def breadcrumbs(self, folder: Path) -> list[dict[str, str]]:
        crumbs = [{"name": "Datastore", "path": ""}]
        current = self.root
        for part in folder.relative_to(self.root).parts:
            current /= part
            crumbs.append({"name": part, "path": self.relative(current)})
        return crumbs

    def _resolve(
        self,
        relative_path: str,
        *,
        must_exist: bool,
        allow_root: bool = True,
    ) -> Path:
        raw = str(relative_path or "").replace("\\", "/").strip("/")
        if "\x00" in raw:
            raise DatastoreError("The datastore path is invalid.")
        candidate = self.root.joinpath(*Path(raw).parts)
        try:
            resolved = candidate.resolve(strict=must_exist)
            resolved.relative_to(self.root.resolve())
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            raise DatastoreError("The datastore path is invalid or unavailable.") from exc
        if not allow_root and resolved == self.root.resolve():
            raise DatastoreError("The datastore root cannot be changed or deleted.")
        current = self.root
        for part in candidate.relative_to(self.root).parts:
            current /= part
            if current.exists() and current.is_symlink():
                raise DatastoreError("Symbolic links are not supported in the datastore.")
        return resolved

    def _unique_entries(self, relative_paths: list[str]) -> list[Path]:
        if not relative_paths:
            raise DatastoreError("Select at least one file or folder.")
        if len(relative_paths) > 500:
            raise DatastoreError("Select no more than 500 items at once.")
        paths: list[Path] = []
        seen: set[Path] = set()
        for value in relative_paths:
            path = self._resolve(value, must_exist=True, allow_root=False)
            if path in seen:
                continue
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise DatastoreError("Bulk operations support regular files and folders only.")
            seen.add(path)
            paths.append(path)
        return paths

    @staticmethod
    def _validate_name(name: str) -> str:
        value = str(name or "").strip()
        if not value or value in {".", ".."}:
            raise DatastoreError("Enter a file or folder name.")
        if len(value) > 255 or "/" in value or "\\" in value or "\x00" in value:
            raise DatastoreError("Names must be 255 characters or fewer and cannot contain slashes.")
        return value

    @staticmethod
    def _ensure_available(path: Path) -> None:
        if path.exists() or path.is_symlink():
            raise DatastoreError(f"{path.name} already exists. Rename or remove it first.")


def format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("bytes", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{int(amount)} bytes" if unit == "bytes" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"
