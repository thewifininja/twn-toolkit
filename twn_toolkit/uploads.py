"""Explicit, cross-process upload reservations and atomic publication.

Staging lives outside served roots. A live owner holds a flock for its entire
upload; the registry lock covers only local accounting and filesystem work,
never network reads. Closing a stream aborts it. Only commit publishes it.
"""
from __future__ import annotations

import fcntl
import json
import logging
import os
import secrets
import shutil
from pathlib import Path

from .datastore import DatastoreError
from .file_transactions import file_transaction
from .operational import OperationalSettingsStore, directory_bytes

BUFFER_BYTES = 256 * 1024
RESERVATION_BYTES = 1024 * 1024
MAX_RESERVATION_STEP = 64 * 1024 * 1024
logger = logging.getLogger(__name__)


def _identity(path):
    try:
        stat = path.lstat()
    except FileNotFoundError:
        return None
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_mode]


def _credit(record):
    original = record["original"]
    return original[2] if original and _identity(Path(record["destination"])) == original else 0


class Upload:
    def __init__(self, store, destination, *, max_bytes, overwrite, expected_bytes=None):
        self.store, self.destination = store, destination
        self.max_bytes, self.overwrite = max_bytes, overwrite
        self.expected_bytes = expected_bytes
        self.total = 0
        self.closed = False
        self.committed = False
        self._buffer = bytearray()
        self._file = self._owner = self._parent = None
        self.registry = store.instance / ".upload-reservations"
        self.registry.mkdir(mode=0o700, exist_ok=True)
        self.token = secrets.token_hex(16)
        self.directory = self.registry / self.token
        self.temporary = self.directory / "data"
        self.name = str(self.temporary)
        self._lock = self.registry / "registry"
        try:
            with file_transaction(self._lock):
                records = self._records()
                if any(r["destination"] == str(destination) for r in records.values()):
                    raise DatastoreError("Another upload is already writing this destination.")
                if destination.is_symlink() or (destination.exists() and not destination.is_file()):
                    raise DatastoreError("The upload destination must be a regular file.")
                if not overwrite:
                    store._ensure_available(destination)
                if expected_bytes is not None and not 0 <= expected_bytes <= max_bytes:
                    raise DatastoreError("Declared upload size exceeds the file limit.")
                self._parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                if os.fstat(self._parent).st_dev != self.registry.stat().st_dev:
                    raise DatastoreError("Upload staging and destination must be on the same filesystem.")
                self.directory.mkdir(mode=0o700)
                self._owner = os.open(self.directory / "owner", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600)
                fcntl.flock(self._owner, fcntl.LOCK_EX)
                self._record = {"destination": str(destination), "root": str(store.root),
                                "original": _identity(destination), "capacity": 0}
                self._save_record()
                self._file = self.temporary.open("xb", buffering=0)
                os.chmod(self.temporary, 0o600)
                self._reserve(expected_bytes or 0, records, exact=True)
        except BaseException:
            self.abort()
            raise

    def _save_record(self):
        temporary = self.directory / "record.tmp"
        descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(self._record, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.directory / "record.json")

    def _records(self):
        records = {}
        for directory in self.registry.iterdir():
            if directory.name.startswith("."):
                continue
            if len(directory.name) != 32 or any(c not in "0123456789abcdef" for c in directory.name) or not directory.is_dir() or directory.is_symlink():
                raise DatastoreError("The upload reservation registry is invalid.")
            descriptor = os.open(directory / "owner", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    try:
                        record = json.loads((directory / "record.json").read_text())
                        if not isinstance(record["capacity"], int) or record["capacity"] < 0:
                            raise ValueError("Invalid capacity")
                        destination, root = Path(record["destination"]), Path(record["root"])
                        roots = {(self.store.instance / name).resolve() for name in
                                 ("datastore", "tftp_runtime", "ssh_transfer_runtime", "ftp_runtime")}
                        if root not in roots or destination == root or not destination.is_relative_to(root):
                            raise ValueError("Invalid destination")
                        original = record["original"]
                        if original is not None and (not isinstance(original, list) or len(original) != 5 or
                                                     any(type(value) is not int for value in original)):
                            raise ValueError("Invalid destination identity")
                    except (OSError, ValueError, KeyError, TypeError) as exc:
                        raise DatastoreError("The upload reservation registry is unreadable.") from exc
                    records[directory.name] = record
                else:
                    # An exited process cannot publish. Its private files and its
                    # reservation can be reclaimed together while holding the registry.
                    self._remove_directory(directory)
            finally:
                os.close(descriptor)
        return records

    @staticmethod
    def _remove_directory(directory):
        for name in ("data", "record.tmp", "record.json", "owner"):
            (directory / name).unlink(missing_ok=True)
        directory.rmdir()

    def _settings(self):
        return OperationalSettingsStore(str(self.store.instance)).get()

    def _capacity(self, records):
        settings = self._settings()
        disk = os.fstat(self._file.fileno())
        pending = 0
        growth = 0
        for token, record in records.items():
            if token == self.token:
                continue
            stage = self.registry / token / "data"
            try:
                stat = stage.stat()
            except FileNotFoundError:
                written = 0
                device = self.registry.stat().st_dev
            else:
                written, device = stat.st_size, stat.st_dev
            if device == disk.st_dev:
                pending += max(0, record["capacity"] - written)
            if record["root"] == str(self.store.root):
                growth += max(0, record["capacity"] - _credit(record))
        physical = disk.st_size + shutil.disk_usage(self.registry).free - int(settings["minimum_free_gib"]) * 1024**3 - pending
        logical = self.max_bytes
        if self.store.root_name == "datastore":
            logical = int(settings["datastore_quota_gib"]) * 1024**3 - directory_bytes(self.store.root) + _credit(self._record) - growth
        return logical, physical

    def _reserve(self, needed, records, *, exact=False):
        logical, physical = self._capacity(records)
        if needed > logical:
            raise DatastoreError("The configured datastore quota would be exceeded.")
        if needed > physical:
            raise DatastoreError("The upload would cross the configured minimum free-disk reserve.")
        step = min(MAX_RESERVATION_STEP, max(RESERVATION_BYTES, self._record["capacity"]))
        desired = needed if exact else max(needed, self._record["capacity"] + step)
        # Do not reserve all remaining space merely because a growth window will
        # not fit. The caller may still have room for a small upload.
        capacity = desired if desired <= min(logical, physical, self.max_bytes) else needed
        self._record["capacity"] = capacity
        self._save_record()

    def _check_parent(self):
        current = self.store.folder(self.store.relative(self.destination.parent)).stat()
        original = os.fstat(self._parent)
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
            raise DatastoreError("The upload destination folder changed during the transfer.")

    def write(self, data):
        if self.closed:
            raise DatastoreError("The upload is closed.")
        try:
            needed = self.total + len(data)
            if needed > self.max_bytes:
                raise DatastoreError(f"Uploads may not exceed {self.max_bytes // (1024 * 1024)} MiB per file.")
            if self.expected_bytes is not None and needed > self.expected_bytes:
                raise DatastoreError("Upload exceeds its declared size.")
            if needed > self._record["capacity"]:
                with file_transaction(self._lock):
                    records = self._records()
                    self._reserve(needed, records)
            # Keep buffering bounded even if a caller supplies a large chunk.
            view = memoryview(data)
            while view:
                count = min(len(view), BUFFER_BYTES - len(self._buffer))
                self._buffer.extend(view[:count])
                self.total += count
                view = view[count:]
                if len(self._buffer) == BUFFER_BYTES:
                    self.flush()
            return len(data)
        except BaseException:
            self.abort()
            raise

    def flush(self):
        if self.closed:
            raise DatastoreError("The upload is closed.")
        if not self._buffer:
            return
        try:
            with file_transaction(self._lock):
                self._check_parent()
                reserve = int(self._settings()["minimum_free_gib"]) * 1024**3
                if shutil.disk_usage(self.registry).free - len(self._buffer) < reserve:
                    raise DatastoreError("The upload would cross the configured minimum free-disk reserve.")
                view = memoryview(self._buffer)
                while view:
                    count = self._file.write(view)
                    if not count:
                        raise OSError("Upload write made no progress.")
                    view = view[count:]
                del view
                self._buffer.clear()
        except BaseException:
            self.abort()
            raise

    def tell(self):
        return self.total

    def fileno(self):
        if self.closed:
            raise ValueError("I/O operation on closed upload.")
        return self._file.fileno()

    def commit(self):
        if self.committed:
            return self.destination, self.total
        if self.closed:
            raise DatastoreError("The upload is closed; it cannot be published.")
        try:
            if self.expected_bytes is not None and self.total != self.expected_bytes:
                raise DatastoreError("Upload ended before its declared size was received.")
            self.flush()
            with file_transaction(self._lock):
                self._check_parent()
                records = self._records()
                self._reserve(self.total, records, exact=True)
                if self.overwrite and _identity(self.destination) != self._record["original"]:
                    raise DatastoreError("The destination changed during the upload.")
                os.fsync(self._file.fileno())
                try:
                    if self.overwrite:
                        os.replace(self.temporary, self.destination.name, dst_dir_fd=self._parent)
                    else:
                        os.link(self.temporary, self.destination.name, dst_dir_fd=self._parent, follow_symlinks=False)
                except FileExistsError as exc:
                    raise DatastoreError("The upload destination already exists.") from exc
                self.committed = True
                self._finish()
            return self.destination, self.total
        except BaseException:
            self.abort()
            raise

    def _finish(self):
        self.closed = True
        self._buffer = bytearray()
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                logger.exception("Could not close upload staging %s", self.directory)
            finally:
                self._file = None
        try:
            if self.directory.exists():
                self._remove_directory(self.directory)
        except OSError:
            # Publication is irreversible. Leave a recoverable, unlocked record
            # rather than report a failed transfer after publishing successfully.
            logger.exception("Could not clean upload staging %s", self.directory)
        finally:
            for name in ("_owner", "_parent"):
                descriptor = getattr(self, name)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        logger.exception("Could not close upload descriptor for %s", self.directory)
                    finally:
                        setattr(self, name, None)

    def abort(self):
        if not self.closed:
            with file_transaction(self._lock):
                self._finish()

    close = abort

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.abort()
