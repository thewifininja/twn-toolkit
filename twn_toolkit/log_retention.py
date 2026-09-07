"""Best-effort operational log retention without replacing writers' file descriptors."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

# Only launcher-owned operational logs; never audit/evidence databases or user files.
LOG_NAMES = (
    "twn-toolkit-access.log", "twn-toolkit-error.log", "twn-automation.log",
    "twn-distributed.log", "twn-supervisor.log", "twn-tftp.log",
    "twn-ssh-transfer.log", "twn-ftp.log", "twn-iperf3.log",
    "twn-toolkit-restart.log", "twn-service.log", "twn-service-error.log",
    "twn-service-web.log", "twn-service-web-error.log",
)
MAX_BACKUPS = 10
COPY_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class LogPolicy:
    max_bytes: int = 5 * 1024 * 1024
    backups: int = 3

    @classmethod
    def from_environment(cls):
        values = {}
        for field, key, default, low, high in (
            ("max_bytes", "TWN_LOG_MAX_BYTES", cls.max_bytes, 64 * 1024, 64 * 1024 * 1024),
            ("backups", "TWN_LOG_BACKUPS", cls.backups, 1, MAX_BACKUPS),
        ):
            raw = os.environ.get(key, str(default))
            try:
                value = int(raw)
                if not low <= value <= high:
                    raise ValueError()
            except ValueError:
                print(f"Invalid {key}; using default {default} (allowed {low}–{high}).", flush=True)
                value = default
            values[field] = value
        return cls(**values)


def rotate_log(path: Path, policy: LogPolicy) -> bool:
    """Archive at most the newest max_bytes, then truncate the SAME inode.

    Copy/truncate can lose concurrent writes. Save and fsync the archive before
    truncation; copy/rename failures leave the live log intact. O_NONBLOCK avoids
    hanging on a substituted FIFO; symlinks and hard links are never truncated.
    """
    # This reserved staging name is reused after interrupted rotations, so a
    # crash cannot accumulate anonymous archive copies. The supervisor is the
    # sole rotator; unlink removes a substituted symlink without following it.
    staging = path.with_name(f".{path.name}.rotation")
    staging.unlink(missing_ok=True)
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise OSError("Operational log must be a singly linked regular file owned by this user")
        # A reduced archive count takes effect even when this log is below threshold.
        for number in range(policy.backups + 1, MAX_BACKUPS + 1):
            path.with_name(f"{path.name}.{number}").unlink(missing_ok=True)
        if info.st_size < policy.max_bytes:
            return False
        temporary = None
        try:
            archive_fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            temporary = staging
            with os.fdopen(archive_fd, "wb") as archive:
                remaining = min(info.st_size, policy.max_bytes)
                os.lseek(fd, info.st_size - remaining, os.SEEK_SET)
                while remaining:
                    chunk = os.read(fd, min(remaining, COPY_CHUNK_BYTES))
                    if not chunk:
                        raise OSError("Operational log changed during archive copy")
                    archive.write(chunk)
                    remaining -= len(chunk)
                archive.flush()
                os.fsync(archive.fileno())
            for number in range(policy.backups - 1, 0, -1):
                source = path.with_name(f"{path.name}.{number}")
                try:
                    os.replace(source, path.with_name(f"{path.name}.{number + 1}"))
                except FileNotFoundError:
                    pass
            os.replace(temporary, path.with_name(f"{path.name}.1"))
            temporary = None
            os.ftruncate(fd, 0)
            return True
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    finally:
        os.close(fd)


class LogRetention:
    """One bounded tail copy per supervisor sweep, independent of recovery state."""
    def __init__(self, instance: Path, policy: LogPolicy | None = None, *, root: Path | None = None):
        self.paths = [instance / name for name in LOG_NAMES]
        if root is not None:
            self.paths.extend(root / ".twn-upgrades" / name for name in ("upgrade.log", "service-reload.log"))
        self.policy = policy if policy is not None else LogPolicy.from_environment()
        self.cursor = 0

    def maintain_next(self):
        path = self.paths[self.cursor]
        self.cursor = (self.cursor + 1) % len(self.paths)
        try:
            return rotate_log(path, self.policy)
        except OSError as exc:
            # Failure to retain logs must not disable worker supervision.
            print(f"Could not retain {path.name}: {type(exc).__name__}: {exc}", flush=True)
            return False
