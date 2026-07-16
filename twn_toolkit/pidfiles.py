from __future__ import annotations

import os
import fcntl
import signal
import subprocess
import time
from pathlib import Path
from typing import IO


def write_pid_file(path_value: str) -> None:
    if not path_value:
        return
    path = Path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{os.getpid()}\n", encoding="utf-8")
    os.chmod(path, 0o600)


def remove_own_pid_file(path_value: str) -> None:
    """Remove a PID file only when it still belongs to this process."""
    if not path_value:
        return
    path = Path(path_value)
    try:
        recorded_pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    if recorded_pid == os.getpid():
        path.unlink(missing_ok=True)


def acquire_singleton_lock(root: Path, name: str) -> IO[str] | None:
    path = root.resolve() / f".twn-{name}.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+", encoding="utf-8")
    os.chmod(path, 0o600)
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    return handle


def record_lock_owner(handle: IO[str]) -> None:
    handle.seek(0)
    handle.truncate()
    handle.write(f"{os.getpid()}\n")
    handle.flush()


def matching_daemon_pids(
    output: str,
    module: str,
    instance: Path,
    *,
    required_text: str = "",
) -> list[int]:
    marker = f"-m {module} --instance {instance.resolve()} "
    matches = []
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=1)
        if (
            len(parts) != 2
            or marker not in parts[1]
            or " --daemon" not in parts[1]
            or (required_text and required_text not in parts[1])
        ):
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid != os.getpid():
            matches.append(pid)
    return matches


def stop_matching_daemons(
    module: str,
    instance: Path,
    *,
    keep_pid: int = 0,
    required_text: str = "",
    timeout: float = 5.0,
) -> list[int]:
    try:
        processes = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    matched = [
        pid for pid in matching_daemon_pids(
            processes.stdout, module, instance, required_text=required_text,
        )
        if pid != keep_pid
    ]
    for pid in matched:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + timeout
    remaining = set(matched)
    while remaining and time.time() < deadline:
        for pid in tuple(remaining):
            try:
                os.kill(pid, 0)
            except OSError:
                remaining.discard(pid)
        if remaining:
            time.sleep(0.1)
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return matched
