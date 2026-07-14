from __future__ import annotations

import os
from pathlib import Path


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
