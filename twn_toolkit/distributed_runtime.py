from __future__ import annotations

import argparse
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any


RUNTIME_FILES = (
    "distributed-status.json",
    "distributed-job-results.json",
    "twn-distributed.pid",
    ".twn-distributed.lock",
)
ACTIVATION_FILE = "distributed-agent-activation.json"


def agent_activation(instance_path: str | Path) -> dict[str, Any]:
    """Return the durable activation epoch used to reject pre-standalone work."""
    instance = Path(instance_path)
    path = instance / ACTIVATION_FILE
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        activation_id = str(payload.get("activation_id", ""))
        if len(activation_id) == 32:
            bytes.fromhex(activation_id)
            return {"activation_id": activation_id}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return rotate_agent_activation(instance)


def clear_inactive_distributed_runtime(instance_path: str | Path) -> dict[str, Any]:
    """Clear transient coordination state without destroying enrollment trust."""
    instance = Path(instance_path)
    removed: list[str] = []
    for name in RUNTIME_FILES:
        path = instance / name
        if path.exists():
            path.unlink(missing_ok=True)
            removed.append(name)
    for pattern in (".distributed-status.json.*.tmp", ".distributed-job-results.json.*.tmp"):
        for path in instance.glob(pattern):
            path.unlink(missing_ok=True)
            removed.append(path.name)
    activation = rotate_agent_activation(instance)
    return {"removed": sorted(set(removed)), **activation}


def rotate_agent_activation(instance_path: str | Path) -> dict[str, str]:
    instance = Path(instance_path)
    instance.mkdir(parents=True, exist_ok=True)
    path = instance / ACTIVATION_FILE
    payload = {"activation_id": secrets.token_hex(16)}
    fd, temporary_name = tempfile.mkstemp(
        dir=instance, prefix=".distributed-agent-activation-", suffix=".json"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Maintain distributed runtime state.")
    parser.add_argument("action", choices=("clear-inactive",))
    parser.add_argument("--instance", required=True)
    args = parser.parse_args()
    if args.action == "clear-inactive":
        clear_inactive_distributed_runtime(args.instance)


if __name__ == "__main__":
    main()
