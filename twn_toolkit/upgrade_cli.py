from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .upgrade_manager import (
    ACTIVE_STATES,
    ReleaseClient,
    TERMINAL_STATES,
    UpgradeError,
    UpgradeManager,
    validate_release_bundle,
)
from .version import APP_VERSION


def _confirm(prompt: str, assume_yes: bool) -> None:
    if assume_yes:
        return
    if not sys.stdin.isatty():
        raise UpgradeError("Confirmation is required; rerun with --yes after reviewing the operation.")
    if input(f"{prompt} [y/N] ").strip().lower() not in {"y", "yes"}:
        raise UpgradeError("Operation cancelled.")


def _wait(manager: UpgradeManager, request_id: str) -> int:
    previous = ""
    while True:
        status = manager.status()
        if status.get("id") != request_id:
            time.sleep(0.5)
            continue
        message = str(status.get("message", ""))
        if message and message != previous:
            print(message, flush=True)
            previous = message
        state = str(status.get("state", ""))
        if state in TERMINAL_STATES:
            if status.get("error"):
                print(f"Reason: {status['error']}", file=sys.stderr)
            return 0 if state in {"succeeded", "backup_created", "rolled_back"} and not status.get("error") else 1
        if state not in ACTIVE_STATES and state != "starting":
            return 1
        time.sleep(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Upgrade and recover The WiFi Ninja's Toolkit.")
    parser.add_argument("--root", required=True)
    parser.add_argument("--instance", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    upgrade = subparsers.add_parser("upgrade")
    upgrade.add_argument("--bundle")
    upgrade.add_argument("--version")
    upgrade.add_argument("--yes", action="store_true")
    backup = subparsers.add_parser("backup")
    backup.add_argument("--yes", action="store_true")
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("backup_id", nargs="?")
    rollback.add_argument("--yes", action="store_true")
    subparsers.add_parser("status")
    args = parser.parse_args()
    manager = UpgradeManager(Path(args.root), Path(args.instance), APP_VERSION)
    actor = {"id": "", "username": "local-updater", "remote_ip": "local"}
    try:
        if args.command == "status":
            status = manager.status()
            if not status:
                print("No upgrade or recovery operation has run yet.")
            else:
                print(f"{status.get('state', 'unknown')}: {status.get('message', '')}")
                if status.get("error"):
                    print(f"Reason: {status['error']}")
            return 0
        if args.command == "backup":
            _confirm("Stop the toolkit briefly and create a complete recovery point?", args.yes)
            request = manager.launch_backup(actor)
            return _wait(manager, request["id"])
        if args.command == "rollback":
            backups = manager.backups()
            backup_id = args.backup_id or (backups[0]["id"] if backups else "")
            if not backup_id:
                raise UpgradeError("No recovery points are available.")
            selected = next((item for item in backups if item["id"] == backup_id), None)
            if not selected:
                raise UpgradeError("The selected recovery point does not exist.")
            _confirm(
                f"Replace current code and instance data with recovery point {backup_id} (v{selected.get('from_version', '?')})?",
                args.yes,
            )
            request = manager.launch_rollback(backup_id, actor)
            return _wait(manager, request["id"])
        if args.bundle:
            bundle = Path(args.bundle).expanduser().resolve()
            manifest = validate_release_bundle(bundle, current_version=APP_VERSION)
            target = manifest["version"]
        else:
            client = ReleaseClient()
            release = client.release(APP_VERSION, args.version)
            target = release["version"]
            print(f"Downloading verified toolkit v{target} bundle…", flush=True)
            bundle = manager.download_release(release, client)
            validate_release_bundle(bundle, current_version=APP_VERSION)
        _confirm(
            f"Upgrade v{APP_VERSION} to v{target}? A complete recovery point will be created automatically.",
            args.yes,
        )
        request = manager.launch_upgrade(bundle, actor)
        return _wait(manager, request["id"])
    except UpgradeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
