from __future__ import annotations

import argparse
import os
import signal
import sys
import time
import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .automation import AutomationEngine, AutomationStore
from .auth import load_or_create_secret_key
from .operational import OperationalSettingsStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the toolkit automation scheduler.")
    parser.add_argument("--instance", required=True)
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--pid-file", default="")
    parser.add_argument("--log-file", default="")
    args = parser.parse_args()
    if args.daemon:
        _daemonize(args.pid_file, args.log_file)
    instance_path = str(Path(args.instance).resolve())
    os.environ["TWN_TOOLKIT_INSTANCE_PATH"] = instance_path
    store = AutomationStore(
        instance_path,
        load_or_create_secret_key(instance_path),
    )
    engine = AutomationEngine(store)
    operational = OperationalSettingsStore(instance_path).get()
    max_workers = int(operational["max_concurrent_automations"])
    max_pending = max_workers + int(operational["max_queued_automations"])
    executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="twn-automation")
    futures: dict[object, str] = {}
    heartbeat_path = Path(instance_path) / "automation-heartbeat.json"
    running = True
    next_retention_check = 0.0

    def stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while running:
            now = time.time()
            if now >= next_retention_check:
                try:
                    store.prune_history_if_due(now)
                except Exception as exc:
                    print(f"Automation history pruning failed: {exc}", file=sys.stderr)
                next_retention_check = now + 3600
            for future in list(futures):
                if future.done():
                    automation_id = futures.pop(future)
                    try: future.result()
                    except Exception as exc: store.record_error(automation_id, f"{type(exc).__name__}: {exc}")
            available = max(0, max_pending - len(futures))
            active_ids = set(futures.values())
            for automation in store.claim_due(limit=max(1, available)) if available else []:
                if operational["skip_overlapping_automations"] and automation["id"] in active_ids:
                    store.record_observation(automation["id"], "skipped", "Skipped because the previous run is still active.")
                    continue
                future = executor.submit(engine.process_automation, automation)
                futures[future] = automation["id"]; active_ids.add(automation["id"])
            _write_heartbeat(heartbeat_path, max_workers, futures)
            time.sleep(max(0.2, args.poll_seconds))
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        heartbeat_path.unlink(missing_ok=True)
        if args.pid_file:
            try:
                Path(args.pid_file).unlink()
            except FileNotFoundError:
                pass


def _daemonize(pid_file: str, log_file: str) -> None:
    """Detach once for the POSIX platforms supported by the toolkit."""
    first_child = os.fork()
    if first_child > 0:
        os._exit(0)
    os.setsid()
    second_child = os.fork()
    if second_child > 0:
        os._exit(0)
    os.chdir("/")
    os.umask(0o077)
    stdin_fd = os.open(os.devnull, os.O_RDONLY)
    log_path = Path(log_file) if log_file else Path(os.devnull)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(stdin_fd, sys.stdin.fileno())
    os.dup2(log_fd, sys.stdout.fileno())
    os.dup2(log_fd, sys.stderr.fileno())
    os.close(stdin_fd)
    os.close(log_fd)
    if pid_file:
        path = Path(pid_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{os.getpid()}\n", encoding="utf-8")
        os.chmod(path, 0o600)


def _write_heartbeat(path: Path, max_workers: int, futures: dict[object, str]) -> None:
    payload = {
        "updated_at": time.time(), "pid": os.getpid(), "max_workers": max_workers,
        "active": sum(1 for future in futures if future.running()),
        "queued": sum(1 for future in futures if not future.running() and not future.done()),
        "tracked": len(futures),
    }
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8"); os.chmod(temporary, 0o600); os.replace(temporary, path)


if __name__ == "__main__":
    main()
