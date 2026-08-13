from __future__ import annotations

import argparse
import os
import signal
import sys
import time
import json
import secrets
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from .automation import AutomationEngine, AutomationStore
from .auth import load_or_create_secret_key
from .live_tools import LiveToolRunner, LiveToolStore
from .operational import OperationalSettingsStore
from .ping_investigation import finalize_pending_ping_sessions
from .snmp_investigation import finalize_pending_snmp_sessions
from .pidfiles import (
    acquire_singleton_lock,
    record_lock_owner,
    remove_own_pid_file,
    write_pid_file,
)
from .system_identity import collect_startup_state, collect_system_identity


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the toolkit automation scheduler.")
    parser.add_argument("--instance", required=True)
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--pid-file", default="")
    parser.add_argument("--log-file", default="")
    args = parser.parse_args()
    instance_directory = Path(args.instance).resolve()
    singleton = acquire_singleton_lock(instance_directory, "automation")
    if singleton is None:
        return
    if args.daemon:
        _daemonize(args.pid_file, args.log_file)
    else:
        write_pid_file(args.pid_file)
    record_lock_owner(singleton)
    instance_path = str(instance_directory)
    os.environ["TWN_TOOLKIT_INSTANCE_PATH"] = instance_path
    store = AutomationStore(
        instance_path,
        load_or_create_secret_key(instance_path),
    )
    engine = AutomationEngine(store)
    live_store = LiveToolStore(instance_path)
    live_store.release_stale_claims()
    live_runner = LiveToolRunner(live_store)
    operational = OperationalSettingsStore(instance_path).get()
    max_workers = int(operational["max_concurrent_automations"])
    max_pending = max_workers + int(operational["max_queued_automations"])
    executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="twn-automation")
    live_max_workers = 4
    live_executor = ThreadPoolExecutor(
        max_workers=live_max_workers, thread_name_prefix="twn-live-tool"
    )
    futures: dict[object, dict[str, str]] = {}
    live_futures: dict[object, str] = {}
    heartbeat_path = Path(instance_path) / "automation-heartbeat.json"
    running = True
    next_retention_check = 0.0
    next_lease_renewal = 0.0
    next_startup_check = 0.0
    next_live_finalization = 0.0

    def stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while running:
            now = time.time()
            if now >= next_live_finalization:
                try:
                    finalized = finalize_pending_ping_sessions(instance_path)
                    for failure in finalized["failures"]:
                        print(
                            "Ping case evidence finalization failed for "
                            f"{failure['session_id']}: {failure['error']}",
                            file=sys.stderr,
                        )
                    snmp_finalized = finalize_pending_snmp_sessions(instance_path)
                    for failure in snmp_finalized["failures"]:
                        print(
                            "SNMP monitor case evidence finalization failed for "
                            f"{failure['session_id']}: {failure['error']}",
                            file=sys.stderr,
                        )
                except Exception as exc:
                    print(
                        "Ping case evidence finalization failed: "
                        f"{type(exc).__name__}: {exc}",
                        file=sys.stderr,
                    )
                next_live_finalization = now + 1
            if now >= next_retention_check:
                try:
                    store.prune_history_if_due(now)
                except Exception as exc:
                    print(f"Automation history pruning failed: {exc}", file=sys.stderr)
                try:
                    live_store.cleanup()
                except Exception as exc:
                    print(f"Live tool cleanup failed: {exc}", file=sys.stderr)
                next_retention_check = now + 3600
            if now >= next_startup_check:
                try:
                    startup = collect_startup_state(instance_path)
                    if store.has_pending_startup_events(startup):
                        store.enqueue_startup_events(
                            collect_system_identity(instance_path),
                            now=now,
                        )
                except Exception as exc:
                    print(
                        f"Startup automation dispatch failed: {exc}",
                        file=sys.stderr,
                    )
                next_startup_check = now + 1
            for future in list(futures):
                if future.done():
                    work = futures.pop(future)
                    try:
                        future.result()
                    except Exception as exc:
                        if work["kind"] == "check":
                            store.record_error(
                                work["automation_id"],
                                f"{type(exc).__name__}: {exc}",
                            )
            if now >= next_lease_renewal:
                for work in futures.values():
                    if work["kind"] == "job":
                        store.renew_job_lease(work["id"])
                next_lease_renewal = now + 30
            available = max(0, max_pending - len(futures))
            active_ids = {work["automation_id"] for work in futures.values()}
            checking_ids = {
                work["automation_id"]
                for work in futures.values()
                if work["kind"] == "check"
            }
            while available:
                jobs = store.claim_jobs(
                    limit=1,
                    exclude_automation_ids=active_ids,
                )
                if not jobs:
                    break
                job = jobs[0]
                future = executor.submit(engine.process_job, job)
                futures[future] = {
                    "kind": "job",
                    "id": job["id"],
                    "automation_id": job["automation_id"],
                }
                active_ids.add(job["automation_id"])
                available -= 1
            due_automations = (
                store.claim_due(
                    limit=max(1, available),
                    exclude_automation_ids=checking_ids,
                )
                if available
                else []
            )
            for automation in due_automations:
                if operational["skip_overlapping_automations"] and automation["id"] in active_ids:
                    store.record_observation(automation["id"], "skipped", "Skipped because the previous run is still active.")
                    continue
                future = executor.submit(engine.process_automation, automation)
                futures[future] = {
                    "kind": "check",
                    "id": automation["id"],
                    "automation_id": automation["id"],
                }
                active_ids.add(automation["id"])
            for future in list(live_futures):
                if future.done():
                    session_id = live_futures.pop(future)
                    try:
                        future.result()
                    except Exception as exc:
                        print(
                            f"Live tool session {session_id} failed: "
                            f"{type(exc).__name__}: {exc}",
                            file=sys.stderr,
                        )
            live_available = max(0, live_max_workers - len(live_futures))
            for live_session in (
                live_store.claim_due(limit=live_available) if live_available else []
            ):
                future = live_executor.submit(live_runner.process, live_session)
                live_futures[future] = live_session["id"]
            _write_heartbeat(
                heartbeat_path, max_workers, futures, live_futures=live_futures
            )
            wait_seconds = live_store.seconds_until_next_due(
                maximum=max(0.2, args.poll_seconds)
            )
            pending_futures = [*futures, *live_futures]
            if pending_futures:
                wait(
                    pending_futures,
                    timeout=wait_seconds,
                    return_when=FIRST_COMPLETED,
                )
            else:
                time.sleep(wait_seconds)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        live_executor.shutdown(wait=False, cancel_futures=True)
        heartbeat_path.unlink(missing_ok=True)
        remove_own_pid_file(args.pid_file)


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
    write_pid_file(pid_file)


def _write_heartbeat(
    path: Path,
    max_workers: int,
    futures: dict[object, dict[str, str]],
    *,
    live_futures: dict[object, str] | None = None,
) -> None:
    live_futures = live_futures or {}
    payload = {
        "updated_at": time.time(), "pid": os.getpid(), "max_workers": max_workers,
        "active": sum(1 for future in futures if future.running()),
        "queued": sum(1 for future in futures if not future.running() and not future.done()),
        "tracked": len(futures),
        "active_checks": sum(
            1
            for future, work in futures.items()
            if work["kind"] == "check" and future.running()
        ),
        "active_jobs": sum(
            1
            for future, work in futures.items()
            if work["kind"] == "job" and future.running()
        ),
        "live_tools_active": sum(
            1 for future in live_futures if future.running()
        ),
        "live_tools_tracked": len(live_futures),
    }
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8"); os.chmod(temporary, 0o600); os.replace(temporary, path)


if __name__ == "__main__":
    main()
