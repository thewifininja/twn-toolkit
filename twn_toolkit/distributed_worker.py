from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import sqlite3
import socket
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

from .distributed_agents import DistributedSettingsStore
from .distributed_runtime import agent_activation, clear_inactive_distributed_runtime
from .distributed_transport import EnrollmentServer
from .distributed_transport import EnrollmentClient, EnrollmentTransportError
from .pidfiles import (
    acquire_singleton_lock,
    record_lock_owner,
    remove_own_pid_file,
    write_pid_file,
)
from .version import APP_VERSION
from .distributed_capabilities import advertised_capabilities, execute_capability
from .distributed_operations import OperationReceipts, execute_owned
from .distributed_jobs import JOB_PROTOCOL_VERSION, DistributedJobStore
from .distributed_http import prune_dispatch_cache
from .distributed_dispatch_cache import DISPATCH_CACHE_SWEEP_SECONDS
from .distributed_payloads import PAYLOAD_CLEANUP_INTERVAL_SECONDS
from .distributed_polling import InteractivePollGate, RetryBackoff, pause, poll_retry_delay, regular_poll_delay, RETRY_INITIAL_SECONDS


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the TWN Toolkit Mainframe enrollment listener."
    )
    parser.add_argument("--instance", required=True)
    parser.add_argument("--pid-file", default="")
    parser.add_argument("--log-file", default="")
    parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    instance = Path(args.instance).resolve()
    singleton = acquire_singleton_lock(instance, "distributed")
    if singleton is None:
        raise SystemExit("The distributed toolkit worker is already running.")
    if args.daemon:
        _daemonize(args.pid_file, args.log_file)
    else:
        write_pid_file(args.pid_file)
    record_lock_owner(singleton)
    settings = DistributedSettingsStore(instance).get()
    if settings["role"] == "standalone":
        clear_inactive_distributed_runtime(instance)
        remove_own_pid_file(args.pid_file)
        return

    servers: list[EnrollmentServer] = []
    running = True

    def stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        if settings["role"] == "mainframe":
            for interface in settings["mainframe_listen_interfaces"]:
                server = EnrollmentServer(
                    instance,
                    interface,
                    int(settings["mainframe_port"]),
                    advertised_hosts=list(settings["mainframe_advertised_hosts"]),
                )
                server.start()
                servers.append(server)
                print(
                    f"Mainframe enrollment listener ready on {interface}:{server.port}",
                    flush=True,
                )
        execution_threads: list[threading.Thread] = []
        poll_gate = InteractivePollGate()
        control_backoff = RetryBackoff()
        if settings["role"] == "agent":
            agent_activation(instance)  # Establish one epoch before starting concurrent lanes.
            for lane in range(3):
                thread = threading.Thread(
                    target=_interactive_lane,
                    args=(instance, settings, lambda: running, poll_gate),
                    name=f"twn-interactive-{lane + 1}",
                    daemon=True,
                )
                thread.start()
                execution_threads.append(thread)
            thread = threading.Thread(
                target=_regular_lane, args=(instance, settings, lambda: running),
                name="twn-regular", daemon=True,
            )
            thread.start()
            execution_threads.append(thread)
        job_store = DistributedJobStore(instance) if settings["role"] == "mainframe" else None
        next_payload_cleanup = 0.0
        next_cache_cleanup = 0.0
        while running:
            if job_store is not None and time.monotonic() >= next_payload_cleanup:
                next_payload_cleanup = time.monotonic() + PAYLOAD_CLEANUP_INTERVAL_SECONDS
                try:
                    job_store.prune_payloads()
                except (OSError, sqlite3.Error, ValueError) as exc:
                    print(f"Distributed payload cleanup failed: {type(exc).__name__}", file=sys.stderr, flush=True)
            if settings["role"] == "agent" and time.monotonic() >= next_cache_cleanup:
                next_cache_cleanup = time.monotonic() + DISPATCH_CACHE_SWEEP_SECONDS
                try:
                    prune_dispatch_cache(instance)
                except (OSError, ValueError) as exc:
                    print(f"Agent dispatch cache cleanup failed: {type(exc).__name__}", file=sys.stderr, flush=True)
            if settings["role"] == "agent":
                if any(not thread.is_alive() for thread in execution_threads):
                    raise RuntimeError("An Agent execution thread stopped unexpectedly.")
                sync_requested = instance / "mso-sync-requested"
                sync_requested.unlink(missing_ok=True)
                status = _agent_tick(instance, settings, control_only=True)
                pause(regular_poll_delay(status, control_backoff), lambda: running and not sync_requested.exists())
            else:
                time.sleep(0.25)
    except Exception as exc:
        print(f"Mainframe enrollment listener failed: {exc}", file=sys.stderr)
        raise
    finally:
        running = False
        deadline = time.monotonic() + 30
        for thread in locals().get("execution_threads", []):
            thread.join(timeout=max(0, deadline - time.monotonic()))
        for server in reversed(servers):
            server.stop()
        remove_own_pid_file(args.pid_file)


def _regular_lane(instance: Path, settings: dict[str, object], running: Callable[[], bool]) -> None:
    """One executor, no local work queue; status reporting runs independently."""
    backoff = RetryBackoff()
    client = EnrollmentClient(
        instance, str(settings["agent_mainframe_url"]),
        str(settings.get("agent_mainframe_fallback_url", "")),
    )
    while running():
        # The control loop alone handles pending enrollment/certificate writes.
        if not client.enrolled():
            pause(5, running)
            continue
        status = _agent_tick(
            instance, {**settings, "agent_wait_seconds": 20}, write_status=False, running=running,
        )
        pause(regular_poll_delay(status, backoff), running)


def _interactive_lane(
    instance: Path,
    settings: dict[str, object],
    running: object,
    gate: InteractivePollGate | None = None,
) -> None:
    client = EnrollmentClient(
        instance,
        str(settings["agent_mainframe_url"]),
        str(settings.get("agent_mainframe_fallback_url", "")),
    )
    activation_id = agent_activation(instance)["activation_id"]
    receipts = OperationReceipts(instance)
    receipts.discard_other_activations(activation_id)
    gate = gate or InteractivePollGate()
    receipt_backoff = RetryBackoff()
    while callable(running) and running():
        # A sibling can hold the idle poll for 20 seconds. Publish completed
        # output through the non-claiming control endpoint before joining it.
        try:
            while running():
                completed = receipts.pending("interactive", activation_id)
                if not completed:
                    break
                result = client.heartbeat(
                    advertised_capabilities(), toolkit_version=APP_VERSION,
                    platform=f"{platform.system()} {platform.release()}".strip(),
                    hostname=socket.gethostname(), activation_id=activation_id,
                    results=completed, wait_seconds=0, control_only=True,
                )
                if result.get("job_protocol") != JOB_PROTOCOL_VERSION:
                    raise ValueError("Upgrade the Mainframe for owned operation delivery.")
                acknowledgements = result.get("acknowledgements", [])
                if not any(
                    ack.get("id") == completed[0]["id"]
                    and ack.get("attempt_token") == completed[0]["attempt_token"]
                    and ack.get("status") in {"accepted", "rejected"}
                    for ack in acknowledgements if isinstance(ack, dict)
                ):
                    raise ValueError("Mainframe did not acknowledge the completed operation.")
                receipts.acknowledge(acknowledgements)
            receipt_backoff.reset()
        except (EnrollmentTransportError, OSError, ValueError, sqlite3.Error):
            pause(receipt_backoff.delay(), running)
            continue
        with gate.enter(running) as admitted:
            if not admitted or not running():
                return
            try:
                response = client.interactive(
                    receipts.pending("interactive", activation_id), wait_seconds=20, activation_id=activation_id
                )
                if response.get("job_protocol") != JOB_PROTOCOL_VERSION:
                    raise ValueError("Upgrade the Mainframe for owned operation delivery.")
                receipts.acknowledge(response.get("acknowledgements", []))
                retry = poll_retry_delay(response)
                gate.backoff.reset()
                if not response.get("requests"):
                    # Keep the gate while pacing: another local lane must not
                    # immediately replace a throttled or failed poll.
                    pause(retry, running)
            except (EnrollmentTransportError, OSError, ValueError, sqlite3.Error):
                pause(gate.backoff.delay(), running)
                continue
        # Do not start a newly delivered claim after shutdown was requested.
        # Its unstarted claim can expire safely on the Mainframe.
        if not running():
            return
        # Other lanes may now fetch work while this one executes. Lease
        # renewal also bypasses the poll gate.
        try:
            _execute_jobs(instance, response.get("requests", []), client=client, lane="interactive")
        except (EnrollmentTransportError, OSError, ValueError, sqlite3.Error):
            pause(RETRY_INITIAL_SECONDS, running)


def _agent_tick(
    instance: Path, settings: dict[str, object], *,
    control_only: bool = False, write_status: bool = True,
    running: Callable[[], bool] = lambda: True,
) -> dict[str, object]:
    client = EnrollmentClient(
        instance,
        str(settings["agent_mainframe_url"]),
        str(settings.get("agent_mainframe_fallback_url", "")),
    )
    activation_id = agent_activation(instance)["activation_id"]
    status_path = instance / "distributed-status.json"
    results_path = instance / "distributed-job-results.json"
    now = time.time()
    wait_seconds = float(settings.get("agent_wait_seconds", 0) or 0)
    try:
        if write_status and client.pending():
            enrollment = client.poll()
            if enrollment["state"] != "approved":
                status = {
                    "role": "agent",
                    "state": enrollment["state"],
                    "checked_at": now,
                    "last_connected_at": 0,
                    "error": "",
                }
                if write_status:
                    _write_status(status_path, status)
                return status
        if not client.enrolled():
            status = {
                "role": "agent",
                "state": "not_enrolled",
                "checked_at": now,
                "last_connected_at": 0,
                "error": "",
            }
            if write_status:
                _write_status(status_path, status)
            return status
        receipts = OperationReceipts(instance)
        receipts.discard_other_activations(activation_id)
        # A pre-owned-operation worker persisted results without an ownership
        # token. The Mainframe migration has already made their outcome unknown.
        results_path.unlink(missing_ok=True)
        pending_results = receipts.pending("regular", activation_id)
        from .mso import MsoStore
        reported_mso = None
        if control_only:
            try:
                reported_mso = MsoStore(instance).peer_status()
            except (OSError, ValueError, sqlite3.Error):
                pass  # MSO storage failure must not break the Agent control lane.
        result = client.heartbeat(
            advertised_capabilities(),
            toolkit_version=APP_VERSION,
            platform=f"{platform.system()} {platform.release()}".strip(),
            hostname=socket.gethostname(),
            activation_id=activation_id,
            results=pending_results,
            wait_seconds=0 if control_only else wait_seconds,
            control_only=control_only,
            **({"mso_status": reported_mso} if reported_mso is not None else {}),
        )
        if result.get("job_protocol") != JOB_PROTOCOL_VERSION:
            raise ValueError("Upgrade the Mainframe for owned operation delivery.")
        receipts.acknowledge(result.get("acknowledgements", []))
        mso_error = ""
        if control_only and result.get("mso_protocol") == 1:
            from .mso import MsoStore
            mso = None
            try:
                mso = MsoStore(instance)
                proposal = mso.request(types=result.get("mso_types", ["ping.profile"]))
                mso.receive(client.mso_exchange(proposal), proposal)
                mso.sync_status("")
            except (EnrollmentTransportError, OSError, ValueError, sqlite3.Error) as exc:
                mso_error = " ".join(str(exc).split())[:240]
                if mso is not None:
                    try:
                        mso.sync_status(mso_error)
                    except (OSError, ValueError, sqlite3.Error):
                        pass  # The control status below still reports the sync failure.
        if not control_only and running():
            _execute_jobs(instance, result.get("jobs", []), client=client, lane="regular")
        completed = receipts.pending("regular", activation_id)
        if completed and not control_only:
            followup = client.heartbeat(advertised_capabilities(), toolkit_version=APP_VERSION,
                platform=f"{platform.system()} {platform.release()}".strip(), hostname=socket.gethostname(),
                activation_id=activation_id, results=completed, wait_seconds=0, control_only=True)
            if followup.get("job_protocol") != JOB_PROTOCOL_VERSION:
                raise ValueError("Upgrade the Mainframe for owned operation delivery.")
            receipts.acknowledge(followup.get("acknowledgements", []))
        status = {
            "role": "agent",
            "state": str(result.get("state", "connected")),
            "retry_after_seconds": poll_retry_delay(result),
            "checked_at": now,
            "last_connected_at": now,
            "error": "",
        }
        if mso_error:
            status["mso_error"] = mso_error
    except (EnrollmentTransportError, OSError, ValueError, sqlite3.Error) as exc:
        previous = _read_status(status_path)
        status = {
            "role": "agent",
            "state": "disconnected",
            "checked_at": now,
            "last_connected_at": float(previous.get("last_connected_at", 0) or 0),
            "error": " ".join(str(exc).split())[:240],
        }
    if write_status:
        _write_status(status_path, status)
    return status


def _execute_jobs(instance: Path, jobs: object, *, client, lane="regular") -> None:
    execute_owned(instance, jobs, client, lane, execute_capability)


def _read_results(path: Path) -> list[dict[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return payload[:16] if isinstance(payload, list) else []


def _read_status(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_status(path: Path, payload: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _daemonize(pid_file: str, log_file: str) -> None:
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


if __name__ == "__main__":
    main()
