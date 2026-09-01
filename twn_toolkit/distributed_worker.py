from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import socket
import sys
import threading
import time
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
        interactive_threads: list[threading.Thread] = []
        if settings["role"] == "agent":
            for lane in range(3):
                thread = threading.Thread(
                    target=_interactive_lane,
                    args=(instance, settings, lambda: running),
                    name=f"twn-interactive-{lane + 1}",
                    daemon=True,
                )
                thread.start()
                interactive_threads.append(thread)
        while running:
            if settings["role"] == "agent":
                _agent_tick(instance, {**settings, "agent_wait_seconds": 20})
                time.sleep(0.05)
            else:
                time.sleep(0.25)
    except Exception as exc:
        print(f"Mainframe enrollment listener failed: {exc}", file=sys.stderr)
        raise
    finally:
        for thread in locals().get("interactive_threads", []):
            thread.join(timeout=30)
        for server in reversed(servers):
            server.stop()
        remove_own_pid_file(args.pid_file)


def _interactive_lane(
    instance: Path,
    settings: dict[str, object],
    running: object,
) -> None:
    client = EnrollmentClient(
        instance,
        str(settings["agent_mainframe_url"]),
        str(settings.get("agent_mainframe_fallback_url", "")),
    )
    activation_id = agent_activation(instance)["activation_id"]
    results: list[dict[str, object]] = []
    while callable(running) and running():
        try:
            response = client.interactive(
                results, wait_seconds=20, activation_id=activation_id
            )
            results = _execute_jobs(instance, response.get("requests", []))
        except (EnrollmentTransportError, OSError, ValueError):
            time.sleep(0.5)


def _agent_tick(instance: Path, settings: dict[str, object]) -> dict[str, object]:
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
        if client.pending():
            enrollment = client.poll()
            if enrollment["state"] != "approved":
                status = {
                    "role": "agent",
                    "state": enrollment["state"],
                    "checked_at": now,
                    "last_connected_at": 0,
                    "error": "",
                }
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
            _write_status(status_path, status)
            return status
        pending_results = _read_results(results_path)
        result = client.heartbeat(
            advertised_capabilities(),
            toolkit_version=APP_VERSION,
            platform=f"{platform.system()} {platform.release()}".strip(),
            hostname=socket.gethostname(),
            activation_id=activation_id,
            results=pending_results,
            wait_seconds=wait_seconds,
        )
        if pending_results:
            results_path.unlink(missing_ok=True)
        completed = _execute_jobs(instance, result.get("jobs", []))
        if completed:
            try:
                followup = client.heartbeat(
                    advertised_capabilities(),
                    toolkit_version=APP_VERSION,
                    platform=f"{platform.system()} {platform.release()}".strip(),
                    hostname=socket.gethostname(),
                    activation_id=activation_id,
                    results=completed,
                    wait_seconds=wait_seconds,
                )
                more_completed = _execute_jobs(instance, followup.get("jobs", []))
                if more_completed:
                    _write_status(results_path, more_completed)
            except (EnrollmentTransportError, OSError, ValueError):
                _write_status(results_path, completed)
        status = {
            "role": "agent",
            "state": str(result.get("state", "connected")),
            "checked_at": now,
            "last_connected_at": now,
            "error": "",
        }
    except (EnrollmentTransportError, OSError, ValueError) as exc:
        previous = _read_status(status_path)
        status = {
            "role": "agent",
            "state": "disconnected",
            "checked_at": now,
            "last_connected_at": float(previous.get("last_connected_at", 0) or 0),
            "error": " ".join(str(exc).split())[:240],
        }
    _write_status(status_path, status)
    return status


def _execute_jobs(instance: Path, jobs: object) -> list[dict[str, object]]:
    if not isinstance(jobs, list):
        return []
    activation_id = agent_activation(instance)["activation_id"]
    results: list[dict[str, object]] = []
    for job in jobs[:16]:
        if not isinstance(job, dict):
            continue
        job_id = str(job.get("id", ""))
        capability = str(job.get("capability_id", ""))
        version = str(job.get("capability_version", ""))
        try:
            output = execute_capability(
                instance, capability, version, job.get("inputs", {})
            )
        except Exception as exc:
            results.append(
                {
                    "id": job_id,
                    "state": "failed",
                    "output": {},
                    "error": " ".join(str(exc).split())[:1000],
                }
            )
        else:
            results.append(
                {
                    "id": job_id,
                    "state": "succeeded",
                    "output": output,
                    "error": "",
                }
            )
    return results


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
