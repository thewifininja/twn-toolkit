from __future__ import annotations

import argparse
import json
import math
import os
import signal
import subprocess
import time
from pathlib import Path

from .automation_heartbeat import (
    AUTOMATION_HEARTBEAT_MAX_AGE_SECONDS,
    automation_heartbeat_fresh,
)
from .pidfiles import (
    acquire_singleton_lock,
    matching_daemon_pids,
    pid_is_running,
    process_marker_ready,
    record_lock_owner,
    remove_own_pid_file,
    stop_matching_daemons,
    write_pid_file,
)


# Central recovery policy; independent of authentication or transfer limits.
RESTART_TIMEOUT_SECONDS = 30
RESTART_COOLDOWN_SECONDS = 30
SWEEP_INTERVAL_SECONDS = 5
SERVICES = (
    ("automation", "", "twn-automation.pid", "", "automation-restart", "automation-heartbeat.json"),
    ("TFTP", "tftp_settings.json", "twn-tftp.pid", "twn-tftp.ready", "tftp-restart", ""),
    ("SFTP/SCP", "ssh_transfer_settings.json", "twn-ssh-transfer.pid", "twn-ssh-transfer.ready", "ssh-transfer-restart", ""),
    ("FTP", "ftp_settings.json", "twn-ftp.pid", "twn-ftp.ready", "ftp-restart", ""),
)


def supervise_once(root: Path, instance: Path, retry_after: dict[str, float], *, stopping=lambda: False) -> None:
    for label, settings, pid_name, ready_name, command, heartbeat_name in SERVICES:
        if stopping():
            return
        try:
            if time.monotonic() < retry_after.get(pid_name, 0):
                continue
            if settings and not _enabled(instance / settings):
                continue
            if _operation_active(instance / f"{pid_name}.lock"):
                continue
            healthy = (process_marker_ready(instance / pid_name, instance / ready_name)
                       if ready_name else _pid_running(instance / pid_name))
            if healthy and heartbeat_name:
                healthy = _heartbeat_fresh(instance / heartbeat_name, AUTOMATION_HEARTBEAT_MAX_AGE_SECONDS)
            if healthy:
                retry_after.pop(pid_name, None)
                continue
            print(f"Supervisor restarting {label}.", flush=True)
            result = subprocess.run([str(root / "twn"), command], cwd=root,
                                    timeout=RESTART_TIMEOUT_SECONDS, check=False)
            retry_after[pid_name] = time.monotonic() + RESTART_COOLDOWN_SECONDS
            if result.returncode:
                print(f"Could not restart {label}: command exited with status {result.returncode}.", flush=True)
        except Exception as exc:
            # A broken health probe or restart must not abandon the other services.
            retry_after[pid_name] = time.monotonic() + RESTART_COOLDOWN_SECONDS
            print(f"Could not supervise {label}: {type(exc).__name__}: {exc}", flush=True)
    if stopping() or time.monotonic() < retry_after.get("iperf", 0):
        return
    try:
        if (instance / "iperf_servers.sqlite3").exists():
            restored = _restore_iperf_listeners(instance)
            if restored:
                print(f"Supervisor restored {restored} managed iPerf3 listener{'s' if restored != 1 else ''}.", flush=True)
            retry_after.pop("iperf", None)
    except Exception as exc:
        retry_after["iperf"] = time.monotonic() + RESTART_COOLDOWN_SECONDS
        print(f"Could not supervise managed iPerf3 listeners: {type(exc).__name__}: {exc}", flush=True)


def _write_heartbeat(path: Path) -> None:
    try:
        path.write_text(json.dumps({"updated_at": time.time(), "pid": os.getpid()}), encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError as exc:
        # Report publication failures without stopping recovery.
        print(f"Could not write supervisor heartbeat: {type(exc).__name__}: {exc}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("instance", "root", "pid-file", "log-file"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    instance = Path(args.instance).resolve()
    singleton = acquire_singleton_lock(instance, "supervisor")
    if singleton is None:
        return
    heartbeat = instance / "supervisor-heartbeat.json"
    try:
        if args.daemon:
            _daemonize(args.pid_file, args.log_file)
        else:
            write_pid_file(args.pid_file)
        record_lock_owner(singleton)
        running = True
        def stop(*_args):
            nonlocal running
            running = False
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        retry_after: dict[str, float] = {}
        while running:
            if args.daemon and not _owns_pid_file(Path(args.pid_file)):
                break
            supervise_once(root, instance, retry_after, stopping=lambda: not running)
            _write_heartbeat(heartbeat)
            for _ in range(int(SWEEP_INTERVAL_SECONDS / 0.1)):
                if not running:
                    break
                time.sleep(0.1)
    finally:
        try:
            remove_own_pid_file(args.pid_file)
            _remove_own_heartbeat(heartbeat)
        finally:
            singleton.close()


def _owns_pid_file(path: Path) -> bool:
    try:
        return int(path.read_text(encoding="utf-8").strip()) == os.getpid()
    except (OSError, ValueError):
        return False


def _operation_active(lock_path: Path) -> bool:
    try:
        owner = int((lock_path / "owner").read_text(encoding="utf-8").strip())
        os.kill(owner, 0)
    except (FileNotFoundError, OSError, ValueError):
        return False
    return True


def _remove_own_heartbeat(path: Path) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if int(payload.get("pid", 0)) == os.getpid():
            path.unlink(missing_ok=True)
    except (OSError, TypeError, ValueError, AttributeError):
        pass


def matching_supervisor_pids(output: str, root: Path, instance: Path) -> list[int]:
    return matching_daemon_pids(
        output,
        "twn_toolkit.supervisor_worker",
        instance,
        required_text=f"--root {root.resolve()} --daemon",
    )


def stop_matching_supervisors(
    root: Path,
    instance: Path,
    *,
    keep_pid: int = 0,
    timeout: float = 5.0,
) -> list[int]:
    return stop_matching_daemons(
        "twn_toolkit.supervisor_worker",
        instance,
        keep_pid=keep_pid,
        required_text=f"--root {root.resolve()} --daemon",
        timeout=timeout,
    )


def _enabled(path: Path) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False
    if not isinstance(data, dict) or not isinstance(data.get("enabled", False), bool):
        raise ValueError("Service settings must contain a boolean enabled value.")
    return data.get("enabled", False)


def _restore_iperf_listeners(instance: Path) -> int:
    from .iperf_server import IperfServerStore

    return IperfServerStore(instance).ensure_workers()


def _pid_running(path: Path) -> bool:
    try: return pid_is_running(int(path.read_text(encoding="utf-8").strip()))
    except (OSError, ValueError): return False


def _heartbeat_fresh(path: Path, maximum_age: int) -> bool:
    return automation_heartbeat_fresh(path, maximum_age)


def _daemonize(pid_file: str, log_file: str) -> None:
    first = os.fork()
    if first > 0: os._exit(0)
    os.setsid(); second = os.fork()
    if second > 0: os._exit(0)
    os.chdir("/"); os.umask(0o077)
    stdin_fd = os.open(os.devnull, os.O_RDONLY); path = Path(log_file); path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(stdin_fd, 0); os.dup2(log_fd, 1); os.dup2(log_fd, 2); os.close(stdin_fd); os.close(log_fd)
    write_pid_file(pid_file)


if __name__ == "__main__": main()
