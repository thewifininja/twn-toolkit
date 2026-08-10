from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

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


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--instance", required=True); parser.add_argument("--root", required=True); parser.add_argument("--pid-file", required=True); parser.add_argument("--log-file", required=True); parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    instance = Path(args.instance).resolve()
    singleton = acquire_singleton_lock(instance, "supervisor")
    if singleton is None:
        return
    if args.daemon: _daemonize(args.pid_file, args.log_file)
    else: write_pid_file(args.pid_file)
    record_lock_owner(singleton)
    running = True
    retry_after: dict[str, float] = {}
    signal.signal(signal.SIGTERM, lambda *_: _stop()); signal.signal(signal.SIGINT, lambda *_: _stop())
    def supervise() -> None:
        services = [
            ("automation", True, "twn-automation.pid", "", "automation-restart", "automation-heartbeat.json"),
            ("TFTP", _enabled(instance / "tftp_settings.json"), "twn-tftp.pid", "twn-tftp.ready", "tftp-restart", ""),
            ("SFTP/SCP", _enabled(instance / "ssh_transfer_settings.json"), "twn-ssh-transfer.pid", "twn-ssh-transfer.ready", "ssh-transfer-restart", ""),
            ("FTP", _enabled(instance / "ftp_settings.json"), "twn-ftp.pid", "twn-ftp.ready", "ftp-restart", ""),
        ]
        for label, enabled, pid_name, ready_name, command, heartbeat_name in services:
            if not enabled: continue
            if _operation_active(instance / f"{pid_name}.lock"):
                continue
            healthy = (
                process_marker_ready(instance / pid_name, instance / ready_name)
                if ready_name
                else _pid_running(instance / pid_name)
            )
            if healthy and heartbeat_name:
                healthy = _heartbeat_fresh(instance / heartbeat_name, 20)
            if healthy:
                retry_after.pop(pid_name, None)
                continue
            if time.time() < retry_after.get(pid_name, 0):
                continue
            print(f"Supervisor restarting {label}.", flush=True)
            subprocess.run([str(root / "twn"), command], cwd=root, timeout=30, check=False)
            retry_after[pid_name] = time.time() + 30
        iperf_database = instance / "iperf_servers.sqlite3"
        if iperf_database.exists():
            try:
                restored = _restore_iperf_listeners(instance)
                if restored:
                    print(
                        f"Supervisor restored {restored} managed iPerf3 "
                        f"listener{'s' if restored != 1 else ''}.",
                        flush=True,
                    )
            except Exception as exc:
                print(
                    f"Could not supervise managed iPerf3 listeners: "
                    f"{type(exc).__name__}: {exc}",
                    flush=True,
                )
    def _stop() -> None:
        nonlocal running; running = False
    heartbeat = instance / "supervisor-heartbeat.json"
    try:
        while running:
            if args.daemon and not _owns_pid_file(Path(args.pid_file)):
                break
            supervise()
            heartbeat.write_text(json.dumps({"updated_at": time.time(), "pid": os.getpid()}), encoding="utf-8")
            os.chmod(heartbeat, 0o600)
            for _ in range(50):
                if not running: break
                time.sleep(0.1)
    finally:
        remove_own_pid_file(args.pid_file)
        _remove_own_heartbeat(heartbeat)


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
    except (OSError, TypeError, ValueError):
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
    try: return bool(json.loads(path.read_text(encoding="utf-8")).get("enabled"))
    except (OSError, ValueError): return False


def _restore_iperf_listeners(instance: Path) -> int:
    from .iperf_server import IperfServerStore

    return IperfServerStore(instance).ensure_workers()


def _pid_running(path: Path) -> bool:
    try: return pid_is_running(int(path.read_text(encoding="utf-8").strip()))
    except (OSError, ValueError): return False


def _heartbeat_fresh(path: Path, maximum_age: int) -> bool:
    try: return time.time() - float(json.loads(path.read_text(encoding="utf-8"))["updated_at"]) <= maximum_age
    except (OSError, ValueError, KeyError): return False


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
