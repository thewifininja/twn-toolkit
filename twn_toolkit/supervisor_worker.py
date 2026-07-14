from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from .pidfiles import remove_own_pid_file, write_pid_file


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--instance", required=True); parser.add_argument("--root", required=True); parser.add_argument("--pid-file", required=True); parser.add_argument("--log-file", required=True); parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    if args.daemon: _daemonize(args.pid_file, args.log_file)
    instance, root = Path(args.instance), Path(args.root)
    running = True
    retry_after: dict[str, float] = {}
    signal.signal(signal.SIGTERM, lambda *_: _stop()); signal.signal(signal.SIGINT, lambda *_: _stop())
    def supervise() -> None:
        services = [
            ("automation", True, "twn-automation.pid", "automation-restart", "automation-heartbeat.json"),
            ("TFTP", _enabled(instance / "tftp_settings.json"), "twn-tftp.pid", "tftp-restart", ""),
            ("SFTP/SCP", _enabled(instance / "ssh_transfer_settings.json"), "twn-ssh-transfer.pid", "ssh-transfer-restart", ""),
            ("FTP", _enabled(instance / "ftp_settings.json"), "twn-ftp.pid", "ftp-restart", ""),
        ]
        for label, enabled, pid_name, command, heartbeat_name in services:
            if not enabled: continue
            healthy = _pid_running(instance / pid_name)
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
    def _stop() -> None:
        nonlocal running; running = False
    heartbeat = instance / "supervisor-heartbeat.json"
    try:
        while running:
            supervise()
            heartbeat.write_text(json.dumps({"updated_at": time.time(), "pid": os.getpid()}), encoding="utf-8")
            os.chmod(heartbeat, 0o600)
            for _ in range(10):
                if not running: break
                time.sleep(0.5)
    finally:
        remove_own_pid_file(args.pid_file); heartbeat.unlink(missing_ok=True)


def _enabled(path: Path) -> bool:
    try: return bool(json.loads(path.read_text(encoding="utf-8")).get("enabled"))
    except (OSError, ValueError): return False


def _pid_running(path: Path) -> bool:
    try: os.kill(int(path.read_text(encoding="utf-8").strip()), 0); return True
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
