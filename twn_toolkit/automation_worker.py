from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path

from .automation import AutomationEngine, AutomationStore
from .auth import load_or_create_secret_key


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
    store = AutomationStore(
        instance_path,
        load_or_create_secret_key(instance_path),
    )
    engine = AutomationEngine(store)
    running = True

    def stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while running:
            engine.run_once()
            time.sleep(max(0.2, args.poll_seconds))
    finally:
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


if __name__ == "__main__":
    main()
