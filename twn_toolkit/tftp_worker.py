from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from .datastore import LocalDatastore
from .tftp import TFTPHistoryStore, TFTPServer, TFTPSettingsStore, clear_tftp_runtime
from .pidfiles import remove_own_pid_file, write_pid_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the toolkit-contained TFTP server.")
    parser.add_argument("--instance", required=True)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--pid-file", default="")
    parser.add_argument("--log-file", default="")
    args = parser.parse_args()
    if args.daemon:
        _daemonize(args.pid_file, args.log_file)
    instance = str(Path(args.instance).resolve())
    settings = TFTPSettingsStore(instance).get()
    if not settings["enabled"]:
        raise SystemExit("TFTP is disabled in toolkit settings.")
    if settings["root_mode"] == "temporary":
        datastore = LocalDatastore(instance, "tftp_runtime")
        root_prefix = ""
    else:
        datastore = LocalDatastore(instance)
        root_prefix = settings["datastore_root"]
        datastore.list(root_prefix)
    server = TFTPServer(
        datastore,
        TFTPHistoryStore(instance),
        settings,
        root_prefix=root_prefix,
    )

    def stop(_signum: int, _frame: object) -> None:
        server.stop()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever()
    finally:
        if settings["root_mode"] == "temporary":
            clear_tftp_runtime(instance)
        remove_own_pid_file(args.pid_file)


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
