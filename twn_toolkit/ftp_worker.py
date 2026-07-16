from __future__ import annotations

import argparse
import ipaddress
import os
import signal
import sys
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import DTPHandler, FTPHandler
from pyftpdlib.log import logger
from pyftpdlib.servers import FTPServer
from werkzeug.security import check_password_hash

from .datastore import LocalDatastore, MAX_UPLOAD_BYTES
from .ftp_server import FTPSettingsStore, clear_ftp_runtime
from .pidfiles import (
    acquire_singleton_lock,
    close_inherited_file_descriptors,
    record_lock_owner,
    remove_own_pid_file,
    write_pid_file,
)
from .ssh_transfer_server import SSHTransferHistoryStore
from .tftp import format_incoming_filename


class HashedAuthorizer(DummyAuthorizer):
    password_hash = ""
    def validate_authentication(self, username, password, handler):
        if username not in self.user_table or not check_password_hash(self.password_hash, password):
            raise AuthenticationFailed


class BoundedDTPHandler(DTPHandler):
    """Abort uploads before a client can exceed the datastore file ceiling."""
    def handle_read(self):
        try:
            chunk = self.recv(self.ac_in_buffer_size)
        except OSError:
            self.handle_error()
            return
        if not chunk:
            self.transfer_finished = True
            return
        if self.receive and self.tot_bytes_received + len(chunk) > MAX_UPLOAD_BYTES:
            self.cmd_channel._upload_limit_exceeded = True
            self._resp = ("552 Upload exceeds the 1 GiB file limit.", logger.warning)
            self.close()
            return
        self.tot_bytes_received += len(chunk)
        if self._data_wrapper is not None:
            chunk = self._data_wrapper(chunk)
        try:
            self.file_obj.write(chunk)
        except OSError:
            self.handle_error()

    handle_read_event = handle_read


def build_handler(instance: str, settings: dict):
    runtime = settings["root_mode"] == "temporary"
    store = LocalDatastore(instance, "ftp_runtime" if runtime else "datastore")
    root = store.folder("") if runtime else store.folder(settings["datastore_root"])
    history = SSHTransferHistoryStore(instance)
    trusted = [ipaddress.ip_network(value) for value in settings["allowed_networks"]]
    authorizer = HashedAuthorizer(); authorizer.password_hash = settings["password_hash"]
    permissions = "el" + ("r" if settings["allow_read"] else "") + ("w" if settings["allow_write"] else "")
    authorizer.add_user(settings["username"], "unused", str(root), perm=permissions)

    class ContainedFTP(FTPHandler):
        _pending_upload = None
        _requested_upload = ""
        _upload_limit_exceeded = False
        def on_connect(self):
            if not any(ipaddress.ip_address(self.remote_ip) in network for network in trusted): self.close_when_done()
        def ftp_STOR(self, file, mode="w"):
            if not settings["allow_write"]: return self.respond("550 Uploads disabled.")
            requested = Path(file).name
            stored = format_incoming_filename(settings["incoming_filename_pattern"], requested, self.remote_ip)
            destination = root / stored
            if destination.exists() and not settings["allow_overwrite"]: return self.respond("550 Destination exists.")
            temporary = root / f".{stored}.{os.getpid()}.{id(self)}.part"
            self._pending_upload, self._requested_upload = destination, requested
            self._upload_limit_exceeded = False
            return super().ftp_STOR(str(temporary), mode)
        def on_file_received(self, file):
            source = Path(file); destination = self._pending_upload
            try:
                if self._upload_limit_exceeded: raise OSError("Upload exceeded the 1 GiB file limit.")
                os.chmod(source, 0o600); os.replace(source, destination)
                history.record(client=self.remote_ip, protocol="FTP", operation="upload", filename=self._requested_upload, stored_filename=destination.name, bytes=destination.stat().st_size, status="success", message="")
            except Exception as exc:
                source.unlink(missing_ok=True); history.record(client=self.remote_ip, protocol="FTP", operation="upload", filename=self._requested_upload, stored_filename="", bytes=0, status="error", message=str(exc))
        def on_incomplete_file_received(self, file):
            path = Path(file); size = path.stat().st_size if path.exists() else 0; path.unlink(missing_ok=True)
            message = "Upload exceeded the 1 GiB file limit." if self._upload_limit_exceeded else "Upload did not complete."
            history.record(client=self.remote_ip, protocol="FTP", operation="upload", filename=self._requested_upload or path.name, stored_filename="", bytes=size, status="error", message=message)
        def on_file_sent(self, file):
            path = Path(file); history.record(client=self.remote_ip, protocol="FTP", operation="download", filename=path.name, stored_filename=path.name, bytes=path.stat().st_size, status="success", message="")

    ContainedFTP.authorizer = authorizer
    ContainedFTP.dtp_handler = BoundedDTPHandler
    ContainedFTP.passive_ports = range(settings["passive_start"], settings["passive_end"] + 1)
    ContainedFTP.banner = "The WiFi Ninja's Toolkit contained FTP service"
    return ContainedFTP


def _daemonize(pid_file: str, log_file: str, lock_fd: int):
    first = os.fork()
    if first > 0: os._exit(0)
    os.setsid(); second = os.fork()
    if second > 0: os._exit(0)
    os.chdir("/"); os.umask(0o077)
    stdin_fd = os.open(os.devnull, os.O_RDONLY); path = Path(log_file); path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(stdin_fd, sys.stdin.fileno()); os.dup2(log_fd, sys.stdout.fileno()); os.dup2(log_fd, sys.stderr.fileno()); os.close(stdin_fd); os.close(log_fd)
    close_inherited_file_descriptors(preserve={lock_fd})


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--instance", required=True); parser.add_argument("--daemon", action="store_true"); parser.add_argument("--pid-file", required=True); parser.add_argument("--log-file", required=True)
    args = parser.parse_args()
    singleton = acquire_singleton_lock(Path(args.instance).resolve().parent, "ftp")
    if singleton is None:
        return
    if args.daemon: _daemonize(args.pid_file, args.log_file, singleton.fileno())
    record_lock_owner(singleton)
    settings = FTPSettingsStore(args.instance).get()
    if not settings["enabled"]: raise SystemExit("FTP is disabled.")
    write_pid_file(args.pid_file)
    server = FTPServer((settings["bind_host"], settings["port"]), build_handler(args.instance, settings))
    server.max_cons = settings["max_connections"]
    server.max_cons_per_ip = settings["max_connections_per_ip"]
    signal.signal(signal.SIGTERM, lambda *_: server.close_all()); signal.signal(signal.SIGINT, lambda *_: server.close_all())
    try: server.serve_forever(timeout=1, blocking=True, handle_exit=False)
    finally:
        remove_own_pid_file(args.pid_file)
        if settings["root_mode"] == "temporary": clear_ftp_runtime(args.instance)


if __name__ == "__main__": main()
