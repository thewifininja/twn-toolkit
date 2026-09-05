from __future__ import annotations

import argparse
import ipaddress
import os
import signal
import sys
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import DTPHandler, FTPHandler
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.log import logger
from werkzeug.security import check_password_hash

from .datastore import DatastoreError, LocalDatastore, MAX_UPLOAD_BYTES
from .uploads import Upload
from .ftp_server import FTPSettingsStore, clear_ftp_runtime
from .pidfiles import (
    acquire_singleton_lock,
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
        except (OSError, DatastoreError) as exc:
            self.cmd_channel._upload_error = str(exc)
            self._resp = ("552 Upload could not be stored.", logger.warning)
            self.close()

    def close(self):
        upload = getattr(self, "file_obj", None)
        if isinstance(upload, Upload) and not upload.closed:
            if self.transfer_finished and not self.cmd_channel._upload_limit_exceeded:
                try:
                    upload.commit()
                except (OSError, DatastoreError) as exc:
                    self.cmd_channel._upload_error = str(exc)
                    self.transfer_finished = False
                    self._resp = ("552 Upload could not be published.", logger.warning)
            else:
                upload.abort()
        super().close()

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

    class UploadFilesystem(AbstractedFS):
        def open(self, filename, mode):
            upload = self.cmd_channel._pending_upload
            if upload is not None and str(filename) == upload.name and "w" in mode:
                return upload
            return super().open(filename, mode)

    class ContainedFTP(FTPHandler):
        _pending_upload = None
        _requested_upload = ""
        _upload_limit_exceeded = False
        _upload_error = ""

        def on_connect(self):
            if not any(ipaddress.ip_address(self.remote_ip) in network for network in trusted):
                self.close_when_done()

        def ftp_STOR(self, file, mode="w"):
            if not settings["allow_write"]:
                return self.respond("550 Uploads disabled.")
            if mode != "w" or self._restart_position:
                self._restart_position = 0
                return self.respond("550 Only complete sequential uploads are supported.")
            if self._pending_upload is not None and not self._pending_upload.closed:
                return self.respond("450 An upload is already in progress.")
            requested = Path(file).name
            stored = format_incoming_filename(settings["incoming_filename_pattern"], requested, self.remote_ip)
            try:
                self._pending_upload = store.begin_upload(
                    store.relative(root), stored, max_bytes=MAX_UPLOAD_BYTES,
                    overwrite=settings["allow_overwrite"],
                )
            except (OSError, DatastoreError) as exc:
                return self.respond(f"550 {exc}")
            self._requested_upload = requested
            self._upload_limit_exceeded = False
            self._upload_error = ""
            result = super().ftp_STOR(self._pending_upload.name, mode)
            if result is None:
                self._pending_upload.abort()
            return result

        def on_disconnect(self):
            if self._pending_upload is not None:
                self._pending_upload.abort()

        def on_file_received(self, file):
            upload = self._pending_upload
            history.record(client=self.remote_ip, protocol="FTP", operation="upload",
                           filename=self._requested_upload, stored_filename=upload.destination.name,
                           bytes=upload.total, status="success", message="")
            self._pending_upload = None

        def on_incomplete_file_received(self, file):
            upload = self._pending_upload
            if upload is None:
                return
            upload.abort()
            message = self._upload_error or ("Upload exceeded the 1 GiB file limit." if self._upload_limit_exceeded else "Upload did not complete.")
            history.record(client=self.remote_ip, protocol="FTP", operation="upload",
                           filename=self._requested_upload, stored_filename="", bytes=upload.total,
                           status="error", message=message)
            self._pending_upload = None

        def on_file_sent(self, file):
            path = Path(file); history.record(client=self.remote_ip, protocol="FTP", operation="download", filename=path.name, stored_filename=path.name, bytes=path.stat().st_size, status="success", message="")

    ContainedFTP.abstracted_fs = UploadFilesystem
    ContainedFTP.authorizer = authorizer
    ContainedFTP.dtp_handler = BoundedDTPHandler
    ContainedFTP.passive_ports = range(settings["passive_start"], settings["passive_end"] + 1)
    ContainedFTP.banner = "TWN Toolkit contained FTP service"
    return ContainedFTP


def _daemonize(pid_file: str, log_file: str):
    first = os.fork()
    if first > 0: os._exit(0)
    os.setsid(); second = os.fork()
    if second > 0: os._exit(0)
    os.chdir("/"); os.umask(0o077)
    stdin_fd = os.open(os.devnull, os.O_RDONLY); path = Path(log_file); path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(stdin_fd, sys.stdin.fileno()); os.dup2(log_fd, sys.stdout.fileno()); os.dup2(log_fd, sys.stderr.fileno()); os.close(stdin_fd); os.close(log_fd)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--instance", required=True); parser.add_argument("--daemon", action="store_true"); parser.add_argument("--pid-file", required=True); parser.add_argument("--ready-file", default=""); parser.add_argument("--log-file", required=True)
    args = parser.parse_args()
    singleton = acquire_singleton_lock(Path(args.instance).resolve(), "ftp")
    if singleton is None:
        return
    if args.daemon: _daemonize(args.pid_file, args.log_file)
    record_lock_owner(singleton)
    # pyftpdlib.servers creates multiprocessing synchronization primitives at
    # import time. Import it only after detaching so its resource tracker and
    # macOS kqueue belong to the final daemon, not the launcher or updater.
    from pyftpdlib.servers import FTPServer
    write_pid_file(args.pid_file)
    settings = None
    server = None
    try:
        settings = FTPSettingsStore(args.instance).get()
        if not settings["enabled"]: raise SystemExit("FTP is disabled.")
        server = FTPServer((settings["bind_host"], settings["port"]), build_handler(args.instance, settings))
        server.max_cons = settings["max_connections"]
        server.max_cons_per_ip = settings["max_connections_per_ip"]
        signal.signal(signal.SIGTERM, lambda *_: server.close_all()); signal.signal(signal.SIGINT, lambda *_: server.close_all())
        write_pid_file(args.ready_file)
        server.serve_forever(timeout=1, blocking=True, handle_exit=False)
    finally:
        if server is not None:
            server.close_all()
        remove_own_pid_file(args.ready_file)
        remove_own_pid_file(args.pid_file)
        try:
            if settings is not None and settings["root_mode"] == "temporary": clear_ftp_runtime(args.instance)
        finally:
            singleton.close()


if __name__ == "__main__": main()
