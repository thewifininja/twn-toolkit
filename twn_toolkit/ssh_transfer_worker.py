from __future__ import annotations

import argparse
import errno
import ipaddress
import logging
import struct
import stat
import os
import shlex
import signal
import socket
import threading
import time
import sys
import weakref
from pathlib import Path
from typing import Any, Callable

import paramiko

from .datastore import DatastoreError, LocalDatastore
from .ssh_transfer_server import (
    SSHTransferHistoryStore, SSHTransferSettingsStore, ensure_ssh_host_key,
    DEFAULT_SSH_TRANSFER_SETTINGS,
)
from .tftp import format_incoming_filename
from .pidfiles import (
    acquire_singleton_lock,
    record_lock_owner,
    remove_own_pid_file,
    write_pid_file,
)
from .ssh_security import disabled_ssh_algorithms

from .transfer_limits import ActiveChannel, ChannelActivity, ConnectionAdmission

CLIENT_IDLE_TIMEOUT_SECONDS = DEFAULT_SSH_TRANSFER_SETTINGS["idle_timeout_seconds"]
SFTP_PACKET_BYTES = 1024 * 1024
SFTP_READ_BYTES = 64 * 1024
logger = logging.getLogger(__name__)


class TransferContext:
    def __init__(self, instance: str, settings: dict[str, Any], client_ip: str) -> None:
        settings = {**DEFAULT_SSH_TRANSFER_SETTINGS, **settings}
        self.instance, self.settings, self.client_ip = instance, settings, client_ip
        self.activity = ChannelActivity(settings["max_channels"])
        self._workers = set()
        self._workers_lock = threading.Lock()
        self._history = None
        self._history_lock = threading.Lock()
        self.store = LocalDatastore(instance, "ssh_transfer_runtime" if settings["root_mode"] == "temporary" else "datastore")
        self.root = self.store.folder("") if settings["root_mode"] == "temporary" else self.store.folder(settings["datastore_root"])

    @property
    def history(self):
        # A silent, unauthenticated peer should not open/create a history DB.
        with self._history_lock:
            if self._history is None:
                self._history = SSHTransferHistoryStore(self.instance)
            return self._history

    def track_worker(self, worker):
        with self._workers_lock:
            self._workers = {item for item in self._workers if item.is_alive()}
            self._workers.add(worker)

    def join_workers(self):
        with self._workers_lock:
            workers = list(self._workers)
        for worker in workers:
            if worker.ident is not None:
                worker.join()

    def path(self, requested: str, *, write: bool = False) -> Path:
        raw = str(requested).replace("\\", "/").strip("/")
        if any(part in {"", ".", ".."} for part in Path(raw).parts):
            raise OSError("Invalid transfer path.")
        if write:
            name = format_incoming_filename(self.settings["incoming_filename_pattern"], Path(raw).name, self.client_ip)
            candidate = self.root / name
        else:
            candidate = self.root.joinpath(*Path(raw).parts)
        resolved_parent = candidate.parent.resolve()
        try: resolved_parent.relative_to(self.root.resolve())
        except ValueError as exc: raise OSError("Transfer path escapes the configured root.") from exc
        if candidate.is_symlink() or any(parent.is_symlink() for parent in candidate.parents if parent != self.root.parent):
            raise OSError("Symbolic links are not supported.")
        return candidate

    def record(self, protocol: str, operation: str, filename: str, status: str, **extra: Any) -> None:
        try:
            self.history.record(client=self.client_ip, protocol=protocol, operation=operation,
                                filename=filename, status=status, **extra)
        except Exception:
            # History failure must not turn a published transfer into a protocol
            # failure or prevent cleanup of other handles in the same session.
            logger.exception("Could not record %s transfer history", protocol)


class AtomicWriteHandle(paramiko.SFTPHandle):
    """Only an explicit SFTP CLOSE commits; session cleanup calls abort first."""
    def __init__(self, context: TransferContext, requested: str, *, overwrite: bool | None = None) -> None:
        super().__init__()
        self.context, self.requested = context, requested
        self.started_at = time.time()
        self.total, self.failed = 0, False
        self._status = None
        self.destination = context.path(requested, write=True)
        self.upload = context.store.begin_upload(
            context.store.relative(self.destination.parent), self.destination.name,
            overwrite=context.settings["allow_overwrite"] if overwrite is None else overwrite,
        )
        self.temporary = self.upload.temporary

    def write(self, offset: int, data: bytes):
        if self._status is not None:
            return paramiko.SFTP_FAILURE
        if offset != self.total:
            self.abort("Upload writes must use consecutive offsets.")
            return paramiko.SFTP_BAD_MESSAGE
        try:
            self.upload.write(data)
            self.total += len(data)
            return paramiko.SFTP_OK
        except (OSError, DatastoreError) as exc:
            self.abort(str(exc))
            return paramiko.SFTP_FAILURE

    def abort(self, message="Upload session ended before the file was closed."):
        if self._status is not None:
            return
        self.failed = True
        self._status = paramiko.SFTP_FAILURE
        self.upload.abort()
        self.context.record("SFTP", "upload", self.requested, "error",
                            stored_filename="", bytes=self.total, message=message, started_at=self.started_at)

    def close(self):
        if self._status is not None:
            return self._status
        try:
            self.upload.commit()
        except (OSError, DatastoreError) as exc:
            self.abort(str(exc))
            return paramiko.SFTP_FAILURE
        self._status = paramiko.SFTP_OK
        self.context.record("SFTP", "upload", self.requested, "success",
                            stored_filename=self.destination.name, bytes=self.total, message="", started_at=self.started_at)
        return self._status


class ReadHandle(paramiko.SFTPHandle):
    """Count bytes actually read; report completion only on explicit CLOSE."""
    def __init__(self, context, path):
        super().__init__()
        self.context, self.requested = context, path
        self.started_at = time.time()
        self.target = context.path(path)
        descriptor = os.open(self.target, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise OSError("Only regular files can be downloaded.")
        self.readfile = os.fdopen(descriptor, "rb")
        self.size = metadata.st_size
        self.total = self.covered = 0
        self.finished = False

    def read(self, offset, length):
        data = super().read(offset, min(length, SFTP_READ_BYTES))
        if isinstance(data, bytes):
            self.total += len(data)
            if offset <= self.covered:
                self.covered = max(self.covered, offset + len(data))
        return data

    def _finish(self, explicit):
        if self.finished:
            return paramiko.SFTP_OK
        self.finished = True
        super().close()
        complete = explicit and self.covered >= self.size
        self.context.record("SFTP", "download", self.requested,
                            "success" if complete else "error", stored_filename=self.target.name,
                            bytes=self.total, started_at=self.started_at,
                            message="" if complete else "Download closed without a confirmed complete sequential read.")
        return paramiko.SFTP_OK

    def close(self):
        return self._finish(True)

    def abort(self):
        return self._finish(False)


class BoundedSFTPServer(paramiko.SFTPServer):
    """Small adapter for the pinned Paramiko dispatch/handle-table contract."""
    def __init__(self, *args, context, **kwargs):
        super().__init__(*args, context=context, **kwargs)
        context.track_worker(self)

    def _read_packet(self):
        size = struct.unpack(">I", self._read_all(4))[0]
        if not 1 <= size <= SFTP_PACKET_BYTES:
            raise paramiko.SFTPError("SFTP packet exceeds the supported size.")
        data = self._read_all(size)
        return data[0], data[1:]

    def _process(self, operation, request_number, message):
        from paramiko.sftp import CMD_OPEN, CMD_OPENDIR, CMD_CLOSE
        self.server.context.activity.touch(self.sock)
        if operation in {CMD_OPEN, CMD_OPENDIR}:
            if len(self.file_table) + len(self.folder_table) >= self.server.context.settings["max_open_handles"]:
                self._send_status(request_number, paramiko.SFTP_FAILURE, "Open handle limit reached.")
                return
        if operation == CMD_CLOSE:
            handle_id = message.get_binary()
            if handle_id in self.file_table:
                handle = self.file_table.pop(handle_id)
                # Paramiko's default dispatcher ignores close()'s return value.
                status = handle.close()
                self._send_status(request_number, paramiko.SFTP_OK if status is None else status)
            elif handle_id in self.folder_table:
                del self.folder_table[handle_id]
                self._send_status(request_number, paramiko.SFTP_OK)
            else:
                self._send_status(request_number, paramiko.SFTP_BAD_MESSAGE, "Invalid handle")
            return
        return super()._process(operation, request_number, message)


class ContainedSFTP(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, context: TransferContext, **kwargs):
        super().__init__(server, *args, **kwargs); self.context = context
        self._uploads = weakref.WeakSet()

    def session_ended(self):
        # Paramiko subsequently closes its handle table. Invalidate unfinished
        # uploads first so that cleanup cannot publish partial files.
        for handle in list(self._uploads):
            handle.abort()

    def list_folder(self, path):
        if not self.context.settings["allow_read"]: return paramiko.SFTP_PERMISSION_DENIED
        try:
            folder = self.context.root if path in {"", "/", "."} else self.context.path(path)
            values = []
            for item in folder.iterdir():
                if item.is_symlink(): continue
                if len(values) >= self.context.settings["max_directory_entries"]:
                    return paramiko.SFTP_FAILURE
                attributes = paramiko.SFTPAttributes.from_stat(item.stat()); attributes.filename = item.name; values.append(attributes)
            return values
        except OSError: return paramiko.SFTP_FAILURE

    def stat(self, path):
        try:
            target = self.context.root if path in {"", "/", "."} else self.context.path(path)
            return paramiko.SFTPAttributes.from_stat(target.stat())
        except OSError: return paramiko.SFTP_NO_SUCH_FILE
    lstat = stat

    def open(self, path, flags, attr):
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        if writing:
            if not self.context.settings["allow_write"]: return paramiko.SFTP_PERMISSION_DENIED
            if flags & (os.O_APPEND | os.O_RDWR):
                return paramiko.SFTP_OP_UNSUPPORTED
            try:
                handle = AtomicWriteHandle(
                    self.context, path,
                    overwrite=self.context.settings["allow_overwrite"] and bool(flags & os.O_TRUNC) and not bool(flags & os.O_EXCL),
                )
                self._uploads.add(handle)
                return handle
            except (OSError, DatastoreError) as exc:
                self.context.record("SFTP", "upload", path, "error", stored_filename="", bytes=0, message=str(exc)); return paramiko.SFTP_FAILURE
        if not self.context.settings["allow_read"]: return paramiko.SFTP_PERMISSION_DENIED
        try:
            handle = ReadHandle(self.context, path)
            self._uploads.add(handle)
            return handle
        except OSError as exc:
            self.context.record("SFTP", "download", path, "error", stored_filename="", bytes=0, message=str(exc)); return paramiko.SFTP_NO_SUCH_FILE


class TransferServer(paramiko.ServerInterface):
    def __init__(self, context: TransferContext): self.context = context
    def check_auth_password(self, username, password):
        from werkzeug.security import check_password_hash
        valid = username == self.context.settings["username"] and check_password_hash(self.context.settings["password_hash"], password)
        return paramiko.AUTH_SUCCESSFUL if valid else paramiko.AUTH_FAILED
    def get_allowed_auths(self, username): return "password"
    def check_channel_request(self, kind, chanid):
        if kind == "session" and self.context.activity.admit(chanid):
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_shell_request(self, channel): return False
    def check_channel_subsystem_request(self, channel, name):
        if not self.context.settings["allow_sftp"] or name != "sftp":
            return False
        if not self.context.activity.start_service(channel):
            return False
        channel.settimeout(self.context.settings["idle_timeout_seconds"])
        self.context.activity.touch(channel)
        return super().check_channel_subsystem_request(channel, name)
    def check_channel_exec_request(self, channel, command):
        if not self.context.settings["allow_scp"]: return False
        try: parts = shlex.split(command.decode() if isinstance(command, bytes) else command)
        except ValueError: return False
        if len(parts) != 3 or parts[0] != "scp" or parts[1] not in {"-f", "-t"}: return False
        if not self.context.activity.start_service(channel):
            return False
        channel.settimeout(self.context.settings.get("idle_timeout_seconds", CLIENT_IDLE_TIMEOUT_SECONDS))
        handler = _scp_send if parts[1] == "-f" else _scp_receive
        worker = threading.Thread(target=handler, args=(ActiveChannel(channel, self.context.activity), self.context, parts[2]), daemon=True)
        self.context.track_worker(worker)
        worker.start()
        return True


def _recv_exact(channel, size):
    value = bytearray()
    while len(value) < size:
        chunk = channel.recv(size - len(value))
        if not chunk: raise OSError("Connection closed.")
        value.extend(chunk)
    return bytes(value)


def _read_line(channel, limit=8192):
    value = bytearray()
    while len(value) < limit:
        byte = _recv_exact(channel, 1); value.extend(byte)
        if byte == b"\n": return bytes(value)
    raise OSError("Protocol line too long.")


def _scp_send(channel, context: TransferContext, requested: str):
    try:
        if not context.settings["allow_read"]: raise OSError("Downloads disabled.")
        target = context.path(requested)
        if not target.is_file(): raise OSError("File not found.")
        _recv_exact(channel, 1)
        channel.sendall(f"C0600 {target.stat().st_size} {target.name}\n".encode()); _recv_exact(channel, 1)
        with target.open("rb") as source:
            while chunk := source.read(1024 * 1024): channel.sendall(chunk)
        channel.sendall(b"\x00"); _recv_exact(channel, 1)
        context.record("SCP", "download", requested, "success", stored_filename=target.name, bytes=target.stat().st_size, message="")
    except Exception as exc:
        try: channel.sendall(b"\x01" + str(exc).encode()[:1000] + b"\n")
        except Exception: pass
        context.record("SCP", "download", requested, "error", stored_filename="", bytes=0, message=str(exc))
    finally: channel.close()


def _scp_receive(channel, context: TransferContext, requested: str):
    upload = None; total = 0
    try:
        if not context.settings["allow_write"]: raise OSError("Uploads disabled.")
        channel.sendall(b"\x00"); header = _read_line(channel)
        if not header.startswith(b"C"): raise OSError("Only regular files are accepted.")
        _mode, size_text, sent_name = header.decode(errors="replace").rstrip("\n").split(" ", 2)
        size = int(size_text)
        if size < 0 or size > context.store.upload_limit(): raise OSError("File exceeds upload limit.")
        destination = context.path(sent_name or requested, write=True)
        upload = context.store.begin_upload(
            context.store.relative(destination.parent), destination.name,
            overwrite=context.settings["allow_overwrite"],
            expected_bytes=size,
        )
        channel.sendall(b"\x00")
        remaining = size
        while remaining:
            chunk = channel.recv(min(1024 * 1024, remaining))
            if not chunk: raise OSError("Connection closed during upload.")
            upload.write(chunk); remaining -= len(chunk); total += len(chunk)
        if _recv_exact(channel, 1) != b"\x00": raise OSError("Remote SCP client reported failure.")
        upload.commit()
        channel.sendall(b"\x00")
        context.record("SCP", "upload", sent_name, "success", stored_filename=destination.name, bytes=total, message="")
    except Exception as exc:
        try: channel.sendall(b"\x01" + str(exc).encode()[:1000] + b"\n")
        except Exception: pass
        context.record("SCP", "upload", requested, "error", stored_filename="", bytes=total, message=str(exc))
    finally:
        if upload is not None: upload.abort()
        channel.close()


def serve(
    instance: str,
    stop: threading.Event,
    on_ready: Callable[[], None] | None = None,
) -> None:
    settings = SSHTransferSettingsStore(instance).get()
    key = ensure_ssh_host_key(instance)
    family = socket.AF_INET6 if ":" in settings["bind_host"] else socket.AF_INET
    trusted = [ipaddress.ip_network(value) for value in settings["allowed_networks"]]
    admission = ConnectionAdmission(settings["max_connections"], settings["max_connections_per_ip"])
    workers = set()

    def handle(client, client_ip, accepted_at):
        transport = None
        context = None
        try:
            context = TransferContext(instance, settings, client_ip)
            transport = paramiko.Transport(client, disabled_algorithms=disabled_ssh_algorithms(
                allow_legacy_algorithms=bool(settings["allow_legacy_algorithms"])))
            transport.banner_timeout = settings["authentication_timeout_seconds"]
            transport.handshake_timeout = settings["authentication_timeout_seconds"]
            transport.add_server_key(key)
            transport.set_subsystem_handler("sftp", BoundedSFTPServer, ContainedSFTP, context=context)
            transport.start_server(event=threading.Event(), server=TransferServer(context))
            authenticated = False
            while transport.is_active() and not stop.is_set():
                if not authenticated:
                    if transport.is_authenticated():
                        authenticated = True
                        context.activity.touch()
                    elif time.monotonic() - accepted_at >= settings["authentication_timeout_seconds"]:
                        break
                channel = transport.accept(0.1)
                if channel is not None:
                    context.activity.bind(channel)
                if authenticated and context.activity.expire(settings["idle_timeout_seconds"]):
                    break
        except (OSError, EOFError, paramiko.SSHException):
            logger.debug("SSH transfer connection ended", exc_info=True)
        finally:
            if transport is not None:
                transport.close()
                # Transport.join prevents new subsystem/exec workers from being
                # started after the cleanup snapshot. Keep the admission slot
                # until all owned workers have released their files/reservations.
                if transport.ident is not None:
                    transport.join()
            if context is not None:
                context.join_workers()
            client.close()
            admission.release(client)

    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((settings["bind_host"], settings["port"]))
        listener.listen(settings["max_connections"])
        listener.settimeout(0.2)
        try:
            if on_ready is not None:
                on_ready()
            resource_limited = False
            while not stop.is_set():
                try:
                    client, address = listener.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    if exc.errno not in {errno.EMFILE, errno.ENFILE}:
                        raise
                    if not resource_limited:
                        logger.warning("SSH transfer admission paused: file descriptor capacity exhausted.")
                    resource_limited = True
                    stop.wait(0.2)
                    continue
                resource_limited = False
                client_ip = address[0]
                if not any(ipaddress.ip_address(client_ip) in network for network in trusted) or not admission.acquire(client, client_ip):
                    client.close()
                    continue
                workers = {worker for worker in workers if worker.is_alive()}
                worker = threading.Thread(target=handle, args=(client, client_ip, time.monotonic()), daemon=True)
                try:
                    worker.start()
                except BaseException:
                    admission.release(client)
                    client.close()
                    raise
                workers.add(worker)
        finally:
            admission.close()
            deadline = time.monotonic() + 5
            for worker in workers:
                worker.join(max(0, deadline - time.monotonic()))


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--instance", required=True); parser.add_argument("--pid-file", required=True); parser.add_argument("--ready-file", default=""); parser.add_argument("--log-file", required=True); parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    singleton = acquire_singleton_lock(
        Path(args.instance).resolve(), "ssh-transfer",
    )
    if singleton is None:
        return 0
    if args.daemon: _daemonize(args.pid_file, args.log_file)
    record_lock_owner(singleton)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set()); signal.signal(signal.SIGINT, lambda *_: stop.set())
    write_pid_file(args.pid_file)
    try: serve(args.instance, stop, lambda: write_pid_file(args.ready_file))
    finally:
        remove_own_pid_file(args.ready_file)
        remove_own_pid_file(args.pid_file)
        singleton.close()
    return 0


def _daemonize(pid_file: str, log_file: str) -> None:
    first = os.fork()
    if first > 0: os._exit(0)
    os.setsid(); second = os.fork()
    if second > 0: os._exit(0)
    os.chdir("/"); os.umask(0o077)
    stdin_fd = os.open(os.devnull, os.O_RDONLY)
    path = Path(log_file); path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(stdin_fd, sys.stdin.fileno()); os.dup2(log_fd, sys.stdout.fileno()); os.dup2(log_fd, sys.stderr.fileno())
    os.close(stdin_fd); os.close(log_fd)


if __name__ == "__main__": raise SystemExit(main())
