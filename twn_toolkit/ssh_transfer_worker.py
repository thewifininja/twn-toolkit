from __future__ import annotations

import argparse
import ipaddress
import os
import secrets
import shlex
import signal
import socket
import threading
import time
import sys
from pathlib import Path
from typing import Any

import paramiko

from .datastore import DatastoreError, LocalDatastore, MAX_UPLOAD_BYTES
from .ssh_transfer_server import (
    SSHTransferHistoryStore, SSHTransferSettingsStore, ensure_ssh_host_key,
)
from .tftp import format_incoming_filename
from .pidfiles import remove_own_pid_file, write_pid_file


class TransferContext:
    def __init__(self, instance: str, settings: dict[str, Any], client_ip: str) -> None:
        self.instance, self.settings, self.client_ip = instance, settings, client_ip
        self.history = SSHTransferHistoryStore(instance)
        self.store = LocalDatastore(instance, "ssh_transfer_runtime" if settings["root_mode"] == "temporary" else "datastore")
        self.root = self.store.folder("") if settings["root_mode"] == "temporary" else self.store.folder(settings["datastore_root"])

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
        self.history.record(client=self.client_ip, protocol=protocol, operation=operation,
                            filename=filename, status=status, **extra)


class AtomicWriteHandle(paramiko.SFTPHandle):
    def __init__(self, context: TransferContext, requested: str) -> None:
        super().__init__()
        self.context, self.requested, self.total, self.failed = context, requested, 0, False
        self.destination = context.path(requested, write=True)
        if self.destination.exists() and not context.settings["allow_overwrite"]:
            raise OSError("Destination already exists.")
        self.temporary = self.destination.with_name(f".{self.destination.name}.{os.getpid()}.{threading.get_ident()}.part")
        self.file = self.temporary.open("wb")

    def write(self, offset: int, data: bytes):
        if offset != self.file.tell(): return paramiko.SFTP_BAD_MESSAGE
        self.total += len(data)
        if self.total > MAX_UPLOAD_BYTES:
            self.failed = True
            return paramiko.SFTP_FAILURE
        self.file.write(data); return paramiko.SFTP_OK

    def close(self):
        try:
            self.file.flush(); os.fsync(self.file.fileno()); self.file.close()
            if self.failed:
                raise OSError("File exceeds upload limit.")
            os.chmod(self.temporary, 0o600); os.replace(self.temporary, self.destination)
            self.context.record("SFTP", "upload", self.requested, "success", stored_filename=self.destination.name, bytes=self.total, message="")
            return paramiko.SFTP_OK
        except Exception as exc:
            self.context.record("SFTP", "upload", self.requested, "error", stored_filename="", bytes=self.total, message=str(exc))
            return paramiko.SFTP_FAILURE
        finally:
            if self.temporary.exists(): self.temporary.unlink()


class ContainedSFTP(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, context: TransferContext, **kwargs):
        super().__init__(server, *args, **kwargs); self.context = context

    def list_folder(self, path):
        if not self.context.settings["allow_read"]: return paramiko.SFTP_PERMISSION_DENIED
        try:
            folder = self.context.root if path in {"", "/", "."} else self.context.path(path)
            values = []
            for item in folder.iterdir():
                if item.is_symlink(): continue
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
            try: return AtomicWriteHandle(self.context, path)
            except OSError as exc:
                self.context.record("SFTP", "upload", path, "error", stored_filename="", bytes=0, message=str(exc)); return paramiko.SFTP_FAILURE
        if not self.context.settings["allow_read"]: return paramiko.SFTP_PERMISSION_DENIED
        try:
            target = self.context.path(path); handle = paramiko.SFTPHandle(flags); handle.readfile = target.open("rb")
            self.context.record("SFTP", "download", path, "success", stored_filename=target.name, bytes=target.stat().st_size, message="")
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
    def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_shell_request(self, channel): return False
    def check_channel_subsystem_request(self, channel, name):
        return self.context.settings["allow_sftp"] and name == "sftp" and super().check_channel_subsystem_request(channel, name)
    def check_channel_exec_request(self, channel, command):
        if not self.context.settings["allow_scp"]: return False
        try: parts = shlex.split(command.decode() if isinstance(command, bytes) else command)
        except ValueError: return False
        if len(parts) != 3 or parts[0] != "scp" or parts[1] not in {"-f", "-t"}: return False
        handler = _scp_send if parts[1] == "-f" else _scp_receive
        threading.Thread(target=handler, args=(channel, self.context, parts[2]), daemon=True).start(); return True


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
    temporary = None; total = 0
    try:
        if not context.settings["allow_write"]: raise OSError("Uploads disabled.")
        channel.sendall(b"\x00"); header = _read_line(channel)
        if not header.startswith(b"C"): raise OSError("Only regular files are accepted.")
        _mode, size_text, sent_name = header.decode(errors="replace").rstrip("\n").split(" ", 2)
        size = int(size_text)
        if size < 0 or size > MAX_UPLOAD_BYTES: raise OSError("File exceeds upload limit.")
        destination = context.path(sent_name or requested, write=True)
        if destination.exists() and not context.settings["allow_overwrite"]: raise OSError("Destination already exists.")
        temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(6)}.part")
        channel.sendall(b"\x00")
        with temporary.open("wb") as target:
            remaining = size
            while remaining:
                chunk = channel.recv(min(1024 * 1024, remaining))
                if not chunk: raise OSError("Connection closed during upload.")
                target.write(chunk); remaining -= len(chunk); total += len(chunk)
        if _recv_exact(channel, 1) != b"\x00": raise OSError("Remote SCP client reported failure.")
        os.chmod(temporary, 0o600); os.replace(temporary, destination); channel.sendall(b"\x00")
        context.record("SCP", "upload", sent_name, "success", stored_filename=destination.name, bytes=total, message="")
    except Exception as exc:
        try: channel.sendall(b"\x01" + str(exc).encode()[:1000] + b"\n")
        except Exception: pass
        context.record("SCP", "upload", requested, "error", stored_filename="", bytes=total, message=str(exc))
    finally:
        if temporary and temporary.exists(): temporary.unlink()
        channel.close()


def serve(instance: str, stop: threading.Event) -> None:
    settings = SSHTransferSettingsStore(instance).get(); key = ensure_ssh_host_key(instance)
    family = socket.AF_INET6 if ":" in settings["bind_host"] else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((settings["bind_host"], settings["port"])); listener.listen(50); listener.settimeout(1)
    trusted = [ipaddress.ip_network(value) for value in settings["allowed_networks"]]
    while not stop.is_set():
        try: client, address = listener.accept()
        except socket.timeout: continue
        client_ip = address[0]
        if not any(ipaddress.ip_address(client_ip) in network for network in trusted): client.close(); continue
        def handle(sock=client, ip=client_ip):
            transport = None
            try:
                context = TransferContext(instance, settings, ip); transport = paramiko.Transport(sock); transport.add_server_key(key)
                transport.set_subsystem_handler("sftp", paramiko.SFTPServer, ContainedSFTP, context=context)
                transport.start_server(server=TransferServer(context))
                while transport.is_active() and not stop.wait(0.5): pass
            finally:
                if transport: transport.close()
                sock.close()
        threading.Thread(target=handle, daemon=True).start()
    listener.close()


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--instance", required=True); parser.add_argument("--pid-file", required=True); parser.add_argument("--log-file", required=True); parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    if args.daemon: _daemonize(args.pid_file, args.log_file)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set()); signal.signal(signal.SIGINT, lambda *_: stop.set())
    write_pid_file(args.pid_file)
    try: serve(args.instance, stop)
    finally: remove_own_pid_file(args.pid_file)
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
