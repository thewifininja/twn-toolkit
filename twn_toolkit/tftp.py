from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import struct
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from string import Formatter
from typing import Any

from .datastore import DatastoreError, LocalDatastore, MAX_UPLOAD_BYTES


DEFAULT_SETTINGS = {
    "enabled": False,
    "bind_host": "127.0.0.1",
    "port": 1069,
    "allow_read": True,
    "allow_write": False,
    "allow_overwrite": False,
    "root_mode": "datastore",
    "datastore_root": "",
    "incoming_filename_pattern": "{filename}",
    "allowed_networks": ["127.0.0.0/8", "::1/128"],
}


class TFTPSettingsStore:
    def __init__(self, instance_path: str) -> None:
        self.path = Path(instance_path) / "tftp_settings.json"

    def get(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return dict(DEFAULT_SETTINGS)
        return self.validate({**DEFAULT_SETTINGS, **raw})

    def save(self, value: dict[str, Any]) -> dict[str, Any]:
        settings = self.validate(value)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(6)}.tmp")
        temporary.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
        return settings

    @staticmethod
    def validate(value: dict[str, Any]) -> dict[str, Any]:
        bind_host = str(value.get("bind_host", "")).strip()
        try:
            ipaddress.ip_address(bind_host)
        except ValueError as exc:
            raise ValueError("TFTP bind address must be a specific IPv4 or IPv6 address.") from exc
        try:
            port = int(value.get("port", 1069))
        except (TypeError, ValueError) as exc:
            raise ValueError("TFTP port must be a whole number from 1–65535.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("TFTP port must be a whole number from 1–65535.")
        networks = []
        raw_networks = value.get("allowed_networks", [])
        if isinstance(raw_networks, str):
            raw_networks = raw_networks.replace(",", "\n").splitlines()
        for raw in raw_networks:
            text = str(raw).strip()
            if not text:
                continue
            try:
                networks.append(str(ipaddress.ip_network(text, strict=False)))
            except ValueError as exc:
                raise ValueError(f"Invalid trusted TFTP address or network: {text}") from exc
        if not networks:
            raise ValueError("Enter at least one trusted TFTP client address or network.")
        enabled = bool(value.get("enabled", False))
        allow_read = bool(value.get("allow_read", False))
        allow_write = bool(value.get("allow_write", False))
        if enabled and not (allow_read or allow_write):
            raise ValueError("Enable TFTP reads, writes, or both before starting the service.")
        root_mode = str(value.get("root_mode", "datastore")).strip()
        if root_mode not in {"datastore", "temporary"}:
            raise ValueError("Choose a datastore folder or temporary-file TFTP root.")
        if root_mode == "temporary" and allow_write:
            raise ValueError("Temporary-file mode is download-only; disable TFTP uploads.")
        datastore_root = str(value.get("datastore_root", "")).replace("\\", "/").strip("/")
        if datastore_root in {".", ".."} or any(part == ".." for part in Path(datastore_root).parts):
            raise ValueError("The selected TFTP datastore folder is invalid.")
        pattern = validate_incoming_filename_pattern(
            str(value.get("incoming_filename_pattern", "{filename}"))
        )
        return {
            "enabled": enabled,
            "bind_host": bind_host,
            "port": port,
            "allow_read": allow_read,
            "allow_write": allow_write,
            "allow_overwrite": bool(value.get("allow_overwrite", False)) and allow_write,
            "root_mode": root_mode,
            "datastore_root": datastore_root,
            "incoming_filename_pattern": pattern,
            "allowed_networks": networks,
        }


class TFTPHistoryStore:
    def __init__(self, instance_path: str) -> None:
        self.path = Path(instance_path) / "tftp_history.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS transfers (
                    id TEXT PRIMARY KEY,
                    started_at REAL NOT NULL,
                    finished_at REAL NOT NULL,
                    client TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL DEFAULT '',
                    bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS transfers_recent ON transfers(started_at DESC);
                """
            )
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(transfers)")
            }
            if "stored_filename" not in columns:
                connection.execute(
                    "ALTER TABLE transfers ADD COLUMN stored_filename TEXT NOT NULL DEFAULT ''"
                )

    def record(self, **values: Any) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO transfers (
                    id, started_at, finished_at, client, operation, filename,
                    stored_filename, bytes, status, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["id"], values["started_at"], values["finished_at"],
                    values["client"], values["operation"], values["filename"],
                    values.get("stored_filename", values["filename"]),
                    values["bytes"], values["status"], values["message"],
                ),
            )
            connection.execute(
                "DELETE FROM transfers WHERE id NOT IN (SELECT id FROM transfers ORDER BY started_at DESC LIMIT 1000)"
            )

    def recent(self, limit: int = 25) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM transfers ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def clear(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("DELETE FROM transfers").rowcount)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
            if self.path.exists():
                os.chmod(self.path, 0o600)


class TFTPServer:
    def __init__(
        self,
        datastore: LocalDatastore,
        history: TFTPHistoryStore,
        settings: dict[str, Any],
        root_prefix: str = "",
    ) -> None:
        self.datastore = datastore
        self.history = history
        self.settings = TFTPSettingsStore.validate(settings)
        self.root_prefix = root_prefix.replace("\\", "/").strip("/")
        self.networks = [ipaddress.ip_network(value) for value in self.settings["allowed_networks"]]
        self.running = True
        self.socket: socket.socket | None = None
        self.transfer_slots = threading.BoundedSemaphore(20)

    def serve_forever(self) -> None:
        bind_ip = ipaddress.ip_address(self.settings["bind_host"])
        family = socket.AF_INET6 if bind_ip.version == 6 else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as listener:
            listener.bind((self.settings["bind_host"], self.settings["port"]))
            listener.settimeout(1.0)
            self.socket = listener
            while self.running:
                try:
                    packet, client = listener.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not self._client_allowed(client[0]):
                    self._send_error(listener, client, 2, "Access denied")
                    continue
                try:
                    request = self._parse_request(packet)
                except ValueError as exc:
                    self._send_error(listener, client, 4, str(exc))
                    continue
                if not self.transfer_slots.acquire(blocking=False):
                    self._send_error(listener, client, 0, "TFTP server is busy")
                    continue
                threading.Thread(
                    target=self._handle_transfer_with_slot,
                    args=(request, client, family),
                    daemon=True,
                ).start()

    def stop(self) -> None:
        self.running = False
        if self.socket:
            self.socket.close()

    def _handle_transfer(
        self, request: dict[str, Any], client: tuple[Any, ...], family: int
    ) -> None:
        started = time.time()
        operation = "read" if request["opcode"] == 1 else "write"
        transferred = 0
        stored_filename = request["filename"]
        status = "error"
        message = "Transfer failed."
        try:
            if operation == "read":
                if not self.settings["allow_read"]:
                    raise PermissionError("TFTP downloads are disabled")
                transferred = self._send_file(request, client, family)
            else:
                if not self.settings["allow_write"]:
                    raise PermissionError("TFTP uploads are disabled")
                transferred, stored_filename = self._receive_file(request, client, family)
            status = "success"
            message = "Transfer completed."
        except (DatastoreError, OSError, PermissionError, TimeoutError, ValueError) as exc:
            message = str(exc) or "Transfer failed."
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as error_socket:
                    self._send_error(
                        error_socket,
                        client,
                        2 if isinstance(exc, (DatastoreError, PermissionError)) else 0,
                        message,
                    )
            except OSError:
                pass
        finally:
            try:
                self.history.record(
                    id=secrets.token_hex(12), started_at=started, finished_at=time.time(),
                    client=str(client[0]), operation=operation, filename=request["filename"],
                    stored_filename=stored_filename,
                    bytes=transferred, status=status, message=message[:500],
                )
            except (OSError, sqlite3.Error):
                pass

    def _handle_transfer_with_slot(
        self, request: dict[str, Any], client: tuple[Any, ...], family: int
    ) -> None:
        try:
            self._handle_transfer(request, client, family)
        finally:
            self.transfer_slots.release()

    def _send_file(self, request: dict[str, Any], client: tuple[Any, ...], family: int) -> int:
        path = self.datastore.file(self._rooted_path(request["filename"]))
        block_size, timeout, oack = self._options(request["options"], path.stat().st_size)
        with socket.socket(family, socket.SOCK_DGRAM) as transfer:
            transfer.connect(client)
            transfer.settimeout(timeout)
            if oack:
                self._exchange(transfer, self._oack(oack), 4, 0)
            block = 1
            total = 0
            with path.open("rb") as source:
                while True:
                    payload = source.read(block_size)
                    self._exchange(transfer, struct.pack("!HH", 3, block) + payload, 4, block)
                    total += len(payload)
                    if len(payload) < block_size:
                        return total
                    block = (block + 1) & 0xFFFF

    def _receive_file(
        self, request: dict[str, Any], client: tuple[Any, ...], family: int
    ) -> tuple[int, str]:
        declared_size = int(request["options"].get("tsize", "0"))
        if declared_size < 0 or declared_size > MAX_UPLOAD_BYTES:
            raise DatastoreError("Declared TFTP upload size exceeds the 1 GiB datastore limit.")
        block_size, timeout, oack = self._options(
            request["options"], declared_size, write=True
        )
        filename = request["filename"].replace("\\", "/").strip("/")
        requested_parent, _, requested_name = filename.rpartition("/")
        pattern = self.settings["incoming_filename_pattern"]
        if pattern == "{filename}":
            parent = self._rooted_path(requested_parent)
            name = requested_name
        else:
            parent = self.root_prefix
            name = format_incoming_filename(
                pattern,
                requested_name,
                str(client[0]),
            )
        if not name:
            raise DatastoreError("A destination filename is required.")
        total = 0
        expected = 1
        with tempfile.TemporaryFile() as temporary, socket.socket(family, socket.SOCK_DGRAM) as transfer:
            transfer.connect(client)
            transfer.settimeout(timeout)
            response = self._oack(oack) if oack else struct.pack("!HH", 4, 0)
            for _attempt in range(6):
                transfer.send(response)
                while True:
                    try:
                        packet = transfer.recv(65535)
                    except socket.timeout:
                        break
                    if len(packet) < 4:
                        continue
                    opcode, block = struct.unpack("!HH", packet[:4])
                    if opcode == 5:
                        raise OSError("Client cancelled the upload.")
                    if opcode != 3:
                        continue
                    if block == ((expected - 1) & 0xFFFF):
                        transfer.send(struct.pack("!HH", 4, block))
                        continue
                    if block != expected:
                        continue
                    payload = packet[4:]
                    total += len(payload)
                    if total > MAX_UPLOAD_BYTES:
                        self._send_error(transfer, None, 3, "Upload exceeds datastore limit")
                        raise DatastoreError("TFTP upload exceeds the 1 GiB datastore limit.")
                    temporary.write(payload)
                    response = struct.pack("!HH", 4, block)
                    if len(payload) < block_size:
                        temporary.seek(0)
                        try:
                            self.datastore.save_upload(
                                parent, name, temporary,
                                overwrite=self.settings["allow_overwrite"],
                            )
                        except DatastoreError as exc:
                            self._send_error(transfer, None, 6, str(exc))
                            raise
                        transfer.send(response)
                        stored = "/".join(part for part in (parent, name) if part)
                        return total, stored
                    transfer.send(response)
                    expected = (expected + 1) & 0xFFFF
                # The expected block timed out; retransmit the last ACK/OACK.
            raise TimeoutError("TFTP upload timed out.")

    def _exchange(
        self, transfer: socket.socket, payload: bytes, expected_opcode: int, expected_block: int
    ) -> None:
        for _attempt in range(6):
            transfer.send(payload)
            try:
                response = transfer.recv(65535)
            except socket.timeout:
                continue
            if len(response) >= 4:
                opcode, block = struct.unpack("!HH", response[:4])
                if opcode == 5:
                    raise OSError("TFTP client reported an error.")
                if opcode == expected_opcode and block == expected_block:
                    return
        raise TimeoutError("TFTP transfer timed out.")

    @staticmethod
    def _parse_request(packet: bytes) -> dict[str, Any]:
        if len(packet) < 4:
            raise ValueError("Malformed TFTP request")
        opcode = struct.unpack("!H", packet[:2])[0]
        if opcode not in {1, 2}:
            raise ValueError("Expected a read or write request")
        fields = packet[2:].split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        if len(fields) < 2:
            raise ValueError("Malformed TFTP request")
        if (len(fields) - 2) % 2:
            raise ValueError("Malformed TFTP option list")
        try:
            filename = fields[0].decode("utf-8")
            mode = fields[1].decode("ascii").lower()
            options = {
                fields[index].decode("ascii").lower(): fields[index + 1].decode("ascii")
                for index in range(2, len(fields) - 1, 2)
            }
        except (UnicodeDecodeError, IndexError) as exc:
            raise ValueError("Malformed TFTP request") from exc
        if mode != "octet":
            raise ValueError("Only octet (binary) transfers are supported")
        if not filename:
            raise ValueError("A filename is required")
        return {"opcode": opcode, "filename": filename, "mode": mode, "options": options}

    @staticmethod
    def _options(
        options: dict[str, str], file_size: int, *, write: bool = False
    ) -> tuple[int, float, dict[str, str]]:
        block_size = 512
        timeout = 3.0
        accepted: dict[str, str] = {}
        if "blksize" in options:
            requested = int(options["blksize"])
            if not 8 <= requested <= 65464:
                raise ValueError("Invalid TFTP block size")
            block_size = requested
            accepted["blksize"] = str(requested)
        if "timeout" in options:
            requested_timeout = int(options["timeout"])
            if not 1 <= requested_timeout <= 10:
                raise ValueError("Invalid TFTP timeout")
            timeout = float(requested_timeout)
            accepted["timeout"] = str(requested_timeout)
        if "tsize" in options:
            accepted["tsize"] = str(int(options["tsize"])) if write else str(file_size)
        return block_size, timeout, accepted

    def _client_allowed(self, value: str) -> bool:
        address = ipaddress.ip_address(value)
        return any(address.version == network.version and address in network for network in self.networks)

    def _rooted_path(self, requested: str) -> str:
        requested = requested.replace("\\", "/").strip("/")
        if any(part == ".." for part in Path(requested).parts):
            raise DatastoreError("The requested TFTP path is outside the configured root.")
        return "/".join(part for part in (self.root_prefix, requested) if part)

    @staticmethod
    def _oack(options: dict[str, str]) -> bytes:
        payload = b"".join(
            key.encode("ascii") + b"\0" + value.encode("ascii") + b"\0"
            for key, value in options.items()
        )
        return struct.pack("!H", 6) + payload

    @staticmethod
    def _send_error(
        target: socket.socket,
        client: tuple[Any, ...] | None,
        code: int,
        message: str,
    ) -> None:
        packet = struct.pack("!HH", 5, code) + message.encode("utf-8", "replace")[:500] + b"\0"
        if client is None:
            target.send(packet)
        else:
            target.sendto(packet, client)


def tftp_process_status(instance_path: str) -> dict[str, Any]:
    pid_path = Path(instance_path) / "twn-tftp.pid"
    pid = 0
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
    except (FileNotFoundError, OSError, ValueError):
        return {"running": False, "pid": None}
    return {"running": True, "pid": pid}


INCOMING_FILENAME_TOKENS = {"timestamp", "client_ip", "filename", "stem", "suffix"}


def validate_incoming_filename_pattern(value: str) -> str:
    pattern = value.strip() or "{filename}"
    if len(pattern) > 200 or "/" in pattern or "\\" in pattern:
        raise ValueError("Incoming filename patterns must be 200 characters or fewer without slashes.")
    try:
        fields = {
            field_name
            for _literal, field_name, format_spec, conversion in Formatter().parse(pattern)
            if field_name
            if not format_spec and not conversion
        }
        if any(field not in INCOMING_FILENAME_TOKENS for field in fields):
            raise ValueError
        format_incoming_filename(pattern, "config.cfg", "192.0.2.10", datetime(2026, 1, 2, 3, 4, 5))
    except (KeyError, ValueError):
        raise ValueError(
            "Incoming filename pattern tokens are {timestamp}, {client_ip}, {filename}, {stem}, and {suffix}."
        ) from None
    return pattern


def format_incoming_filename(
    pattern: str,
    requested_filename: str,
    client_ip: str,
    now: datetime | None = None,
) -> str:
    filename = Path(requested_filename.replace("\\", "/")).name
    if not filename:
        raise DatastoreError("A destination filename is required.")
    path = Path(filename)
    safe_client = "".join(
        character if character.isalnum() or character in {".", "-"} else "_"
        for character in client_ip
    )
    result = pattern.format(
        timestamp=(now or datetime.now()).strftime("%Y%m%d-%H%M%S"),
        client_ip=safe_client,
        filename=filename,
        stem=path.stem,
        suffix=path.suffix,
    )
    return LocalDatastore._validate_name(result)


def clear_tftp_runtime(instance_path: str) -> None:
    LocalDatastore(instance_path, "tftp_runtime").clear()
