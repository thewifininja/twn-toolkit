from __future__ import annotations

import ipaddress
import json
import os
import secrets
import shlex
import socket
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash

from .datastore import DatastoreError, LocalDatastore, MAX_UPLOAD_BYTES
from .tftp import format_incoming_filename, validate_incoming_filename_pattern


DEFAULT_SSH_TRANSFER_SETTINGS = {
    "enabled": False, "bind_host": "127.0.0.1", "port": 2022,
    "username": "toolkit", "password_hash": "", "allow_sftp": True,
    "allow_scp": True, "allow_read": True, "allow_write": False,
    "allow_overwrite": False, "root_mode": "datastore", "datastore_root": "",
    "allow_legacy_algorithms": False,
    "incoming_filename_pattern": "{filename}",
    "allowed_networks": ["127.0.0.0/8", "::1/128"],
}


class SSHTransferSettingsStore:
    def __init__(self, instance_path: str) -> None:
        self.path = Path(instance_path) / "ssh_transfer_settings.json"

    def get(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return dict(DEFAULT_SSH_TRANSFER_SETTINGS)
        return self.validate({**DEFAULT_SSH_TRANSFER_SETTINGS, **raw})

    def save(self, value: dict[str, Any], password: str = "") -> dict[str, Any]:
        existing = self.get()
        candidate = {**existing, **value}
        if password:
            if len(password) < 12:
                raise ValueError("SSH transfer passwords must be at least 12 characters.")
            candidate["password_hash"] = generate_password_hash(password)
        settings = self.validate(candidate)
        if settings["enabled"] and not settings["password_hash"]:
            raise ValueError("Set a service password before enabling SSH file transfers.")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(6)}.tmp")
        temporary.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
        return settings

    @staticmethod
    def validate(value: dict[str, Any]) -> dict[str, Any]:
        bind_host = str(value.get("bind_host", "")).strip()
        try: ipaddress.ip_address(bind_host)
        except ValueError as exc: raise ValueError("SSH transfer bind address must be IPv4 or IPv6.") from exc
        try: port = int(value.get("port", 2022))
        except (TypeError, ValueError) as exc: raise ValueError("SSH transfer port must be 1–65535.") from exc
        if not 1 <= port <= 65535: raise ValueError("SSH transfer port must be 1–65535.")
        username = str(value.get("username", "")).strip()
        if not 1 <= len(username) <= 64 or any(character.isspace() for character in username):
            raise ValueError("SSH transfer username must be 1–64 characters without spaces.")
        networks = []
        raw_networks = value.get("allowed_networks", [])
        if isinstance(raw_networks, str): raw_networks = raw_networks.replace(",", "\n").splitlines()
        for raw in raw_networks:
            if str(raw).strip():
                try: networks.append(str(ipaddress.ip_network(str(raw).strip(), strict=False)))
                except ValueError as exc: raise ValueError(f"Invalid trusted SSH transfer network: {raw}") from exc
        if not networks: raise ValueError("Enter at least one trusted SSH transfer client network.")
        root_mode = str(value.get("root_mode", "datastore"))
        if root_mode not in {"datastore", "temporary"}: raise ValueError("Choose a datastore or temporary root.")
        allow_read, allow_write = bool(value.get("allow_read")), bool(value.get("allow_write"))
        if root_mode == "temporary" and allow_write: raise ValueError("Temporary-file mode is download-only.")
        enabled = bool(value.get("enabled"))
        allow_sftp, allow_scp = bool(value.get("allow_sftp")), bool(value.get("allow_scp"))
        if enabled and not (allow_sftp or allow_scp): raise ValueError("Enable SFTP, SCP, or both.")
        if enabled and not (allow_read or allow_write): raise ValueError("Enable downloads, uploads, or both.")
        datastore_root = str(value.get("datastore_root", "")).replace("\\", "/").strip("/")
        if any(part == ".." for part in Path(datastore_root).parts): raise ValueError("Datastore root is invalid.")
        return {
            "enabled": enabled, "bind_host": bind_host, "port": port,
            "username": username, "password_hash": str(value.get("password_hash", "")),
            "allow_sftp": allow_sftp, "allow_scp": allow_scp,
            "allow_read": allow_read, "allow_write": allow_write,
            "allow_legacy_algorithms": bool(value.get("allow_legacy_algorithms", False)),
            "allow_overwrite": bool(value.get("allow_overwrite")) and allow_write,
            "root_mode": root_mode, "datastore_root": datastore_root,
            "incoming_filename_pattern": validate_incoming_filename_pattern(str(value.get("incoming_filename_pattern", "{filename}"))),
            "allowed_networks": networks,
        }


class SSHTransferHistoryStore:
    def __init__(self, instance_path: str) -> None:
        self.path = Path(instance_path) / "ssh_transfer_history.sqlite3"
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS transfers
                (id TEXT PRIMARY KEY, started_at REAL NOT NULL, client TEXT NOT NULL,
                 protocol TEXT NOT NULL, operation TEXT NOT NULL, filename TEXT NOT NULL,
                 stored_filename TEXT NOT NULL, bytes INTEGER NOT NULL, status TEXT NOT NULL,
                 message TEXT NOT NULL)""")

    def record(self, **values: Any) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO transfers VALUES (?,?,?,?,?,?,?,?,?,?)", (
                secrets.token_hex(12), values.get("started_at", time.time()), values["client"],
                values["protocol"], values["operation"], values["filename"],
                values.get("stored_filename", values["filename"]), values.get("bytes", 0),
                values["status"], values.get("message", ""),
            ))
            connection.execute(
                "DELETE FROM transfers WHERE UPPER(protocol)=UPPER(?) AND id NOT IN "
                "(SELECT id FROM transfers WHERE UPPER(protocol)=UPPER(?) ORDER BY started_at DESC LIMIT 1000)",
                (values["protocol"], values["protocol"]),
            )

    def recent(self, limit: int = 25, protocols: set[str] | None = None) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if not protocols:
                rows = connection.execute("SELECT * FROM transfers ORDER BY started_at DESC LIMIT ?", (limit,))
            else:
                normalized = sorted({str(value).upper() for value in protocols})
                placeholders = ",".join("?" for _ in normalized)
                rows = connection.execute(
                    f"SELECT * FROM transfers WHERE UPPER(protocol) IN ({placeholders}) ORDER BY started_at DESC LIMIT ?",
                    (*normalized, limit),
                )
            return [dict(row) for row in rows]

    def clear(self, protocols: set[str] | None = None) -> int:
        with self._connect() as connection:
            if not protocols:
                return int(connection.execute("DELETE FROM transfers").rowcount)
            normalized = sorted({str(value).upper() for value in protocols})
            placeholders = ",".join("?" for _ in normalized)
            return int(connection.execute(
                f"DELETE FROM transfers WHERE UPPER(protocol) IN ({placeholders})",
                normalized,
            ).rowcount)

    @contextmanager
    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            yield connection; connection.commit()
        finally: connection.close()


def ssh_transfer_process_status(instance_path: str) -> dict[str, Any]:
    pid_path = Path(instance_path) / "twn-ssh-transfer.pid"
    try:
        pid = int(pid_path.read_text().strip()); os.kill(pid, 0)
    except (FileNotFoundError, OSError, ValueError): return {"running": False, "pid": None}
    return {"running": True, "pid": pid}


def ensure_ssh_host_key(instance_path: str):
    import paramiko
    path = Path(instance_path) / "ssh_transfer_host_key"
    if path.exists(): return paramiko.RSAKey.from_private_key_file(str(path))
    key = paramiko.RSAKey.generate(3072); key.write_private_key_file(str(path)); os.chmod(path, 0o600); return key


def transfer_root(instance_path: str, settings: dict[str, Any]) -> LocalDatastore:
    store = LocalDatastore(instance_path, "ssh_transfer_runtime" if settings["root_mode"] == "temporary" else "datastore")
    if settings["root_mode"] == "datastore": store.list(settings["datastore_root"])
    return store


def clear_ssh_transfer_runtime(instance_path: str) -> None:
    LocalDatastore(instance_path, "ssh_transfer_runtime").clear()
