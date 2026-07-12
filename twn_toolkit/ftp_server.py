from __future__ import annotations

import ipaddress
import json
import os
import secrets
from pathlib import Path
from typing import Any

from werkzeug.security import generate_password_hash

from .tftp import validate_incoming_filename_pattern


DEFAULT_FTP_SETTINGS = {
    "enabled": False, "bind_host": "127.0.0.1", "port": 2121,
    "passive_start": 30000, "passive_end": 30049, "username": "toolkit",
    "max_connections": 50, "max_connections_per_ip": 5,
    "password_hash": "", "allow_read": True, "allow_write": False,
    "allow_overwrite": False, "root_mode": "datastore", "datastore_root": "",
    "incoming_filename_pattern": "{filename}",
    "allowed_networks": ["127.0.0.0/8", "::1/128"],
}


class FTPSettingsStore:
    def __init__(self, instance_path: str) -> None: self.path = Path(instance_path) / "ftp_settings.json"
    def get(self) -> dict[str, Any]:
        try: raw = json.loads(self.path.read_text())
        except (FileNotFoundError, OSError, json.JSONDecodeError): return dict(DEFAULT_FTP_SETTINGS)
        return self.validate({**DEFAULT_FTP_SETTINGS, **raw})
    def save(self, value: dict[str, Any], password: str = "") -> dict[str, Any]:
        candidate = {**self.get(), **value}
        if password:
            if len(password) < 12: raise ValueError("FTP passwords must be at least 12 characters.")
            candidate["password_hash"] = generate_password_hash(password)
        settings = self.validate(candidate)
        if settings["enabled"] and not settings["password_hash"]: raise ValueError("Set a password before enabling FTP.")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(6)}.tmp")
        temporary.write_text(json.dumps(settings, indent=2) + "\n"); os.chmod(temporary, 0o600); os.replace(temporary, self.path)
        return settings
    @staticmethod
    def validate(value: dict[str, Any]) -> dict[str, Any]:
        bind = str(value.get("bind_host", "")).strip()
        try: ipaddress.ip_address(bind)
        except ValueError as exc: raise ValueError("FTP bind address must be IPv4 or IPv6.") from exc
        try:
            port, start, end = int(value.get("port", 2121)), int(value.get("passive_start", 30000)), int(value.get("passive_end", 30049))
            max_connections = int(value.get("max_connections", 50)); max_per_ip = int(value.get("max_connections_per_ip", 5))
        except (TypeError, ValueError) as exc: raise ValueError("FTP ports must be whole numbers.") from exc
        if not 1 <= port <= 65535 or not 1 <= start <= end <= 65535 or end - start > 500:
            raise ValueError("FTP control/passive ports must be valid; passive range may contain at most 501 ports.")
        if not 1 <= max_connections <= 500 or not 1 <= max_per_ip <= max_connections:
            raise ValueError("FTP connection limits must allow 1–500 total connections and no more per client than the total.")
        username = str(value.get("username", "")).strip()
        if not username or len(username) > 64 or any(c.isspace() for c in username): raise ValueError("FTP username must be 1–64 characters without spaces.")
        networks = []; raw = value.get("allowed_networks", [])
        if isinstance(raw, str): raw = raw.replace(",", "\n").splitlines()
        for item in raw:
            if str(item).strip():
                try: networks.append(str(ipaddress.ip_network(str(item).strip(), strict=False)))
                except ValueError as exc: raise ValueError(f"Invalid trusted FTP network: {item}") from exc
        if not networks: raise ValueError("Enter at least one trusted FTP network.")
        mode = str(value.get("root_mode", "datastore")); write = bool(value.get("allow_write"))
        if mode not in {"datastore", "temporary"}: raise ValueError("Choose a datastore or temporary FTP root.")
        if mode == "temporary" and write: raise ValueError("Temporary FTP mode is download-only.")
        root = str(value.get("datastore_root", "")).replace("\\", "/").strip("/")
        if any(part == ".." for part in Path(root).parts): raise ValueError("FTP datastore root is invalid.")
        return {"enabled": bool(value.get("enabled")), "bind_host": bind, "port": port,
                "passive_start": start, "passive_end": end, "username": username,
                "max_connections": max_connections, "max_connections_per_ip": max_per_ip,
                "password_hash": str(value.get("password_hash", "")), "allow_read": bool(value.get("allow_read")),
                "allow_write": write, "allow_overwrite": bool(value.get("allow_overwrite")) and write,
                "root_mode": mode, "datastore_root": root,
                "incoming_filename_pattern": validate_incoming_filename_pattern(str(value.get("incoming_filename_pattern", "{filename}"))),
                "allowed_networks": networks}


def ftp_process_status(instance_path: str) -> dict[str, Any]:
    path = Path(instance_path) / "twn-ftp.pid"
    try: pid = int(path.read_text().strip()); os.kill(pid, 0)
    except (FileNotFoundError, OSError, ValueError): return {"running": False, "pid": None}
    return {"running": True, "pid": pid}


def clear_ftp_runtime(instance_path: str) -> None:
    from .datastore import LocalDatastore
    LocalDatastore(instance_path, "ftp_runtime").clear()
