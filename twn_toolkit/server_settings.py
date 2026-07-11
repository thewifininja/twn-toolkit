from __future__ import annotations

import ipaddress
import json
import os
import tempfile
import re
from pathlib import Path
from typing import Any


DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_INSTANCE_NAME = ""
DEFAULT_PREFERRED_FQDN = ""
DEFAULT_ALLOWED_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]
ALLOWED_LISTEN_HOSTS = {"127.0.0.1", "0.0.0.0"}
LOOPBACK_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class ServerSettingsStore:
    def __init__(self, instance_path: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "server_settings.json"
        self.previous_path = self.instance_path / "server_settings.previous.json"

    def get(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "listen_host": DEFAULT_LISTEN_HOST,
                "allowed_networks": list(DEFAULT_ALLOWED_NETWORKS),
                "instance_name": DEFAULT_INSTANCE_NAME,
                "preferred_fqdn": DEFAULT_PREFERRED_FQDN,
            }
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(f"Could not read server settings: {exc}") from exc
        listen_host = str(data.get("listen_host", DEFAULT_LISTEN_HOST))
        if listen_host not in ALLOWED_LISTEN_HOSTS:
            listen_host = DEFAULT_LISTEN_HOST
        try:
            networks = normalize_allowed_networks(data.get("allowed_networks", []))
        except ValueError:
            networks = []
        try:
            instance_name = normalize_instance_name(data.get("instance_name", ""))
            preferred_fqdn = normalize_preferred_fqdn(data.get("preferred_fqdn", ""))
        except ValueError:
            instance_name = ""
            preferred_fqdn = ""
        return {
            "listen_host": listen_host,
            "allowed_networks": networks,
            "instance_name": instance_name,
            "preferred_fqdn": preferred_fqdn,
        }

    def save(
        self,
        listen_host: str,
        allowed_networks: str | list[str],
        instance_name: str | None = None,
        preferred_fqdn: str | None = None,
    ) -> dict[str, Any]:
        if listen_host not in ALLOWED_LISTEN_HOSTS:
            raise ValueError("Choose localhost-only or all network interfaces.")
        networks = normalize_allowed_networks(allowed_networks)
        current = self.get()
        settings = {
            "listen_host": listen_host,
            "allowed_networks": networks,
            "instance_name": normalize_instance_name(
                current["instance_name"] if instance_name is None else instance_name
            ),
            "preferred_fqdn": normalize_preferred_fqdn(
                current["preferred_fqdn"] if preferred_fqdn is None else preferred_fqdn
            ),
        }
        self._write(self.previous_path, self.get())
        self._write(self.path, settings)
        return settings

    def client_allowed(
        self,
        address: str | None,
        settings: dict[str, Any] | None = None,
    ) -> bool:
        if not address:
            return False
        try:
            client = ipaddress.ip_address(address)
        except ValueError:
            return False
        if any(client in network for network in LOOPBACK_NETWORKS):
            return True
        active = settings or self.get()
        for value in active.get("allowed_networks", []):
            network = ipaddress.ip_network(value, strict=False)
            if client.version == network.version and client in network:
                return True
        return False

    def restore_previous(self) -> bool:
        if not self.previous_path.exists():
            return False
        os.replace(self.previous_path, self.path)
        return True

    def _write(self, path: Path, data: dict[str, Any]) -> None:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            dir=self.instance_path, prefix=f".{path.stem}-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)


def normalize_allowed_networks(values: str | list[str]) -> list[str]:
    if isinstance(values, str):
        raw_values = values.replace(",", "\n").splitlines()
    elif isinstance(values, list):
        raw_values = values
    else:
        raise ValueError("Trusted hosts must be IP addresses or CIDR networks.")

    networks: list[str] = []
    for raw_value in raw_values:
        value = str(raw_value).strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid trusted host or network: {value}") from exc
        normalized = str(network)
        if normalized not in networks:
            networks.append(normalized)
    return networks


def normalize_instance_name(value: Any) -> str:
    value = str(value or "").strip().lower()
    if not value:
        return ""
    if len(value) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", value):
        raise ValueError(
            "Short instance name must be 1–63 letters, numbers, or hyphens and cannot begin or end with a hyphen."
        )
    return value


def normalize_preferred_fqdn(value: Any) -> str:
    value = str(value or "").strip().lower()
    if not value:
        return ""
    if len(value) > 253 or value.endswith(".") or "://" in value or "/" in value or ":" in value:
        raise ValueError("Preferred FQDN must be a DNS name without a scheme, port, path, or trailing dot.")
    labels = value.split(".")
    if len(labels) < 2:
        raise ValueError("Preferred FQDN must contain at least two DNS labels.")
    if any(
        len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(
            "Preferred FQDN labels must be 1–63 letters, numbers, or hyphens and cannot begin or end with a hyphen."
        )
    return value
