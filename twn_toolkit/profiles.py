from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class JsonListStore:
    """Small owner-readable JSON list store used by toolkit profile classes."""

    def __init__(self, instance_path: str, filename: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / filename

    def all(self) -> list[dict[str, Any]]:
        return sorted(self._read(), key=lambda profile: profile["name"].lower())

    def get(self, name: str) -> dict[str, Any] | None:
        return next((profile for profile in self._read() if profile["name"] == name), None)

    def _upsert(
        self,
        profile: dict[str, Any],
        *,
        original_name: str = "",
        clear_existing_default: bool = False,
    ) -> None:
        replaced_names = {profile["name"]}
        if original_name:
            replaced_names.add(original_name)
        profiles = [item for item in self._read() if item["name"] not in replaced_names]
        if clear_existing_default:
            profiles = [{**item, "is_default": False} for item in profiles]
        profiles.append(profile)
        self._write(profiles)

    def delete(self, name: str) -> bool:
        profiles = self._read()
        remaining = [profile for profile in profiles if profile["name"] != name]
        if len(remaining) == len(profiles):
            return False
        self._write(remaining)
        return True

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()

    def replace_all(self, profiles: list[dict[str, Any]]) -> None:
        self._write(profiles)

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return self._default_profiles()
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _default_profiles(self) -> list[dict[str, Any]]:
        return []

    def _write(self, profiles: list[dict[str, Any]]) -> None:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(profiles, handle, indent=2)
        os.chmod(self.path, 0o600)


class ProfileStore(JsonListStore):
    def __init__(self, instance_path: str, filename: str = "profiles.json") -> None:
        super().__init__(instance_path, filename)

    def upsert(self, profile: dict[str, Any]) -> None:
        self._upsert(
            profile,
            clear_existing_default=bool(profile.get("is_default")),
        )

    def delete(self, name: str) -> None:
        super().delete(name)


class FortiAuthenticatorProfileStore(ProfileStore):
    def __init__(self, instance_path: str) -> None:
        super().__init__(instance_path, "fortiauthenticator_profiles.json")


class PingProfileStore(JsonListStore):
    def __init__(self, instance_path: str, filename: str = "ping_profiles.json") -> None:
        super().__init__(instance_path, filename)

    def upsert(self, profile: dict[str, Any], original_name: str = "") -> None:
        self._upsert(profile, original_name=original_name)


class DNSProfileStore(PingProfileStore):
    """Store one kind of reusable DNS-tool list profile."""

    def __init__(self, instance_path: str, kind: str) -> None:
        if kind not in {"hosts", "servers"}:
            raise ValueError("DNS profile kind must be 'hosts' or 'servers'.")
        super().__init__(instance_path, f"dns_{kind}_profiles.json")


class RadiusProfileStore(PingProfileStore):
    """Store RADIUS servers and test credentials in separate files."""

    def __init__(self, instance_path: str, kind: str) -> None:
        if kind not in {"servers", "credentials", "attributes"}:
            raise ValueError("Unknown RADIUS profile kind.")
        super().__init__(instance_path, f"radius_{kind}_profiles.json")


class SNMPCredentialProfileStore(PingProfileStore):
    def __init__(self, instance_path: str) -> None:
        super().__init__(instance_path, "snmp_credentials_profiles.json")


class SNMPHostProfileStore(PingProfileStore):
    def __init__(self, instance_path: str) -> None:
        super().__init__(instance_path, "snmp_host_profiles.json")


class SNMPOidProfileStore(PingProfileStore):
    DEFAULTS = [
        {
            "name": "System Identity",
            "source": "\n".join(
                (
                    "System Description = 1.3.6.1.2.1.1.1.0",
                    "System Object ID = 1.3.6.1.2.1.1.2.0",
                    "System Uptime = 1.3.6.1.2.1.1.3.0",
                    "System Contact = 1.3.6.1.2.1.1.4.0",
                    "System Name = 1.3.6.1.2.1.1.5.0",
                    "System Location = 1.3.6.1.2.1.1.6.0",
                )
            ),
        },
        {
            "name": "Interface Summary",
            "source": "\n".join(
                (
                    "walk: Interface Name = 1.3.6.1.2.1.31.1.1.1.1",
                    "walk: Interface Description = 1.3.6.1.2.1.2.2.1.2",
                    "walk: Administrative Status = 1.3.6.1.2.1.2.2.1.7",
                    "walk: Operational Status = 1.3.6.1.2.1.2.2.1.8",
                )
            ),
        },
    ]

    def __init__(self, instance_path: str) -> None:
        super().__init__(instance_path, "snmp_oid_profiles.json")

    def _default_profiles(self) -> list[dict[str, Any]]:
        return [dict(profile) for profile in self.DEFAULTS]


class PortScanProfileStore(PingProfileStore):
    def __init__(self, instance_path: str, kind: str) -> None:
        if kind not in {"hosts", "ports"}:
            raise ValueError("Port scanner profile kind must be 'hosts' or 'ports'.")
        super().__init__(instance_path, f"port_scan_{kind}_profiles.json")


class NTPHostProfileStore(PingProfileStore):
    def __init__(self, instance_path: str) -> None:
        super().__init__(instance_path, "ntp_host_profiles.json")


class TracerouteHostProfileStore(PingProfileStore):
    def __init__(self, instance_path: str) -> None:
        super().__init__(instance_path, "traceroute_host_profiles.json")
