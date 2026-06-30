from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class ProfileStore:
    def __init__(self, instance_path: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "profiles.json"

    def all(self) -> list[dict[str, Any]]:
        return sorted(self._read(), key=lambda profile: profile["name"].lower())

    def get(self, name: str) -> dict[str, Any] | None:
        return next((profile for profile in self._read() if profile["name"] == name), None)

    def upsert(self, profile: dict[str, Any]) -> None:
        profiles = [item for item in self._read() if item["name"] != profile["name"]]
        if profile.get("is_default"):
            profiles = [{**item, "is_default": False} for item in profiles]
        profiles.append(profile)
        self._write(profiles)

    def delete(self, name: str) -> None:
        self._write([profile for profile in self._read() if profile["name"] != name])

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write(self, profiles: list[dict[str, Any]]) -> None:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(profiles, handle, indent=2)
        os.chmod(self.path, 0o600)


class PingProfileStore:
    def __init__(self, instance_path: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "ping_profiles.json"

    def all(self) -> list[dict[str, Any]]:
        return sorted(self._read(), key=lambda profile: profile["name"].lower())

    def get(self, name: str) -> dict[str, Any] | None:
        return next((profile for profile in self._read() if profile["name"] == name), None)

    def upsert(self, profile: dict[str, Any], original_name: str = "") -> None:
        replaced_names = {profile["name"]}
        if original_name:
            replaced_names.add(original_name)
        profiles = [item for item in self._read() if item["name"] not in replaced_names]
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

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write(self, profiles: list[dict[str, Any]]) -> None:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(profiles, handle, indent=2)
        os.chmod(self.path, 0o600)
