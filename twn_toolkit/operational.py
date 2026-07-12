from __future__ import annotations

import json
import os
import secrets
import shutil
from pathlib import Path
from typing import Any


DEFAULT_OPERATIONAL_SETTINGS = {
    "max_concurrent_automations": 4,
    "max_queued_automations": 20,
    "skip_overlapping_automations": True,
    "datastore_quota_gib": 10,
    "automation_artifact_quota_gib": 10,
    "minimum_free_gib": 2,
}


class OperationalSettingsStore:
    def __init__(self, instance_path: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "operational_settings.json"

    def get(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError):
            raw = {}
        return self.validate({**DEFAULT_OPERATIONAL_SETTINGS, **raw})

    def save(self, values: dict[str, Any]) -> dict[str, Any]:
        settings = self.validate({**self.get(), **values})
        self.instance_path.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(5)}.tmp")
        temporary.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600); os.replace(temporary, self.path)
        return settings

    @staticmethod
    def validate(values: dict[str, Any]) -> dict[str, Any]:
        try:
            concurrent = int(values["max_concurrent_automations"])
            queued = int(values["max_queued_automations"])
            datastore = int(values["datastore_quota_gib"])
            artifacts = int(values["automation_artifact_quota_gib"])
            minimum_free = int(values["minimum_free_gib"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Operational limits must be whole numbers.") from exc
        if not 1 <= concurrent <= 32: raise ValueError("Concurrent automations must be 1–32.")
        if not 0 <= queued <= 200: raise ValueError("Queued automations must be 0–200.")
        if not 1 <= datastore <= 1024 or not 1 <= artifacts <= 1024: raise ValueError("Storage quotas must be 1–1024 GiB.")
        if not 0 <= minimum_free <= 100: raise ValueError("Minimum free space must be 0–100 GiB.")
        return {
            "max_concurrent_automations": concurrent,
            "max_queued_automations": queued,
            "skip_overlapping_automations": bool(values.get("skip_overlapping_automations", True)),
            "datastore_quota_gib": datastore,
            "automation_artifact_quota_gib": artifacts,
            "minimum_free_gib": minimum_free,
        }

    def storage_summary(self) -> dict[str, Any]:
        settings = self.get()
        datastore = self.instance_path / "datastore"
        artifacts = self.instance_path / "automation_artifacts"
        usage = shutil.disk_usage(self.instance_path)
        return {
            **settings,
            "datastore_bytes": directory_bytes(datastore),
            "artifact_bytes": directory_bytes(artifacts),
            "disk_total_bytes": usage.total,
            "disk_free_bytes": usage.free,
            "disk_used_bytes": usage.used,
        }


def directory_bytes(path: Path) -> int:
    total = 0
    if not path.exists(): return 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try: total += (Path(root) / name).stat().st_size
            except OSError: pass
    return total


def ensure_storage_capacity(instance_path: str | Path, area: str, incoming_bytes: int, *, existing_bytes: int = 0) -> None:
    instance = Path(instance_path)
    settings = OperationalSettingsStore(str(instance)).get()
    root = instance / ("datastore" if area == "datastore" else "automation_artifacts")
    quota_gib = settings["datastore_quota_gib" if area == "datastore" else "automation_artifact_quota_gib"]
    projected = directory_bytes(root) - max(0, existing_bytes) + max(0, incoming_bytes)
    if projected > quota_gib * 1024**3:
        raise ValueError(f"The {area.replace('_', ' ')} quota of {quota_gib} GiB would be exceeded.")
    free = shutil.disk_usage(instance).free
    if free - max(0, incoming_bytes) < settings["minimum_free_gib"] * 1024**3:
        raise ValueError("This write would cross the configured minimum free-disk reserve.")
