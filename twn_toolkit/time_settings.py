from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .schedule_tools import local_timezone_name


DEFAULT_TIMEZONE = ""
COMMON_TIMEZONES = (
    "UTC",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Phoenix",
    "America/Los_Angeles",
    "America/Anchorage",
    "Pacific/Honolulu",
    "America/Puerto_Rico",
    "America/Toronto",
    "America/Vancouver",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Asia/Tokyo",
    "Asia/Singapore",
    "Australia/Sydney",
)


class TimeSettingsStore:
    """Persist the toolkit timezone without changing the host operating system."""

    def __init__(self, instance_path: str | Path) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "time_settings.json"

    def get(self) -> dict[str, str]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, TypeError):
            raw = {}
        if not isinstance(raw, dict):
            raw = {}
        try:
            configured = normalize_timezone_name(raw.get("timezone", DEFAULT_TIMEZONE))
        except ValueError:
            configured = DEFAULT_TIMEZONE
        return {"timezone": configured}

    def save(self, timezone_name: Any) -> dict[str, str]:
        settings = {"timezone": normalize_timezone_name(timezone_name)}
        self.instance_path.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(
            f".{self.path.name}.{secrets.token_hex(5)}.tmp"
        )
        try:
            temporary.write_text(
                json.dumps(settings, indent=2) + "\n", encoding="utf-8"
            )
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
        return settings

    def resolved_timezone(self) -> str:
        return self.get()["timezone"] or local_timezone_name()

    def snapshot(self, *, now: datetime | None = None) -> dict[str, str]:
        configured = self.get()["timezone"]
        host_timezone = local_timezone_name()
        resolved = configured or host_timezone
        values = localized_time_values(
            now or datetime.now(timezone.utc), resolved
        )
        return {
            "timezone": configured,
            "host_timezone": host_timezone,
            "resolved_timezone": resolved,
            "source": "Explicit timezone" if configured else "Host timezone",
            "current_iso": values["local"],
            "current_display": values["display"],
            "utc_offset": _utc_offset(values["local"]),
        }


def normalize_timezone_name(value: Any) -> str:
    timezone_name = str(value or "").strip()
    if not timezone_name:
        return DEFAULT_TIMEZONE
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            f"Unknown IANA timezone: {timezone_name}. Use a name such as America/New_York."
        ) from exc
    return timezone_name


def resolve_toolkit_timezone(instance_path: str | Path | None) -> str:
    if instance_path:
        return TimeSettingsStore(instance_path).resolved_timezone()
    return local_timezone_name()


def localized_time_values(
    value: datetime | float | int,
    timezone_name: str,
) -> dict[str, str]:
    zone = ZoneInfo(normalize_timezone_name(timezone_name) or "UTC")
    if isinstance(value, datetime):
        utc_value = value
        if utc_value.tzinfo is None:
            utc_value = utc_value.replace(tzinfo=timezone.utc)
        else:
            utc_value = utc_value.astimezone(timezone.utc)
    else:
        utc_value = datetime.fromtimestamp(float(value), timezone.utc)
    local_value = utc_value.astimezone(zone)
    hour = local_value.strftime("%I").lstrip("0") or "12"
    display = (
        f"{local_value.strftime('%b')} {local_value.day}, {local_value.year} "
        f"{hour}:{local_value.strftime('%M:%S %p %Z')}"
    )
    return {
        "utc": utc_value.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "local": local_value.isoformat(timespec="seconds"),
        "display": display,
        "timezone": timezone_name,
    }


def _utc_offset(local_iso: str) -> str:
    try:
        offset = datetime.fromisoformat(local_iso).strftime("%z")
    except ValueError:
        return "UTC"
    if not offset:
        return "UTC"
    sign = offset[0]
    hours, minutes = offset[1:3], offset[3:5]
    return f"UTC{sign}{hours}:{minutes}"
