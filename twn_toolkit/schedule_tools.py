from __future__ import annotations

import calendar
import os
import secrets
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .network_tools import ToolInputError


RULE_TYPES = {
    "once",
    "daily",
    "weekly",
    "interval_weeks",
    "monthly_date",
    "monthly_weekday",
}
WEEKDAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
ORDINAL_NAMES = {1: "first", 2: "second", 3: "third", 4: "fourth", 5: "fifth", -1: "last"}


def validate_schedule_config(config: dict[str, Any]) -> dict[str, Any]:
    timezone_name = str(config.get("timezone", "")).strip() or local_timezone_name()
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ToolInputError(f"Unknown schedule timezone: {timezone_name}") from exc
    missed_policy = str(config.get("missed_policy", "grace"))
    if missed_policy not in {"run_late", "grace", "skip"}:
        raise ToolInputError("Select a valid missed-run policy.")
    try:
        grace_minutes = int(config.get("grace_minutes", 30))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Schedule grace period must be a whole number.") from exc
    if not 1 <= grace_minutes <= 1440:
        raise ToolInputError("Schedule grace period must be between 1 and 1440 minutes.")
    raw_rules = config.get("rules", [])
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ToolInputError("Add at least one schedule rule.")
    if len(raw_rules) > 50:
        raise ToolInputError("A schedule condition can contain at most 50 rules.")
    rules = [_validate_rule(rule, index) for index, rule in enumerate(raw_rules, 1)]
    ids = [rule["id"] for rule in rules]
    if len(ids) != len(set(ids)):
        raise ToolInputError("Schedule rule identifiers must be unique.")
    return {
        "timezone": timezone_name,
        "missed_policy": missed_policy,
        "grace_minutes": grace_minutes,
        "rules": rules,
    }


def local_timezone_name() -> str:
    tzinfo = datetime.now().astimezone().tzinfo
    candidates = [str(getattr(tzinfo, "key", "") or ""), os.environ.get("TZ", "")]
    timezone_file = Path("/etc/timezone")
    if timezone_file.exists():
        try:
            candidates.append(timezone_file.read_text(encoding="utf-8").strip())
        except OSError:
            pass
    try:
        localtime = Path("/etc/localtime").resolve()
        marker = "zoneinfo/"
        if marker in str(localtime):
            candidates.append(str(localtime).split(marker, 1)[1])
    except OSError:
        pass
    for candidate in candidates:
        if not candidate:
            continue
        try:
            ZoneInfo(candidate)
        except ZoneInfoNotFoundError:
            continue
        return candidate
    return "UTC"


def schedule_occurrence(
    config: dict[str, Any], after_timestamp: float
) -> dict[str, Any] | None:
    normalized = validate_schedule_config(config)
    tz = ZoneInfo(normalized["timezone"])
    after = datetime.fromtimestamp(after_timestamp, timezone.utc)
    candidates: list[tuple[datetime, dict[str, Any]]] = []
    for rule in normalized["rules"]:
        occurrence = _next_rule_occurrence(rule, tz, after)
        if occurrence is not None:
            candidates.append((occurrence, rule))
    if not candidates:
        return None
    scheduled = min(item[0] for item in candidates)
    matching = [rule for occurrence, rule in candidates if occurrence == scheduled]
    local = scheduled.astimezone(tz)
    return {
        "timestamp": scheduled.timestamp(),
        "scheduled_utc": scheduled.isoformat(),
        "scheduled_local": local.isoformat(),
        "display": local.strftime("%Y-%m-%d %I:%M %p %Z"),
        "timezone": normalized["timezone"],
        "rule_ids": [rule["id"] for rule in matching],
        "rules": [describe_schedule_rule(rule) for rule in matching],
    }


def schedule_preview(
    config: dict[str, Any], after_timestamp: float, limit: int = 5
) -> list[dict[str, Any]]:
    occurrences = []
    cursor = after_timestamp
    for _ in range(max(0, min(limit, 20))):
        occurrence = schedule_occurrence(config, cursor)
        if occurrence is None:
            break
        occurrences.append(occurrence)
        cursor = float(occurrence["timestamp"]) + 0.001
    return occurrences


def schedule_should_fire(config: dict[str, Any], scheduled_at: float, now: float) -> bool:
    normalized = validate_schedule_config(config)
    lateness = max(0.0, now - scheduled_at)
    if normalized["missed_policy"] == "run_late":
        return True
    if normalized["missed_policy"] == "skip":
        return lateness <= 60
    return lateness <= normalized["grace_minutes"] * 60


def describe_schedule_rule(rule: dict[str, Any]) -> str:
    rule_type = rule["type"]
    at = _display_time(rule["time"])
    if rule_type == "once":
        return f"Once on {rule['date']} at {at}"
    if rule_type == "daily":
        return f"Every day at {at}"
    if rule_type == "weekly":
        days = ", ".join(WEEKDAY_NAMES[item] for item in rule["weekdays"])
        return f"Every {days} at {at}"
    if rule_type == "interval_weeks":
        anchor = date.fromisoformat(rule["anchor_date"])
        return (
            f"Every {rule['interval']} weeks on {WEEKDAY_NAMES[anchor.weekday()]} "
            f"at {at}, starting {rule['anchor_date']}"
        )
    if rule_type == "monthly_date":
        return f"Day {rule['day']} of every month at {at}"
    return (
        f"The {ORDINAL_NAMES[rule['ordinal']]} {WEEKDAY_NAMES[rule['weekday']]} "
        f"of every month at {at}"
    )


def _validate_rule(raw: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ToolInputError(f"Schedule rule {index} is invalid.")
    rule_type = str(raw.get("type", ""))
    if rule_type not in RULE_TYPES:
        raise ToolInputError(f"Schedule rule {index} has an unknown type.")
    rule_id = str(raw.get("id", "")).strip() or secrets.token_hex(6)
    if not rule_id.replace("-", "").replace("_", "").isalnum() or len(rule_id) > 64:
        raise ToolInputError(f"Schedule rule {index} has an invalid identifier.")
    result: dict[str, Any] = {"id": rule_id, "type": rule_type}
    result["time"] = _validate_time(raw.get("time", ""), index)
    if rule_type == "once":
        result["date"] = _validate_date(raw.get("date", ""), index)
    elif rule_type == "weekly":
        weekdays = _integer_list(raw.get("weekdays", []), 0, 6, f"rule {index} weekdays")
        if not weekdays:
            raise ToolInputError(f"Schedule rule {index} needs at least one weekday.")
        result["weekdays"] = sorted(set(weekdays))
    elif rule_type == "interval_weeks":
        try:
            interval = int(raw.get("interval", 2))
        except (TypeError, ValueError) as exc:
            raise ToolInputError(f"Schedule rule {index} interval must be a whole number.") from exc
        if not 1 <= interval <= 52:
            raise ToolInputError(f"Schedule rule {index} interval must be 1–52 weeks.")
        result["interval"] = interval
        result["anchor_date"] = _validate_date(raw.get("anchor_date", ""), index)
    elif rule_type == "monthly_date":
        try:
            day = int(raw.get("day", 1))
        except (TypeError, ValueError) as exc:
            raise ToolInputError(f"Schedule rule {index} day must be a whole number.") from exc
        if not 1 <= day <= 31:
            raise ToolInputError(f"Schedule rule {index} day must be 1–31.")
        result["day"] = day
    elif rule_type == "monthly_weekday":
        try:
            ordinal = int(raw.get("ordinal", 1))
            weekday = int(raw.get("weekday", 0))
        except (TypeError, ValueError) as exc:
            raise ToolInputError(f"Schedule rule {index} monthly values are invalid.") from exc
        if ordinal not in ORDINAL_NAMES or not 0 <= weekday <= 6:
            raise ToolInputError(f"Schedule rule {index} monthly weekday is invalid.")
        result.update({"ordinal": ordinal, "weekday": weekday})
    return result


def _next_rule_occurrence(
    rule: dict[str, Any], tz: ZoneInfo, after_utc: datetime
) -> datetime | None:
    local_after = after_utc.astimezone(tz)
    target_time = datetime_time.fromisoformat(rule["time"])
    if rule["type"] == "once":
        candidate = _resolve_local(datetime.combine(date.fromisoformat(rule["date"]), target_time), tz)
        return candidate.astimezone(timezone.utc) if candidate.astimezone(timezone.utc) > after_utc else None
    if rule["type"] == "daily":
        for offset in range(0, 3):
            candidate = _resolve_local(datetime.combine(local_after.date() + timedelta(days=offset), target_time), tz)
            if candidate.astimezone(timezone.utc) > after_utc:
                return candidate.astimezone(timezone.utc)
    if rule["type"] == "weekly":
        for offset in range(0, 15):
            day = local_after.date() + timedelta(days=offset)
            if day.weekday() in rule["weekdays"]:
                candidate = _resolve_local(datetime.combine(day, target_time), tz)
                if candidate.astimezone(timezone.utc) > after_utc:
                    return candidate.astimezone(timezone.utc)
    if rule["type"] == "interval_weeks":
        anchor = date.fromisoformat(rule["anchor_date"])
        start = max(anchor, local_after.date())
        for offset in range(0, rule["interval"] * 7 + 8):
            day = start + timedelta(days=offset)
            if day < anchor or (day - anchor).days % (rule["interval"] * 7):
                continue
            candidate = _resolve_local(datetime.combine(day, target_time), tz)
            if candidate.astimezone(timezone.utc) > after_utc:
                return candidate.astimezone(timezone.utc)
    if rule["type"] in {"monthly_date", "monthly_weekday"}:
        year, month = local_after.year, local_after.month
        for _ in range(0, 36):
            if rule["type"] == "monthly_date":
                max_day = calendar.monthrange(year, month)[1]
                day_number = rule["day"] if rule["day"] <= max_day else None
            else:
                day_number = _monthly_weekday_day(year, month, rule["weekday"], rule["ordinal"])
            if day_number:
                candidate = _resolve_local(datetime(year, month, day_number, target_time.hour, target_time.minute), tz)
                if candidate.astimezone(timezone.utc) > after_utc:
                    return candidate.astimezone(timezone.utc)
            year, month = (year + 1, 1) if month == 12 else (year, month + 1)
    return None


def _resolve_local(naive: datetime, tz: ZoneInfo) -> datetime:
    # fold=0 selects the first occurrence when clocks move backward.
    candidate = naive.replace(tzinfo=tz, fold=0)
    round_trip = candidate.astimezone(timezone.utc).astimezone(tz).replace(tzinfo=None)
    if round_trip == naive:
        return candidate
    # Spring-forward gaps move to the next valid wall-clock minute.
    for minutes in range(1, 181):
        adjusted = naive + timedelta(minutes=minutes)
        candidate = adjusted.replace(tzinfo=tz, fold=0)
        round_trip = candidate.astimezone(timezone.utc).astimezone(tz).replace(tzinfo=None)
        if round_trip == adjusted:
            return candidate
    raise ToolInputError("Could not resolve a daylight-saving schedule time.")


def _monthly_weekday_day(year: int, month: int, weekday: int, ordinal: int) -> int | None:
    days = [
        day
        for day in range(1, calendar.monthrange(year, month)[1] + 1)
        if date(year, month, day).weekday() == weekday
    ]
    if ordinal == -1:
        return days[-1]
    return days[ordinal - 1] if len(days) >= ordinal else None


def _validate_time(value: Any, index: int) -> str:
    try:
        parsed = datetime_time.fromisoformat(str(value))
    except ValueError as exc:
        raise ToolInputError(f"Schedule rule {index} needs a valid time.") from exc
    return parsed.strftime("%H:%M")


def _validate_date(value: Any, index: int) -> str:
    try:
        return date.fromisoformat(str(value)).isoformat()
    except ValueError as exc:
        raise ToolInputError(f"Schedule rule {index} needs a valid date.") from exc


def _integer_list(values: Any, minimum: int, maximum: int, label: str) -> list[int]:
    if not isinstance(values, list):
        raise ToolInputError(f"Invalid {label}.")
    try:
        parsed = [int(value) for value in values]
    except (TypeError, ValueError) as exc:
        raise ToolInputError(f"Invalid {label}.") from exc
    if any(value < minimum or value > maximum for value in parsed):
        raise ToolInputError(f"Invalid {label}.")
    return parsed


def _display_time(value: str) -> str:
    return datetime.strptime(value, "%H:%M").strftime("%-I:%M %p")
