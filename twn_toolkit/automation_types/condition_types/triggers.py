"""Event-source registrations for manual, calendar, and startup automations."""

from typing import Any, Mapping

from .network_triggers import (
    _evaluate_manual,
    _evaluate_schedule,
    _parse_manual_form,
    _parse_schedule_form,
    _validate_manual,
    _validate_schedule,
)
from ..models import ConditionResult, ConditionType
from ...network_tools import ToolInputError


def _validate_startup(config: dict[str, Any]) -> dict[str, Any]:
    mode = str(config.get("mode", "host_boot"))
    if mode not in {"host_boot", "toolkit_start"}:
        raise ToolInputError("Select a valid startup event.")
    try:
        network_wait_seconds = int(config.get("network_wait_seconds", 120))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Startup network wait must be a whole number.") from exc
    if not 0 <= network_wait_seconds <= 600:
        raise ToolInputError("Startup network wait must be between 0 and 600 seconds.")
    return {
        "mode": mode,
        "network_wait_seconds": network_wait_seconds,
    }


def _evaluate_startup(config: dict[str, Any]) -> ConditionResult:
    normalized = _validate_startup(config)
    return ConditionResult(
        met=False,
        status="armed",
        summary=(
            "Waiting for the next host boot."
            if normalized["mode"] == "host_boot"
            else "Waiting for the next toolkit start."
        ),
        evidence={"trigger": "startup", **normalized},
    )


def _parse_startup_form(form: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "mode": form.get("startup_mode", "host_boot"),
        "network_wait_seconds": form.get("startup_network_wait_seconds", "120"),
    }


def registered_triggers() -> tuple[ConditionType, ...]:
    return (
        ConditionType("schedule.calendar", "Calendar schedule", "Trigger from one or more one-time or recurring calendar rules.", _validate_schedule, _evaluate_schedule, _parse_schedule_form),
        ConditionType("manual.trigger", "Manual trigger", "Run attached actions only when a user explicitly starts the automation.", _validate_manual, _evaluate_manual, _parse_manual_form),
        ConditionType("system.startup", "System startup", "Run once after a host boot or after each complete toolkit start.", _validate_startup, _evaluate_startup, _parse_startup_form),
    )


__all__ = ("registered_triggers",)
