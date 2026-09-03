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


def _validate_interface_change(config: dict[str, Any]) -> dict[str, Any]:
    families = [str(item) for item in config.get("families", ["ipv4", "ipv6"])]
    if not families or any(item not in {"ipv4", "ipv6"} for item in families):
        raise ToolInputError("Select IPv4, IPv6, or both.")
    interfaces = sorted({str(item).strip() for item in config.get("interfaces", []) if str(item).strip()})
    try:
        stabilization_seconds = int(config.get("stabilization_seconds", 5))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Stabilization must be a whole number of seconds.") from exc
    if not 1 <= stabilization_seconds <= 300:
        raise ToolInputError("Stabilization must be between 1 and 300 seconds.")
    return {
        "interfaces": interfaces,
        "families": sorted(set(families)),
        "include_loopback": bool(config.get("include_loopback", False)),
        "include_link_local": bool(config.get("include_link_local", False)),
        "include_temporary": bool(config.get("include_temporary", False)),
        "include_virtual": bool(config.get("include_virtual", False)),
        "stabilization_seconds": stabilization_seconds,
        "emit_initial": bool(config.get("emit_initial", False)),
    }


def _evaluate_interface_change(config: dict[str, Any]) -> ConditionResult:
    normalized = _validate_interface_change(config)
    return ConditionResult(
        met=False,
        status="armed",
        summary="Watching for network interface address changes.",
        evidence={"trigger": "network_interface_change", **normalized},
    )


def _parse_interface_change_form(form: Mapping[str, Any]) -> dict[str, Any]:
    getlist = getattr(form, "getlist", None)
    families = getlist("network_family") if getlist else ["ipv4", "ipv6"]
    interfaces = (
        [item.strip() for item in str(form.get("network_interfaces", "")).split(",") if item.strip()]
    )
    if getlist:
        interfaces = [str(item).strip() for item in getlist("network_interface") if str(item).strip()]
    if form.get("network_scope", "all") == "all":
        interfaces = []
    elif not interfaces:
        raise ToolInputError("Select at least one interface or watch all eligible interfaces.")
    return {
        "families": families,
        "interfaces": interfaces,
        "include_loopback": form.get("network_include_loopback") == "on",
        "include_link_local": form.get("network_include_link_local") == "on",
        "include_temporary": form.get("network_include_temporary") == "on",
        "include_virtual": form.get("network_include_virtual") == "on",
        "stabilization_seconds": form.get("network_stabilization_seconds", "5"),
        "emit_initial": form.get("network_emit_initial") == "on",
    }


def registered_triggers() -> tuple[ConditionType, ...]:
    return (
        ConditionType("schedule.calendar", "Calendar schedule", "Trigger from one or more one-time or recurring calendar rules.", _validate_schedule, _evaluate_schedule, _parse_schedule_form),
        ConditionType("manual.trigger", "Manual trigger", "Run attached actions only when a user explicitly starts the automation.", _validate_manual, _evaluate_manual, _parse_manual_form),
        ConditionType("system.startup", "System startup", "Run once after a host boot or after each complete toolkit start.", _validate_startup, _evaluate_startup, _parse_startup_form),
        ConditionType("network.interface_change", "Network interface change", "Run when local interface addresses are added or removed.", _validate_interface_change, _evaluate_interface_change, _parse_interface_change_form),
    )


__all__ = ("registered_triggers",)
