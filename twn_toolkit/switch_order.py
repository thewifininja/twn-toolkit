"""Pure managed-switch inventory and reorder planning helpers."""
from __future__ import annotations
from typing import Any
from .fortigate import FortiGateError


def managed_switch_order(items: list[dict[str, Any]]) -> list[dict[str, str]]:
    switches: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        identifier = str(
            item.get("switch-id")
            or item.get("switch_id")
            or item.get("name")
            or item.get("serial")
            or item.get("sn")
            or ""
        ).strip()
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        display_name = str(
            item.get("name")
            or item.get("switch-id")
            or item.get("switch_id")
            or identifier
        ).strip()
        description = str(item.get("description") or "").strip()
        serial = str(item.get("sn") or item.get("serial") or "").strip()
        switches.append(
            {
                "id": identifier,
                "name": display_name,
                "description": description,
                "serial": serial,
            }
        )
    return switches


def switch_order_moves(
    current_ids: list[str],
    desired_ids: list[str],
) -> list[dict[str, str]]:
    simulated = list(current_ids)
    moves: list[dict[str, str]] = []
    for index in range(1, len(desired_ids)):
        switch_id = desired_ids[index]
        after = desired_ids[index - 1]
        switch_index = simulated.index(switch_id)
        if switch_index > 0 and simulated[switch_index - 1] == after:
            continue
        simulated.remove(switch_id)
        after_index = simulated.index(after)
        simulated.insert(after_index + 1, switch_id)
        moves.append({"switch_id": switch_id, "after": after})
    return moves


def _switch_order_error_summary(exc: FortiGateError, progress: str) -> str:
    if exc.status_code == 403:
        return (
            "FortiGate did not allow the reorder. Confirm the selected API profile has read-write access "
            f"to managed FortiSwitches. {progress}"
        )
    if exc.status_code == 401:
        return (
            "FortiGate rejected the API token while applying the reorder. Confirm the token, trusted hosts, "
            f"and API administrator status. {progress}"
        )
    return f"The reorder could not be verified. {progress}"


def _valid_switch_order(original, desired):
    return (len(original) >= 2 and len(original) == len(set(original))
            and len(desired) == len(original) and len(desired) == len(set(desired))
            and set(desired) == set(original))
