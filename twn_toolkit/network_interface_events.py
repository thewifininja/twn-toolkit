from __future__ import annotations

import ipaddress
import json
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any
from .automation_types.models import ConditionResult


class InterfaceObservationError(RuntimeError):
    """Raised when the host interface inventory cannot be observed safely."""


def collect_interface_snapshot() -> dict[str, list[dict[str, Any]]]:
    """Return a normalized, deterministically ordered interface snapshot."""
    if platform.system() == "Linux":
        return _linux_snapshot()
    if platform.system() == "Darwin":
        return _macos_snapshot()
    raise InterfaceObservationError("Network interface observation is unsupported on this platform.")


def filter_snapshot(
    snapshot: dict[str, list[dict[str, Any]]],
    *,
    interfaces: list[str] | None = None,
    families: list[str] | None = None,
    include_loopback: bool = False,
    include_link_local: bool = False,
    include_temporary: bool = False,
    include_virtual: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    selected = {item for item in interfaces or [] if item}
    wanted_families = set(families or ["ipv4", "ipv6"])
    result: dict[str, list[dict[str, Any]]] = {}
    for name, addresses in snapshot.items():
        if selected and name not in selected:
            continue
        if not include_virtual and _virtual_interface(name):
            continue
        kept = []
        for item in addresses:
            address = ipaddress.ip_interface(str(item["address"]))
            family = "ipv4" if address.version == 4 else "ipv6"
            if family not in wanted_families:
                continue
            if not include_loopback and address.ip.is_loopback:
                continue
            if not include_link_local and address.ip.is_link_local:
                continue
            if not include_temporary and bool(item.get("temporary")):
                continue
            if address.ip.is_multicast or address.ip.is_unspecified:
                continue
            kept.append({"address": str(address), "family": family, "temporary": bool(item.get("temporary"))})
        if kept:
            result[name] = sorted(kept, key=lambda item: (item["family"], item["address"]))
    return dict(sorted(result.items()))


def compare_snapshots(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    changes = []
    for name in sorted(set(previous) | set(current)):
        before = {item["address"] for item in previous.get(name, [])}
        after = {item["address"] for item in current.get(name, [])}
        added = sorted(after - before)
        removed = sorted(before - after)
        if added or removed:
            changes.append({
                "interface": name,
                "change_types": (["address_removed"] if removed else []) + (["address_added"] if added else []),
                "added_addresses": added,
                "removed_addresses": removed,
                "previous_addresses": sorted(before),
                "current_addresses": sorted(after),
            })
    return {"changed": bool(changes), "changes": changes[:50], "truncated": len(changes) > 50}


def _linux_snapshot() -> dict[str, list[dict[str, Any]]]:
    binary = shutil.which("ip")
    if not binary:
        raise InterfaceObservationError("Install iproute2 to observe network interface changes.")
    completed = subprocess.run([binary, "-j", "address", "show"], capture_output=True, text=True, timeout=10, check=False)
    if completed.returncode:
        raise InterfaceObservationError("The ip command could not enumerate network interfaces.")
    try:
        rows = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise InterfaceObservationError("The ip command returned invalid interface data.") from exc
    snapshot: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        name = str(row.get("ifname", "")).strip()
        if not name:
            continue
        values = []
        for info in row.get("addr_info", []):
            family = str(info.get("family", ""))
            local = str(info.get("local", ""))
            prefix = info.get("prefixlen")
            if family not in {"inet", "inet6"} or not local or prefix is None:
                continue
            flags = {str(flag).lower() for flag in info.get("flags", [])}
            values.append({"address": f"{local}/{int(prefix)}", "temporary": "temporary" in flags or "mngtmpaddr" in flags})
        snapshot[name] = values
    return snapshot


def _macos_snapshot() -> dict[str, list[dict[str, Any]]]:
    binary = shutil.which("ifconfig") or "/sbin/ifconfig"
    completed = subprocess.run([binary, "-a"], capture_output=True, text=True, timeout=10, check=False)
    if completed.returncode:
        raise InterfaceObservationError("ifconfig could not enumerate network interfaces.")
    snapshot: dict[str, list[dict[str, Any]]] = {}
    current = ""
    for raw in completed.stdout.splitlines():
        if raw and not raw[0].isspace() and ":" in raw:
            current = raw.split(":", 1)[0]
            snapshot.setdefault(current, [])
            continue
        fields = raw.strip().split()
        if not current or not fields or fields[0] not in {"inet", "inet6"}:
            continue
        try:
            if fields[0] == "inet":
                address = ipaddress.ip_address(fields[1])
                mask = int(fields[3], 16) if len(fields) > 3 and fields[2] == "netmask" else 0xFFFFFFFF
                prefix = f"{mask:032b}".count("1")
            else:
                address = ipaddress.ip_address(fields[1].split("%", 1)[0])
                prefix = int(fields[fields.index("prefixlen") + 1])
        except (ValueError, IndexError):
            continue
        snapshot[current].append({"address": f"{address}/{prefix}", "temporary": "temporary" in fields})
    return snapshot


def _virtual_interface(name: str) -> bool:
    return name.startswith(("docker", "veth", "virbr", "br-", "podman", "cni", "flannel", "tailscale", "tun", "tap", "wg"))



def evaluate_interface_change(
    instance_path: str | Path, automation_id: str, config: dict[str, Any],
    *, snapshot: dict[str, list[dict[str, Any]]] | None = None,
    now: float | None = None,
) -> ConditionResult:
    """Compare a durable baseline and emit only a stabilized address change."""
    observed_at = time.time() if now is None else float(now)
    current = filter_snapshot(
        collect_interface_snapshot() if snapshot is None else snapshot,
        interfaces=config.get("interfaces", []), families=config.get("families", ["ipv4", "ipv6"]),
        include_loopback=bool(config.get("include_loopback")),
        include_link_local=bool(config.get("include_link_local")),
        include_temporary=bool(config.get("include_temporary")),
        include_virtual=bool(config.get("include_virtual")),
    )
    state_directory = Path(instance_path) / "automation-network-baselines"
    path = state_directory / f"{automation_id}.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    except (OSError, json.JSONDecodeError, TypeError):
        state = None
    if not isinstance(state, dict):
        state = {"baseline": current, "pending": None, "pending_since": None}
        _save_state(path, state)
        return ConditionResult(False, "baseline", "Established the network interface baseline.", {"trigger": "network_interface_change", "current": current})
    baseline = state.get("baseline", {})
    comparison = compare_snapshots(baseline, current)
    if not comparison["changed"]:
        state.update(pending=None, pending_since=None)
        _save_state(path, state)
        return ConditionResult(False, "clear", "No network interface address changes.", {"trigger": "network_interface_change", "current": current})
    if state.get("pending") != current:
        state.update(pending=current, pending_since=observed_at)
        _save_state(path, state)
        return ConditionResult(False, "stabilizing", "Network address changes are stabilizing.", {"trigger": "network_interface_change", **comparison})
    wait_seconds = int(config.get("stabilization_seconds", 5))
    if observed_at - float(state.get("pending_since") or observed_at) < wait_seconds:
        return ConditionResult(False, "stabilizing", "Network address changes are stabilizing.", {"trigger": "network_interface_change", **comparison})
    state.update(baseline=current, pending=None, pending_since=None)
    _save_state(path, state)
    summary = "; ".join(
        f"{item['interface']}: +{len(item['added_addresses'])} -{len(item['removed_addresses'])} addresses"
        for item in comparison["changes"]
    )
    return ConditionResult(True, "changed", summary, {"trigger": "network_interface_change", **comparison, "current": current})


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)

__all__ = ("InterfaceObservationError", "collect_interface_snapshot", "compare_snapshots", "filter_snapshot", "evaluate_interface_change")
