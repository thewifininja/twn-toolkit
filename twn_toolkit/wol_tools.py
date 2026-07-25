from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Callable

from .dhcp_tools import normalize_mac
from .network_tools import ToolInputError, parse_ping_targets, ping_hosts


MAX_WOL_TARGETS = 100
WOL_PORTS = {7, 9}
MAX_WOL_REPEATS = 5
MIN_VERIFY_TIMEOUT = 5
MAX_VERIFY_TIMEOUT = 60


def parse_wol_targets(value: str, *, limit: int = MAX_WOL_TARGETS) -> list[dict[str, str]]:
    """Parse ``MAC``, ``Name | MAC``, or ``Name | MAC | verification host`` lines."""
    targets: list[dict[str, str]] = []
    seen_macs: set[str] = set()
    for line_number, raw_line in enumerate(str(value).splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) == 1:
            name, mac, host = "", parts[0], ""
        elif len(parts) == 2:
            name, mac = parts
            host = ""
        elif len(parts) == 3:
            name, mac, host = parts
        else:
            raise ToolInputError(
                f"Line {line_number}: use MAC, Name | MAC, or Name | MAC | verification host."
            )
        if len(name) > 100:
            raise ToolInputError(f"Line {line_number}: device names must be 100 characters or fewer.")
        try:
            normalized_mac = normalize_mac(mac)
        except ToolInputError as exc:
            raise ToolInputError(f"Line {line_number}: {exc}") from exc
        if normalized_mac == "00:00:00:00:00:00":
            raise ToolInputError(f"Line {line_number}: the all-zero MAC address is not a device.")
        if normalized_mac in seen_macs:
            raise ToolInputError(f"Line {line_number}: {normalized_mac} is listed more than once.")
        normalized_host = _verification_host(host, line_number) if host else ""
        seen_macs.add(normalized_mac)
        targets.append({"name": name, "mac": normalized_mac, "host": normalized_host})
        if len(targets) > limit:
            raise ToolInputError(f"Enter no more than {limit} Wake-on-LAN devices.")
    if not targets:
        raise ToolInputError("Enter at least one Wake-on-LAN device.")
    return targets


def format_wol_targets(targets: list[dict[str, str]]) -> str:
    lines = []
    for target in targets:
        name = str(target.get("name", "")).strip()
        mac = str(target.get("mac", "")).strip()
        host = str(target.get("host", "")).strip()
        if host:
            lines.append(f"{name or mac} | {mac} | {host}")
        elif name:
            lines.append(f"{name} | {mac}")
        else:
            lines.append(mac)
    return "\n".join(lines)


def build_magic_packet(mac: str) -> bytes:
    mac_bytes = bytes.fromhex(normalize_mac(mac).replace(":", ""))
    return (b"\xff" * 6) + (mac_bytes * 16)


def available_wol_interfaces() -> list[dict[str, str]]:
    """Return IPv4 source interfaces and their local broadcast addresses."""
    names = [name for _index, name in socket.if_nameindex()]
    discovered = _linux_ip_interfaces() if sys.platform.startswith("linux") else {}
    interfaces = []
    for name in names:
        details = discovered.get(name) or _ifconfig_interface(name) or _scapy_interface(name)
        if not details or not details.get("address"):
            continue
        try:
            parsed_address = ipaddress.IPv4Address(str(details["address"]))
        except ipaddress.AddressValueError:
            continue
        if parsed_address.is_loopback or parsed_address.is_unspecified:
            continue
        interfaces.append(
            {
                "name": name,
                "address": str(details["address"]),
                "broadcast": str(details.get("broadcast", "")),
            }
        )
    return sorted(interfaces, key=lambda item: (not bool(item["broadcast"]), item["name"]))


def run_wake_on_lan(
    targets: list[dict[str, str]],
    *,
    interface_name: str,
    destination_mode: str,
    custom_destination: str = "",
    port: int = 9,
    repeats: int = 3,
    verify: bool = False,
    verify_timeout: int = 20,
    interfaces: list[dict[str, str]] | None = None,
    ping_runner: Callable[[list[str], float], list[dict[str, Any]]] = ping_hosts,
) -> dict[str, Any]:
    if not 1 <= len(targets) <= MAX_WOL_TARGETS:
        raise ToolInputError(f"Select between 1 and {MAX_WOL_TARGETS} devices.")
    interface = next(
        (
            item
            for item in (interfaces if interfaces is not None else available_wol_interfaces())
            if item.get("name") == interface_name
        ),
        None,
    )
    if not interface:
        raise ToolInputError("Select a valid IPv4 source interface.")
    source_address = _valid_ipv4(interface.get("address", ""), "source interface address")
    destination = _wake_destination(destination_mode, custom_destination, interface)
    try:
        normalized_port = int(port)
        normalized_repeats = int(repeats)
        normalized_verify_timeout = int(verify_timeout)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Wake-on-LAN numeric settings must be whole numbers.") from exc
    if normalized_port not in WOL_PORTS:
        raise ToolInputError("Wake-on-LAN UDP port must be 7 or 9.")
    if not 1 <= normalized_repeats <= MAX_WOL_REPEATS:
        raise ToolInputError(f"Repeat count must be between 1 and {MAX_WOL_REPEATS}.")
    if verify and not MIN_VERIFY_TIMEOUT <= normalized_verify_timeout <= MAX_VERIFY_TIMEOUT:
        raise ToolInputError(
            f"Verification timeout must be between {MIN_VERIFY_TIMEOUT} and "
            f"{MAX_VERIFY_TIMEOUT} seconds."
        )

    started = time.monotonic()
    results = _send_magic_packets(
        targets,
        source_address=source_address,
        destination=destination,
        port=normalized_port,
        repeats=normalized_repeats,
    )
    if verify:
        _verify_results(
            results,
            timeout=normalized_verify_timeout,
            ping_runner=ping_runner,
        )
    else:
        for result in results:
            result["verification"] = "not_requested"

    return {
        "interface": interface_name,
        "source_address": source_address,
        "destination": destination,
        "destination_mode": destination_mode,
        "port": normalized_port,
        "repeats": normalized_repeats,
        "verify": bool(verify),
        "verify_timeout": normalized_verify_timeout,
        "results": results,
        "device_count": len(results),
        "packets_sent": sum(int(result["packets_sent"]) for result in results),
        "send_failures": sum(result["send_status"] == "error" for result in results),
        "confirmed_awake": sum(result.get("verification") == "awake" for result in results),
        "verification_configured": sum(bool(result.get("host")) for result in results),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


def _send_magic_packets(
    targets: list[dict[str, str]],
    *,
    source_address: str,
    destination: str,
    port: int,
    repeats: int,
) -> list[dict[str, Any]]:
    results = [
        {
            "name": target.get("name", ""),
            "mac": target["mac"],
            "host": target.get("host", ""),
            "packets_sent": 0,
            "send_status": "sent",
            "send_error": "",
        }
        for target in targets
    ]
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((source_address, 0))
        for _repeat in range(repeats):
            for result in results:
                if result["send_status"] == "error":
                    continue
                try:
                    sock.sendto(build_magic_packet(result["mac"]), (destination, port))
                    result["packets_sent"] += 1
                except OSError as exc:
                    result["send_status"] = "error"
                    result["send_error"] = (
                        f"Could not send from {source_address}: {exc.strerror or str(exc)}"
                    )
    except OSError as exc:
        message = f"Could not open the Wake-on-LAN sender: {exc.strerror or str(exc)}"
        for result in results:
            result["send_status"] = "error"
            result["send_error"] = message
    finally:
        if sock is not None:
            sock.close()
    return results


def _verify_results(
    results: list[dict[str, Any]],
    *,
    timeout: int,
    ping_runner: Callable[[list[str], float], list[dict[str, Any]]],
) -> None:
    pending: dict[str, list[dict[str, Any]]] = {}
    for result in results:
        if result["send_status"] == "error":
            result["verification"] = "not_attempted"
        elif not result.get("host"):
            result["verification"] = "not_configured"
        else:
            result["verification"] = "pending"
            pending.setdefault(result["host"], []).append(result)
    deadline = time.monotonic() + timeout
    while pending:
        hosts = list(pending)
        try:
            samples = ping_runner(hosts, 1.0)
        except ToolInputError as exc:
            for grouped_results in pending.values():
                for result in grouped_results:
                    result["verification"] = "error"
                    result["verification_error"] = str(exc)
            return
        for sample in samples:
            host = str(sample.get("host", ""))
            if host not in pending or not sample.get("reachable"):
                continue
            for result in pending.pop(host):
                result["verification"] = "awake"
                result["latency_ms"] = sample.get("latency_ms")
        remaining = deadline - time.monotonic()
        if not pending or remaining <= 0:
            break
        time.sleep(min(2.0, remaining))
    for grouped_results in pending.values():
        for result in grouped_results:
            result["verification"] = "timeout"


def _wake_destination(
    mode: str, custom_destination: str, interface: dict[str, str]
) -> str:
    if mode == "local":
        broadcast = interface.get("broadcast", "")
        if not broadcast:
            raise ToolInputError(
                "The selected interface does not expose a local IPv4 broadcast address. "
                "Choose another interface or custom destination mode."
            )
        return _valid_ipv4(broadcast, "local broadcast address")
    if mode != "custom":
        raise ToolInputError("Choose local broadcast or custom destination mode.")
    destination = _valid_ipv4(custom_destination, "custom broadcast or relay address")
    parsed = ipaddress.IPv4Address(destination)
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
        raise ToolInputError("Enter a usable unicast, limited-broadcast, or directed-broadcast IPv4 address.")
    return destination


def _valid_ipv4(value: object, label: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ipaddress.AddressValueError as exc:
        raise ToolInputError(f"Enter a valid IPv4 {label}.") from exc


def _verification_host(value: str, line_number: int) -> str:
    try:
        parsed = parse_ping_targets(value, limit=2)
    except ToolInputError as exc:
        raise ToolInputError(f"Line {line_number}: invalid verification host: {exc}") from exc
    if len(parsed) != 1 or parsed[0].get("label"):
        raise ToolInputError(
            f"Line {line_number}: enter one plain hostname or IP address for verification."
        )
    return str(parsed[0]["host"])


def _linux_ip_interfaces() -> dict[str, dict[str, str]]:
    binary = shutil.which("ip")
    if not binary:
        return {}
    try:
        completed = subprocess.run(
            [binary, "-j", "-4", "address", "show"],
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        )
        payload = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return {}
    interfaces: dict[str, dict[str, str]] = {}
    for item in payload:
        name = str(item.get("ifname", ""))
        candidates = [
            address
            for address in item.get("addr_info", [])
            if address.get("family") == "inet" and address.get("local")
        ]
        candidate = next(
            (address for address in candidates if address.get("scope") == "global"),
            candidates[0] if candidates else None,
        )
        if candidate:
            interfaces[name] = {
                "address": str(candidate["local"]),
                "broadcast": str(candidate.get("broadcast", "")),
            }
    return interfaces


def _ifconfig_interface(name: str) -> dict[str, str] | None:
    binary = shutil.which("ifconfig")
    if not binary and os.path.exists("/sbin/ifconfig"):
        binary = "/sbin/ifconfig"
    if not binary:
        return None
    try:
        completed = subprocess.run(
            [binary, name],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(
        r"^\s*inet\s+(\d+(?:\.\d+){3})\s+netmask\s+(\S+)"
        r"(?:\s+broadcast\s+(\d+(?:\.\d+){3}))?",
        completed.stdout,
        re.MULTILINE,
    )
    if not match:
        return None
    address, netmask, broadcast = match.groups()
    if not broadcast:
        try:
            mask = (
                ipaddress.IPv4Address(int(netmask, 16))
                if netmask.lower().startswith("0x")
                else ipaddress.IPv4Address(netmask)
            )
            broadcast = str(
                ipaddress.IPv4Network(f"{address}/{mask}", strict=False).broadcast_address
            )
        except ValueError:
            broadcast = ""
    return {"address": address, "broadcast": broadcast or ""}


def _scapy_interface(name: str) -> dict[str, str] | None:
    try:
        from scapy.all import conf

        interface = conf.ifaces.dev_from_name(name)
        address = str(interface.ip or "")
        if not address or ipaddress.ip_address(address).version != 4:
            return None
        return {"address": address, "broadcast": ""}
    except (ImportError, KeyError, ValueError):
        return None
