#!/usr/bin/python3
"""Root-owned, UID-restricted NetworkManager broker for Raspberry Pi hosts.

This file is copied out of the user-writable checkout by ``twn service install``.
It intentionally uses only the Python standard library and never imports toolkit
application code while running as root.
"""

from __future__ import annotations

import argparse
import configparser
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any


MAX_MESSAGE_BYTES = 512 * 1024
MAX_MATERIAL_BYTES = 2 * 1024 * 1024
BROKER_PROTOCOL_VERSION = 2
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
PROFILE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
MAC_ADDRESS_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
CHECKPOINT_PATTERN = re.compile(r"^/org/freedesktop/NetworkManager/Checkpoint/\d+$")
PROFILE_PREFIX = "twn-pi-"
CHECKPOINT_FLAGS = 0x01 | 0x02 | 0x04
CHECKPOINT_OPERATION_GRACE_SECONDS = 90


class BrokerError(RuntimeError):
    pass


def _run(command: list[str], *, timeout: float = 30.0) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BrokerError(f"Could not run {command[0]}.") from exc
    if result.returncode:
        detail = " ".join((result.stderr or result.stdout).split())[:500]
        raise BrokerError(detail or f"{command[0]} exited with status {result.returncode}.")
    return result.stdout.strip()


def _run_quiet(command: list[str], *, timeout: float = 20.0) -> bool:
    try:
        _run(command, timeout=timeout)
    except BrokerError:
        return False
    return True


def _run_optional(command: list[str], *, timeout: float = 10.0) -> str:
    try:
        return _run(command, timeout=timeout)
    except BrokerError:
        return ""


def _nmcli_rows(output: str, expected: int) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in output.splitlines():
        values: list[str] = []
        value: list[str] = []
        escaped = False
        for character in raw_line:
            if escaped:
                value.append(character)
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == ":" and len(values) < expected - 1:
                values.append("".join(value))
                value = []
            else:
                value.append(character)
        values.append("".join(value))
        if len(values) == expected:
            rows.append(values)
    return rows


def _nmcli_properties(output: str) -> dict[str, list[str]]:
    properties: dict[str, list[str]] = {}
    for raw_line in output.splitlines():
        key, separator, value = raw_line.partition(":")
        if not separator:
            continue
        key = re.sub(r"\[\d+\]$", "", key)
        normalized = value.replace("\\:", ":").replace("\\\\", "\\")
        properties.setdefault(key, []).append(normalized)
    return properties


def _permanent_hardware_address(interface: str, current: str) -> str:
    """Return a stable adapter address without invalidating inventory discovery.

    ``GENERAL.PERM-HWADDR`` is not available in every NetworkManager release.
    It must therefore be queried independently: asking for it alongside the
    supported fields causes nmcli to reject the entire field list on affected
    systems, hiding driver and capability data as well as the address.
    """

    output = _run_optional(
        [
            "nmcli",
            "-t",
            "-f",
            "GENERAL.PERM-HWADDR",
            "device",
            "show",
            interface,
        ]
    )
    permanent = next(
        (
            value
            for value in _nmcli_properties(output).get("GENERAL.PERM-HWADDR", [])
            if value
        ),
        "",
    )
    if not permanent:
        ethtool = _run_optional(["ethtool", "-P", interface])
        match = re.search(
            r"Permanent address:\s*((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})",
            ethtool,
        )
        permanent = match.group(1) if match else ""
    return (permanent or current).upper()


def _iw_binary() -> str:
    discovered = shutil.which("iw")
    if discovered:
        return discovered
    for candidate in ("/usr/sbin/iw", "/sbin/iw"):
        if Path(candidate).is_file():
            return candidate
    return ""


def _wireless_radio_snapshot(interface: str) -> dict[str, str]:
    """Read current radio state without asking NetworkManager to scan."""

    iw = _iw_binary()
    if not iw:
        return {}
    info = _run_optional([iw, "dev", interface, "info"])
    link = _run_optional([iw, "dev", interface, "link"])
    snapshot: dict[str, str] = {}
    for raw_line in info.splitlines():
        line = raw_line.strip()
        if line.startswith("ssid "):
            snapshot["ssid"] = line[5:].strip()
        elif line.startswith("type "):
            snapshot["mode"] = line[5:].strip()
    channel = re.search(
        r"^\s*channel\s+(\d+)\s+\((\d+)\s+MHz\)", info, re.MULTILINE
    )
    if channel:
        snapshot["channel"] = channel.group(1)
        snapshot["frequency_mhz"] = channel.group(2)
    connected = re.search(
        r"^Connected to ((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", link
    )
    if connected:
        snapshot["bssid"] = connected.group(1).upper()
    for raw_line in link.splitlines():
        line = raw_line.strip()
        if line.startswith("SSID: "):
            snapshot["ssid"] = line[6:].strip()
        elif line.startswith("freq: "):
            snapshot.setdefault("frequency_mhz", line[6:].strip())
        elif line.startswith("signal: "):
            snapshot["signal"] = line[8:].strip()
        elif line.startswith("tx bitrate: "):
            snapshot["rate"] = line[12:].strip()
    return snapshot


def _device_tree_value(path: Path) -> str:
    try:
        return path.read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _require_raspberry_pi() -> None:
    compatible = _device_tree_value(Path("/proc/device-tree/compatible"))
    if not any(value.startswith("raspberrypi,") for value in compatible.casefold().split()):
        raise BrokerError("The protected networking broker runs only on Raspberry Pi hardware.")


def _safe_interface(value: Any, *, require_present: bool = True) -> str:
    interface = str(value or "").strip()
    if not INTERFACE_PATTERN.fullmatch(interface):
        raise BrokerError("The request contains an invalid network interface.")
    if require_present and not (Path("/sys/class/net") / interface).exists():
        raise BrokerError(f"Network interface {interface} is not present.")
    return interface


def _safe_mac_address(value: Any) -> str:
    address = str(value or "").strip().upper()
    if address and not MAC_ADDRESS_PATTERN.fullmatch(address):
        raise BrokerError("The request contains an invalid hardware address.")
    return address


def _interface_for_mac(address: str) -> str:
    if not address:
        return ""
    try:
        candidates = sorted(
            Path("/sys/class/net").iterdir(), key=lambda path: path.name
        )
    except OSError:
        return ""
    expected = address.casefold()
    for candidate in candidates:
        try:
            current = (
                candidate.joinpath("address")
                .read_text(encoding="ascii")
                .strip()
                .casefold()
            )
        except OSError:
            continue
        if current == expected:
            return candidate.name
    return ""


def _safe_text(value: Any, *, limit: int = 253, required: bool = False) -> str:
    text = str(value or "")
    if required and not text:
        raise BrokerError("The request omitted a required value.")
    if len(text) > limit or any(character in text for character in "\x00\r\n"):
        raise BrokerError("The request contains an invalid text value.")
    return text


def _safe_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise BrokerError(f"The request contains an invalid {label} value.")
    return value


def _safe_integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise BrokerError(f"The request contains an invalid {label} value.")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise BrokerError(f"The request contains an invalid {label} value.") from exc
    if not minimum <= number <= maximum:
        raise BrokerError(f"The request contains an invalid {label} value.")
    return number


def _safe_dns_servers(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 6:
        raise BrokerError("The DNS server collection is invalid.")
    servers: list[str] = []
    for item in value:
        try:
            address = ipaddress.ip_address(str(item))
        except ValueError as exc:
            raise BrokerError("A DNS server address is invalid.") from exc
        rendered = str(address)
        if rendered not in servers:
            servers.append(rendered)
    return servers


def _adapter_identity_keys(interface: str, mac_address: str) -> set[str]:
    keys = {f"name:{interface.casefold()}"}
    if mac_address:
        keys.add(f"mac:{mac_address.casefold()}")
    return keys


def _device_type(interface: str) -> str:
    output = _run(
        ["nmcli", "-g", "GENERAL.TYPE", "device", "show", interface]
    ).strip().lower()
    return output.splitlines()[0] if output else ""


def _resolve_interface(
    name: Any,
    mac_address: Any,
    expected_type: str,
) -> tuple[str, bool]:
    fallback = _safe_interface(name, require_present=False)
    address = _safe_mac_address(mac_address)
    resolved = _interface_for_mac(address) or fallback
    present = (Path("/sys/class/net") / resolved).exists()
    if present and _device_type(resolved) != expected_type:
        raise BrokerError(
            f"Network interface {resolved} is not a {expected_type} adapter."
        )
    return resolved, present


def _validate_private_ipv4(settings: dict[str, Any]) -> dict[str, Any]:
    try:
        network = ipaddress.ip_network(str(settings.get("network", "")), strict=True)
        gateway = ipaddress.ip_address(str(settings.get("gateway", "")))
        dhcp_start = ipaddress.ip_address(str(settings.get("dhcp_start", "")))
        dhcp_end = ipaddress.ip_address(str(settings.get("dhcp_end", "")))
    except ValueError as exc:
        raise BrokerError("The private IPv4 configuration is invalid.") from exc
    unusable = {network.network_address, network.broadcast_address}
    if (
        network.version != 4
        or not 16 <= network.prefixlen <= 29
        or any(
            address.version != 4 or address not in network or address in unusable
            for address in (gateway, dhcp_start, dhcp_end)
        )
        or int(dhcp_start) > int(dhcp_end)
        or int(dhcp_start) <= int(gateway) <= int(dhcp_end)
    ):
        raise BrokerError("The private IPv4 configuration is invalid.")
    return {
        "network": str(network),
        "gateway": str(gateway),
        "dhcp_start": str(dhcp_start),
        "dhcp_end": str(dhcp_end),
        "lease_time": _safe_integer(
            settings.get("lease_time"), "DHCP lease time", 120, 31_536_000
        ),
    }


def _validate_wired_settings(settings: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(settings)
    interface, present = _resolve_interface(
        normalized.get("interface"), normalized.get("adapter_mac"), "ethernet"
    )
    normalized["interface"] = interface
    normalized["adapter_mac"] = _safe_mac_address(normalized.get("adapter_mac"))
    normalized["interface_present"] = present
    mode = str(normalized.get("ipv4_mode", ""))
    if mode not in {"dhcp", "static", "shared", "disabled"}:
        raise BrokerError("The wired IPv4 mode is invalid.")
    normalized["ipv4_mode"] = mode
    ipv6_mode = str(normalized.get("ipv6_mode", "auto"))
    if ipv6_mode not in {"auto", "disabled"}:
        raise BrokerError("The wired IPv6 mode is invalid.")
    normalized["ipv6_mode"] = ipv6_mode
    normalized["dns_servers"] = _safe_dns_servers(
        normalized.get("dns_servers", [])
    )
    # NetworkManager rejects ipv4.dns on shared connections.  In shared mode
    # the Pi advertises itself as DNS through NetworkManager's local dnsmasq
    # instance and forwards queries using the system resolver.
    if mode not in {"dhcp", "static"}:
        normalized["dns_servers"] = []
    normalized["autoconnect"] = _safe_bool(
        normalized.get("autoconnect"), "autoconnect"
    )
    normalized["mtu"] = _safe_integer(
        normalized.get("mtu"), "MTU", 0, 9000
    )
    normalized["route_metric"] = _safe_integer(
        normalized.get("route_metric"), "route metric", 0, 65_535
    )
    if mode == "static":
        try:
            address = ipaddress.ip_interface(str(normalized.get("address", "")))
        except ValueError as exc:
            raise BrokerError("The static IPv4 address is invalid.") from exc
        if address.version != 4:
            raise BrokerError("The static interface address must be IPv4.")
        gateway_text = _safe_text(normalized.get("gateway"), limit=64)
        if gateway_text:
            try:
                gateway = ipaddress.ip_address(gateway_text)
            except ValueError as exc:
                raise BrokerError("The static IPv4 gateway is invalid.") from exc
            if gateway.version != 4 or gateway not in address.network:
                raise BrokerError("The static IPv4 gateway is outside the interface network.")
            normalized["gateway"] = str(gateway)
        normalized["address"] = str(address)
    elif mode == "shared":
        normalized.update(_validate_private_ipv4(normalized))
    return normalized


def _validate_configuration(configuration: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(configuration)
    country = str(normalized.get("country", ""))
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise BrokerError("The wireless country code is invalid.")
    raw_profiles = normalized.get("profiles")
    if not isinstance(raw_profiles, list) or len(raw_profiles) > 32:
        raise BrokerError("The network profile collection is invalid.")
    profiles: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    names: set[str] = set()
    active_wifi: set[str] = set()
    active_wired: set[str] = set()
    bridged_uplinks: set[str] = set()
    private_networks: list[ipaddress.IPv4Network] = []
    for raw_profile in raw_profiles:
        if not isinstance(raw_profile, dict):
            raise BrokerError("A network profile is invalid.")
        identifier = str(raw_profile.get("id", ""))
        if not PROFILE_ID_PATTERN.fullmatch(identifier) or identifier in identifiers:
            raise BrokerError("A network profile identifier is invalid or duplicated.")
        identifiers.add(identifier)
        name = _safe_text(raw_profile.get("name"), limit=80, required=True)
        if name.casefold() in names:
            raise BrokerError("A network profile name is duplicated.")
        names.add(name.casefold())
        kind = str(raw_profile.get("kind", ""))
        if kind not in {"wifi-ap", "wifi-client", "wired"}:
            raise BrokerError("A network profile type is invalid.")
        enabled = _safe_bool(raw_profile.get("enabled"), "enabled-profile")
        if kind == "wired":
            profile = _validate_wired_settings(raw_profile)
            if enabled:
                interface = profile["interface"]
                resources = _adapter_identity_keys(
                    interface, str(profile.get("adapter_mac", ""))
                )
                if active_wired & resources:
                    raise BrokerError("An Ethernet adapter is assigned more than once.")
                active_wired.update(resources)
                if profile["ipv4_mode"] == "shared":
                    private_networks.append(ipaddress.ip_network(profile["network"]))
        else:
            profile = dict(raw_profile)
            profile["country"] = country
            profile["mode"] = (
                "client"
                if kind == "wifi-client"
                else str(profile.get("network_mode", ""))
            )
            profile = _validate_settings(profile, require_present=False)
            wifi_interface, wifi_present = _resolve_interface(
                profile["wifi_interface"], profile.get("adapter_mac"), "wifi"
            )
            profile["wifi_interface"] = wifi_interface
            profile["adapter_mac"] = _safe_mac_address(
                profile.get("adapter_mac")
            )
            profile["interface_present"] = wifi_present
            if enabled:
                resources = _adapter_identity_keys(
                    wifi_interface, str(profile.get("adapter_mac", ""))
                )
                if active_wifi & resources:
                    raise BrokerError("A Wi-Fi adapter is assigned more than once.")
                active_wifi.update(resources)
                if kind == "wifi-ap" and profile["mode"] == "bridge":
                    uplink, uplink_present = _resolve_interface(
                        profile["uplink_interface"],
                        profile.get("uplink_mac"),
                        "ethernet",
                    )
                    profile["uplink_interface"] = uplink
                    profile["uplink_mac"] = _safe_mac_address(
                        profile.get("uplink_mac")
                    )
                    profile["uplink_present"] = uplink_present
                    uplink_resources = _adapter_identity_keys(
                        uplink, str(profile.get("uplink_mac", ""))
                    )
                    if bridged_uplinks & uplink_resources:
                        raise BrokerError("An Ethernet adapter is bridged more than once.")
                    bridged_uplinks.update(uplink_resources)
                elif kind == "wifi-ap":
                    uplink, uplink_present = _resolve_interface(
                        profile["uplink_interface"],
                        profile.get("uplink_mac"),
                        "ethernet",
                    )
                    profile["uplink_interface"] = uplink
                    profile["uplink_mac"] = _safe_mac_address(
                        profile.get("uplink_mac")
                    )
                    profile["uplink_present"] = uplink_present
                    private_networks.append(ipaddress.ip_network(profile["network"]))
        profile.update(
            {
                "id": identifier,
                "name": name,
                "kind": kind,
                "enabled": enabled,
            }
        )
        profiles.append(profile)
    if bridged_uplinks & active_wired:
        raise BrokerError(
            "An Ethernet adapter cannot have its own profile while serving as a bridge port."
        )
    for index, network in enumerate(private_networks):
        if any(network.overlaps(other) for other in private_networks[index + 1 :]):
            raise BrokerError("Private DHCP networks overlap.")
    return {"schema_version": 2, "country": country, "profiles": profiles}


def network_interface_inventory() -> list[dict[str, Any]]:
    output = _run_optional(
        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"]
    )
    inventory: list[dict[str, Any]] = []
    for name, device_type, state, connection in _nmcli_rows(output, 4):
        if device_type not in {"wifi", "ethernet"}:
            continue
        details = _nmcli_properties(
            _run_optional(
                [
                    "nmcli",
                    "-t",
                    "-f",
                    (
                        "GENERAL.HWADDR,GENERAL.VENDOR,"
                        "GENERAL.PRODUCT,GENERAL.DRIVER,GENERAL.MTU,GENERAL.UDI,"
                        "IP4.ADDRESS,IP4.GATEWAY,IP4.DNS,IP6.ADDRESS,"
                        "WIFI-PROPERTIES.AP,WIFI-PROPERTIES.2GHZ,"
                        "WIFI-PROPERTIES.5GHZ,WIFI-PROPERTIES.6GHZ"
                    ),
                    "device",
                    "show",
                    name,
                ]
            )
        )
        def first(key: str) -> str:
            return next((value for value in details.get(key, []) if value), "")

        current_mac = first("GENERAL.HWADDR")
        permanent_mac = _permanent_hardware_address(name, current_mac)
        item: dict[str, Any] = {
            "name": name,
            "type": device_type,
            "state": state,
            "connection": "" if connection == "--" else connection,
            "mac_address": permanent_mac.upper(),
            "current_mac": current_mac.upper(),
            "vendor": first("GENERAL.VENDOR"),
            "product": first("GENERAL.PRODUCT"),
            "driver": first("GENERAL.DRIVER"),
            "mtu": first("GENERAL.MTU"),
            "bus": "USB" if "/usb" in first("GENERAL.UDI") else "Built-in",
            "ipv4_addresses": details.get("IP4.ADDRESS", []),
            "ipv4_gateway": first("IP4.GATEWAY"),
            "dns_servers": details.get("IP4.DNS", []),
            "ipv6_addresses": details.get("IP6.ADDRESS", []),
        }
        if device_type == "wifi":
            item.update(
                {
                    "ap": first("WIFI-PROPERTIES.AP") == "yes",
                    "band_2ghz": first("WIFI-PROPERTIES.2GHZ") == "yes",
                    "band_5ghz": first("WIFI-PROPERTIES.5GHZ") == "yes",
                    "band_6ghz": first("WIFI-PROPERTIES.6GHZ") == "yes",
                    "radio": {},
                }
            )
            if item["connection"]:
                item["radio"] = _wireless_radio_snapshot(name)
        else:
            item["carrier"] = _ethernet_has_carrier(name)
        inventory.append(item)
    return inventory


def _ethernet_has_carrier(
    interface: str, *, sys_class_net: Path = Path("/sys/class/net")
) -> bool:
    """Return false only when the kernel explicitly reports no wired link."""

    try:
        carrier = (sys_class_net / interface / "carrier").read_text(
            encoding="utf-8"
        ).strip()
    except OSError:
        # Virtual adapters and some drivers do not expose carrier. Do not make
        # an otherwise usable profile dormant merely because it is unknown.
        return True
    return carrier != "0"


def _keep_usb_interface_awake(
    interface: str, *, sys_class_net: Path = Path("/sys/class/net")
) -> bool:
    """Disable runtime autosuspend for a toolkit-managed USB network adapter.

    Some USB Ethernet chipsets can remain present while their PHY stops
    negotiating after hot-plug or an idle transition.  Network profiles are
    expected to survive those transitions, so favor link reliability over the
    small power saving while the adapter is managed by the toolkit.
    """

    try:
        device = (sys_class_net / interface / "device").resolve(strict=True)
    except OSError:
        return False
    for candidate in (device, *device.parents):
        if not (candidate / "idVendor").is_file():
            continue
        control = candidate / "power" / "control"
        try:
            control.write_text("on\n", encoding="utf-8")
        except OSError:
            return False
        return True
    return False


def _interface_presence_signature(
    *, sys_class_net: Path = Path("/sys/class/net")
) -> tuple[tuple[str, str, str], ...]:
    """Return a cheap hot-plug/link signature without polling NetworkManager."""

    interfaces: list[tuple[str, str, str]] = []
    try:
        paths = list(sys_class_net.iterdir())
    except OSError:
        return ()
    for path in paths:
        if path.name == "lo":
            continue
        try:
            address = (path / "address").read_text(encoding="utf-8").strip().upper()
        except OSError:
            address = ""
        try:
            carrier = (path / "carrier").read_text(encoding="utf-8").strip()
        except OSError:
            carrier = ""
        interfaces.append((path.name, address, carrier))
    return tuple(sorted(interfaces))


def _parse_iw_stations(output: str) -> list[dict[str, Any]]:
    stations: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = re.match(r"Station ((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", line)
        if match:
            current = {"mac_address": match.group(1).upper()}
            stations.append(current)
            continue
        if current is None or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        normalized_key = key.replace(" ", "_").replace("/", "_")
        if normalized_key in {
            "inactive_time",
            "rx_bytes",
            "rx_packets",
            "tx_bytes",
            "tx_packets",
            "tx_retries",
            "tx_failed",
            "signal",
            "signal_avg",
            "tx_bitrate",
            "rx_bitrate",
            "connected_time",
        }:
            current[normalized_key] = value
    return stations


def _dhcp_leases() -> list[dict[str, Any]]:
    leases: list[dict[str, Any]] = []
    root = Path("/var/lib/NetworkManager")
    try:
        paths = sorted(root.glob("dnsmasq*.leases"))
    except OSError:
        return leases
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or not MAC_ADDRESS_PATTERN.fullmatch(fields[1]):
                continue
            try:
                address = ipaddress.ip_address(fields[2])
                expires_at = int(fields[0])
            except ValueError:
                continue
            leases.append(
                {
                    "expires_at": expires_at,
                    "mac_address": fields[1].upper(),
                    "ip_address": str(address),
                    "hostname": "" if fields[3] == "*" else fields[3][:253],
                }
            )
    return leases


def _neighbor_telemetry(interface: str) -> dict[str, dict[str, str]]:
    neighbors: dict[str, dict[str, str]] = {}
    for line in _run_optional(
        ["ip", "neigh", "show", "dev", interface]
    ).splitlines():
        fields = line.split()
        if "lladdr" not in fields or not fields:
            continue
        index = fields.index("lladdr")
        if index + 1 >= len(fields) or not MAC_ADDRESS_PATTERN.fullmatch(
            fields[index + 1]
        ):
            continue
        try:
            address = str(ipaddress.ip_address(fields[0]))
        except ValueError:
            continue
        neighbors[fields[index + 1].upper()] = {
            "ip_address": address,
            "neighbor_state": fields[-1].upper(),
        }
    return neighbors


def wireless_client_telemetry(
    configuration: dict[str, Any], profile_records: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    iw = _iw_binary()
    leases = _dhcp_leases()
    results: list[dict[str, Any]] = []
    for profile in configuration.get("profiles", []):
        if (
            not isinstance(profile, dict)
            or not profile.get("enabled")
            or profile.get("kind") != "wifi-ap"
        ):
            continue
        try:
            interface, present = _resolve_interface(
                profile.get("wifi_interface"),
                profile.get("adapter_mac"),
                "wifi",
            )
        except BrokerError:
            interface = str(profile.get("wifi_interface", ""))
            present = False
        bridge_record = next(
            (
                record
                for record in profile_records
                if record.get("logical_id") == profile.get("id")
                and record.get("role") == "bridge"
            ),
            {},
        )
        neighbor_interface = str(bridge_record.get("interface") or interface)
        neighbors = _neighbor_telemetry(neighbor_interface)
        stations = (
            _parse_iw_stations(
                _run_optional([iw, "dev", interface, "station", "dump"])
            )
            if present and iw
            else []
        )
        station_by_mac = {station["mac_address"]: station for station in stations}
        relevant_leases = []
        network = None
        if profile.get("network_mode") == "nat":
            try:
                network = ipaddress.ip_network(str(profile.get("network", "")))
            except ValueError:
                network = None
        if network is not None:
            for lease in leases:
                if ipaddress.ip_address(lease["ip_address"]) not in network:
                    continue
                relevant_leases.append(lease)
        macs = set(station_by_mac)
        macs.update(lease["mac_address"] for lease in relevant_leases)
        macs.update(neighbors)
        clients = []
        for mac in sorted(macs):
            station = dict(station_by_mac.get(mac) or {})
            lease = next(
                (item for item in relevant_leases if item["mac_address"] == mac),
                {},
            )
            client = {"mac_address": mac, **station}
            client["ip_address"] = str(
                lease.get("ip_address")
                or (neighbors.get(mac) or {}).get("ip_address", "")
            )
            client["hostname"] = str(lease.get("hostname", ""))
            client["lease_expires_at"] = int(lease.get("expires_at") or 0)
            client["neighbor_state"] = str(
                (neighbors.get(mac) or {}).get("neighbor_state", "")
            )
            clients.append(client)
        info = (
            _run_optional([iw, "dev", interface, "info"])
            if present and iw
            else ""
        )
        channel_match = re.search(r"channel\s+(\d+)\s+\((\d+)\s+MHz", info)
        results.append(
            {
                "profile_id": str(profile.get("id", "")),
                "profile_name": str(profile.get("name", "")),
                "interface": interface,
                "available": present,
                "channel": channel_match.group(1) if channel_match else "",
                "frequency_mhz": channel_match.group(2) if channel_match else "",
                "client_count": len(clients),
                "clients": clients,
                "station_metrics_available": bool(iw),
            }
        )
    return results


def wired_client_telemetry(
    configuration: dict[str, Any], profile_records: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return downstream clients for toolkit-managed private wired networks."""

    leases = _dhcp_leases()
    results: list[dict[str, Any]] = []
    for profile in configuration.get("profiles", []):
        if (
            not isinstance(profile, dict)
            or not profile.get("enabled")
            or profile.get("kind") != "wired"
            or profile.get("ipv4_mode") != "shared"
        ):
            continue
        try:
            interface, present = _resolve_interface(
                profile.get("interface"),
                profile.get("adapter_mac"),
                "ethernet",
            )
        except BrokerError:
            interface = str(profile.get("interface", ""))
            present = False
        record = next(
            (
                item
                for item in profile_records
                if item.get("logical_id") == profile.get("id")
                and item.get("role") == "wired"
            ),
            {},
        )
        neighbor_interface = str(record.get("interface") or interface)
        try:
            network = ipaddress.ip_network(str(profile.get("network", "")))
        except ValueError:
            network = None
        relevant_leases = []
        if network is not None:
            relevant_leases = [
                lease
                for lease in leases
                if ipaddress.ip_address(lease["ip_address"]) in network
            ]
        neighbors = {
            mac: observation
            for mac, observation in _neighbor_telemetry(neighbor_interface).items()
            if network is not None
            and ipaddress.ip_address(observation["ip_address"]) in network
        }
        macs = {lease["mac_address"] for lease in relevant_leases}
        macs.update(neighbors)
        clients = []
        for mac in sorted(macs):
            lease = next(
                (item for item in relevant_leases if item["mac_address"] == mac),
                {},
            )
            neighbor = neighbors.get(mac) or {}
            clients.append(
                {
                    "mac_address": mac,
                    "ip_address": str(
                        lease.get("ip_address") or neighbor.get("ip_address", "")
                    ),
                    "hostname": str(lease.get("hostname", "")),
                    "lease_expires_at": int(lease.get("expires_at") or 0),
                    "neighbor_state": str(neighbor.get("neighbor_state", "")),
                }
            )
        results.append(
            {
                "profile_id": str(profile.get("id", "")),
                "profile_name": str(profile.get("name", "")),
                "interface": interface,
                "available": present,
                "network": str(network) if network is not None else "",
                "client_count": len(clients),
                "clients": clients,
            }
        )
    return results


def _validate_settings(
    settings: dict[str, Any], *, require_present: bool = True
) -> dict[str, Any]:
    normalized = dict(settings)
    mode = str(normalized.get("mode", ""))
    if mode not in {"nat", "bridge", "client"}:
        raise BrokerError("The request contains an unsupported networking mode.")
    normalized["mode"] = mode
    normalized["wifi_interface"] = _safe_interface(
        normalized.get("wifi_interface"), require_present=require_present
    )
    country = str(normalized.get("country", ""))
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise BrokerError("The wireless country code is invalid.")
    normalized["country"] = country
    ssid = _safe_text(normalized.get("ssid"), limit=32, required=True)
    if len(ssid.encode("utf-8")) > 32:
        raise BrokerError("The Wi-Fi SSID exceeds 32 bytes.")
    normalized["ssid"] = ssid
    normalized["hidden"] = _safe_bool(normalized.get("hidden"), "hidden-network")
    normalized["autoconnect"] = _safe_bool(
        normalized.get("autoconnect"), "autoconnect"
    )
    security = str(normalized.get("security", ""))
    allowed_security = (
        {"wpa2", "wpa2-wpa3", "wpa3"}
        if mode in {"nat", "bridge"}
        else {"open", "wpa2", "wpa2-wpa3", "wpa3", "peap", "eap-tls"}
    )
    if security not in allowed_security:
        raise BrokerError("The request contains an unsupported Wi-Fi security mode.")
    normalized["security"] = security
    if security in {"wpa2", "wpa2-wpa3", "wpa3"}:
        passphrase = _safe_text(
            normalized.get("passphrase"), limit=63, required=True
        )
        if len(passphrase) < 8:
            raise BrokerError("The Wi-Fi passphrase must contain at least 8 characters.")
        normalized["passphrase"] = passphrase
    elif security in {"peap", "eap-tls"}:
        normalized["identity"] = _safe_text(
            normalized.get("identity"), required=True
        )
        normalized["anonymous_identity"] = _safe_text(
            normalized.get("anonymous_identity")
        )
        ca_source = str(normalized.get("ca_source", ""))
        allowed_ca_sources = {"system", "upload"}
        if security == "peap" and not normalized.get(
            "verify_server_certificate", True
        ):
            allowed_ca_sources.add("none")
        if ca_source not in allowed_ca_sources:
            raise BrokerError("The certificate trust source is invalid.")
        if ca_source == "upload" and not normalized.get("ca_path"):
            raise BrokerError("The uploaded CA certificate is unavailable.")
        normalized["ca_source"] = ca_source
        normalized["server_domain"] = _safe_text(
            normalized.get("server_domain")
        )
        if ca_source != "none" and not normalized["server_domain"]:
            raise BrokerError("The authentication-server domain is required.")
        if security == "peap":
            normalized["password"] = _safe_text(
                normalized.get("password"), limit=1024, required=True
            )
        elif not normalized.get("private_key_path") or not normalized.get(
            "client_certificate_path"
        ):
            raise BrokerError("The EAP-TLS client identity is unavailable.")

    if mode in {"nat", "bridge"}:
        normalized["client_isolation"] = _safe_bool(
            normalized.get("client_isolation"), "client-isolation"
        )
        band = str(normalized.get("band", ""))
        if band not in {"auto", "2.4", "5"}:
            raise BrokerError("The wireless band is invalid.")
        normalized["band"] = band
        normalized["channel"] = _safe_integer(
            normalized.get("channel"), "wireless channel", 0, 196
        )
        uplink = _safe_interface(
            normalized.get("uplink_interface"), require_present=require_present
        )
        if uplink == normalized["wifi_interface"]:
            raise BrokerError("The Wi-Fi interface cannot also be the wired uplink.")
        normalized["uplink_interface"] = uplink

    if mode == "nat":
        try:
            network = ipaddress.ip_network(
                str(normalized.get("network", "")), strict=True
            )
            gateway = ipaddress.ip_address(str(normalized.get("gateway", "")))
            dhcp_start = ipaddress.ip_address(
                str(normalized.get("dhcp_start", ""))
            )
            dhcp_end = ipaddress.ip_address(str(normalized.get("dhcp_end", "")))
        except ValueError as exc:
            raise BrokerError("The NAT address configuration is invalid.") from exc
        unusable = {network.network_address, network.broadcast_address}
        if (
            network.version != 4
            or not 16 <= network.prefixlen <= 29
            or any(
                address.version != 4
                or address not in network
                or address in unusable
                for address in (gateway, dhcp_start, dhcp_end)
            )
            or int(dhcp_start) > int(dhcp_end)
            or int(dhcp_start) <= int(gateway) <= int(dhcp_end)
        ):
            raise BrokerError("The NAT address configuration is invalid.")
        normalized.update(
            {
                "network": str(network),
                "gateway": str(gateway),
                "dhcp_start": str(dhcp_start),
                "dhcp_end": str(dhcp_end),
                "lease_time": _safe_integer(
                    normalized.get("lease_time"),
                    "DHCP lease time",
                    120,
                    31_536_000,
                ),
            }
        )
    elif mode == "bridge":
        normalized["vlan_id"] = _safe_integer(
            normalized.get("vlan_id"), "VLAN ID", 0, 4094
        )
    return normalized


def _sync_directory(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _sync_directory(path.parent)


def _unlink_json(path: Path) -> None:
    path.unlink(missing_ok=True)
    _sync_directory(path.parent)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _config_text(sections: list[tuple[str, dict[str, Any]]]) -> str:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    for section, values in sections:
        parser[section] = {
            key: str(value).lower() if isinstance(value, bool) else str(value)
            for key, value in values.items()
            if value is not None and value != ""
        }
    from io import StringIO

    output = StringIO()
    parser.write(output, space_around_delimiters=False)
    return output.getvalue()


def _security_sections(settings: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    security = str(settings.get("security", ""))
    if security == "open":
        return []
    if security in {"wpa2", "wpa2-wpa3", "wpa3"}:
        key_management = "sae" if security == "wpa3" else "wpa-psk"
        pmf = "3" if security == "wpa3" else ("2" if security == "wpa2-wpa3" else "1")
        return [
            (
                "wifi-security",
                {
                    "key-mgmt": key_management,
                    "psk": _safe_text(settings.get("passphrase"), limit=63, required=True),
                    "proto": "rsn;",
                    "pairwise": "ccmp;",
                    "group": "ccmp;",
                    "pmf": pmf,
                },
            )
        ]
    if security not in {"peap", "eap-tls"}:
        raise BrokerError("The request contains an unsupported Wi-Fi security mode.")
    enterprise: dict[str, Any] = {
        "eap": "peap;" if security == "peap" else "tls;",
        "identity": _safe_text(settings.get("identity"), required=True),
    }
    anonymous = _safe_text(settings.get("anonymous_identity"))
    if anonymous:
        enterprise["anonymous-identity"] = anonymous
    server_domain = _safe_text(settings.get("server_domain"))
    if server_domain:
        enterprise["domain-suffix-match"] = server_domain
    ca_path = _safe_text(settings.get("ca_path"), limit=1024)
    if ca_path:
        enterprise["ca-cert"] = ca_path
    elif settings.get("ca_source") == "system":
        enterprise["system-ca-certs"] = True
    else:
        enterprise["system-ca-certs"] = False
    if security == "peap":
        enterprise["phase2-auth"] = "mschapv2"
        enterprise["password"] = _safe_text(
            settings.get("password"), limit=1024, required=True
        )
    else:
        private_key = _safe_text(settings.get("private_key_path"), limit=1024, required=True)
        client_certificate = _safe_text(
            settings.get("client_certificate_path"), limit=1024, required=True
        )
        enterprise["private-key"] = private_key
        enterprise["client-cert"] = client_certificate
        key_password = _safe_text(settings.get("private_key_password"), limit=1024)
        if key_password:
            enterprise["private-key-password"] = key_password
    return [
        ("wifi-security", {"key-mgmt": "wpa-eap"}),
        ("802-1x", enterprise),
    ]


def _wifi_sections(settings: dict[str, Any], *, access_point: bool) -> list[tuple[str, dict[str, Any]]]:
    wifi: dict[str, Any] = {
        "mode": "ap" if access_point else "infrastructure",
        "ssid": _safe_text(settings.get("ssid"), limit=32, required=True),
        "hidden": bool(settings.get("hidden")),
    }
    adapter_mac = _safe_mac_address(settings.get("adapter_mac"))
    if adapter_mac:
        wifi["mac-address"] = adapter_mac
    if access_point:
        band = str(settings.get("band", "auto"))
        if band == "2.4":
            wifi["band"] = "bg"
        elif band == "5":
            wifi["band"] = "a"
        channel = int(settings.get("channel") or 0)
        if channel:
            wifi["channel"] = channel
        wifi["ap-isolation"] = 1 if settings.get("client_isolation") else 0
    return [("wifi", wifi), *_security_sections(settings)]


def _build_wired_profile(
    settings: dict[str, Any], transaction_id: str
) -> dict[str, str]:
    interface = str(settings["interface"])
    identifier = f"{PROFILE_PREFIX}{transaction_id}-wired"
    profile_uuid = str(uuid.uuid4())
    ipv4_mode = str(settings["ipv4_mode"])
    dns_servers = list(settings.get("dns_servers") or [])
    ipv4: dict[str, Any]
    if ipv4_mode == "dhcp":
        ipv4 = {"method": "auto"}
    elif ipv4_mode == "static":
        address = str(settings["address"])
        gateway = str(settings.get("gateway", ""))
        ipv4 = {
            "method": "manual",
            "address1": f"{address},{gateway}" if gateway else address,
            "never-default": not bool(gateway),
        }
    elif ipv4_mode == "shared":
        gateway = str(settings["gateway"])
        prefix = str(settings["network"]).split("/", 1)[-1]
        ipv4 = {
            "method": "shared",
            "address1": f"{gateway}/{prefix}",
            "shared-dhcp-range": (
                f"{settings['dhcp_start']},{settings['dhcp_end']}"
            ),
            "shared-dhcp-lease-time": int(settings["lease_time"]),
        }
    else:
        ipv4 = {"method": "disabled"}
    route_metric = int(settings.get("route_metric") or 0)
    if route_metric and ipv4_mode in {"dhcp", "static"}:
        ipv4["route-metric"] = route_metric
    if dns_servers and ipv4_mode in {"dhcp", "static"}:
        ipv4["dns"] = ";".join(dns_servers) + ";"
        if ipv4_mode == "dhcp":
            ipv4["ignore-auto-dns"] = True
    ethernet: dict[str, Any] = {}
    adapter_mac = _safe_mac_address(settings.get("adapter_mac"))
    if adapter_mac:
        ethernet["mac-address"] = adapter_mac
    mtu = int(settings.get("mtu") or 0)
    if mtu:
        ethernet["mtu"] = mtu
    sections = [
        (
            "connection",
            {
                "id": identifier,
                "uuid": profile_uuid,
                "type": "ethernet",
                "autoconnect": bool(settings.get("autoconnect", True)),
            },
        ),
        ("ethernet", ethernet),
        ("ipv4", ipv4),
        (
            "ipv6",
            {
                "method": (
                    "disabled"
                    if settings.get("ipv6_mode") == "disabled"
                    else "auto"
                )
            },
        ),
    ]
    if not adapter_mac:
        sections[0][1]["interface-name"] = interface
    return {
        "role": "wired",
        "id": identifier,
        "uuid": profile_uuid,
        "filename": f"{identifier}.nmconnection",
        "interface": interface,
        "content": _config_text(sections),
    }


def build_configuration_profiles(
    configuration: dict[str, Any], transaction_id: str
) -> list[dict[str, str]]:
    configuration = _validate_configuration(configuration)
    profiles: list[dict[str, str]] = []
    for index, logical in enumerate(configuration["profiles"]):
        if not logical["enabled"]:
            continue
        suffix = f"{transaction_id[:10]}{index:02x}"
        if logical["kind"] == "wired":
            built = [_build_wired_profile(logical, suffix)]
        else:
            legacy = dict(logical)
            legacy["country"] = configuration["country"]
            legacy["mode"] = (
                "client"
                if logical["kind"] == "wifi-client"
                else logical["network_mode"]
            )
            built = build_connection_profiles(
                legacy, suffix, require_present=False
            )
        for profile in built:
            profile["logical_id"] = str(logical["id"])
            profile["logical_name"] = str(logical["name"])
            profile["logical_kind"] = str(logical["kind"])
            if (
                logical["kind"] in {"wifi-ap", "wifi-client"}
                and not profile.get("interface")
            ):
                profile["interface"] = str(logical["wifi_interface"])
            profiles.append(profile)
    return profiles


def build_connection_profiles(
    settings: dict[str, Any],
    transaction_id: str,
    *,
    require_present: bool = True,
) -> list[dict[str, str]]:
    if isinstance(settings.get("profiles"), list):
        return build_configuration_profiles(settings, transaction_id)
    settings = _validate_settings(settings, require_present=require_present)
    mode = settings["mode"]
    wifi_interface = settings["wifi_interface"]
    autoconnect = bool(settings.get("autoconnect", True))
    profiles: list[dict[str, str]] = []

    def profile(role: str, sections: list[tuple[str, dict[str, Any]]]) -> dict[str, str]:
        identifier = f"{PROFILE_PREFIX}{transaction_id}-{role}"
        profile_uuid = str(uuid.uuid4())
        metadata = sections[0][1]
        interface_name = metadata.pop("_interface")
        bind_by_mac = bool(metadata.pop("_bind_by_mac", False))
        connection = {
            "id": identifier,
            "uuid": profile_uuid,
            "type": metadata.pop("_type"),
            "autoconnect": autoconnect,
        }
        if not bind_by_mac:
            connection["interface-name"] = interface_name
        controller = metadata.pop("_controller", "")
        if controller:
            connection["controller"] = controller
            connection["port-type"] = "bridge"
        if connection["type"] == "bridge":
            connection["autoconnect-ports"] = 1
        body = [("connection", connection), *sections[1:]]
        return {
            "role": role,
            "id": identifier,
            "uuid": profile_uuid,
            "filename": f"{identifier}.nmconnection",
            "interface": interface_name,
            "content": _config_text(body),
        }

    if mode == "nat":
        gateway = _safe_text(settings.get("gateway"), limit=64, required=True)
        prefix = str(settings.get("network", "")).split("/", 1)[-1]
        sections = [
            (
                "profile",
                {
                    "_type": "wifi",
                    "_interface": wifi_interface,
                    "_bind_by_mac": bool(settings.get("adapter_mac")),
                },
            ),
            *_wifi_sections(settings, access_point=True),
            (
                "ipv4",
                {
                    "method": "shared",
                    "address1": f"{gateway}/{prefix}",
                    "shared-dhcp-range": (
                        f"{_safe_text(settings.get('dhcp_start'), limit=64, required=True)},"
                        f"{_safe_text(settings.get('dhcp_end'), limit=64, required=True)}"
                    ),
                    "shared-dhcp-lease-time": int(settings.get("lease_time") or 3600),
                },
            ),
            ("ipv6", {"method": "disabled"}),
        ]
        profiles.append(profile("hotspot", sections))
    elif mode == "client":
        sections = [
            (
                "profile",
                {
                    "_type": "wifi",
                    "_interface": wifi_interface,
                    "_bind_by_mac": bool(settings.get("adapter_mac")),
                },
            ),
            *_wifi_sections(settings, access_point=False),
            ("ipv4", {"method": "auto"}),
            ("ipv6", {"method": "auto"}),
        ]
        profiles.append(profile("client", sections))
    else:
        uplink = _safe_interface(settings.get("uplink_interface"))
        vlan_id = int(settings.get("vlan_id") or 0)
        bridge_interface = f"twnbr{transaction_id[:5]}"
        bridge_ipv4 = (
            {"method": "disabled"}
            if vlan_id
            else {"method": "auto", "may-fail": True}
        )
        bridge_ipv6 = (
            {"method": "disabled"}
            if vlan_id
            else {"method": "auto", "may-fail": True}
        )
        bridge_sections = [
            (
                "profile",
                {"_type": "bridge", "_interface": bridge_interface},
            ),
            ("ethernet", {}),
            ("bridge", {}),
            ("ipv4", bridge_ipv4),
            ("ipv6", bridge_ipv6),
        ]
        bridge = profile("bridge", bridge_sections)
        profiles.append(bridge)
        if vlan_id:
            port_interface = f"twnv{vlan_id}"
            port_sections = [
                (
                    "profile",
                    {
                        "_type": "vlan",
                        "_interface": port_interface,
                        "_controller": bridge_interface,
                    },
                ),
                ("vlan", {"parent": uplink, "id": vlan_id}),
                ("bridge-port", {}),
            ]
        else:
            port_sections = [
                (
                    "profile",
                    {
                        "_type": "ethernet",
                        "_interface": uplink,
                        "_controller": bridge_interface,
                        "_bind_by_mac": bool(settings.get("uplink_mac")),
                    },
                ),
                (
                    "ethernet",
                    {
                        "mac-address": _safe_mac_address(
                            settings.get("uplink_mac")
                        )
                    },
                ),
                ("bridge-port", {}),
            ]
        profiles.append(profile("uplink", port_sections))
        wifi_sections = [
            (
                "profile",
                {
                    "_type": "wifi",
                    "_interface": wifi_interface,
                    "_controller": bridge_interface,
                    "_bind_by_mac": bool(settings.get("adapter_mac")),
                },
            ),
            *_wifi_sections(settings, access_point=True),
            ("bridge-port", {}),
        ]
        profiles.append(profile("hotspot", wifi_sections))
    return profiles


class PiNetworkBroker:
    def __init__(
        self,
        *,
        socket_path: Path,
        allowed_uid: int,
        toolkit_root: Path,
        connection_directory: Path = Path("/etc/NetworkManager/system-connections"),
        state_directory: Path = Path("/etc/twn-toolkit/pi-networking"),
    ) -> None:
        self.socket_path = socket_path
        self.allowed_uid = allowed_uid
        self.toolkit_root = toolkit_root.resolve()
        self.material_root = (self.toolkit_root / "instance" / "raspberry_pi_networking_material").resolve()
        self.connection_directory = connection_directory
        self.state_directory = state_directory
        self.current_path = state_directory / "current.json"
        self.pending_path = state_directory / "pending.json"
        self.certificate_directory = state_directory / "certificates"
        self._lock = threading.RLock()
        self._stopping = threading.Event()
        self._interface_signature: tuple[tuple[str, str, str], ...] | None = None
        self._next_reconcile_at = 0.0

    def _peer_uid(self, connection: socket.socket) -> int:
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, _gid = struct.unpack("3i", credentials)
        return uid

    def _copy_material(self, settings: dict[str, Any], transaction_id: str) -> None:
        sources = settings.pop("material", {})
        if not isinstance(sources, dict):
            raise BrokerError("Certificate material is invalid.")
        target = self.certificate_directory / transaction_id
        copied: dict[str, str] = {}
        allowed = {"ca", "client_certificate", "private_key", "bundle"}
        try:
            for key, raw_path in sources.items():
                if key not in allowed:
                    raise BrokerError("Certificate material contains an unsupported file.")
                source = Path(str(raw_path)).resolve(strict=True)
                try:
                    source.relative_to(self.material_root)
                except ValueError as exc:
                    raise BrokerError("Certificate material is outside the toolkit instance.") from exc
                source_stat = source.lstat()
                if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_uid != self.allowed_uid:
                    raise BrokerError("Certificate material has an invalid owner or file type.")
                if source_stat.st_size > MAX_MATERIAL_BYTES:
                    raise BrokerError("Certificate material exceeds the 2 MiB limit.")
                target.mkdir(parents=True, mode=0o700, exist_ok=True)
                destination = target / source.name
                source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    data = os.read(source_descriptor, MAX_MATERIAL_BYTES + 1)
                finally:
                    os.close(source_descriptor)
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    os.write(descriptor, data)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                copied[key] = str(destination)
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            raise
        if copied.get("ca"):
            settings["ca_path"] = copied["ca"]
        if copied.get("bundle"):
            settings["client_certificate_path"] = copied["bundle"]
            settings["private_key_path"] = copied["bundle"]
        else:
            if copied.get("client_certificate"):
                settings["client_certificate_path"] = copied["client_certificate"]
            if copied.get("private_key"):
                settings["private_key_path"] = copied["private_key"]

    def _copy_configuration_material(
        self, configuration: dict[str, Any], transaction_id: str
    ) -> None:
        profiles = configuration.get("profiles")
        if not isinstance(profiles, list):
            raise BrokerError("The network profile collection is invalid.")
        for profile in profiles:
            if not isinstance(profile, dict):
                raise BrokerError("A network profile is invalid.")
            identifier = str(profile.get("id", ""))
            if not PROFILE_ID_PATTERN.fullmatch(identifier):
                raise BrokerError("A network profile identifier is invalid.")
            self._copy_material(profile, f"{transaction_id}/{identifier}")

    def _checkpoint_create(self, timeout_seconds: int) -> str:
        output = _run(
            [
                "busctl",
                "--system",
                "call",
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager",
                "org.freedesktop.NetworkManager",
                "CheckpointCreate",
                "aouu",
                "0",
                str(timeout_seconds),
                str(CHECKPOINT_FLAGS),
            ]
        )
        match = re.search(r'"(/org/freedesktop/NetworkManager/Checkpoint/\d+)"', output)
        if not match:
            raise BrokerError("NetworkManager did not return a rollback checkpoint.")
        return match.group(1)

    @staticmethod
    def _checkpoint_action(method: str, checkpoint: str) -> None:
        if not CHECKPOINT_PATTERN.fullmatch(checkpoint):
            raise BrokerError("The saved NetworkManager checkpoint is invalid.")
        _run(
            [
                "busctl",
                "--system",
                "call",
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager",
                "org.freedesktop.NetworkManager",
                method,
                "o",
                checkpoint,
            ]
        )

    def _write_profiles(self, profiles: list[dict[str, str]]) -> None:
        self.connection_directory.mkdir(parents=True, exist_ok=True)
        for profile in profiles:
            path = self.connection_directory / profile["filename"]
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, profile["content"].encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _run(["nmcli", "connection", "load", str(path)])

    @staticmethod
    def _active_connections() -> list[dict[str, str]]:
        output = _run(
            ["nmcli", "-t", "-f", "UUID,TYPE", "connection", "show", "--active"]
        )
        values = []
        for line in output.splitlines():
            profile_uuid, separator, connection_type = line.partition(":")
            if separator and connection_type != "loopback":
                values.append({"uuid": profile_uuid, "type": connection_type})
        return values

    @staticmethod
    def _wifi_enabled() -> bool:
        return _run(["nmcli", "-t", "radio", "wifi"]) == "enabled"

    @staticmethod
    def _wait_for_wifi_interface(interface: str, *, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                state_output = _run(
                    ["nmcli", "-g", "GENERAL.STATE", "device", "show", interface]
                )
            except BrokerError:
                state_output = ""
            match = re.match(r"\s*(\d+)", state_output)
            if match and 30 <= int(match.group(1)) <= 100:
                return
            time.sleep(0.1)
        raise BrokerError(
            f"Wi-Fi interface {interface} did not become available after enabling the radio."
        )

    def _activate(self, settings: dict[str, Any], profiles: list[dict[str, str]]) -> None:
        country = str(settings.get("country", ""))
        if not re.fullmatch(r"[A-Z]{2}", country):
            raise BrokerError("The wireless country code is invalid.")
        wifi_interface = _safe_interface(settings.get("wifi_interface"))
        _run(["raspi-config", "nonint", "do_wifi_country", country])
        _run(["nmcli", "radio", "wifi", "on"])
        if settings["mode"] == "nat":
            uplink = _safe_interface(settings.get("uplink_interface"))
            gateway = _run(["nmcli", "-g", "IP4.GATEWAY", "device", "show", uplink])
            if not gateway:
                raise BrokerError(
                    f"The selected NAT uplink {uplink} has no active IPv4 gateway."
                )
        self._activate_profiles(str(settings["mode"]), wifi_interface, profiles)

    def _activate_configuration(
        self,
        configuration: dict[str, Any],
        profiles: list[dict[str, str]],
        *,
        skip_active: bool = False,
    ) -> list[dict[str, str]]:
        enabled = []
        for raw_profile in configuration.get("profiles", []):
            if not isinstance(raw_profile, dict) or not raw_profile.get("enabled"):
                continue
            profile = dict(raw_profile)
            if profile.get("kind") == "wired":
                interface, present = _resolve_interface(
                    profile.get("interface"),
                    profile.get("adapter_mac"),
                    "ethernet",
                )
                profile["interface"] = interface
                profile["interface_present"] = present
            else:
                interface, present = _resolve_interface(
                    profile.get("wifi_interface"),
                    profile.get("adapter_mac"),
                    "wifi",
                )
                profile["wifi_interface"] = interface
                profile["interface_present"] = present
                if profile.get("kind") == "wifi-ap":
                    uplink, uplink_present = _resolve_interface(
                        profile.get("uplink_interface"),
                        profile.get("uplink_mac"),
                        "ethernet",
                    )
                    profile["uplink_interface"] = uplink
                    profile["uplink_present"] = uplink_present
            enabled.append(profile)

        logical_by_id = {
            str(profile.get("id", "")): profile for profile in enabled
        }
        for record in profiles:
            logical = logical_by_id.get(str(record.get("logical_id", "")))
            if not logical:
                continue
            role = str(record.get("role", ""))
            if role in {"client", "hotspot", "wired"}:
                record["interface"] = str(
                    logical.get("interface") or logical.get("wifi_interface") or ""
                )
            elif role == "uplink":
                record["interface"] = str(logical.get("uplink_interface", ""))
        if any(profile.get("kind") in {"wifi-ap", "wifi-client"} for profile in enabled):
            _run(
                [
                    "raspi-config",
                    "nonint",
                    "do_wifi_country",
                    str(configuration["country"]),
                ]
            )
            _run(["nmcli", "radio", "wifi", "on"])
        dormant: list[dict[str, str]] = []
        dormant_ids: set[str] = set()
        for logical in enabled:
            required: list[tuple[str, bool, bool]] = []
            if logical.get("kind") == "wired":
                required.append(
                    (
                        str(logical.get("interface", "")),
                        bool(logical.get("interface_present")),
                        True,
                    )
                )
            else:
                required.append(
                    (
                        str(logical.get("wifi_interface", "")),
                        bool(logical.get("interface_present")),
                        False,
                    )
                )
                if logical.get("kind") == "wifi-ap":
                    required.append(
                        (
                            str(logical.get("uplink_interface", "")),
                            bool(logical.get("uplink_present")),
                            True,
                        )
                    )
            for interface, present, _requires_carrier in required:
                if interface and present:
                    _keep_usb_interface_awake(interface)
            missing = [
                interface
                for interface, present, _requires_carrier in required
                if not interface or not present
            ]
            no_carrier = [
                interface
                for interface, present, requires_carrier in required
                if interface
                and present
                and requires_carrier
                and not _ethernet_has_carrier(interface)
            ]
            if missing or no_carrier:
                logical_id = str(logical.get("id", ""))
                dormant_ids.add(logical_id)
                reasons = []
                if missing:
                    reasons.append("Missing " + ", ".join(missing))
                if no_carrier:
                    reasons.append("No carrier on " + ", ".join(no_carrier))
                dormant.append(
                    {
                        "id": logical_id,
                        "name": str(logical.get("name", logical_id)),
                        "reason": "; ".join(reasons),
                    }
                )
        for record in profiles:
            if str(record.get("logical_id", "")) in dormant_ids:
                _run_quiet(
                    [
                        "nmcli",
                        "connection",
                        "down",
                        "uuid",
                        str(record.get("uuid", "")),
                    ]
                )
        active_uuids = (
            {connection["uuid"] for connection in self._active_connections()}
            if skip_active
            else set()
        )
        role_order = {"bridge": 10, "wired": 20, "uplink": 20, "client": 30, "hotspot": 30}
        ordered = sorted(
            [
                profile
                for profile in profiles
                if str(profile.get("logical_id", "")) not in dormant_ids
            ],
            key=lambda profile: (role_order.get(str(profile.get("role", "")), 25), str(profile.get("id", ""))),
        )
        for profile in ordered:
            if profile["uuid"] in active_uuids:
                continue
            role = str(profile.get("role", ""))
            if role == "bridge":
                _run(
                    [
                        "nmcli",
                        "--wait",
                        "0",
                        "connection",
                        "up",
                        "uuid",
                        profile["uuid"],
                    ]
                )
                continue
            interface = str(profile.get("interface", ""))
            command = ["nmcli", "connection", "up", "uuid", profile["uuid"]]
            if role in {"client", "hotspot"}:
                self._wait_for_wifi_interface(_safe_interface(interface))
                command.extend(["ifname", interface])
            _run(command, timeout=60)

        for logical in enabled:
            if str(logical.get("id", "")) in dormant_ids:
                continue
            if logical.get("kind") != "wifi-ap" or logical.get("network_mode") != "nat":
                continue
            uplink = _safe_interface(logical.get("uplink_interface"))
            gateway = _run(
                ["nmcli", "-g", "IP4.GATEWAY", "device", "show", uplink]
            )
            if not gateway:
                raise BrokerError(
                    f"The selected NAT uplink {uplink} has no active IPv4 gateway."
                )
        return dormant

    def _activate_profiles(
        self,
        mode: str,
        wifi_interface: str,
        profiles: list[dict[str, str]],
        *,
        skip_active: bool = False,
    ) -> None:
        active_uuids = (
            {connection["uuid"] for connection in self._active_connections()}
            if skip_active
            else set()
        )
        by_role = {str(profile.get("role", "")): profile for profile in profiles}
        if mode == "bridge":
            if not {"bridge", "uplink", "hotspot"}.issubset(by_role):
                raise BrokerError("The saved bridge profile set is incomplete.")
            if by_role["bridge"]["uuid"] not in active_uuids:
                _run(
                    [
                        "nmcli",
                        "--wait",
                        "0",
                        "connection",
                        "up",
                        "uuid",
                        by_role["bridge"]["uuid"],
                    ]
                )
            if by_role["uplink"]["uuid"] not in active_uuids:
                _run(
                    [
                        "nmcli",
                        "connection",
                        "up",
                        "uuid",
                        by_role["uplink"]["uuid"],
                    ],
                    timeout=60,
                )
            if by_role["hotspot"]["uuid"] not in active_uuids:
                self._wait_for_wifi_interface(wifi_interface)
                _run(
                    [
                        "nmcli",
                        "connection",
                        "up",
                        "uuid",
                        by_role["hotspot"]["uuid"],
                        "ifname",
                        wifi_interface,
                    ],
                    timeout=60,
                )
            return
        if mode not in {"nat", "client"} or not profiles:
            raise BrokerError("The saved wireless profile set is incomplete.")
        selected = profiles[-1]
        if selected["uuid"] in active_uuids:
            return
        self._wait_for_wifi_interface(wifi_interface)
        _run(
            [
                "nmcli",
                "connection",
                "up",
                "uuid",
                selected["uuid"],
                "ifname",
                wifi_interface,
            ],
            timeout=60,
        )

    def _ensure_managed_profiles_active(self, managed: dict[str, Any]) -> None:
        profiles = list(managed.get("profiles") or [])
        if not profiles:
            return
        reloadable_profiles = [profile for profile in profiles if profile.get("filename")]
        if reloadable_profiles:
            loaded_uuids = {
                line.strip()
                for line in _run(
                    ["nmcli", "-t", "-f", "UUID", "connection", "show"]
                ).splitlines()
                if line.strip()
            }
            for profile in reloadable_profiles:
                profile_uuid = str(profile.get("uuid", ""))
                if profile_uuid in loaded_uuids:
                    continue
                filename = str(profile.get("filename", ""))
                if Path(filename).name != filename:
                    raise BrokerError(
                        "A managed NetworkManager profile path is invalid."
                    )
                path = self.connection_directory / filename
                if not path.is_file():
                    raise BrokerError(
                        f"Managed NetworkManager profile {filename} is missing."
                    )
                _run(["nmcli", "connection", "load", str(path)])
                loaded_uuids.add(profile_uuid)
        configuration = managed.get("configuration")
        if isinstance(configuration, dict):
            self._activate_configuration(
                configuration,
                profiles,
                skip_active=True,
            )
            return
        self._activate_profiles(
            str(managed.get("mode", "")),
            _safe_interface(managed.get("wifi_interface")),
            profiles,
            skip_active=True,
        )

    def _cleanup_profiles(self, profiles: list[dict[str, Any]]) -> None:
        for profile in profiles:
            profile_uuid = str(profile.get("uuid", ""))
            if profile_uuid:
                _run_quiet(["nmcli", "connection", "delete", "uuid", profile_uuid])
            filename = str(profile.get("filename", ""))
            if filename.startswith(PROFILE_PREFIX) and filename.endswith(".nmconnection"):
                (self.connection_directory / filename).unlink(missing_ok=True)
        _run_quiet(["nmcli", "connection", "reload"])

    def _restore_country(self, country: str) -> None:
        if re.fullmatch(r"[A-Z]{2}", country or ""):
            _run_quiet(["raspi-config", "nonint", "do_wifi_country", country])

    @staticmethod
    def _restore_wifi_radio(enabled: bool) -> None:
        _run_quiet(["nmcli", "radio", "wifi", "on" if enabled else "off"])

    def _rollback_locked(self, pending: dict[str, Any]) -> None:
        checkpoint = str(pending.get("checkpoint", ""))
        if checkpoint:
            try:
                self._checkpoint_action("CheckpointRollback", checkpoint)
            except BrokerError:
                pass
        self._cleanup_profiles(list(pending.get("profiles") or []))
        self._restore_country(str(pending.get("rollback_country", "")))
        self._restore_wifi_radio(bool(pending.get("rollback_wifi_enabled", True)))
        if "previous_managed" in pending:
            previous_managed = dict(pending.get("previous_managed") or {})
            if previous_managed:
                _write_json(self.current_path, previous_managed)
                self._ensure_managed_profiles_active(previous_managed)
            else:
                _unlink_json(self.current_path)
        certificate_directory = str(pending.get("certificate_directory", ""))
        if certificate_directory:
            shutil.rmtree(certificate_directory, ignore_errors=True)
        _unlink_json(self.pending_path)

    def _expire_pending_locked(self) -> None:
        pending = _read_json(self.pending_path)
        if pending and time.time() >= float(pending.get("expires_at") or 0):
            self._rollback_locked(pending)

    def apply(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._expire_pending_locked()
            if _read_json(self.pending_path):
                raise BrokerError("Confirm or roll back the current pending network change first.")
            requested_configuration = request.get("configuration")
            configuration = (
                dict(requested_configuration)
                if isinstance(requested_configuration, dict)
                else None
            )
            settings = dict(request.get("settings") or {})
            transaction_id = secrets.token_hex(8)
            timeout_seconds = int(request.get("rollback_seconds") or 120)
            if not 60 <= timeout_seconds <= 300:
                raise BrokerError("The rollback timeout must be between 60 and 300 seconds.")
            certificate_directory = str(self.certificate_directory / transaction_id)
            checkpoint = ""
            profile_records: list[dict[str, str]] = []
            rollback_country = ""
            rollback_wifi_enabled = True
            try:
                if configuration is not None:
                    self._copy_configuration_material(configuration, transaction_id)
                    configuration = _validate_configuration(configuration)
                    profiles = build_configuration_profiles(configuration, transaction_id)
                else:
                    self._copy_material(settings, transaction_id)
                    profiles = build_connection_profiles(settings, transaction_id)
                profile_records = [
                    {key: value for key, value in profile.items() if key != "content"}
                    for profile in profiles
                ]
                rollback_country = _run(
                    ["raspi-config", "nonint", "get_wifi_country"]
                )
                rollback_wifi_enabled = self._wifi_enabled()
                current = _read_json(self.current_path)
                previous_connections = (
                    list(current.get("previous_connections") or [])
                    if "previous_connections" in current
                    else self._active_connections()
                )
                previous_country = str(
                    current.get("previous_country", rollback_country)
                )
                previous_wifi_enabled = bool(
                    current.get("previous_wifi_enabled", rollback_wifi_enabled)
                )
                checkpoint = self._checkpoint_create(
                    timeout_seconds + CHECKPOINT_OPERATION_GRACE_SECONDS
                )
                self._write_profiles(profiles)
                if configuration is not None:
                    dormant = self._activate_configuration(configuration, profiles)
                else:
                    dormant = []
                    self._activate(settings, profiles)
                token = secrets.token_urlsafe(24)
                expires_at = time.time() + timeout_seconds
                pending = {
                    "token": token,
                    "kind": "apply",
                    "checkpoint": checkpoint,
                    "profiles": profile_records,
                    "rollback_country": rollback_country,
                    "rollback_wifi_enabled": rollback_wifi_enabled,
                    "previous_country": previous_country,
                    "previous_wifi_enabled": previous_wifi_enabled,
                    "previous_connections": previous_connections,
                    "previous_managed": current,
                    "certificate_directory": certificate_directory,
                    "expires_at": expires_at,
                }
                if configuration is not None:
                    pending["configuration"] = self._redacted_configuration(
                        configuration
                    )
                    pending["profile_count"] = len(
                        [profile for profile in configuration["profiles"] if profile["enabled"]]
                    )
                    pending["dormant_profiles"] = dormant
                else:
                    pending.update(
                        {
                            "mode": settings["mode"],
                            "ssid": settings.get("ssid", ""),
                            "wifi_interface": settings.get("wifi_interface", ""),
                        }
                    )
                _write_json(self.pending_path, pending)
            except Exception:
                if checkpoint:
                    self._rollback_locked(
                        {
                            "checkpoint": checkpoint,
                            "profiles": profile_records,
                            "rollback_country": rollback_country,
                            "rollback_wifi_enabled": rollback_wifi_enabled,
                            "certificate_directory": certificate_directory,
                        }
                    )
                else:
                    shutil.rmtree(certificate_directory, ignore_errors=True)
                raise
            return {
                "token": token,
                "expires_at": expires_at,
                "transaction_id": transaction_id,
                "dormant_profiles": dormant,
            }

    @staticmethod
    def _redacted_configuration(configuration: dict[str, Any]) -> dict[str, Any]:
        redacted = {
            "schema_version": 2,
            "country": str(configuration.get("country", "")),
            "profiles": [],
        }
        for raw_profile in configuration.get("profiles", []):
            profile = dict(raw_profile)
            for key in (
                "passphrase",
                "password",
                "private_key_password",
                "interface_present",
                "uplink_present",
            ):
                profile.pop(key, None)
            redacted["profiles"].append(profile)
        return redacted

    def disable(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._expire_pending_locked()
            if _read_json(self.pending_path):
                raise BrokerError("Confirm or roll back the current pending network change first.")
            current = _read_json(self.current_path)
            if not current:
                raise BrokerError("Raspberry Pi networking is not managed by this toolkit.")
            timeout_seconds = int(request.get("rollback_seconds") or 120)
            if not 60 <= timeout_seconds <= 300:
                raise BrokerError("The rollback timeout must be between 60 and 300 seconds.")
            rollback_country = _run(
                ["raspi-config", "nonint", "get_wifi_country"]
            )
            rollback_wifi_enabled = self._wifi_enabled()
            checkpoint = self._checkpoint_create(
                timeout_seconds + CHECKPOINT_OPERATION_GRACE_SECONDS
            )
            token = secrets.token_urlsafe(24)
            try:
                for profile in current.get("profiles") or []:
                    _run_quiet(["nmcli", "connection", "down", "uuid", str(profile.get("uuid", ""))])
                for connection in current.get("previous_connections") or []:
                    profile_uuid = str(connection.get("uuid", ""))
                    if profile_uuid:
                        _run_quiet(["nmcli", "connection", "up", "uuid", profile_uuid], timeout=60)
                self._restore_country(str(current.get("previous_country", "")))
                self._restore_wifi_radio(
                    bool(current.get("previous_wifi_enabled", True))
                )
                expires_at = time.time() + timeout_seconds
                pending = {
                    "token": token,
                    "kind": "disable",
                    "checkpoint": checkpoint,
                    "previous_managed": current,
                    "profiles": [],
                    "rollback_country": rollback_country,
                    "rollback_wifi_enabled": rollback_wifi_enabled,
                    "expires_at": expires_at,
                }
                _write_json(self.pending_path, pending)
            except Exception:
                self._checkpoint_action("CheckpointRollback", checkpoint)
                self._restore_country(rollback_country)
                self._restore_wifi_radio(rollback_wifi_enabled)
                self._ensure_managed_profiles_active(current)
                raise
            return {"token": token, "expires_at": expires_at}

    def confirm(self, token: str) -> dict[str, Any]:
        with self._lock:
            self._expire_pending_locked()
            pending = _read_json(self.pending_path)
            if not pending or not secrets.compare_digest(str(pending.get("token", "")), token):
                raise BrokerError("The pending network change is no longer available.")
            previous_managed = dict(pending.get("previous_managed") or {})
            if pending["kind"] == "apply":
                managed = {
                    "profiles": pending.get("profiles") or [],
                    "previous_connections": pending.get("previous_connections") or [],
                    "previous_country": pending.get("previous_country", ""),
                    "previous_wifi_enabled": bool(
                        pending.get("previous_wifi_enabled", True)
                    ),
                    "certificate_directory": pending.get("certificate_directory", ""),
                    "confirmed_at": time.time(),
                }
                if isinstance(pending.get("configuration"), dict):
                    managed["configuration"] = pending["configuration"]
                    managed["profile_count"] = int(
                        pending.get("profile_count") or 0
                    )
                else:
                    managed.update(
                        {
                            "mode": pending.get("mode", ""),
                            "ssid": pending.get("ssid", ""),
                            "wifi_interface": pending.get("wifi_interface", ""),
                        }
                    )
                try:
                    _write_json(self.current_path, managed)
                    self._checkpoint_action(
                        "CheckpointDestroy", str(pending["checkpoint"])
                    )
                except Exception:
                    if previous_managed:
                        _write_json(self.current_path, previous_managed)
                    else:
                        _unlink_json(self.current_path)
                    raise
                _unlink_json(self.pending_path)
                self._cleanup_profiles(
                    list(previous_managed.get("profiles") or [])
                )
                old_certificates = str(
                    previous_managed.get("certificate_directory", "")
                )
                if (
                    old_certificates
                    and old_certificates != pending.get("certificate_directory")
                ):
                    shutil.rmtree(old_certificates, ignore_errors=True)
            else:
                try:
                    _unlink_json(self.current_path)
                    self._checkpoint_action(
                        "CheckpointDestroy", str(pending["checkpoint"])
                    )
                except Exception:
                    if previous_managed:
                        _write_json(self.current_path, previous_managed)
                    raise
                _unlink_json(self.pending_path)
                self._cleanup_profiles(
                    list(previous_managed.get("profiles") or [])
                )
                old_certificates = str(previous_managed.get("certificate_directory", ""))
                if old_certificates:
                    shutil.rmtree(old_certificates, ignore_errors=True)
            return {"managed": _read_json(self.current_path)}

    def rollback(self, token: str) -> dict[str, Any]:
        with self._lock:
            pending = _read_json(self.pending_path)
            if not pending or not secrets.compare_digest(str(pending.get("token", "")), token):
                raise BrokerError("The pending network change is no longer available.")
            self._rollback_locked(pending)
            return {"managed": _read_json(self.current_path)}

    def scan(self, interface: str) -> dict[str, Any]:
        interface = _safe_interface(interface)
        radio_was_enabled = self._wifi_enabled()
        if not radio_was_enabled:
            _run(["nmcli", "radio", "wifi", "on"])
            self._wait_for_wifi_interface(interface)
        try:
            output = _run(
                [
                    "nmcli",
                    "-t",
                    "-f",
                    "SSID,SIGNAL,SECURITY,FREQ",
                    "device",
                    "wifi",
                    "list",
                    "ifname",
                    interface,
                    "--rescan",
                    "yes",
                ],
                timeout=20,
            )
        finally:
            if not radio_was_enabled:
                self._restore_wifi_radio(False)
        networks = []
        seen = set()
        for line in output.splitlines():
            fields = line.rsplit(":", 3)
            if len(fields) != 4 or not fields[0] or fields[0] in seen:
                continue
            seen.add(fields[0])
            networks.append(
                {
                    "ssid": fields[0].replace("\\:", ":").replace("\\\\", "\\"),
                    "signal": fields[1],
                    "security": fields[2],
                    "frequency": fields[3],
                }
            )
        return {"networks": networks[:100]}

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("protocol_version") != BROKER_PROTOCOL_VERSION:
            raise BrokerError(
                "Reinstall the toolkit service to update the Raspberry Pi network broker."
            )
        operation = str(request.get("operation", ""))
        if operation == "status":
            with self._lock:
                self._expire_pending_locked()
                pending = _read_json(self.pending_path)
                managed = _read_json(self.current_path)
                inventory = network_interface_inventory()
                configuration = managed.get("configuration")
                wireless_telemetry = (
                    wireless_client_telemetry(
                        configuration, list(managed.get("profiles") or [])
                    )
                    if isinstance(configuration, dict)
                    else []
                )
                wired_telemetry = (
                    wired_client_telemetry(
                        configuration, list(managed.get("profiles") or [])
                    )
                    if isinstance(configuration, dict)
                    else []
                )
                try:
                    active_uuids = {
                        connection["uuid"] for connection in self._active_connections()
                    }
                except BrokerError:
                    active_uuids = set()
                profile_status = []
                by_mac = {
                    str(item.get("mac_address", "")).casefold(): item
                    for item in inventory
                    if item.get("mac_address")
                }
                by_name = {str(item.get("name", "")): item for item in inventory}
                if isinstance(configuration, dict):
                    for profile in configuration.get("profiles", []):
                        if not isinstance(profile, dict):
                            continue
                        expected_name = str(
                            profile.get("interface")
                            if profile.get("kind") == "wired"
                            else profile.get("wifi_interface")
                        )
                        adapter = by_mac.get(
                            str(profile.get("adapter_mac", "")).casefold()
                        ) or by_name.get(expected_name)
                        uplink = None
                        if profile.get("kind") == "wifi-ap":
                            uplink = by_mac.get(
                                str(profile.get("uplink_mac", "")).casefold()
                            ) or by_name.get(
                                str(profile.get("uplink_interface", ""))
                            )
                        records = [
                            record
                            for record in managed.get("profiles") or []
                            if record.get("logical_id") == profile.get("id")
                        ]
                        active = bool(records) and all(
                            str(record.get("uuid", "")) in active_uuids
                            for record in records
                        )
                        state = "disabled"
                        if profile.get("enabled"):
                            hardware_present = bool(adapter) and (
                                profile.get("kind") != "wifi-ap" or bool(uplink)
                            )
                            no_carrier = bool(hardware_present) and (
                                (
                                    profile.get("kind") == "wired"
                                    and adapter.get("carrier") is False
                                )
                                or (
                                    profile.get("kind") == "wifi-ap"
                                    and uplink.get("carrier") is False
                                )
                            )
                            state = (
                                "active"
                                if active
                                else (
                                    "missing"
                                    if not hardware_present
                                    else "no-carrier" if no_carrier else "inactive"
                                )
                            )
                        profile_status.append(
                            {
                                "id": str(profile.get("id", "")),
                                "name": str(profile.get("name", "")),
                                "kind": str(profile.get("kind", "")),
                                "state": state,
                                "interface": str(
                                    adapter.get("name", "") if adapter else expected_name
                                ),
                                "mac_address": str(
                                    adapter.get("mac_address", "")
                                    if adapter
                                    else profile.get("adapter_mac", "")
                                ),
                            }
                        )
                return {
                    "protocol_version": BROKER_PROTOCOL_VERSION,
                    "managed": managed,
                    "interfaces": inventory,
                    "profile_status": profile_status,
                    "wireless_clients": wireless_telemetry,
                    "wired_clients": wired_telemetry,
                    "pending": {
                        key: pending.get(key)
                        for key in (
                            "token",
                            "kind",
                            "mode",
                            "ssid",
                            "profile_count",
                            "expires_at",
                        )
                        if pending.get(key) not in {None, ""}
                    },
                }
        if operation == "apply":
            return self.apply(request)
        if operation == "disable":
            return self.disable(request)
        if operation == "confirm":
            return self.confirm(_safe_text(request.get("token"), limit=128, required=True))
        if operation == "rollback":
            return self.rollback(_safe_text(request.get("token"), limit=128, required=True))
        if operation == "scan":
            return self.scan(str(request.get("interface", "")))
        raise BrokerError("The requested Raspberry Pi networking operation is not supported.")

    def _monitor(self) -> None:
        while not self._stopping.wait(1.0):
            try:
                with self._lock:
                    self._expire_pending_locked()
                    if _read_json(self.pending_path):
                        continue
                    signature = _interface_presence_signature()
                    now = time.monotonic()
                    should_reconcile = (
                        signature != self._interface_signature
                        or now >= self._next_reconcile_at
                    )
                    if not should_reconcile:
                        continue
                    managed = _read_json(self.current_path)
                    if managed:
                        self._ensure_managed_profiles_active(managed)
                    self._interface_signature = signature
                    self._next_reconcile_at = float("inf")
            except Exception as exc:
                self._next_reconcile_at = time.monotonic() + 10.0
                print(
                    "Raspberry Pi network monitor error: "
                    + " ".join(str(exc).split())[:500],
                    flush=True,
                )

    def serve_forever(self) -> None:
        _require_raspberry_pi()
        self.state_directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.state_directory, 0o700)
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.socket_path.parent, 0o711)
        self.socket_path.unlink(missing_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.socket_path))
        os.chown(self.socket_path, self.allowed_uid, -1)
        os.chmod(self.socket_path, 0o600)
        listener.listen(8)
        listener.settimeout(1.0)
        monitor = threading.Thread(target=self._monitor, daemon=True)
        monitor.start()
        try:
            while not self._stopping.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    try:
                        if self._peer_uid(connection) != self.allowed_uid:
                            raise BrokerError("The calling process is not authorized.")
                        data = bytearray()
                        while b"\n" not in data:
                            block = connection.recv(65536)
                            if not block:
                                break
                            data.extend(block)
                            if len(data) > MAX_MESSAGE_BYTES:
                                raise BrokerError("The request is too large.")
                        request = json.loads(bytes(data).split(b"\n", 1)[0])
                        if not isinstance(request, dict):
                            raise BrokerError("The request is invalid.")
                        response = {"ok": True, **self.dispatch(request)}
                    except Exception as exc:
                        response = {"ok": False, "error": " ".join(str(exc).split())[:500]}
                    connection.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
        finally:
            self._stopping.set()
            listener.close()
            self.socket_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("The Raspberry Pi networking broker must run as root.")
    broker = PiNetworkBroker(
        socket_path=Path(args.socket),
        allowed_uid=args.uid,
        toolkit_root=Path(args.root),
    )
    broker.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
