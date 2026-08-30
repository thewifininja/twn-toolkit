from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from .network_tools import ToolInputError


PI_NETWORK_BROKER_SOCKET = "/run/twn-toolkit/pi-network-broker.sock"
PI_NETWORK_BROKER_PROTOCOL_VERSION = 2
PI_NETWORK_ROLLBACK_SECONDS = 120
MAX_BROKER_MESSAGE_BYTES = 512 * 1024
MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
CONNECTION_MODES = {"nat", "bridge", "client"}
AP_SECURITY_MODES = {"wpa2", "wpa2-wpa3", "wpa3"}
MANAGED_PROFILE_KINDS = {"wifi-ap", "wifi-client", "wired"}
WIRED_IPV4_MODES = {"dhcp", "static", "shared", "disabled"}
PROFILE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
MAC_ADDRESS_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
CLIENT_SECURITY_MODES = {
    "open",
    "wpa2",
    "wpa2-wpa3",
    "wpa3",
    "peap",
    "eap-tls",
}


class PiNetworkBrokerError(RuntimeError):
    pass


def _read_device_tree(path: Path) -> str:
    try:
        return path.read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def raspberry_pi_identity(
    *,
    compatible_path: Path = Path("/proc/device-tree/compatible"),
    model_path: Path = Path("/proc/device-tree/model"),
) -> dict[str, Any]:
    compatible = _read_device_tree(compatible_path)
    model = _read_device_tree(model_path)
    identifiers = compatible.casefold().split()
    is_raspberry_pi = any(value.startswith("raspberrypi,") for value in identifiers)
    return {
        "is_raspberry_pi": is_raspberry_pi,
        "model": model or ("Raspberry Pi" if is_raspberry_pi else ""),
        "compatible": compatible,
    }


def _run_readonly(command: list[str], *, timeout: float = 3.0) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _nmcli_rows(output: str, expected: int) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in output.splitlines():
        values: list[str] = []
        value = []
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


def raspberry_pi_network_status(
    *, broker_socket: str = PI_NETWORK_BROKER_SOCKET
) -> dict[str, Any]:
    identity = raspberry_pi_identity()
    status: dict[str, Any] = {
        **identity,
        "supported": False,
        "network_manager": "",
        "network_manager_active": False,
        "broker_available": False,
        "broker_error": "",
        "wifi_enabled": False,
        "country": "",
        "wifi_interfaces": [],
        "wired_interfaces": [],
        "ap_available": False,
        "wired_available": False,
        "active_connections": [],
        "interfaces": [],
        "profile_status": [],
        "wireless_clients": [],
        "wired_clients": [],
        "managed": {},
        "pending": {},
        "limitations": [],
    }
    if not identity["is_raspberry_pi"]:
        return status

    version = _run_readonly(["nmcli", "--version"])
    status["network_manager"] = version
    status["network_manager_active"] = bool(
        version and _run_readonly(["systemctl", "is-active", "NetworkManager"]) == "active"
    )
    radio = _run_readonly(["nmcli", "-t", "radio", "wifi"])
    status["wifi_enabled"] = radio == "enabled"
    status["country"] = _run_readonly(
        ["raspi-config", "nonint", "get_wifi_country"]
    ).upper()
    device_output = _run_readonly(
        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"]
    )
    for device, device_type, state, connection in _nmcli_rows(device_output, 4):
        item = {
            "name": device,
            "type": device_type,
            "state": state,
            "connection": connection,
        }
        if connection and connection != "--":
            status["active_connections"].append(connection)
        if device_type == "wifi":
            properties = _run_readonly(
                [
                    "nmcli",
                    "-t",
                    "-f",
                    "WIFI-PROPERTIES.AP,WIFI-PROPERTIES.WPA2,WIFI-PROPERTIES.2GHZ,WIFI-PROPERTIES.5GHZ,WIFI-PROPERTIES.6GHZ",
                    "device",
                    "show",
                    device,
                ]
            )
            values = {
                line.split(":", 1)[0]: line.split(":", 1)[1]
                for line in properties.splitlines()
                if ":" in line
            }
            item.update(
                {
                    "ap": values.get("WIFI-PROPERTIES.AP") == "yes",
                    "wpa2": values.get("WIFI-PROPERTIES.WPA2") == "yes",
                    "band_2ghz": values.get("WIFI-PROPERTIES.2GHZ") == "yes",
                    "band_5ghz": values.get("WIFI-PROPERTIES.5GHZ") == "yes",
                    "band_6ghz": values.get("WIFI-PROPERTIES.6GHZ") == "yes",
                }
            )
            status["wifi_interfaces"].append(item)
        elif device_type == "ethernet":
            status["wired_interfaces"].append(item)

    status["ap_available"] = any(
        bool(interface.get("ap")) for interface in status["wifi_interfaces"]
    )
    status["wired_available"] = bool(status["wired_interfaces"])

    try:
        status["broker_available"] = Path(broker_socket).exists()
    except OSError as exc:
        status["broker_available"] = False
        status["broker_error"] = (
            "The protected networking socket is not accessible; reinstall the "
            "system service to repair its permissions."
        )
    if status["broker_available"]:
        try:
            locally_detected_interfaces = {
                item.get("name"): item
                for item in (
                    status["wifi_interfaces"] + status["wired_interfaces"]
                )
                if item.get("name")
            }
            broker = request_pi_network_broker(
                {"operation": "status"}, socket_path=broker_socket
            )
            if broker.get("protocol_version") != PI_NETWORK_BROKER_PROTOCOL_VERSION:
                raise PiNetworkBrokerError(
                    "Reinstall the system service to update the Raspberry Pi network broker."
                )
            status["managed"] = broker.get("managed") or {}
            status["pending"] = broker.get("pending") or {}
            status["interfaces"] = broker.get("interfaces") or []
            status["profile_status"] = broker.get("profile_status") or []
            status["wireless_clients"] = broker.get("wireless_clients") or []
            status["wired_clients"] = broker.get("wired_clients") or []
            if status["interfaces"]:
                merged_interfaces = []
                for broker_interface in status["interfaces"]:
                    local_interface = locally_detected_interfaces.get(
                        broker_interface.get("name"), {}
                    )
                    merged = {**local_interface, **broker_interface}
                    if merged.get("type") == "wifi":
                        # A stale or capability-limited broker must not erase a
                        # positive AP/band result obtained from NetworkManager.
                        for capability in (
                            "ap",
                            "wpa2",
                            "band_2ghz",
                            "band_5ghz",
                            "band_6ghz",
                        ):
                            merged[capability] = bool(
                                local_interface.get(capability)
                                or broker_interface.get(capability)
                            )
                    merged_interfaces.append(merged)
                status["interfaces"] = merged_interfaces
                status["wifi_interfaces"] = [
                    item for item in status["interfaces"] if item.get("type") == "wifi"
                ]
                status["wired_interfaces"] = [
                    item
                    for item in status["interfaces"]
                    if item.get("type") == "ethernet"
                ]
                status["ap_available"] = any(
                    bool(item.get("ap")) for item in status["wifi_interfaces"]
                )
                status["wired_available"] = bool(status["wired_interfaces"])
        except (OSError, PiNetworkBrokerError) as exc:
            status["broker_available"] = False
            status["broker_error"] = " ".join(str(exc).split())[:240]

    if not version:
        status["limitations"].append("NetworkManager and nmcli are required.")
    elif not status["network_manager_active"]:
        status["limitations"].append("NetworkManager is not active.")
    if not status["wifi_interfaces"]:
        status["limitations"].append(
            "No NetworkManager Wi-Fi interface was detected; wired management remains available."
        )
    if status["wifi_interfaces"] and not status["ap_available"]:
        status["limitations"].append(
            "The detected Wi-Fi interface does not report access-point support."
        )
    if not status["broker_available"]:
        status["limitations"].append(
            status["broker_error"]
            or "Reinstall the system service to enable protected network changes."
        )
    # Hardware can legitimately be absent during boot or after a removable
    # adapter is unplugged. Keep the management surface available so saved
    # profiles can remain dormant and be edited while their adapter is away.
    status["supported"] = bool(
        version
        and status["network_manager_active"]
        and status["broker_available"]
    )
    return status


def request_pi_network_broker(
    payload: dict[str, Any],
    *,
    socket_path: str = PI_NETWORK_BROKER_SOCKET,
    timeout: float = 20.0,
) -> dict[str, Any]:
    request_payload = dict(payload)
    request_payload["protocol_version"] = PI_NETWORK_BROKER_PROTOCOL_VERSION
    encoded = (
        json.dumps(request_payload, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    if len(encoded) > MAX_BROKER_MESSAGE_BYTES:
        raise PiNetworkBrokerError("The Raspberry Pi networking request is too large.")
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    channel.settimeout(timeout)
    try:
        channel.connect(socket_path)
        channel.sendall(encoded)
        chunks = bytearray()
        while b"\n" not in chunks:
            block = channel.recv(65536)
            if not block:
                break
            chunks.extend(block)
            if len(chunks) > MAX_BROKER_MESSAGE_BYTES:
                raise PiNetworkBrokerError("The Raspberry Pi networking response is too large.")
    finally:
        channel.close()
    try:
        response = json.loads(bytes(chunks).split(b"\n", 1)[0])
    except (ValueError, UnicodeError) as exc:
        raise PiNetworkBrokerError("The Raspberry Pi networking broker returned invalid data.") from exc
    if not isinstance(response, dict):
        raise PiNetworkBrokerError("The Raspberry Pi networking broker returned invalid data.")
    if not response.get("ok"):
        raise PiNetworkBrokerError(str(response.get("error") or "The network operation failed."))
    return response


def _interface(value: Any, label: str) -> str:
    normalized = str(value or "").strip()
    if not INTERFACE_PATTERN.fullmatch(normalized):
        raise ToolInputError(f"Choose a valid {label} interface.")
    return normalized


def _optional_mac_address(value: Any, label: str) -> str:
    normalized = str(value or "").strip().upper()
    if normalized and not MAC_ADDRESS_PATTERN.fullmatch(normalized):
        raise ToolInputError(f"The {label} hardware address is invalid.")
    return normalized


def _ssid(value: Any) -> str:
    normalized = str(value or "")
    if (
        not normalized
        or len(normalized.encode("utf-8")) > 32
        or any(character in normalized for character in "\x00\r\n")
    ):
        raise ToolInputError("Wi-Fi SSIDs must contain between 1 and 32 bytes.")
    return normalized


def _bounded_text(value: Any, label: str, limit: int = 253, *, required: bool = False) -> str:
    normalized = str(value or "").strip()
    if required and not normalized:
        raise ToolInputError(f"Enter {label}.")
    if len(normalized) > limit or any(character in normalized for character in "\x00\r\n"):
        raise ToolInputError(f"{label.capitalize()} must be {limit} characters or fewer.")
    return normalized


def validate_pi_network_settings(values: dict[str, Any]) -> dict[str, Any]:
    mode = str(values.get("mode", "")).strip().lower()
    if mode not in CONNECTION_MODES:
        raise ToolInputError("Choose NAT access point, bridged access point, or Wi-Fi client mode.")
    wifi_interface = _interface(values.get("wifi_interface"), "Wi-Fi")
    country = str(values.get("country", "")).strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise ToolInputError("Enter the two-letter wireless regulatory country code.")
    settings: dict[str, Any] = {
        "mode": mode,
        "wifi_interface": wifi_interface,
        "country": country,
        "ssid": _ssid(values.get("ssid")),
        "hidden": bool(values.get("hidden")),
        "autoconnect": bool(values.get("autoconnect", True)),
    }

    if mode in {"nat", "bridge"}:
        security = str(values.get("security", "wpa2-wpa3")).strip().lower()
        if security not in AP_SECURITY_MODES:
            raise ToolInputError("Choose WPA2, WPA2/WPA3, or WPA3 Personal security.")
        passphrase = str(values.get("passphrase", ""))
        if passphrase and not 8 <= len(passphrase) <= 63:
            raise ToolInputError("Wi-Fi passphrases must contain between 8 and 63 characters.")
        if not passphrase and not values.get("has_passphrase"):
            raise ToolInputError("Enter a Wi-Fi passphrase.")
        band = str(values.get("band", "auto")).strip().lower()
        if band not in {"auto", "2.4", "5"}:
            raise ToolInputError("Choose automatic, 2.4 GHz, or 5 GHz operation.")
        try:
            channel = int(values.get("channel") or 0)
        except (TypeError, ValueError) as exc:
            raise ToolInputError("Wi-Fi channel must be a number.") from exc
        if channel and not 1 <= channel <= 196:
            raise ToolInputError("Choose a valid Wi-Fi channel or leave it automatic.")
        settings.update(
            {
                "security": security,
                "passphrase": passphrase,
                "band": band,
                "channel": channel,
                "client_isolation": bool(values.get("client_isolation")),
            }
        )
    else:
        security = str(values.get("security", "wpa2-wpa3")).strip().lower()
        if security not in CLIENT_SECURITY_MODES:
            raise ToolInputError("Choose a supported Wi-Fi client security mode.")
        settings["security"] = security
        if security in {"wpa2", "wpa2-wpa3", "wpa3"}:
            passphrase = str(values.get("passphrase", ""))
            if passphrase and not 8 <= len(passphrase) <= 63:
                raise ToolInputError("Wi-Fi passphrases must contain between 8 and 63 characters.")
            if not passphrase and not values.get("has_passphrase"):
                raise ToolInputError("Enter the Wi-Fi passphrase.")
            settings["passphrase"] = passphrase
        elif security == "peap":
            identity = _bounded_text(values.get("identity"), "the PEAP identity", 253, required=True)
            password = str(values.get("password", ""))
            if not password and not values.get("has_password"):
                raise ToolInputError("Enter the PEAP password.")
            verify_server = bool(values.get("verify_server_certificate", True))
            ca_source = str(values.get("ca_source", "system")).strip().lower()
            if verify_server and ca_source not in {"system", "upload"}:
                raise ToolInputError("Choose the system trust store or an uploaded CA certificate.")
            server_domain = _bounded_text(values.get("server_domain"), "the authentication-server domain", 253)
            if verify_server and not server_domain:
                raise ToolInputError("Enter the expected authentication-server domain.")
            settings.update(
                {
                    "identity": identity,
                    "anonymous_identity": _bounded_text(
                        values.get("anonymous_identity"), "anonymous identity", 253
                    ),
                    "password": password,
                    "verify_server_certificate": verify_server,
                    "ca_source": ca_source if verify_server else "none",
                    "server_domain": server_domain if verify_server else "",
                }
            )
        elif security == "eap-tls":
            identity = _bounded_text(values.get("identity"), "the EAP-TLS identity", 253, required=True)
            ca_source = str(values.get("ca_source", "system")).strip().lower()
            if ca_source not in {"system", "upload"}:
                raise ToolInputError("Choose the system trust store or an uploaded CA certificate.")
            server_domain = _bounded_text(values.get("server_domain"), "the authentication-server domain", 253, required=True)
            material_format = str(values.get("tls_material_format", "bundle")).strip().lower()
            if material_format not in {"bundle", "separate"}:
                raise ToolInputError("Choose a PKCS#12 bundle or separate certificate and key files.")
            settings.update(
                {
                    "identity": identity,
                    "anonymous_identity": _bounded_text(
                        values.get("anonymous_identity"), "anonymous identity", 253
                    ),
                    "verify_server_certificate": True,
                    "ca_source": ca_source,
                    "server_domain": server_domain,
                    "tls_material_format": material_format,
                    "private_key_password": str(values.get("private_key_password", "")),
                }
            )

    if mode == "nat":
        settings["uplink_interface"] = _interface(values.get("uplink_interface"), "wired uplink")
        try:
            network = ipaddress.ip_network(str(values.get("network", "")), strict=True)
            gateway = ipaddress.ip_address(str(values.get("gateway", "")))
            dhcp_start = ipaddress.ip_address(str(values.get("dhcp_start", "")))
            dhcp_end = ipaddress.ip_address(str(values.get("dhcp_end", "")))
        except ValueError as exc:
            raise ToolInputError("Enter a valid IPv4 network, gateway, and DHCP range.") from exc
        if network.version != 4 or not 16 <= network.prefixlen <= 29:
            raise ToolInputError("NAT networks must be IPv4 with a prefix between /16 and /29.")
        unusable = {network.network_address, network.broadcast_address}
        if any(
            address not in network or address in unusable
            for address in (gateway, dhcp_start, dhcp_end)
        ):
            raise ToolInputError("The gateway and DHCP range must be usable addresses in the NAT network.")
        if (
            int(dhcp_start) > int(dhcp_end)
            or int(dhcp_start) <= int(gateway) <= int(dhcp_end)
        ):
            raise ToolInputError("Enter an ordered DHCP range that does not include the gateway endpoint.")
        try:
            lease_time = int(values.get("lease_time") or 3600)
        except (TypeError, ValueError) as exc:
            raise ToolInputError("DHCP lease time must be a number.") from exc
        if not 120 <= lease_time <= 31_536_000:
            raise ToolInputError("DHCP lease time must be between 120 seconds and one year.")
        settings.update(
            {
                "network": str(network),
                "gateway": str(gateway),
                "dhcp_start": str(dhcp_start),
                "dhcp_end": str(dhcp_end),
                "lease_time": lease_time,
            }
        )
    elif mode == "bridge":
        settings["uplink_interface"] = _interface(values.get("uplink_interface"), "wired uplink")
        try:
            vlan_id = int(values.get("vlan_id") or 0)
        except (TypeError, ValueError) as exc:
            raise ToolInputError("VLAN ID must be a number.") from exc
        if vlan_id and not 1 <= vlan_id <= 4094:
            raise ToolInputError("VLAN ID must be between 1 and 4094, or blank for untagged Ethernet.")
        settings["vlan_id"] = vlan_id
    return settings


def _profile_id(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if not PROFILE_ID_PATTERN.fullmatch(normalized):
        raise ToolInputError(
            "Network profile identifiers must use lowercase letters, numbers, dashes, or underscores."
        )
    return normalized


def _integer(
    value: Any,
    label: str,
    minimum: int,
    maximum: int,
    *,
    default: int = 0,
) -> int:
    try:
        number = int(value if value is not None and value != "" else default)
    except (TypeError, ValueError) as exc:
        raise ToolInputError(f"{label} must be a number.") from exc
    if not minimum <= number <= maximum:
        raise ToolInputError(f"{label} must be between {minimum} and {maximum}.")
    return number


def _dns_servers(value: Any) -> list[str]:
    raw_values = value if isinstance(value, list) else re.split(r"[,\s]+", str(value or ""))
    servers: list[str] = []
    for raw in raw_values:
        normalized = str(raw or "").strip()
        if not normalized:
            continue
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError as exc:
            raise ToolInputError(f"{normalized} is not a valid DNS server address.") from exc
        rendered = str(address)
        if rendered not in servers:
            servers.append(rendered)
    if len(servers) > 6:
        raise ToolInputError("Configure no more than six DNS server addresses per interface.")
    return servers


def _adapter_identity_keys(interface: str, mac_address: str) -> set[str]:
    keys = {f"name:{interface.casefold()}"}
    if mac_address:
        keys.add(f"mac:{mac_address.casefold()}")
    return keys


def _private_ipv4_settings(values: dict[str, Any], *, label: str) -> dict[str, Any]:
    try:
        network = ipaddress.ip_network(str(values.get("network", "")), strict=True)
        gateway = ipaddress.ip_address(str(values.get("gateway", "")))
        dhcp_start = ipaddress.ip_address(str(values.get("dhcp_start", "")))
        dhcp_end = ipaddress.ip_address(str(values.get("dhcp_end", "")))
    except ValueError as exc:
        raise ToolInputError(
            f"Enter a valid IPv4 network, gateway, and DHCP range for {label}."
        ) from exc
    if network.version != 4 or not 16 <= network.prefixlen <= 29:
        raise ToolInputError(
            f"{label.capitalize()} networks must be IPv4 with a prefix between /16 and /29."
        )
    unusable = {network.network_address, network.broadcast_address}
    if any(
        address.version != 4 or address not in network or address in unusable
        for address in (gateway, dhcp_start, dhcp_end)
    ):
        raise ToolInputError(
            f"The gateway and DHCP range must be usable addresses in the {label} network."
        )
    if int(dhcp_start) > int(dhcp_end) or int(dhcp_start) <= int(gateway) <= int(dhcp_end):
        raise ToolInputError(
            "Enter an ordered DHCP range that does not include the gateway endpoint."
        )
    return {
        "network": str(network),
        "gateway": str(gateway),
        "dhcp_start": str(dhcp_start),
        "dhcp_end": str(dhcp_end),
        "lease_time": _integer(
            values.get("lease_time"),
            "DHCP lease time",
            120,
            31_536_000,
            default=3600,
        ),
    }


def _validate_wired_profile(values: dict[str, Any]) -> dict[str, Any]:
    mode = str(values.get("ipv4_mode", "dhcp")).strip().lower()
    if mode not in WIRED_IPV4_MODES:
        raise ToolInputError(
            "Choose DHCP client, static IPv4, private DHCP server, or disabled IPv4."
        )
    profile: dict[str, Any] = {
        "interface": _interface(values.get("interface"), "Ethernet"),
        "adapter_mac": _optional_mac_address(
            values.get("adapter_mac"), "Ethernet adapter"
        ),
        "ipv4_mode": mode,
        "ipv6_mode": (
            "disabled"
            if str(values.get("ipv6_mode", "auto")).strip().lower() == "disabled"
            else "auto"
        ),
        "dns_servers": _dns_servers(values.get("dns_servers")),
        "autoconnect": bool(values.get("autoconnect", True)),
        "mtu": _integer(values.get("mtu"), "MTU", 0, 9000, default=0),
        "route_metric": _integer(
            values.get("route_metric"), "Route metric", 0, 65_535, default=0
        ),
    }
    if mode == "static":
        try:
            address = ipaddress.ip_interface(str(values.get("address", "")))
        except ValueError as exc:
            raise ToolInputError("Enter the static IPv4 address with its prefix length.") from exc
        if address.version != 4:
            raise ToolInputError("The static interface address must be IPv4.")
        gateway_text = str(values.get("gateway", "")).strip()
        if gateway_text:
            try:
                gateway = ipaddress.ip_address(gateway_text)
            except ValueError as exc:
                raise ToolInputError("Enter a valid IPv4 gateway.") from exc
            if gateway.version != 4 or gateway not in address.network:
                raise ToolInputError("The IPv4 gateway must belong to the static interface network.")
            profile["gateway"] = str(gateway)
        else:
            profile["gateway"] = ""
        profile["address"] = str(address)
    elif mode == "shared":
        profile.update(_private_ipv4_settings(values, label="private wired"))
    return profile


def validate_pi_network_configuration(values: dict[str, Any]) -> dict[str, Any]:
    """Validate a complete, simultaneous Raspberry Pi network configuration."""

    country = str(values.get("country", "")).strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise ToolInputError("Enter the two-letter wireless regulatory country code.")
    raw_profiles = values.get("profiles")
    if not isinstance(raw_profiles, list):
        raise ToolInputError("The network profile collection is invalid.")
    if len(raw_profiles) > 32:
        raise ToolInputError("Configure no more than 32 Raspberry Pi network profiles.")

    profiles: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    names: set[str] = set()
    active_wifi: dict[str, str] = {}
    active_wired: dict[str, str] = {}
    bridged_uplinks: dict[str, str] = {}
    private_networks: list[tuple[str, ipaddress.IPv4Network]] = []

    for raw_profile in raw_profiles:
        if not isinstance(raw_profile, dict):
            raise ToolInputError("Each Raspberry Pi network profile must be an object.")
        identifier = _profile_id(raw_profile.get("id"))
        if identifier in identifiers:
            raise ToolInputError(f"Network profile identifier {identifier} is duplicated.")
        identifiers.add(identifier)
        name = _bounded_text(
            raw_profile.get("name"), "a network profile name", 80, required=True
        )
        name_key = name.casefold()
        if name_key in names:
            raise ToolInputError(f"Network profile name {name} is duplicated.")
        names.add(name_key)
        kind = str(raw_profile.get("kind", "")).strip().lower()
        if kind not in MANAGED_PROFILE_KINDS:
            raise ToolInputError(f"Network profile {name} has an unsupported type.")
        enabled = bool(raw_profile.get("enabled", True))

        if kind == "wired":
            normalized = _validate_wired_profile(raw_profile)
            normalized.update(
                {"id": identifier, "name": name, "kind": kind, "enabled": enabled}
            )
            interface = normalized["interface"]
            resources = _adapter_identity_keys(
                interface, str(normalized.get("adapter_mac", ""))
            )
            if enabled:
                assigned = next(
                    (active_wired[key] for key in resources if key in active_wired),
                    "",
                )
                if assigned:
                    raise ToolInputError(
                        f"{interface} is already assigned to {assigned}."
                    )
                active_wired.update({key: name for key in resources})
                if normalized["ipv4_mode"] == "shared":
                    private_networks.append(
                        (name, ipaddress.ip_network(normalized["network"]))
                    )
        else:
            wifi_values = dict(raw_profile)
            wifi_values["country"] = country
            wifi_values["mode"] = (
                "client"
                if kind == "wifi-client"
                else str(raw_profile.get("network_mode", "nat")).strip().lower()
            )
            if kind == "wifi-ap" and wifi_values["mode"] not in {"nat", "bridge"}:
                raise ToolInputError(
                    f"Choose NAT or bridge networking for access point {name}."
                )
            normalized = validate_pi_network_settings(wifi_values)
            normalized.update(
                {
                    "id": identifier,
                    "name": name,
                    "kind": kind,
                    "enabled": enabled,
                    "adapter_mac": _optional_mac_address(
                        raw_profile.get("adapter_mac"), "Wi-Fi adapter"
                    ),
                }
            )
            if kind == "wifi-ap":
                normalized["network_mode"] = normalized.pop("mode")
                normalized["uplink_mac"] = _optional_mac_address(
                    raw_profile.get("uplink_mac"), "wired uplink"
                )
            else:
                normalized.pop("mode", None)
            interface = normalized["wifi_interface"]
            resources = _adapter_identity_keys(
                interface, str(normalized.get("adapter_mac", ""))
            )
            if enabled:
                assigned = next(
                    (active_wifi[key] for key in resources if key in active_wifi),
                    "",
                )
                if assigned:
                    raise ToolInputError(
                        f"{interface} is already assigned to {assigned}."
                    )
                active_wifi.update({key: name for key in resources})
                if kind == "wifi-ap" and normalized["network_mode"] == "bridge":
                    uplink = normalized["uplink_interface"]
                    uplink_resources = _adapter_identity_keys(
                        uplink, str(normalized.get("uplink_mac", ""))
                    )
                    bridged_by = next(
                        (
                            bridged_uplinks[key]
                            for key in uplink_resources
                            if key in bridged_uplinks
                        ),
                        "",
                    )
                    if bridged_by:
                        raise ToolInputError(
                            f"{uplink} is already bridged by {bridged_by}."
                        )
                    bridged_uplinks.update(
                        {key: name for key in uplink_resources}
                    )
                elif kind == "wifi-ap":
                    private_networks.append(
                        (name, ipaddress.ip_network(normalized["network"]))
                    )
        profiles.append(normalized)

    for resource, bridge_name in bridged_uplinks.items():
        if resource in active_wired:
            raise ToolInputError(
                f"The bridged uplink cannot be managed by {active_wired[resource]} while it is bridged by {bridge_name}."
            )
    for index, (name, network) in enumerate(private_networks):
        for other_name, other_network in private_networks[index + 1 :]:
            if network.overlaps(other_network):
                raise ToolInputError(
                    f"Private networks for {name} and {other_name} overlap."
                )
    return {"schema_version": 2, "country": country, "profiles": profiles}


def pi_network_configuration_from_legacy(settings: dict[str, Any]) -> dict[str, Any]:
    """Convert the v0.20/v0.21 single-role settings shape without losing secrets."""

    if not settings:
        return {"schema_version": 2, "country": "", "profiles": []}
    mode = str(settings.get("mode", ""))
    kind = "wifi-client" if mode == "client" else "wifi-ap"
    profile = dict(settings)
    profile.update(
        {
            "id": "legacy-wireless",
            "name": str(settings.get("ssid") or "Existing wireless profile"),
            "kind": kind,
            "enabled": True,
        }
    )
    if kind == "wifi-ap":
        profile["network_mode"] = mode
    profile.pop("mode", None)
    return {
        "schema_version": 2,
        "country": str(settings.get("country", "")),
        "profiles": [profile],
    }


def _certificate_summary(certificate: x509.Certificate) -> dict[str, str]:
    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "not_before": certificate.not_valid_before_utc.isoformat(),
        "not_after": certificate.not_valid_after_utc.isoformat(),
        "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
    }


def _load_certificates(data: bytes) -> list[x509.Certificate]:
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            loader = getattr(x509, "load_pem_x509_certificates", None)
            if loader:
                certificates = list(loader(data))
            else:
                certificates = [x509.load_pem_x509_certificate(data)]
        else:
            certificates = [x509.load_der_x509_certificate(data)]
    except ValueError as exc:
        raise ToolInputError("The uploaded certificate file is not valid PEM or DER data.") from exc
    if not certificates:
        raise ToolInputError("The uploaded certificate file is empty.")
    return certificates


def validate_uploaded_tls_material(
    *,
    ca_data: bytes = b"",
    client_certificate_data: bytes = b"",
    private_key_data: bytes = b"",
    bundle_data: bytes = b"",
    private_key_password: str = "",
) -> dict[str, Any]:
    for data in (ca_data, client_certificate_data, private_key_data, bundle_data):
        if len(data) > MAX_CERTIFICATE_BYTES:
            raise ToolInputError("Each uploaded certificate or key file must be 2 MiB or smaller.")
    result: dict[str, Any] = {}
    if ca_data:
        ca_certificates = _load_certificates(ca_data)
        result["ca"] = _certificate_summary(ca_certificates[0])
    password_bytes = private_key_password.encode("utf-8") if private_key_password else None
    if bundle_data:
        try:
            private_key, certificate, additional = pkcs12.load_key_and_certificates(
                bundle_data, password_bytes
            )
        except ValueError as exc:
            raise ToolInputError("The PKCS#12 bundle or its password is invalid.") from exc
        if private_key is None or certificate is None:
            raise ToolInputError("The PKCS#12 bundle must contain a client certificate and private key.")
        result["client"] = _certificate_summary(certificate)
        result["bundle_ca_count"] = len(additional or [])
    elif client_certificate_data or private_key_data:
        if not client_certificate_data or not private_key_data:
            raise ToolInputError("Upload both the client certificate and its private key.")
        certificate = _load_certificates(client_certificate_data)[0]
        try:
            private_key = serialization.load_pem_private_key(
                private_key_data, password=password_bytes
            )
        except (TypeError, ValueError) as exc:
            raise ToolInputError("The private key or its password is invalid.") from exc
        cert_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_public != key_public:
            raise ToolInputError("The client certificate does not match the uploaded private key.")
        result["client"] = _certificate_summary(certificate)
    return result


class RaspberryPiNetworkStore:
    def __init__(self, instance_path: str, secret_key: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "raspberry_pi_networking.json"
        self.pending_path = self.instance_path / "raspberry_pi_networking_pending.json"
        self.material_root = self.instance_path / "raspberry_pi_networking_material"
        key = base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode("utf-8")).digest())
        self._cipher = Fernet(key)

    def get(self, *, include_secrets: bool = False) -> dict[str, Any]:
        raw = self._read(self.path)
        if not raw:
            return {}
        values = dict(raw.get("settings") or {})
        secrets_payload = self._decrypt_dict(str(raw.get("secrets_encrypted", "")))
        values["has_passphrase"] = bool(secrets_payload.get("passphrase"))
        values["has_password"] = bool(secrets_payload.get("password"))
        values["has_private_key_password"] = bool(
            secrets_payload.get("private_key_password")
        )
        if include_secrets:
            values.update(secrets_payload)
        values["material"] = dict(raw.get("material") or {})
        values["certificate_summary"] = dict(raw.get("certificate_summary") or {})
        values["saved_at"] = float(raw.get("saved_at") or 0)
        return values

    def get_configuration(self, *, include_secrets: bool = False) -> dict[str, Any]:
        raw = self._read(self.path)
        if not raw:
            return {"schema_version": 2, "country": "", "profiles": []}
        if not isinstance(raw.get("configuration"), dict):
            legacy = self.get(include_secrets=include_secrets)
            configuration = pi_network_configuration_from_legacy(legacy)
            if configuration["profiles"]:
                profile = configuration["profiles"][0]
                profile["material"] = dict(legacy.get("material") or {})
                profile["certificate_summary"] = dict(
                    legacy.get("certificate_summary") or {}
                )
            return configuration
        configuration = json.loads(json.dumps(raw["configuration"]))
        secret_profiles = self._decrypt_payload(
            str(raw.get("secrets_encrypted", ""))
        )
        materials = raw.get("material") if isinstance(raw.get("material"), dict) else {}
        summaries = (
            raw.get("certificate_summary")
            if isinstance(raw.get("certificate_summary"), dict)
            else {}
        )
        for profile in configuration.get("profiles", []):
            identifier = str(profile.get("id", ""))
            secrets_payload = (
                secret_profiles.get(identifier, {})
                if isinstance(secret_profiles.get(identifier), dict)
                else {}
            )
            profile["has_passphrase"] = bool(secrets_payload.get("passphrase"))
            profile["has_password"] = bool(secrets_payload.get("password"))
            profile["has_private_key_password"] = bool(
                secrets_payload.get("private_key_password")
            )
            if include_secrets:
                profile.update(
                    {
                        key: str(value)
                        for key, value in secrets_payload.items()
                        if isinstance(key, str) and isinstance(value, str)
                    }
                )
            profile["material"] = dict(materials.get(identifier) or {})
            profile["certificate_summary"] = dict(summaries.get(identifier) or {})
        configuration["saved_at"] = float(raw.get("saved_at") or 0)
        return configuration

    def save_active_configuration(
        self, configuration: dict[str, Any]
    ) -> dict[str, Any]:
        safe = json.loads(json.dumps(configuration))
        secret_profiles: dict[str, dict[str, str]] = {}
        materials: dict[str, dict[str, str]] = {}
        summaries: dict[str, dict[str, Any]] = {}
        for profile in safe.get("profiles", []):
            identifier = str(profile.get("id", ""))
            secrets_payload = {}
            for key in ("passphrase", "password", "private_key_password"):
                value = str(profile.pop(key, ""))
                if value:
                    secrets_payload[key] = value
            if secrets_payload:
                secret_profiles[identifier] = secrets_payload
            material = profile.pop("material", {})
            if isinstance(material, dict) and material:
                materials[identifier] = {
                    str(key): str(value) for key, value in material.items()
                }
            summary = profile.pop("certificate_summary", {})
            if isinstance(summary, dict) and summary:
                summaries[identifier] = summary
            for key in (
                "has_passphrase",
                "has_password",
                "has_private_key_password",
            ):
                profile.pop(key, None)
        payload = {
            "schema_version": 2,
            "configuration": safe,
            "secrets_encrypted": self._encrypt_payload(secret_profiles),
            "material": materials,
            "certificate_summary": summaries,
            "saved_at": time.time(),
        }
        self._write(self.path, payload)
        return self.get_configuration()

    def save_active(
        self,
        settings: dict[str, Any],
        *,
        material: dict[str, str] | None = None,
        certificate_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        safe = dict(settings)
        secret_values = {
            key: str(safe.pop(key, ""))
            for key in ("passphrase", "password", "private_key_password")
            if safe.get(key)
        }
        payload = {
            "settings": safe,
            "secrets_encrypted": self._encrypt_dict(secret_values),
            "material": dict(material or {}),
            "certificate_summary": dict(certificate_summary or {}),
            "saved_at": time.time(),
        }
        self._write(self.path, payload)
        return self.get()

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)

    def save_pending(
        self,
        *,
        kind: str,
        token: str,
        expires_at: float,
        settings: dict[str, Any] | None = None,
        material: dict[str, str] | None = None,
        certificate_summary: dict[str, Any] | None = None,
    ) -> None:
        safe = dict(settings or {})
        secret_values = {
            key: str(safe.pop(key, ""))
            for key in ("passphrase", "password", "private_key_password")
            if safe.get(key)
        }
        self._write(
            self.pending_path,
            {
                "kind": kind,
                "token": token,
                "expires_at": float(expires_at),
                "settings": safe,
                "secrets_encrypted": self._encrypt_dict(secret_values),
                "material": dict(material or {}),
                "certificate_summary": dict(certificate_summary or {}),
            },
        )

    def save_pending_configuration(
        self,
        *,
        kind: str,
        token: str,
        expires_at: float,
        configuration: dict[str, Any] | None = None,
        dormant_profiles: list[dict[str, str]] | None = None,
    ) -> None:
        safe = json.loads(json.dumps(configuration or {}))
        secret_profiles: dict[str, dict[str, str]] = {}
        materials: dict[str, dict[str, str]] = {}
        summaries: dict[str, dict[str, Any]] = {}
        for profile in safe.get("profiles", []):
            identifier = str(profile.get("id", ""))
            secrets_payload = {}
            for key in ("passphrase", "password", "private_key_password"):
                value = str(profile.pop(key, ""))
                if value:
                    secrets_payload[key] = value
            if secrets_payload:
                secret_profiles[identifier] = secrets_payload
            material = profile.pop("material", {})
            if isinstance(material, dict) and material:
                materials[identifier] = {
                    str(key): str(value) for key, value in material.items()
                }
            summary = profile.pop("certificate_summary", {})
            if isinstance(summary, dict) and summary:
                summaries[identifier] = summary
            for key in (
                "has_passphrase",
                "has_password",
                "has_private_key_password",
            ):
                profile.pop(key, None)
        self._write(
            self.pending_path,
            {
                "schema_version": 2,
                "kind": kind,
                "token": token,
                "expires_at": float(expires_at),
                "configuration": safe,
                "secrets_encrypted": self._encrypt_payload(secret_profiles),
                "material": materials,
                "certificate_summary": summaries,
                "dormant_profiles": list(dormant_profiles or []),
            },
        )

    def pending_configuration(
        self, *, include_secrets: bool = False
    ) -> dict[str, Any]:
        raw = self._read_pending()
        if not raw or not isinstance(raw.get("configuration"), dict):
            return {}
        result = dict(raw)
        configuration = json.loads(json.dumps(raw["configuration"]))
        secret_profiles = self._decrypt_payload(
            str(result.pop("secrets_encrypted", ""))
        )
        materials = result.get("material") if isinstance(result.get("material"), dict) else {}
        summaries = (
            result.get("certificate_summary")
            if isinstance(result.get("certificate_summary"), dict)
            else {}
        )
        for profile in configuration.get("profiles", []):
            identifier = str(profile.get("id", ""))
            secret_payload = (
                secret_profiles.get(identifier, {})
                if isinstance(secret_profiles.get(identifier), dict)
                else {}
            )
            if include_secrets:
                profile.update(secret_payload)
            profile["material"] = dict(materials.get(identifier) or {})
            profile["certificate_summary"] = dict(summaries.get(identifier) or {})
        result["configuration"] = configuration
        return result

    def pending(self, *, include_secrets: bool = False) -> dict[str, Any]:
        pending = self._read_pending()
        if not pending:
            return {}
        result = dict(pending)
        settings = dict(result.get("settings") or {})
        secret_values = self._decrypt_dict(str(result.pop("secrets_encrypted", "")))
        if include_secrets:
            settings.update(secret_values)
        result["settings"] = settings
        return result

    def clear_pending(self) -> None:
        self.pending_path.unlink(missing_ok=True)
        self._sync_directory(self.pending_path.parent)

    def stage_material(self, files: dict[str, bytes]) -> dict[str, str]:
        token = secrets.token_hex(12)
        target = self.material_root / token
        target.mkdir(parents=True, mode=0o700)
        os.chmod(target, 0o700)
        paths: dict[str, str] = {}
        names = {
            "ca": "ca-certificate.pem",
            "client_certificate": "client-certificate.pem",
            "private_key": "client-private-key.pem",
            "bundle": "client-identity.p12",
        }
        for key, data in files.items():
            if not data:
                continue
            path = target / names[key]
            path.write_bytes(data)
            os.chmod(path, 0o600)
            paths[key] = str(path)
        return paths

    @staticmethod
    def _read(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Could not read {path.name}.") from exc
        return value if isinstance(value, dict) else {}

    def _read_pending(self) -> dict[str, Any]:
        # The protected broker is authoritative for whether a provisional
        # network change still exists. A torn local pending record must never
        # prevent an administrator from reopening Settings after power loss.
        try:
            return self._read(self.pending_path)
        except RuntimeError:
            return {}

    @staticmethod
    def _sync_directory(path: Path) -> None:
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            os.fsync(descriptor)
        except OSError:
            # Some filesystems do not support directory fsync. The atomic
            # replace still prevents readers from observing a partial write.
            pass
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _write(self, path: Path, payload: dict[str, Any]) -> None:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(5)}.tmp")
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, indent=2) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            self._sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _encrypt_dict(self, values: dict[str, str]) -> str:
        if not values:
            return ""
        return self._cipher.encrypt(json.dumps(values).encode("utf-8")).decode("ascii")

    def _encrypt_payload(self, values: dict[str, Any]) -> str:
        if not values:
            return ""
        return self._cipher.encrypt(json.dumps(values).encode("utf-8")).decode("ascii")

    def _decrypt_dict(self, value: str) -> dict[str, str]:
        if not value:
            return {}
        try:
            decoded = json.loads(self._cipher.decrypt(value.encode("ascii")))
        except (InvalidToken, ValueError, UnicodeError) as exc:
            raise RuntimeError("Could not decrypt the saved Raspberry Pi Wi-Fi credentials.") from exc
        return {
            str(key): str(item)
            for key, item in decoded.items()
            if isinstance(key, str) and isinstance(item, str)
        }

    def _decrypt_payload(self, value: str) -> dict[str, Any]:
        if not value:
            return {}
        try:
            decoded = json.loads(self._cipher.decrypt(value.encode("ascii")))
        except (InvalidToken, ValueError, UnicodeError) as exc:
            raise RuntimeError(
                "Could not decrypt the saved Raspberry Pi network credentials."
            ) from exc
        return decoded if isinstance(decoded, dict) else {}
