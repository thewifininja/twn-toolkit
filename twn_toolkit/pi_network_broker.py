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
BROKER_PROTOCOL_VERSION = 1
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
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


def _validate_settings(settings: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(settings)
    mode = str(normalized.get("mode", ""))
    if mode not in {"nat", "bridge", "client"}:
        raise BrokerError("The request contains an unsupported networking mode.")
    normalized["mode"] = mode
    normalized["wifi_interface"] = _safe_interface(
        normalized.get("wifi_interface")
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
        uplink = _safe_interface(normalized.get("uplink_interface"))
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


def build_connection_profiles(settings: dict[str, Any], transaction_id: str) -> list[dict[str, str]]:
    settings = _validate_settings(settings)
    mode = settings["mode"]
    wifi_interface = settings["wifi_interface"]
    autoconnect = bool(settings.get("autoconnect", True))
    profiles: list[dict[str, str]] = []

    def profile(role: str, sections: list[tuple[str, dict[str, Any]]]) -> dict[str, str]:
        identifier = f"{PROFILE_PREFIX}{transaction_id}-{role}"
        profile_uuid = str(uuid.uuid4())
        metadata = sections[0][1]
        connection = {
            "id": identifier,
            "uuid": profile_uuid,
            "type": metadata.pop("_type"),
            "interface-name": metadata.pop("_interface"),
            "autoconnect": autoconnect,
        }
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
            "content": _config_text(body),
        }

    if mode == "nat":
        gateway = _safe_text(settings.get("gateway"), limit=64, required=True)
        prefix = str(settings.get("network", "")).split("/", 1)[-1]
        sections = [
            ("profile", {"_type": "wifi", "_interface": wifi_interface}),
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
            ("profile", {"_type": "wifi", "_interface": wifi_interface}),
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
                    },
                ),
                ("ethernet", {}),
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
                self.current_path.unlink(missing_ok=True)
        certificate_directory = str(pending.get("certificate_directory", ""))
        if certificate_directory:
            shutil.rmtree(certificate_directory, ignore_errors=True)
        self.pending_path.unlink(missing_ok=True)

    def _expire_pending_locked(self) -> None:
        pending = _read_json(self.pending_path)
        if pending and time.time() >= float(pending.get("expires_at") or 0):
            self._rollback_locked(pending)

    def apply(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._expire_pending_locked()
            if _read_json(self.pending_path):
                raise BrokerError("Confirm or roll back the current pending network change first.")
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
                    "mode": settings["mode"],
                    "ssid": settings.get("ssid", ""),
                    "wifi_interface": settings.get("wifi_interface", ""),
                    "expires_at": expires_at,
                }
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
            return {"token": token, "expires_at": expires_at, "transaction_id": transaction_id}

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
                    "mode": pending.get("mode", ""),
                    "ssid": pending.get("ssid", ""),
                    "wifi_interface": pending.get("wifi_interface", ""),
                    "profiles": pending.get("profiles") or [],
                    "previous_connections": pending.get("previous_connections") or [],
                    "previous_country": pending.get("previous_country", ""),
                    "previous_wifi_enabled": bool(
                        pending.get("previous_wifi_enabled", True)
                    ),
                    "certificate_directory": pending.get("certificate_directory", ""),
                    "confirmed_at": time.time(),
                }
                try:
                    _write_json(self.current_path, managed)
                    self._checkpoint_action(
                        "CheckpointDestroy", str(pending["checkpoint"])
                    )
                except Exception:
                    if previous_managed:
                        _write_json(self.current_path, previous_managed)
                    else:
                        self.current_path.unlink(missing_ok=True)
                    raise
                self.pending_path.unlink(missing_ok=True)
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
                    self.current_path.unlink(missing_ok=True)
                    self._checkpoint_action(
                        "CheckpointDestroy", str(pending["checkpoint"])
                    )
                except Exception:
                    if previous_managed:
                        _write_json(self.current_path, previous_managed)
                    raise
                self.pending_path.unlink(missing_ok=True)
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
                return {
                    "protocol_version": BROKER_PROTOCOL_VERSION,
                    "managed": _read_json(self.current_path),
                    "pending": {
                        key: pending.get(key)
                        for key in ("token", "kind", "mode", "ssid", "expires_at")
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
            except Exception as exc:
                print(
                    "Raspberry Pi network rollback monitor error: "
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
