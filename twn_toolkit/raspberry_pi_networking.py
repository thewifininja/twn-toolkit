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
PI_NETWORK_BROKER_PROTOCOL_VERSION = 1
PI_NETWORK_ROLLBACK_SECONDS = 120
MAX_BROKER_MESSAGE_BYTES = 512 * 1024
MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
CONNECTION_MODES = {"nat", "bridge", "client"}
AP_SECURITY_MODES = {"wpa2", "wpa2-wpa3", "wpa3"}
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
            broker = request_pi_network_broker(
                {"operation": "status"}, socket_path=broker_socket
            )
            if broker.get("protocol_version") != PI_NETWORK_BROKER_PROTOCOL_VERSION:
                raise PiNetworkBrokerError(
                    "Reinstall the system service to update the Raspberry Pi network broker."
                )
            status["managed"] = broker.get("managed") or {}
            status["pending"] = broker.get("pending") or {}
        except (OSError, PiNetworkBrokerError) as exc:
            status["broker_available"] = False
            status["broker_error"] = " ".join(str(exc).split())[:240]

    if not version:
        status["limitations"].append("NetworkManager and nmcli are required.")
    elif not status["network_manager_active"]:
        status["limitations"].append("NetworkManager is not active.")
    if not status["wifi_interfaces"]:
        status["limitations"].append("No NetworkManager Wi-Fi interface was detected.")
    if status["wifi_interfaces"] and not status["ap_available"]:
        status["limitations"].append(
            "The detected Wi-Fi interface does not report access-point support."
        )
    if not status["broker_available"]:
        status["limitations"].append(
            status["broker_error"]
            or "Reinstall the system service to enable protected network changes."
        )
    status["supported"] = bool(
        version
        and status["network_manager_active"]
        and status["wifi_interfaces"]
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

    def pending(self, *, include_secrets: bool = False) -> dict[str, Any]:
        pending = self._read(self.pending_path)
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

    def _write(self, path: Path, payload: dict[str, Any]) -> None:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(5)}.tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def _encrypt_dict(self, values: dict[str, str]) -> str:
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
