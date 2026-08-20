from __future__ import annotations

import ipaddress
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .dhcp_tools import available_interfaces, interface_mac, normalize_mac
from .network_tools import ToolInputError


LLDP_DESTINATION = bytes.fromhex("0180c200000e")
LLDP_ETHERTYPE = bytes.fromhex("88cc")
LLDP_MED_OUI = bytes.fromhex("0012bb")
IEEE_8021_OUI = bytes.fromhex("0080c2")
MIN_FRAME_SIZE = 60
MAX_FRAME_SIZE = 1514
MAX_CUSTOM_TLVS = 12
MAX_CUSTOM_VALUE_BYTES = 128

CAPABILITY_BITS = {
    "other": 1,
    "repeater": 2,
    "bridge": 4,
    "wlan": 8,
    "router": 16,
    "telephone": 32,
    "docsis": 64,
    "station": 128,
    "cvlan": 256,
    "svlan": 512,
    "tpmr": 1024,
}

PRESETS: dict[str, dict[str, Any]] = {
    "generic": {
        "label": "Generic endpoint",
        "description": "A standards-based LLDP endpoint with editable identity and capabilities.",
        "capabilities": ["station"],
        "med_enabled": False,
        "med_class": 0,
        "med_policy_enabled": False,
        "interval_seconds": 30,
        "duration_minutes": 10,
    },
    "phone": {
        "label": "VoIP phone probe",
        "description": "Advertises an LLDP-MED phone asking the switch for its voice policy.",
        "capabilities": ["telephone", "station"],
        "med_enabled": True,
        "med_class": 3,
        "med_policy_enabled": True,
        "med_policy_unknown": True,
        "med_policy_tagged": False,
        "med_policy_vlan": 0,
        "med_policy_priority": 0,
        "med_policy_dscp": 0,
        "interval_seconds": 5,
        "duration_minutes": 10,
    },
    "switch": {
        "label": "Generic bridge",
        "description": "Advertises a bridge identity, PVID, and optional custom organizational TLVs.",
        "capabilities": ["bridge"],
        "med_enabled": False,
        "med_class": 0,
        "med_policy_enabled": False,
        "interval_seconds": 5,
        "duration_minutes": 10,
    },
    "fortiswitch": {
        "label": "FortiSwitch lab baseline",
        "description": "An experimental bridge baseline for capture-led Auto-ISL testing.",
        "capabilities": ["bridge"],
        "med_enabled": False,
        "med_class": 0,
        "med_policy_enabled": False,
        "system_description": "FortiSwitch lab emulation",
        "interval_seconds": 5,
        "duration_minutes": 10,
        "experimental": True,
    },
}


def lldpcli_capability() -> dict[str, Any]:
    executable = _find_lldpcli()
    result: dict[str, Any] = {
        "available": bool(executable),
        "executable": executable or "",
        "version": "",
        "connected": False,
        "message": "",
    }
    if not executable:
        result["message"] = (
            "LLDP observation requires lldpd/lldpcli. Install lldpd and start its local daemon."
        )
        return result
    try:
        completed = subprocess.run(
            [executable, "-v"], capture_output=True, text=True, timeout=3, check=False
        )
        result["version"] = _version_from_text(completed.stdout or completed.stderr)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        _run_lldpcli(executable, "show", "neighbors", "summary")
    except ToolInputError as exc:
        result["message"] = str(exc)
    else:
        result["connected"] = True
        result["message"] = "Connected to the local lldpd control socket."
    return result


def read_neighbors() -> list[dict[str, Any]]:
    executable = _find_lldpcli()
    if not executable:
        raise ToolInputError(
            "LLDP observation requires lldpd/lldpcli. Install lldpd and start its local daemon."
        )
    payload = _run_lldpcli(executable, "show", "neighbors", "details")
    return normalize_neighbors(payload)


def normalize_neighbors(payload: dict[str, Any]) -> list[dict[str, Any]]:
    neighbors: list[dict[str, Any]] = []
    for interface in _named_objects(payload, "interface"):
        chassis = _first_named(interface, "chassis")
        port = _first_named(interface, "port")
        chassis_id = _first_value(chassis, "id")
        port_id = _first_value(port, "id")
        capabilities = [
            str(item.get("type", "")).strip()
            for item in _as_list(chassis.get("capability"))
            if isinstance(item, dict) and item.get("enabled") is True
        ]
        med_policies = []
        for policy in _named_objects(interface, "policy"):
            med_policies.append(
                {
                    "application": str(
                        policy.get("type") or policy.get("application") or ""
                    ),
                    "unknown": _truthy(policy.get("unknown")),
                    "tagged": _truthy(policy.get("tagged")),
                    "vlan": _integer(policy.get("vid") or policy.get("vlan"), 0),
                    "priority": _integer(policy.get("priority"), 0),
                    "dscp": _integer(policy.get("dscp"), 0),
                }
            )
        vlans = []
        for vlan in _named_objects(interface, "vlan"):
            value = vlan.get("vlan-id") or vlan.get("vid") or vlan.get("id")
            if value not in {None, ""}:
                vlans.append(
                    {
                        "id": _integer(value, 0),
                        "name": str(vlan.get("name", "")),
                    }
                )
        neighbors.append(
            {
                "interface": str(interface.get("name", "")),
                "via": str(interface.get("via", "LLDP")),
                "age": str(interface.get("age", "")),
                "system_name": _first_value(chassis, "name"),
                "system_description": _first_value(chassis, "descr"),
                "chassis_id": chassis_id,
                "chassis_id_type": _first_field(chassis, "id", "type"),
                "port_id": port_id,
                "port_id_type": _first_field(port, "id", "type"),
                "port_description": _first_value(port, "descr"),
                "ttl": _integer(_first_value(port, "ttl"), 0),
                "management_addresses": _all_values(chassis, "mgmt-ip"),
                "capabilities": capabilities,
                "med_policies": med_policies,
                "vlans": vlans,
            }
        )
    return sorted(neighbors, key=lambda item: (item["interface"], item["system_name"]))


def default_persona(*, preset: str = "generic", interface: str = "") -> dict[str, Any]:
    if preset not in PRESETS:
        preset = "generic"
    interfaces = available_interfaces()
    selected = interface or preferred_interface(interfaces)
    source_mac = interface_mac(selected) if selected else "02:00:00:00:00:01"
    settings = PRESETS[preset]
    return {
        "name": settings["label"],
        "preset": preset,
        "system_name": "Toolkit LLDP Lab",
        "system_description": settings.get(
            "system_description", "The WiFi Ninja's Toolkit LLDP Lab"
        ),
        "chassis_id": source_mac,
        "port_id": selected or "port-1",
        "port_description": selected or "LLDP Lab port",
        "capabilities": list(settings["capabilities"]),
        "management_address": "",
        "pvid": 0,
        "ttl": 120,
        "med_enabled": bool(settings["med_enabled"]),
        "med_class": int(settings["med_class"]),
        "med_policy_enabled": bool(settings["med_policy_enabled"]),
        "med_policy_unknown": bool(settings.get("med_policy_unknown", False)),
        "med_policy_tagged": bool(settings.get("med_policy_tagged", False)),
        "med_policy_vlan": int(settings.get("med_policy_vlan", 0)),
        "med_policy_priority": int(settings.get("med_policy_priority", 0)),
        "med_policy_dscp": int(settings.get("med_policy_dscp", 0)),
        "interval_seconds": int(settings["interval_seconds"]),
        "duration_minutes": int(settings["duration_minutes"]),
        "quiet_lldpd": True,
        "custom_tlvs": [],
    }


def preferred_interface(interfaces: list[dict[str, str]]) -> str:
    """Favor a normal wired adapter without hiding advanced interface choices."""
    names = [str(item.get("name", "")) for item in interfaces]
    for exact in ("eth0", "en0"):
        if exact in names:
            return exact
    excluded_prefixes = ("lo", "awdl", "llw", "anpi", "utun", "bridge", "ap", "gif", "stf")
    for name in names:
        if name and not name.startswith(excluded_prefixes):
            return name
    return names[0] if names else ""


def persona_from_form(form: Any, *, interface: str) -> dict[str, Any]:
    capabilities = [
        name for name in CAPABILITY_BITS if str(form.get(f"capability_{name}", "")) == "on"
    ]
    custom_tlvs = parse_custom_tlvs(str(form.get("custom_tlvs", "")))
    persona = {
        "name": str(form.get("name", "")).strip(),
        "preset": str(form.get("preset", "generic")).strip(),
        "system_name": str(form.get("system_name", "")).strip(),
        "system_description": str(form.get("system_description", "")).strip(),
        "chassis_id": str(form.get("chassis_id", "")).strip(),
        "port_id": str(form.get("port_id", "")).strip(),
        "port_description": str(form.get("port_description", "")).strip(),
        "capabilities": capabilities,
        "management_address": str(form.get("management_address", "")).strip(),
        "pvid": _integer(form.get("pvid"), 0),
        "ttl": _integer(form.get("ttl"), 120),
        "med_enabled": str(form.get("med_enabled", "")) == "on",
        "med_class": _integer(form.get("med_class"), 3),
        "med_policy_enabled": str(form.get("med_policy_enabled", "")) == "on",
        "med_policy_unknown": str(form.get("med_policy_unknown", "")) == "on",
        "med_policy_tagged": str(form.get("med_policy_tagged", "")) == "on",
        "med_policy_vlan": _integer(form.get("med_policy_vlan"), 0),
        "med_policy_priority": _integer(form.get("med_policy_priority"), 0),
        "med_policy_dscp": _integer(form.get("med_policy_dscp"), 0),
        "interval_seconds": _integer(form.get("interval_seconds"), 30),
        "duration_minutes": _integer(form.get("duration_minutes"), 10),
        "quiet_lldpd": str(form.get("quiet_lldpd", "")) == "on",
        "custom_tlvs": custom_tlvs,
    }
    return validate_persona(persona, interface=interface)


def validate_persona(persona: dict[str, Any], *, interface: str) -> dict[str, Any]:
    valid_interfaces = {item["name"] for item in available_interfaces()}
    if interface not in valid_interfaces:
        raise ToolInputError("Choose a valid network interface.")
    normalized = dict(persona)
    normalized["name"] = _bounded_text(persona.get("name"), "Persona name", 120)
    normalized["system_name"] = _bounded_text(
        persona.get("system_name"), "System name", 255
    )
    normalized["system_description"] = _bounded_text(
        persona.get("system_description"), "System description", 511, required=False
    )
    normalized["port_id"] = _bounded_text(persona.get("port_id"), "Port ID", 255)
    normalized["port_description"] = _bounded_text(
        persona.get("port_description"), "Port description", 255, required=False
    )
    chassis_id = str(persona.get("chassis_id", "")).strip()
    try:
        normalized["chassis_id"] = normalize_mac(chassis_id)
        normalized["chassis_id_subtype"] = "mac"
    except ToolInputError:
        normalized["chassis_id"] = _bounded_text(chassis_id, "Chassis ID", 255)
        normalized["chassis_id_subtype"] = "local"
    capabilities = [
        str(name).lower() for name in persona.get("capabilities", []) if str(name).lower() in CAPABILITY_BITS
    ]
    normalized["capabilities"] = list(dict.fromkeys(capabilities))
    normalized["pvid"] = _bounded_int(persona.get("pvid"), "PVID", 0, 4094)
    normalized["ttl"] = _bounded_int(persona.get("ttl"), "TTL", 10, 65535)
    normalized["interval_seconds"] = _bounded_int(
        persona.get("interval_seconds"), "Transmit interval", 1, 120
    )
    normalized["duration_minutes"] = _bounded_int(
        persona.get("duration_minutes"), "Duration", 1, 60
    )
    normalized["med_class"] = _bounded_int(persona.get("med_class"), "MED class", 0, 4)
    normalized["med_policy_vlan"] = _bounded_int(
        persona.get("med_policy_vlan"), "MED VLAN", 0, 4094
    )
    normalized["med_policy_priority"] = _bounded_int(
        persona.get("med_policy_priority"), "MED priority", 0, 7
    )
    normalized["med_policy_dscp"] = _bounded_int(
        persona.get("med_policy_dscp"), "MED DSCP", 0, 63
    )
    management = str(persona.get("management_address", "")).strip()
    if management:
        try:
            management = str(ipaddress.ip_address(management))
        except ValueError as exc:
            raise ToolInputError("Management address must be a valid IPv4 or IPv6 address.") from exc
    normalized["management_address"] = management
    normalized["custom_tlvs"] = validate_custom_tlvs(persona.get("custom_tlvs", []))
    for field in (
        "med_enabled",
        "med_policy_enabled",
        "med_policy_unknown",
        "med_policy_tagged",
        "quiet_lldpd",
    ):
        normalized[field] = bool(persona.get(field))
    if normalized["med_policy_enabled"] and not normalized["med_enabled"]:
        raise ToolInputError("Enable LLDP-MED before adding a network policy.")
    if normalized["med_enabled"] and normalized["med_class"] not in {1, 2, 3, 4}:
        raise ToolInputError("Choose an LLDP-MED device class.")
    if normalized["med_policy_unknown"]:
        normalized["med_policy_tagged"] = False
        normalized["med_policy_vlan"] = 0
        normalized["med_policy_priority"] = 0
        normalized["med_policy_dscp"] = 0
    return normalized


def quiet_interface_lldp(interface: str) -> str:
    """Disable only lldpd egress on one interface and return its prior status."""
    executable = _find_lldpcli()
    if not executable:
        return ""
    payload = _run_lldpcli(
        executable, "show", "interfaces", "ports", interface, "details"
    )
    record = next(
        (
            item
            for item in _named_objects(payload, "interface")
            if str(item.get("name", "")) == interface
        ),
        None,
    )
    if not record:
        return ""
    status = _first_value(record, "status")
    target = {
        "RX and TX": "rx-only",
        "TX only": "disabled",
    }.get(status)
    if target:
        _execute_lldpcli(
            executable, "configure", "ports", interface, "lldp", "status", target
        )
    return status if target else ""


def restore_interface_lldp(interface: str, status: str) -> None:
    executable = _find_lldpcli()
    target = {
        "RX and TX": "rx-and-tx",
        "TX only": "tx-only",
        "RX only": "rx-only",
        "disabled": "disabled",
    }.get(str(status))
    if not executable or not target:
        return
    _execute_lldpcli(
        executable, "configure", "ports", interface, "lldp", "status", target
    )


def parse_custom_tlvs(value: str) -> list[dict[str, Any]]:
    if not value.strip():
        return []
    result = []
    for line_number, line in enumerate(value.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",", 2)]
        if len(parts) != 3:
            raise ToolInputError(
                f"Custom TLV line {line_number} must be OUI, subtype, value hex."
            )
        result.append({"oui": parts[0], "subtype": parts[1], "value_hex": parts[2]})
    return validate_custom_tlvs(result)


def format_custom_tlvs(items: Iterable[dict[str, Any]]) -> str:
    return "\n".join(
        f"{item.get('oui', '')}, {item.get('subtype', '')}, {item.get('value_hex', '')}"
        for item in items
    )


def validate_custom_tlvs(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        raise ToolInputError("Custom TLVs must be a list.")
    if len(items) > MAX_CUSTOM_TLVS:
        raise ToolInputError(f"Use no more than {MAX_CUSTOM_TLVS} custom TLVs.")
    result = []
    for item in items:
        if not isinstance(item, dict):
            raise ToolInputError("Each custom TLV must contain an OUI, subtype, and value.")
        compact_oui = re.sub(r"[^0-9a-fA-F]", "", str(item.get("oui", "")))
        if len(compact_oui) != 6:
            raise ToolInputError("Each custom TLV OUI must contain exactly three octets.")
        subtype = _bounded_int(item.get("subtype"), "Custom TLV subtype", 0, 255)
        value_hex = re.sub(r"[\s:-]", "", str(item.get("value_hex", "")))
        if len(value_hex) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", value_hex):
            raise ToolInputError("Custom TLV values must contain whole hexadecimal octets.")
        if len(value_hex) // 2 > MAX_CUSTOM_VALUE_BYTES:
            raise ToolInputError(
                f"Custom TLV values may contain at most {MAX_CUSTOM_VALUE_BYTES} bytes."
            )
        result.append(
            {"oui": compact_oui.lower(), "subtype": subtype, "value_hex": value_hex.lower()}
        )
    return result


def build_lldp_frame(
    persona: dict[str, Any], *, interface: str, shutdown: bool = False
) -> tuple[bytes, list[dict[str, Any]]]:
    normalized = validate_persona(persona, interface=interface)
    source_mac = bytes.fromhex(interface_mac(interface).replace(":", ""))
    chassis = normalized["chassis_id"]
    if normalized["chassis_id_subtype"] == "mac":
        chassis_value = bytes([4]) + bytes.fromhex(chassis.replace(":", ""))
    else:
        chassis_value = bytes([7]) + chassis.encode("utf-8")
    tlvs: list[tuple[int, bytes, str]] = [
        (1, chassis_value, "Chassis ID"),
        (2, bytes([7]) + normalized["port_id"].encode("utf-8"), "Port ID"),
        (3, struct.pack("!H", 0 if shutdown else normalized["ttl"]), "TTL"),
    ]
    if not shutdown:
        if normalized["port_description"]:
            tlvs.append((4, normalized["port_description"].encode("utf-8"), "Port description"))
        tlvs.append((5, normalized["system_name"].encode("utf-8"), "System name"))
        if normalized["system_description"]:
            tlvs.append(
                (6, normalized["system_description"].encode("utf-8"), "System description")
            )
        capability_mask = sum(CAPABILITY_BITS[name] for name in normalized["capabilities"])
        tlvs.append((7, struct.pack("!HH", capability_mask, capability_mask), "Capabilities"))
        if normalized["management_address"]:
            tlvs.append((8, _management_value(normalized["management_address"]), "Management address"))
        if normalized["pvid"]:
            value = IEEE_8021_OUI + bytes([1]) + struct.pack("!H", normalized["pvid"])
            tlvs.append((127, value, "IEEE 802.1 PVID"))
        if normalized["med_enabled"]:
            med_caps = 1 | (2 if normalized["med_policy_enabled"] else 0)
            value = LLDP_MED_OUI + bytes([1]) + struct.pack("!HB", med_caps, normalized["med_class"])
            tlvs.append((127, value, "LLDP-MED capabilities"))
            if normalized["med_policy_enabled"]:
                policy = (
                    (1 << 24)
                    | (int(normalized["med_policy_unknown"]) << 23)
                    | (int(normalized["med_policy_tagged"]) << 22)
                    | (normalized["med_policy_vlan"] << 9)
                    | (normalized["med_policy_priority"] << 6)
                    | normalized["med_policy_dscp"]
                )
                tlvs.append(
                    (
                        127,
                        LLDP_MED_OUI + bytes([2]) + struct.pack("!I", policy),
                        "LLDP-MED voice policy",
                    )
                )
        for item in normalized["custom_tlvs"]:
            value = (
                bytes.fromhex(item["oui"])
                + bytes([item["subtype"]])
                + bytes.fromhex(item["value_hex"])
            )
            tlvs.append((127, value, f"Custom {item['oui']} / {item['subtype']}"))
    encoded = bytearray()
    decoded = []
    for tlv_type, value, label in tlvs:
        if len(value) > 511:
            raise ToolInputError(f"{label} exceeds the LLDP TLV length limit.")
        encoded.extend(struct.pack("!H", (tlv_type << 9) | len(value)))
        encoded.extend(value)
        decoded.append({"type": tlv_type, "label": label, "length": len(value)})
    encoded.extend(b"\x00\x00")
    decoded.append({"type": 0, "label": "End", "length": 0})
    frame = LLDP_DESTINATION + source_mac + LLDP_ETHERTYPE + bytes(encoded)
    if len(frame) > MAX_FRAME_SIZE:
        raise ToolInputError(
            "The composed LLDP frame exceeds the Ethernet frame-size limit. "
            "Shorten text fields or remove custom TLVs."
        )
    if len(frame) < MIN_FRAME_SIZE:
        frame += bytes(MIN_FRAME_SIZE - len(frame))
    return frame, decoded


def preview_persona(persona: dict[str, Any], *, interface: str) -> dict[str, Any]:
    frame, tlvs = build_lldp_frame(persona, interface=interface)
    shutdown, _ = build_lldp_frame(persona, interface=interface, shutdown=True)
    return {
        "interface": interface,
        "source_mac": interface_mac(interface),
        "destination_mac": "01:80:c2:00:00:0e",
        "ethertype": "0x88cc",
        "frame_length": len(frame),
        "frame_hex": frame.hex(),
        "shutdown_frame_hex": shutdown.hex(),
        "tlvs": tlvs,
    }


def _management_value(address: str) -> bytes:
    parsed = ipaddress.ip_address(address)
    subtype = 1 if parsed.version == 4 else 2
    # Address length includes the address-family subtype. Interface subtype 1 is unknown.
    return bytes([len(parsed.packed) + 1, subtype]) + parsed.packed + bytes([1]) + struct.pack(
        "!I", 0
    ) + bytes([0])


def _tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack("!H", (tlv_type << 9) | len(value)) + value


def _run_lldpcli(executable: str, *arguments: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [executable, "-f", "json0", *arguments],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ToolInputError(f"Could not run lldpcli: {exc}") from exc
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "lldpcli failed").strip()
        raise ToolInputError(detail[-1000:])
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ToolInputError("lldpcli returned an unreadable response.") from exc
    if not isinstance(payload, dict):
        raise ToolInputError("lldpcli returned an unexpected response.")
    return payload


def _execute_lldpcli(executable: str, *arguments: str) -> None:
    try:
        completed = subprocess.run(
            [executable, *arguments],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ToolInputError(f"Could not configure lldpd: {exc}") from exc
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "lldpcli failed").strip()
        raise ToolInputError(f"Could not configure lldpd: {detail[-1000:]}")


def _find_lldpcli() -> str | None:
    return shutil.which("lldpcli") or next(
        (
            str(path)
            for path in (Path("/opt/homebrew/sbin/lldpcli"), Path("/usr/local/sbin/lldpcli"))
            if path.is_file()
        ),
        None,
    )


def _version_from_text(value: str) -> str:
    match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", value or "")
    return match.group(1) if match else ""


def _named_objects(value: Any, key: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for child_key, child in value.items():
            if child_key == key:
                found.extend(item for item in _as_list(child) if isinstance(item, dict))
            else:
                found.extend(_named_objects(child, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(_named_objects(item, key))
    return found


def _first_named(value: dict[str, Any], key: str) -> dict[str, Any]:
    return next((item for item in _as_list(value.get(key)) if isinstance(item, dict)), {})


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _all_values(value: dict[str, Any], key: str) -> list[str]:
    return [
        str(item.get("value", ""))
        for item in _as_list(value.get(key))
        if isinstance(item, dict) and item.get("value") not in {None, ""}
    ]


def _first_value(value: dict[str, Any], key: str) -> str:
    items = _all_values(value, key)
    return items[0] if items else ""


def _first_field(value: dict[str, Any], key: str, field: str) -> str:
    item = next((item for item in _as_list(value.get(key)) if isinstance(item, dict)), {})
    return str(item.get(field, ""))


def _bounded_text(value: Any, label: str, limit: int, *, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ToolInputError(f"{label} is required.")
    if len(text.encode("utf-8")) > limit:
        raise ToolInputError(f"{label} may contain at most {limit} UTF-8 bytes.")
    return text


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ToolInputError(f"{label} must be a whole number.") from exc
    if not minimum <= result <= maximum:
        raise ToolInputError(f"{label} must be between {minimum} and {maximum}.")
    return result


def _integer(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}
