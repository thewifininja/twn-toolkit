from __future__ import annotations

import ipaddress
import json
import platform
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
        detail = str(exc)
        if platform.system() == "Linux" and "permission denied" in detail.casefold():
            result["message"] = (
                "lldpcli is installed, but the toolkit service cannot access the local "
                "lldpd control socket. Refresh the scoped service permissions with "
                "sudo ./twn service install --network-capabilities."
            )
        else:
            result["message"] = detail
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


def local_lldp_status(interface: str) -> str:
    """Return lldpd's current receive/transmit state for one local interface."""
    executable = _find_lldpcli()
    if not executable:
        raise ToolInputError(
            "Local LLDP control requires lldpd/lldpcli. Install lldpd and start its local daemon."
        )
    valid_interfaces = {item["name"] for item in available_interfaces()}
    if interface not in valid_interfaces:
        raise ToolInputError("Select an available LLDP interface.")
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
    status = _first_value(record or {}, "status")
    if not status:
        raise ToolInputError(f"lldpd did not report a state for {interface}.")
    return status


def set_local_lldp_mode(interface: str, mode: str) -> str:
    """Set one interface to receive-only or normal receive/transmit operation."""
    targets = {
        "receive-only": "rx-only",
        "receive-and-transmit": "rx-and-tx",
    }
    target = targets.get(str(mode))
    if not target:
        raise ToolInputError("Choose a valid local LLDP transmitter state.")
    # Validate the interface and daemon connection before changing state.
    local_lldp_status(interface)
    executable = _find_lldpcli()
    if not executable:
        raise ToolInputError("lldpcli is not available.")
    _execute_lldpcli(
        executable, "configure", "ports", interface, "lldp", "status", target
    )
    return local_lldp_status(interface)


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
            "system_description", "TWN Toolkit LLDP Lab"
        ),
        "source_mac": source_mac,
        "chassis_id": source_mac,
        "chassis_id_subtype": 4,
        "port_id": selected or "port-1",
        "port_id_subtype": 5 if selected else 7,
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
        "source_mac": str(
            form.get("source_mac", interface_mac(interface))
        ).strip(),
        "chassis_id": str(form.get("chassis_id", "")).strip(),
        "chassis_id_subtype": form.get("chassis_id_subtype", ""),
        "port_id": str(form.get("port_id", "")).strip(),
        "port_id_subtype": form.get("port_id_subtype", ""),
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
    try:
        normalized["source_mac"] = normalize_mac(
            str(persona.get("source_mac") or interface_mac(interface))
        )
    except ToolInputError as exc:
        raise ToolInputError(
            "Ethernet source MAC must be a unicast address containing six hexadecimal octets."
        ) from exc
    if normalized["source_mac"] == "00:00:00:00:00:00":
        raise ToolInputError("Ethernet source MAC cannot be all zeroes.")
    chassis_id = str(persona.get("chassis_id", "")).strip()
    chassis_subtype = _identifier_subtype(
        persona.get("chassis_id_subtype"), chassis=True, identifier=chassis_id
    )
    if chassis_subtype == 4:
        try:
            normalized["chassis_id"] = normalize_mac(chassis_id)
        except ToolInputError as exc:
            raise ToolInputError(
                "A MAC-address chassis ID must contain six hexadecimal octets."
            ) from exc
    else:
        normalized["chassis_id"] = _bounded_text(chassis_id, "Chassis ID", 255)
    normalized["chassis_id_subtype"] = chassis_subtype
    normalized["port_id_subtype"] = _identifier_subtype(
        persona.get("port_id_subtype"), chassis=False, identifier=normalized["port_id"]
    )
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
    try:
        status = local_lldp_status(interface)
    except ToolInputError:
        return ""
    target = {
        "RX and TX": "rx-only",
        "TX only": "disabled",
    }.get(status)
    if target:
        _execute_lldpcli(
            executable, "configure", "ports", interface, "lldp", "status", target
        )
    return status if target else ""


def local_lldpd_shutdown_frame(interface: str) -> bytes | None:
    """Build a TTL-zero PDU for lldpd's current local identity on one port."""
    executable = _find_lldpcli()
    if not executable:
        return None
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
        return None
    chassis = _first_named(record, "chassis")
    port = _first_named(record, "port")
    chassis_value = _lldp_identifier(
        _first_field(chassis, "id", "type"),
        _first_value(chassis, "id"),
        chassis=True,
    )
    port_value = _lldp_identifier(
        _first_field(port, "id", "type"),
        _first_value(port, "id"),
        chassis=False,
    )
    if not chassis_value or not port_value:
        return None
    source = bytes.fromhex(interface_mac(interface).replace(":", ""))
    payload = (
        _tlv(1, chassis_value)
        + _tlv(2, port_value)
        + _tlv(3, b"\x00\x00")
        + b"\x00\x00"
    )
    frame = LLDP_DESTINATION + source + LLDP_ETHERTYPE + payload
    return frame + bytes(max(0, MIN_FRAME_SIZE - len(frame)))


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


def lldp_persona_candidates(
    packets: Iterable[bytes], *, interface: str
) -> list[dict[str, Any]]:
    """Return one reviewable candidate per LLDP identity found in a capture."""
    candidates: dict[tuple[Any, ...], dict[str, Any]] = {}
    lldp_frames = 0
    for frame in packets:
        try:
            _lldp_payload_offset(frame)
        except ToolInputError:
            continue
        lldp_frames += 1
        try:
            persona = persona_from_lldp_frame(frame, interface=interface)
        except ToolInputError:
            continue
        key = (
            persona["source_mac"],
            persona["chassis_id_subtype"],
            persona["chassis_id"],
            persona["port_id_subtype"],
            persona["port_id"],
            persona["system_name"],
        )
        if key in candidates:
            candidates[key]["packet_count"] += 1
            continue
        candidates[key] = {
            "frame_hex": frame.hex(),
            "name": persona["name"],
            "system_name": persona["system_name"],
            "source_mac": persona["source_mac"],
            "chassis_id": persona["chassis_id"],
            "port_id": persona["port_id"],
            "capabilities": persona["capabilities"],
            "custom_tlv_count": len(persona["custom_tlvs"]),
            "packet_count": 1,
        }
    if not candidates:
        if lldp_frames:
            raise ToolInputError(
                "The capture contains LLDP traffic, but no complete active identity could be decoded."
            )
        raise ToolInputError("The capture does not contain any LLDP Ethernet frames.")
    return sorted(
        candidates.values(),
        key=lambda item: (item["system_name"].lower(), item["source_mac"]),
    )


def persona_from_lldp_frame(frame: bytes, *, interface: str) -> dict[str, Any]:
    """Decode one Ethernet LLDP frame into an unsaved, editable persona."""
    payload_offset = _lldp_payload_offset(frame)
    source_mac = _format_mac(frame[6:12])
    values: dict[int, list[bytes]] = {}
    offset = payload_offset
    saw_end = False
    while offset + 2 <= len(frame):
        header = struct.unpack_from("!H", frame, offset)[0]
        tlv_type = header >> 9
        length = header & 0x1FF
        offset += 2
        if tlv_type == 0:
            if length:
                raise ToolInputError("The LLDP end TLV is malformed.")
            saw_end = True
            break
        end = offset + length
        if end > len(frame):
            raise ToolInputError("The LLDP frame ends inside a TLV.")
        values.setdefault(tlv_type, []).append(frame[offset:end])
        offset = end
    if not saw_end:
        raise ToolInputError("The LLDP frame has no end TLV.")
    if not all(values.get(kind) for kind in (1, 2, 3)):
        raise ToolInputError("The LLDP frame is missing a mandatory identity TLV.")

    chassis_subtype, chassis_id = _decode_identifier(values[1][0], chassis=True)
    port_subtype, port_id = _decode_identifier(values[2][0], chassis=False)
    if len(values[3][0]) != 2:
        raise ToolInputError("The LLDP TTL TLV is malformed.")
    ttl = struct.unpack("!H", values[3][0])[0]
    if ttl == 0:
        raise ToolInputError("LLDP shutdown advertisements cannot become personas.")

    system_name = _decode_text(_first_tlv(values, 5)) or chassis_id
    system_description = _decode_text(_first_tlv(values, 6))
    port_description = _decode_text(_first_tlv(values, 4))
    capability_mask = 0
    capability_value = _first_tlv(values, 7)
    if len(capability_value) >= 4:
        _supported, capability_mask = struct.unpack("!HH", capability_value[:4])
    capabilities = [
        name for name, bit in CAPABILITY_BITS.items() if capability_mask & bit
    ]
    preset = (
        "phone"
        if "telephone" in capabilities
        else "switch"
        if "bridge" in capabilities
        else "generic"
    )
    persona = default_persona(preset=preset, interface=interface)
    persona.update(
        {
            "name": system_name,
            "preset": preset,
            "system_name": system_name,
            "system_description": system_description,
            "source_mac": source_mac,
            "chassis_id": chassis_id,
            "chassis_id_subtype": chassis_subtype,
            "port_id": port_id,
            "port_id_subtype": port_subtype,
            "port_description": port_description,
            "capabilities": capabilities,
            "management_address": _decode_management_address(
                _first_tlv(values, 8)
            ),
            "ttl": ttl,
            "pvid": 0,
            "med_enabled": False,
            "med_policy_enabled": False,
            "custom_tlvs": [],
        }
    )

    for organization in values.get(127, []):
        if len(organization) < 4:
            raise ToolInputError("An organizational LLDP TLV is malformed.")
        oui = organization[:3]
        subtype = organization[3]
        value = organization[4:]
        if oui == IEEE_8021_OUI and subtype == 1 and len(value) == 2:
            persona["pvid"] = struct.unpack("!H", value)[0]
            continue
        if oui == LLDP_MED_OUI and subtype == 1 and len(value) == 3:
            med_capabilities, med_class = struct.unpack("!HB", value)
            persona["med_enabled"] = True
            persona["med_class"] = med_class
            persona["med_policy_enabled"] = bool(med_capabilities & 2)
            continue
        if oui == LLDP_MED_OUI and subtype == 2 and len(value) == 4:
            policy = struct.unpack("!I", value)[0]
            if (policy >> 24) & 0x1F == 1:
                persona.update(
                    {
                        "med_enabled": True,
                        "med_policy_enabled": True,
                        "med_policy_unknown": bool(policy & (1 << 23)),
                        "med_policy_tagged": bool(policy & (1 << 22)),
                        "med_policy_vlan": (policy >> 9) & 0xFFF,
                        "med_policy_priority": (policy >> 6) & 0x7,
                        "med_policy_dscp": policy & 0x3F,
                    }
                )
                continue
        persona["custom_tlvs"].append(
            {
                "oui": oui.hex(),
                "subtype": subtype,
                "value_hex": value.hex(),
            }
        )
    return validate_persona(persona, interface=interface)


def build_lldp_frame(
    persona: dict[str, Any], *, interface: str, shutdown: bool = False
) -> tuple[bytes, list[dict[str, Any]]]:
    normalized = validate_persona(persona, interface=interface)
    source_mac = bytes.fromhex(normalized["source_mac"].replace(":", ""))
    chassis_value = bytes([normalized["chassis_id_subtype"]]) + _identifier_value(
        normalized["chassis_id"],
        subtype=normalized["chassis_id_subtype"],
        chassis=True,
    )
    port_value = bytes([normalized["port_id_subtype"]]) + _identifier_value(
        normalized["port_id"],
        subtype=normalized["port_id_subtype"],
        chassis=False,
    )
    tlvs: list[tuple[int, bytes, str]] = [
        (1, chassis_value, "Chassis ID"),
        (2, port_value, "Port ID"),
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
        "source_mac": ":".join(f"{octet:02x}" for octet in frame[6:12]),
        "destination_mac": "01:80:c2:00:00:0e",
        "ethertype": "0x88cc",
        "frame_length": len(frame),
        "frame_hex": frame.hex(),
        "shutdown_frame_hex": shutdown.hex(),
        "tlvs": tlvs,
    }


def _lldp_payload_offset(frame: bytes) -> int:
    if len(frame) < 14:
        raise ToolInputError("The Ethernet frame is too short.")
    offset = 12
    ethertype = struct.unpack_from("!H", frame, offset)[0]
    while ethertype in {0x8100, 0x88A8, 0x9100}:
        if len(frame) < offset + 6:
            raise ToolInputError("The Ethernet frame has an incomplete VLAN header.")
        offset += 4
        ethertype = struct.unpack_from("!H", frame, offset)[0]
    if ethertype != 0x88CC:
        raise ToolInputError("The Ethernet frame is not LLDP.")
    return offset + 2


def _first_tlv(values: dict[int, list[bytes]], tlv_type: int) -> bytes:
    return values.get(tlv_type, [b""])[0]


def _decode_text(value: bytes) -> str:
    return value.decode("utf-8", errors="replace").rstrip("\0").strip()


def _format_mac(value: bytes) -> str:
    if len(value) != 6:
        raise ToolInputError("An LLDP MAC address must contain six octets.")
    return ":".join(f"{octet:02x}" for octet in value)


def _decode_identifier(value: bytes, *, chassis: bool) -> tuple[int, str]:
    if len(value) < 2:
        raise ToolInputError("An LLDP identity TLV is empty.")
    subtype = value[0]
    if not 1 <= subtype <= 7:
        raise ToolInputError("An LLDP identity uses an unsupported subtype.")
    mac_subtype = 4 if chassis else 3
    decoded = _format_mac(value[1:]) if subtype == mac_subtype else _decode_text(value[1:])
    if not decoded:
        raise ToolInputError("An LLDP identity TLV has no value.")
    return subtype, decoded


def _identifier_subtype(raw: Any, *, chassis: bool, identifier: str) -> int:
    named = str(raw or "").strip().lower()
    aliases = {
        "mac": 4 if chassis else 3,
        "local": 7,
        "ifname": 6 if chassis else 5,
        "interface name": 6 if chassis else 5,
    }
    if named in aliases:
        return aliases[named]
    try:
        subtype = int(named)
    except (TypeError, ValueError):
        try:
            normalize_mac(identifier)
        except ToolInputError:
            return 7
        return 4 if chassis else 3
    if not 1 <= subtype <= 7:
        raise ToolInputError("LLDP identity subtypes must be between 1 and 7.")
    return subtype


def _identifier_value(value: str, *, subtype: int, chassis: bool) -> bytes:
    mac_subtype = 4 if chassis else 3
    if subtype == mac_subtype:
        return bytes.fromhex(normalize_mac(value).replace(":", ""))
    return value.encode("utf-8")


def _decode_management_address(value: bytes) -> str:
    if len(value) < 2:
        return ""
    address_length = value[0]
    if address_length < 2 or len(value) < 1 + address_length:
        return ""
    subtype = value[1]
    packed = value[2 : 1 + address_length]
    if (subtype, len(packed)) not in {(1, 4), (2, 16)}:
        return ""
    try:
        return str(ipaddress.ip_address(packed))
    except ValueError:
        return ""


def _management_value(address: str) -> bytes:
    parsed = ipaddress.ip_address(address)
    subtype = 1 if parsed.version == 4 else 2
    # Address length includes the address-family subtype. Interface subtype 1 is unknown.
    return bytes([len(parsed.packed) + 1, subtype]) + parsed.packed + bytes([1]) + struct.pack(
        "!I", 0
    ) + bytes([0])


def _tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack("!H", (tlv_type << 9) | len(value)) + value


def _lldp_identifier(kind: str, value: str, *, chassis: bool) -> bytes | None:
    normalized_kind = str(kind).strip().lower().replace("_", " ").replace("-", " ")
    mappings = (
        {
            "chassis component": 1,
            "ifalias": 2,
            "interface alias": 2,
            "port component": 3,
            "mac": 4,
            "mac address": 4,
            "ifname": 6,
            "interface name": 6,
            "local": 7,
        }
        if chassis
        else {
            "ifalias": 1,
            "interface alias": 1,
            "port component": 2,
            "mac": 3,
            "mac address": 3,
            "ifname": 5,
            "interface name": 5,
            "agent circuit id": 6,
            "local": 7,
        }
    )
    subtype = mappings.get(normalized_kind)
    if subtype is None or not value:
        return None
    if normalized_kind in {"mac", "mac address"}:
        try:
            encoded = bytes.fromhex(normalize_mac(value).replace(":", ""))
        except ToolInputError:
            return None
    else:
        encoded = str(value).encode("utf-8")
    if not encoded or len(encoded) > 255:
        return None
    return bytes([subtype]) + encoded


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
            for path in (
                Path("/usr/sbin/lldpcli"),
                Path("/usr/bin/lldpcli"),
                Path("/opt/homebrew/sbin/lldpcli"),
                Path("/usr/local/sbin/lldpcli"),
            )
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
