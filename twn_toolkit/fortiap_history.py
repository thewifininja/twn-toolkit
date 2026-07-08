from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from .fortigate import FortiGateClient, FortiGateError


class WirelessHistorySource(Protocol):
    label: str

    def logs(self, mac: str, vdom: str, hours: int) -> list[dict[str, Any]]:
        ...

    def live_clients(self, mac: str, vdom: str) -> list[dict[str, Any]]:
        ...


@dataclass(frozen=True)
class LocalFortiGateWirelessHistorySource:
    client: FortiGateClient
    label: str = "Local FortiGate"

    def logs(self, mac: str, vdom: str, hours: int) -> list[dict[str, Any]]:
        return self.client.get_wireless_client_logs(mac, vdom, hours)

    def live_clients(self, mac: str, vdom: str) -> list[dict[str, Any]]:
        return self.client.get_wireless_clients(vdom)


def normalize_client_mac(value: str) -> str:
    digits = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(digits) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", digits):
        raise ValueError("Enter a client MAC address as 12 hexadecimal digits.")
    octets = [digits[index : index + 2] for index in range(0, 12, 2)]
    return ":".join(octet.lower() for octet in octets)


def wireless_client_history(
    source: WirelessHistorySource,
    mac: str,
    vdom: str,
    hours: int,
) -> dict[str, Any]:
    normalized_mac = normalize_client_mac(mac)
    if not 1 <= hours <= 168:
        raise ValueError("Choose a time window from 1 hour to 7 days.")

    log_error = ""
    try:
        log_rows = source.logs(normalized_mac, vdom, hours)
    except FortiGateError as exc:
        log_rows = []
        log_error = str(exc)

    events = [
        _wireless_event(row, normalized_mac, source.label)
        for row in log_rows
        if _row_matches_mac(row, normalized_mac) and _row_is_wireless_history_signal(row)
    ]
    events = [event for event in events if event]
    events.sort(key=_event_sort_key)
    timeline_events = _timeline_events(events)

    live_error = ""
    try:
        live_rows = source.live_clients(normalized_mac, vdom)
    except FortiGateError as exc:
        live_rows = []
        live_error = str(exc)

    live_clients = [
        _live_client(row, normalized_mac, source.label)
        for row in live_rows
        if _row_matches_mac(row, normalized_mac)
    ]
    live_clients = [client for client in live_clients if client]

    timeline = _collapse_ap_timeline(timeline_events)
    return {
        "mac": normalized_mac,
        "vdom": vdom,
        "hours": hours,
        "source": source.label,
        "timeline": timeline,
        "log_row_count": len(log_rows),
        "raw_event_count": len(events),
        "omitted_unknown_ap_count": len(events) - len(timeline_events),
        "live_clients": live_clients,
        "log_error": log_error,
        "live_error": live_error,
        "ap_path": _ap_path(timeline),
    }


def _wireless_event(
    row: dict[str, Any],
    normalized_mac: str,
    source_label: str,
) -> dict[str, Any]:
    flattened = _flatten(row)
    details = _first(flattened, "msg", "message", "reason", "detail", "status") or ""
    ap = _ap_name(flattened, details) or "Unknown AP"
    time = _event_time(flattened)
    return {
        "time": time,
        "event": _first(flattened, "event", "action", "logdesc", "subtype", "type") or "wireless event",
        "ap": ap,
        "ssid": _first(flattened, "ssid", "vap", "vap_name") or "",
        "radio": _first(flattened, "radio", "radio_id", "wtp_radio", "band") or "",
        "channel": _first(flattened, "channel", "chan") or "",
        "ip": _first(flattened, "ip", "srcip", "client_ip") or "",
        "details": details,
        "mac": normalized_mac,
        "source": source_label,
        "sort_time": _parse_time(time),
    }


def _live_client(
    row: dict[str, Any],
    normalized_mac: str,
    source_label: str,
) -> dict[str, Any]:
    flattened = _flatten(row)
    details = _first(flattened, "msg", "message", "detail", "status") or ""
    return {
        "host": _first(flattened, "host", "hostname", "name", "user") or "",
        "ap": _ap_name(flattened, details) or "Unknown AP",
        "ssid": _first(flattened, "ssid", "vap", "vap_name") or "",
        "radio": _first(flattened, "radio", "radio_id", "wtp_radio", "band") or "",
        "channel": _first(flattened, "channel", "chan") or "",
        "ip": _first(flattened, "ip", "srcip", "client_ip") or "",
        "signal": _first(flattened, "signal", "rssi") or "",
        "mac": normalized_mac,
        "source": source_label,
    }


def _collapse_ap_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for event in events:
        if timeline and timeline[-1]["ap"] == event["ap"]:
            timeline[-1]["last_time"] = event["time"] or timeline[-1]["last_time"]
            timeline[-1]["event_count"] += 1
            timeline[-1]["events"].append(event)
            for field in ("ssid", "radio", "channel", "ip", "details", "event"):
                if event.get(field):
                    timeline[-1][field] = event[field]
            continue
        timeline.append(
            {
                "ap": event["ap"],
                "first_time": event["time"],
                "last_time": event["time"],
                "event_count": 1,
                "event": event.get("event", ""),
                "ssid": event.get("ssid", ""),
                "radio": event.get("radio", ""),
                "channel": event.get("channel", ""),
                "ip": event.get("ip", ""),
                "details": event.get("details", ""),
                "events": [event],
            }
        )
    return timeline


def _timeline_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    named_events = [event for event in events if event.get("ap") != "Unknown AP"]
    return named_events or events


def _ap_path(timeline: list[dict[str, Any]]) -> list[str]:
    return [item["ap"] for item in timeline if item.get("ap")]


def _row_matches_mac(row: dict[str, Any], normalized_mac: str) -> bool:
    flattened = _flatten(row)
    normalized_digits = normalized_mac.replace(":", "")
    for key, value in flattened.items():
        value_text = str(value)
        value_digits = re.sub(r"[^0-9A-Fa-f]", "", value_text).lower()
        if normalized_digits in value_digits:
            return True
        if "mac" not in key:
            continue
        try:
            if normalize_client_mac(value_text) == normalized_mac:
                return True
        except ValueError:
            continue
    return False


def _row_is_wireless_history_signal(row: dict[str, Any]) -> bool:
    flattened = _flatten(row)
    text = "".join(str(value).lower() for value in flattened.values())
    compact = re.sub(r"[^a-z0-9]+", "", text)
    return any(
        signal in compact
        for signal in (
            "assocreq",
            "associationrequest",
            "authenticationrequestfromwirelessstation",
            "authenticationresponsetowirelessstation",
            "wirelessclientauthenticated",
            "wirelessclientdeauthenticated",
            "wirelessclientdisassociated",
            "wirelessclientleftwtp",
            "wirelessclientipassigned",
        )
    )


def _flatten(value: Any, prefix: str = "") -> dict[str, str]:
    flattened: dict[str, str] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            child_key = f"{prefix}_{key}" if prefix else str(key)
            flattened.update(_flatten(item, child_key.lower().replace("-", "_")))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            flattened.update(_flatten(item, f"{prefix}_{index}"))
    elif value is not None:
        flattened[prefix.lower().replace("-", "_")] = str(value)
    return flattened


def _first(values: dict[str, str], *keys: str) -> str:
    for key in keys:
        normalized_key = key.lower().replace("-", "_")
        if values.get(normalized_key) not in (None, ""):
            return values[normalized_key]
    for key in keys:
        suffix = key.lower().replace("-", "_")
        for candidate, value in values.items():
            if candidate.endswith(f"_{suffix}") and value:
                return value
    return ""


def _event_sort_key(event: dict[str, Any]) -> tuple[datetime, str]:
    return (
        event.get("sort_time") if isinstance(event.get("sort_time"), datetime) else _parse_time(str(event.get("time") or "")),
        str(event.get("ap") or ""),
    )


def _event_time(values: dict[str, str]) -> str:
    date = _first(values, "date")
    time = _first(values, "time")
    if date and time:
        return f"{date} {time}"
    return _first(values, "datetime", "timestamp", "eventtime", "time", "date") or ""


def _ap_name(values: dict[str, str], details: str = "") -> str:
    direct = _first(
        values,
        "ap_name",
        "apname",
        "ap",
        "wtp_name",
        "wtpname",
        "wtp",
        "wtp_id",
        "wtpid",
        "ap_serial",
        "apserial",
        "ap_sn",
        "apsn",
        "ap_id",
        "apid",
        "fap",
        "fap_name",
        "fapname",
        "devid",
    )
    if direct:
        return direct
    message_ap = _ap_from_message(details)
    if message_ap:
        return message_ap
    bssid = _first(values, "bssid", "ap_bssid", "radio_bssid", "ssid_bssid")
    return f"BSSID {bssid}" if bssid else ""


def _ap_from_message(message: str) -> str:
    if not message:
        return ""
    patterns = (
        r"\b(?:FortiAP|AP|WTP|wtp|ap)\s*(?:name)?\s*[:=]\s*['\"]?([^,'\";\]\)]+)",
        r"\b(?:FortiAP|AP|WTP|wtp|ap)\s*\[([^\]]+)\]",
        r"\b(?:FortiAP|AP|WTP|wtp|ap)\s+['\"]([^'\"]+)['\"]",
        r"\b(?:FortiAP|AP|WTP|wtp)\s+([A-Za-z0-9_.:-]+)",
        r"\b(?:from|to|on)\s+(?:FortiAP|AP|WTP|wtp|ap)\s+['\"]?([^,'\";\]\)]+)",
        r"\b(?:ap|wtp)\(([^)]+)\)",
    )
    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
            if candidate:
                return candidate
    return ""


def _parse_time(value: str) -> datetime:
    value = value.strip()
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value[:19], pattern)
        except ValueError:
            continue
    if value.isdigit():
        timestamp = int(value)
        if timestamp > 10_000_000_000_000_000:
            timestamp //= 1_000_000_000
        elif timestamp > 10_000_000_000:
            timestamp //= 1_000
        try:
            return datetime.fromtimestamp(timestamp)
        except (OSError, ValueError):
            pass
    return datetime.min
