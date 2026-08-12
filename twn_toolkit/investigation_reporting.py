from __future__ import annotations

from collections.abc import Callable
from typing import Any


ReportPresentation = dict[str, Any]
PresentationBuilder = Callable[[dict[str, Any]], ReportPresentation]


def event_report_presentation(event: dict[str, Any]) -> ReportPresentation:
    """Build deterministic report data from a retained case event."""
    builder = _PRESENTATION_BUILDERS.get(str(event.get("tool_id", "")))
    if builder is None:
        return {"facts": [], "detail": None}
    return builder(event)


def _dns_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    facts = []
    _fact(facts, "Record type", parameters.get("record_type"))
    _fact(facts, "Successful", metrics.get("successful"))
    _fact(facts, "Failed", metrics.get("failed"))
    _fact(facts, "Average", _unit(metrics.get("average_ms"), "ms"))
    _fact(facts, "Queries", metrics.get("completed_queries"))
    _fact(facts, "Success rate", _unit(metrics.get("success_rate"), "%"))
    _fact(facts, "Achieved load", _unit(metrics.get("achieved_qps"), "QPS"))

    results = _sequence(details.get("results"))
    if results:
        rows = []
        for raw_result in results:
            result = _mapping(raw_result)
            rows.append(
                [
                    _named_target(result, "host_label", "host"),
                    _named_target(result, "server_label", "server"),
                    _text(result.get("record_type")),
                    _text(result.get("status")),
                    "\n".join(_text(answer) for answer in _sequence(result.get("answers")))
                    or "—",
                    _unit(result.get("response_ms"), "ms"),
                ]
            )
        return {
            "facts": facts,
            "detail": _table(
                ["Query", "Resolver", "Type", "Outcome", "Answers", "Time"],
                rows,
            ),
        }

    load = _mapping(details.get("load_result"))
    if load:
        return {
            "facts": facts,
            "detail": _metrics(
                [
                    ("Queries", load.get("completed_queries")),
                    ("Success rate", _unit(load.get("success_rate"), "%")),
                    ("Achieved load", _unit(load.get("achieved_qps"), "QPS")),
                    ("Elapsed", _unit(load.get("elapsed_seconds"), "seconds")),
                ]
            ),
        }
    return {"facts": facts, "detail": None}


def _port_scan_presentation(event: dict[str, Any]) -> ReportPresentation:
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    facts = []
    for label, key in (
        ("Tested", "combinations"),
        ("Open", "open"),
        ("Closed", "closed"),
        ("Timed out", "timeout"),
        ("Errors", "error"),
    ):
        _fact(facts, label, metrics.get(key))
    rows = []
    for raw_result in _sequence(details.get("results")):
        result = _mapping(raw_result)
        rows.append(
            [
                _named_target(result, "label", "host"),
                _text(result.get("port")),
                _text(result.get("service")),
                _text(result.get("status")),
                _unit(result.get("elapsed_ms"), "ms"),
                _text(result.get("detail")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Host", "Port", "Service", "Status", "Response", "Detail"], rows
        )
        if rows
        else None,
    }


def _traceroute_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    result = _mapping(details.get("result"))
    facts = []
    _fact(facts, "Destination", result.get("host") or details.get("host"))
    _fact(facts, "Method", result.get("method") or parameters.get("method"))
    _fact(facts, "Hops", metrics.get("hop_count"))
    if "reached" in metrics:
        _fact(facts, "Result", "Reached" if metrics.get("reached") else "Not reached")
    rows = []
    for raw_hop in _sequence(result.get("hops") or details.get("hops")):
        hop = _mapping(raw_hop)
        address = ", ".join(_text(value) for value in _sequence(hop.get("addresses")))
        name = _optional_text(hop.get("name"))
        identity = name
        if name and address:
            identity = f"{name}\n{address}"
        elif address:
            identity = address
        rows.append(
            [
                _text(hop.get("number")),
                identity or "No response",
                _unit(hop.get("average_ms"), "ms") or "—",
                _unit(hop.get("loss_percent"), "%") or "—",
                " · ".join(_text(value) for value in _sequence(hop.get("latencies_ms")))
                or "—",
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Hop", "Responder", "Average", "Loss", "Probe times"], rows
        )
        if rows
        else None,
    }


def _ntp_presentation(event: dict[str, Any]) -> ReportPresentation:
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    facts = []
    _fact(facts, "Servers", metrics.get("server_count"))
    _fact(facts, "Synchronized", metrics.get("synchronized"))
    _fact(facts, "Samples", metrics.get("sample_count"))
    rows = []
    for raw_result in _sequence(details.get("results")):
        result = _mapping(raw_result)
        rows.append(
            [
                _named_target(result, "label", "host"),
                "Synchronized" if result.get("synchronized") else _text(result.get("status")),
                _signed_unit(result.get("offset_ms"), "ms") or "—",
                _unit(result.get("delay_ms"), "ms") or "—",
                _unit(result.get("jitter_ms"), "ms") or "—",
                _text(result.get("stratum")),
                f"{_text(result.get('successful_samples'))}/{_text(result.get('total_samples'))}",
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Server", "State", "Offset", "Delay", "Jitter", "Stratum", "Samples"],
            rows,
        )
        if rows
        else None,
    }


def _path_mtu_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    result = _mapping(details.get("result"))
    facts = []
    _fact(facts, "Destination", result.get("host") or details.get("host"))
    _fact(facts, "Family", result.get("family") or parameters.get("family"))
    _fact(facts, "Path MTU", _unit(metrics.get("mtu"), "bytes"))
    _fact(facts, "Probes", metrics.get("probe_count"))
    rows = []
    for raw_probe in _sequence(result.get("probes")):
        probe = _mapping(raw_probe)
        rows.append(
            [
                _text(probe.get("mtu")),
                _text(probe.get("payload")),
                "Passed" if probe.get("success") else "Failed",
                _text(probe.get("detail")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(["MTU", "Payload", "Result", "Probe output"], rows)
        if rows
        else None,
    }


def _speed_test_presentation(event: dict[str, Any]) -> ReportPresentation:
    metrics = _mapping(event.get("metrics"))
    facts = []
    _fact(facts, "Download", _unit(metrics.get("download_mbps"), "Mbps"))
    _fact(facts, "Upload", _unit(metrics.get("upload_mbps"), "Mbps"))
    _fact(facts, "Latency", _unit(metrics.get("latency_ms"), "ms"))
    _fact(facts, "Jitter", _unit(metrics.get("jitter_ms"), "ms"))
    return {"facts": facts, "detail": None}


def _table(columns: list[str], rows: list[list[str]]) -> ReportPresentation:
    return {"kind": "table", "columns": columns, "rows": rows}


def _metrics(values: list[tuple[str, Any]]) -> ReportPresentation:
    metrics = []
    for label, value in values:
        if value is not None and value != "":
            metrics.append({"label": label, "value": _text(value)})
    return {"kind": "metrics", "values": metrics}


def _fact(facts: list[dict[str, str]], label: str, value: Any) -> None:
    if value is not None and value != "":
        facts.append({"label": label, "value": _text(value)})


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _named_target(value: dict[str, Any], label_key: str, target_key: str) -> str:
    label = _optional_text(value.get(label_key))
    target = _optional_text(value.get(target_key))
    return f"{label}\n{target}" if label and target else label or target or "—"


def _unit(value: Any, unit: str) -> str:
    return f"{_text(value)} {unit}" if value is not None and value != "" else ""


def _signed_unit(value: Any, unit: str) -> str:
    if value is None or value == "":
        return ""
    try:
        rendered = f"{float(value):+.3f}"
    except (TypeError, ValueError):
        rendered = _text(value)
    return f"{rendered} {unit}"


def _text(value: Any) -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _optional_text(value: Any) -> str:
    return "" if value is None or value == "" else str(value)


_PRESENTATION_BUILDERS: dict[str, PresentationBuilder] = {
    "tools.dns_response": _dns_presentation,
    "tools.port_scanner": _port_scan_presentation,
    "tools.traceroute": _traceroute_presentation,
    "tools.ntp_test": _ntp_presentation,
    "tools.path_mtu": _path_mtu_presentation,
    "tools.speed_test": _speed_test_presentation,
}
