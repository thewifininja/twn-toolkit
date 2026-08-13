from __future__ import annotations

from collections.abc import Callable
from typing import Any


ReportPresentation = dict[str, Any]
PresentationBuilder = Callable[[dict[str, Any]], ReportPresentation]


def case_report_contents(
    events: list[dict[str, Any]], artifacts: list[dict[str, Any]]
) -> dict[str, Any]:
    """Resolve the saved report selection and its reusable presentations."""
    presentations = {
        str(event["id"]): event_report_presentation(event) for event in events
    }
    report_events = [
        event for event in events if event.get("report_placement") == "main"
    ]
    report_artifacts = [
        artifact
        for artifact in artifacts
        if artifact.get("report_placement") == "appendix"
    ]
    result_events = [
        event
        for event in report_events
        if presentations[str(event["id"])]["detail"]
    ]
    result_labels = {
        str(event["id"]): f"R-{index:02d}"
        for index, event in enumerate(result_events, start=1)
    }
    return {
        "event_presentations": presentations,
        "report_events": report_events,
        "report_artifacts": report_artifacts,
        "report_result_events": result_events,
        "report_result_labels": result_labels,
        "detailed_result_event_ids": {
            str(event["id"])
            for event in events
            if presentations[str(event["id"])]["detail"]
        },
    }


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


def _ping_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    facts = []
    _fact(facts, "Session", parameters.get("title"))
    if event.get("event_type") == "ping.session.started":
        _fact(facts, "Targets", metrics.get("target_count"))
        _fact(
            facts,
            "Interval",
            _unit(parameters.get("interval_seconds"), "seconds"),
        )
        _fact(
            facts,
            "Timeout",
            _unit(parameters.get("timeout_seconds"), "seconds"),
        )
        return {"facts": facts, "detail": None}

    _fact(facts, "Duration", _duration(parameters.get("duration_seconds")))
    _fact(facts, "Rounds", metrics.get("rounds"))
    _fact(facts, "Probes", metrics.get("probes_sent"))
    _fact(facts, "Replies", metrics.get("replies_received"))
    _fact(facts, "Response rate", _unit(metrics.get("response_rate"), "%"))
    _fact(
        facts,
        "Configuration revisions",
        parameters.get("configuration_revision_count"),
    )
    _fact(facts, "Retained samples", metrics.get("retained_samples"))
    if metrics.get("omitted_samples"):
        _fact(facts, "Earlier samples omitted", metrics.get("omitted_samples"))
    _fact(facts, "Ended by", _termination(parameters.get("termination")))
    evidence = _mapping(details.get("evidence"))
    _fact(facts, "Sample evidence", evidence.get("filename"))
    rows = []
    for raw_target in _sequence(details.get("target_summaries")):
        target = _mapping(raw_target)
        minimum = target.get("minimum_latency_ms")
        average = target.get("average_latency_ms")
        maximum = target.get("maximum_latency_ms")
        latency = "—"
        if average is not None:
            latency = (
                f"{_text(minimum)} / {_text(average)} / {_text(maximum)} ms"
            )
        rows.append(
            [
                _named_target(target, "label", "host"),
                _text(target.get("observation")),
                (
                    f"{_text(target.get('replies_received'))} / "
                    f"{_text(target.get('retained_probes'))}\n"
                    f"{_unit(target.get('response_rate'), '%')}"
                ),
                latency,
                _text(target.get("reply_interruptions")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            [
                "Target",
                "Observation",
                "Replies / retained probes",
                "Latency min / avg / max",
                "Reply interruptions",
            ],
            rows,
        )
        if rows
        else _metrics(
            [("Observation", "The session ended before any probes completed.")]
        ),
    }


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


def _duration(value: Any) -> str:
    try:
        seconds = max(0, int(round(float(value))))
    except (TypeError, ValueError):
        return ""
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes or hours:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def _termination(value: Any) -> str:
    return {
        "manual": "Operator stop",
        "case_closed": "Case closure",
        "lease_expired": "Browser lease expired",
        "error": "Monitor error",
    }.get(str(value or ""), _text(value))


_PRESENTATION_BUILDERS: dict[str, PresentationBuilder] = {
    "tools.ping": _ping_presentation,
    "tools.dns_response": _dns_presentation,
    "tools.port_scanner": _port_scan_presentation,
    "tools.traceroute": _traceroute_presentation,
    "tools.ntp_test": _ntp_presentation,
    "tools.path_mtu": _path_mtu_presentation,
    "tools.speed_test": _speed_test_presentation,
}
