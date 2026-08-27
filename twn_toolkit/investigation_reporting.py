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


def _snmp_presentation(event: dict[str, Any]) -> ReportPresentation:
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    facts = []
    if str(event.get("event_type", "")).startswith("snmp.monitor."):
        _fact(facts, "Session", _mapping(event.get("parameters")).get("title"))
        if event.get("event_type") == "snmp.monitor.started":
            _fact(facts, "Interfaces", metrics.get("interface_count"))
            _fact(
                facts,
                "Interval",
                _unit(_mapping(event.get("parameters")).get("interval_seconds"), "seconds"),
            )
            return {"facts": facts, "detail": None}
        parameters = _mapping(event.get("parameters"))
        _fact(facts, "Duration", _duration(parameters.get("duration_seconds")))
        _fact(facts, "Interfaces", metrics.get("interface_count"))
        _fact(facts, "Polls", metrics.get("polls"))
        _fact(facts, "Successful", metrics.get("successful_polls"))
        _fact(facts, "Failed", metrics.get("failed_polls"))
        _fact(facts, "Rate measurements", metrics.get("rate_measurements"))
        _fact(facts, "Ended by", _termination(parameters.get("termination")))
        evidence = _mapping(details.get("evidence"))
        _fact(facts, "Sample evidence", evidence.get("filename"))
        monitor_rows = []
        for raw_target in _sequence(details.get("target_summaries")):
            target = _mapping(raw_target)
            monitor_rows.append(
                [
                    _named_target(target, "host_name", "host"),
                    _text(target.get("interface_label")),
                    _text(target.get("final_oper_status")),
                    _rate(target.get("average_download_bps")),
                    _rate(target.get("peak_download_bps")),
                    _rate(target.get("average_upload_bps")),
                    _rate(target.get("peak_upload_bps")),
                    (
                        f"{_text(target.get('successful_samples'))} / "
                        f"{_text(target.get('failed_samples'))}"
                    ),
                ]
            )
        return {
            "facts": facts,
            "detail": _table(
                [
                    "Device", "Interface", "Final state", "Avg down", "Peak down",
                    "Avg up", "Peak up", "Successful / failed",
                ],
                monitor_rows,
            )
            if monitor_rows
            else _metrics([("Observation", "No interface polls completed.")]),
        }
    _fact(facts, "Polls", metrics.get("poll_count"))
    _fact(facts, "Successful", metrics.get("successful_polls"))
    _fact(facts, "Failed", metrics.get("failed_polls"))
    _fact(facts, "Values", metrics.get("returned_values"))
    rows = []
    for raw_result in _sequence(details.get("results")):
        result = _mapping(raw_result)
        host = _named_target(result, "host_name", "host")
        profile = _text(result.get("profile_name"))
        result_rows = _sequence(result.get("rows"))
        if not result_rows:
            rows.append(
                [
                    host,
                    profile,
                    "—",
                    "—",
                    _text(result.get("status")),
                    _text(result.get("error")),
                    _unit(result.get("elapsed_ms"), "ms"),
                ]
            )
        for raw_row in result_rows:
            row = _mapping(raw_row)
            rows.append(
                [
                    host,
                    profile,
                    _text(row.get("label") or row.get("oid")),
                    _text(row.get("value")),
                    _text(row.get("status") or result.get("status")),
                    _text(row.get("error")),
                    _unit(row.get("response_ms"), "ms"),
                ]
            )
    return {
        "facts": facts,
        "detail": _table(
            ["Host", "OID profile", "Value", "Result", "Status", "Error", "Time"],
            rows,
        )
        if rows
        else None,
    }


def _certificate_presentation(event: dict[str, Any]) -> ReportPresentation:
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    result = _mapping(details.get("result"))
    facts = []
    _fact(facts, "Target", _host_port(result.get("host"), result.get("port")))
    _fact(facts, "Overall", _validity(metrics.get("overall_valid")))
    _fact(facts, "System trust", _validity(metrics.get("system_trust_valid")))
    _fact(facts, "Hostname", _validity(metrics.get("hostname_valid")))
    _fact(facts, "Chain order", _validity(metrics.get("chain_order_valid")))
    _fact(facts, "Presented", metrics.get("presented_certificates"))
    _fact(facts, "Response", _unit(metrics.get("elapsed_ms"), "ms"))
    tls = _mapping(result.get("tls"))
    _fact(facts, "TLS", tls.get("version"))
    _fact(facts, "Cipher", tls.get("cipher"))
    rows = []
    for raw_certificate in _sequence(result.get("certificates")):
        certificate = _mapping(raw_certificate)
        expires = str(certificate.get("not_after") or "").replace("T", " ")
        if expires.endswith("+00:00"):
            expires = f"{expires[:-6]} UTC"
        rows.append(
            [
                _text(certificate.get("role")),
                _text(certificate.get("common_name") or certificate.get("subject")),
                _text(certificate.get("issuer")),
                (
                    f"{_text(expires)}\n"
                    f"{_text(certificate.get('days_remaining'))} days remaining"
                ),
                _text(certificate.get("sha256_fingerprint")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Certificate role", "Subject", "Issuer", "Validity", "SHA-256"], rows
        )
        if rows
        else None,
    }


def _dhcp_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    targets = _mapping(event.get("targets"))
    facts = []
    _fact(facts, "Interface", targets.get("interface"))
    _fact(facts, "Client MAC", targets.get("client_mac"))
    _fact(facts, "Requested options", len(_sequence(parameters.get("requested_options"))))
    _fact(facts, "Offers", metrics.get("offer_count"))
    rows = []
    for raw_offer in _sequence(details.get("offers")):
        offer = _mapping(raw_offer)
        options = []
        for raw_option in _sequence(offer.get("options")):
            option = _mapping(raw_option)
            options.append(f"{_text(option.get('name') or option.get('code'))}: {_text(option.get('value'))}")
        rows.append(
            [
                _text(offer.get("offered_address")),
                _text(offer.get("server_address")),
                _unit(offer.get("response_time_ms"), "ms"),
                _text(offer.get("relay_address")),
                "\n".join(options) or "—",
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Offered address", "Server", "Response", "Relay", "Options"], rows
        )
        if rows
        else _metrics([("Observation", "No DHCP offers were received.")]),
    }


def _radius_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    facts = []
    _fact(facts, "Protocol", parameters.get("protocol"))
    _fact(facts, "Attempts", metrics.get("attempt_count"))
    _fact(facts, "Successful", metrics.get("successful_attempts"))
    _fact(facts, "Failed", metrics.get("failed_attempts"))
    rows = []
    for raw_result in _sequence(details.get("results")):
        result = _mapping(raw_result)
        attributes = [
            f"{_text(_mapping(attribute).get('name'))}: {_text(_mapping(attribute).get('value'))}"
            for attribute in _sequence(result.get("attributes"))
        ]
        rows.append(
            [
                _named_target(result, "server_name", "server"),
                _text(result.get("port")),
                _text(result.get("status")),
                _unit(result.get("response_ms"), "ms"),
                "\n".join(attributes) or "—",
                _text(result.get("error")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Server", "Port", "Response", "Time", "Reply attributes", "Error"], rows
        )
        if rows
        else None,
    }


def _wol_presentation(event: dict[str, Any]) -> ReportPresentation:
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    outcome = _mapping(details.get("outcome"))
    facts = []
    _fact(facts, "Devices", metrics.get("device_count"))
    _fact(facts, "Packets sent", metrics.get("packets_sent"))
    _fact(facts, "Send failures", metrics.get("send_failures"))
    _fact(facts, "Confirmed awake", metrics.get("confirmed_awake"))
    _fact(facts, "Elapsed", _unit(metrics.get("elapsed_ms"), "ms"))
    rows = []
    for raw_result in _sequence(outcome.get("results")):
        result = _mapping(raw_result)
        rows.append(
            [
                _named_target(result, "name", "host"),
                _text(result.get("mac")),
                _text(result.get("send_status")),
                _text(result.get("packets_sent")),
                _text(result.get("verification")),
                _unit(result.get("latency_ms"), "ms"),
                _text(result.get("send_error")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Device", "MAC", "Send", "Packets", "Verification", "Latency", "Error"],
            rows,
        )
        if rows
        else None,
    }


def _iperf_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    if str(event.get("event_type", "")).startswith("iperf.server."):
        targets = _mapping(event.get("targets"))
        facts = []
        _fact(facts, "Listener", _host_port(targets.get("bind_address"), targets.get("port")))
        if event.get("event_type") == "iperf.server.started":
            return {"facts": facts, "detail": None}
        _fact(facts, "Duration", _duration(parameters.get("duration_seconds")))
        _fact(facts, "Completed tests", metrics.get("test_count"))
        _fact(facts, "Transferred", _unit(metrics.get("transferred_bytes"), "bytes"))
        _fact(facts, "Peak", _unit(metrics.get("peak_mbps"), "Mbps"))
        _fact(facts, "Results evidence", _mapping(details.get("evidence")).get("filename"))
        rows = []
        for raw_result in _sequence(details.get("results")):
            server_result = _mapping(raw_result)
            rows.append(
                [
                    _host_port(server_result.get("source_ip"), server_result.get("source_port")),
                    _text(server_result.get("protocol")),
                    _text(server_result.get("direction")),
                    _unit(server_result.get("summary_megabits_per_second"), "Mbps"),
                    _text(server_result.get("transferred_display")),
                ]
            )
        return {
            "facts": facts,
            "detail": _table(
                ["Client", "Protocol", "Direction", "Rate", "Transferred"], rows
            )
            if rows
            else _metrics([("Observation", "No client tests completed.")]),
        }
    result = _mapping(details.get("result"))
    connection = _mapping(result.get("connection"))
    facts = []
    _fact(facts, "Protocol", result.get("protocol") or parameters.get("protocol"))
    _fact(facts, "Direction", result.get("direction"))
    _fact(facts, "Remote", _host_port(connection.get("remote_host"), connection.get("remote_port")))
    _fact(facts, "Duration", _unit(parameters.get("duration_seconds"), "seconds"))
    _fact(facts, "Streams", parameters.get("parallel_streams"))
    _fact(facts, "Transferred", result.get("transferred_display"))
    _fact(facts, "Sender", _unit(metrics.get("sender_mbps"), "Mbps"))
    _fact(facts, "Receiver", _unit(metrics.get("receiver_mbps"), "Mbps"))
    _fact(facts, "Retransmits", metrics.get("retransmits"))
    _fact(facts, "Lost packets", metrics.get("lost_packets"))
    _fact(facts, "Jitter", _unit(metrics.get("jitter_ms"), "ms"))
    rows = []
    for index, raw_interval in enumerate(_sequence(result.get("intervals")), start=1):
        interval = _mapping(raw_interval)
        rows.append(
            [
                _text(index),
                _unit(interval.get("start"), "s"),
                _unit(interval.get("end"), "s"),
                _unit(interval.get("megabits_per_second"), "Mbps"),
                _text(interval.get("bytes_display")),
                _text(interval.get("retransmits")),
                _unit(interval.get("jitter_ms"), "ms"),
                _unit(interval.get("lost_percent"), "%"),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Interval", "Start", "End", "Rate", "Transferred", "Retransmits", "Jitter", "Loss"],
            rows,
        )
        if rows
        else None,
    }


def _multicast_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    result = _mapping(details.get("result"))
    facts = []
    _fact(facts, "Mode", result.get("mode") or parameters.get("mode"))
    _fact(facts, "Group", _host_port(result.get("group"), result.get("port")))
    _fact(facts, "Membership", result.get("membership") or parameters.get("membership"))
    _fact(facts, "Packets sent", metrics.get("packets_sent"))
    _fact(facts, "Packets received", metrics.get("packets_received"))
    _fact(facts, "Packets lost", metrics.get("packets_lost"))
    _fact(facts, "Loss", _unit(metrics.get("loss_percent"), "%"))
    _fact(facts, "Average rate", _unit(metrics.get("average_mbps"), "Mbps"))
    _fact(facts, "Jitter", _unit(metrics.get("jitter_ms"), "ms"))
    rows = []
    for raw_source in _sequence(result.get("sources")):
        source = _mapping(raw_source)
        rows.append(
            [
                _host_port(source.get("address"), source.get("port")),
                _text(source.get("packets")),
                _text(source.get("bytes")),
                _unit(source.get("first_seen_seconds"), "s"),
                _unit(source.get("last_seen_seconds"), "s"),
                _text(source.get("expected")),
            ]
        )
    for raw_stream in _sequence(result.get("rtp_streams")):
        stream = _mapping(raw_stream)
        rows.append(
            [
                f"RTP {stream.get('ssrc', '')}",
                _text(stream.get("packets")),
                "—",
                "—",
                _unit(stream.get("interarrival_jitter_ms"), "ms jitter"),
                f"missing {stream.get('observed_missing', 0)}",
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Source / stream", "Packets", "Bytes", "First", "Last / jitter", "Expected / loss"],
            rows,
        )
        if rows
        else None,
    }


def _syslog_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    targets = _mapping(event.get("targets"))
    facts = []
    _fact(facts, "Mode", parameters.get("mode"))
    _fact(facts, "Endpoint", _host_port(targets.get("host"), targets.get("port")))
    _fact(facts, "Protocol", parameters.get("protocol"))
    _fact(facts, "Messages", metrics.get("message_count"))
    _fact(facts, "Bytes", metrics.get("byte_count"))
    _fact(facts, "Facility", parameters.get("facility"))
    _fact(facts, "Severity", parameters.get("severity"))
    _fact(facts, "Duration", _unit(parameters.get("duration_seconds"), "seconds"))
    _fact(facts, "Generated evidence", _mapping(details.get("evidence")).get("filename"))
    rows = [
        [
            _host_port(_mapping(source).get("source"), _mapping(source).get("port")),
            _text(_mapping(source).get("messages")),
        ]
        for source in _sequence(details.get("sources"))
    ]
    return {
        "facts": facts,
        "detail": _table(["Source", "Messages"], rows) if rows else None,
    }


def _api_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    result = _mapping(details.get("result"))
    targets = _mapping(event.get("targets"))
    facts = []
    _fact(facts, "Method", parameters.get("method"))
    _fact(facts, "Origin", targets.get("origin"))
    _fact(facts, "Status", metrics.get("status"))
    _fact(facts, "Response", _unit(metrics.get("elapsed_ms"), "ms"))
    _fact(facts, "Response bytes", metrics.get("response_bytes"))
    _fact(facts, "Truncated", metrics.get("response_truncated"))
    _fact(facts, "TLS verification", parameters.get("verify_tls"))
    _fact(facts, "Resolved addresses", ", ".join(_text(value) for value in _sequence(result.get("resolved_addresses"))))
    _fact(facts, "Request headers", ", ".join(_text(value) for value in _sequence(parameters.get("request_header_names"))))
    _fact(facts, "Response headers", ", ".join(_text(value) for value in _sequence(result.get("response_header_names"))))
    _fact(facts, "Request body", _unit(parameters.get("request_body_bytes"), "bytes (content omitted)"))
    return {"facts": facts, "detail": None}


def _packet_replay_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    plan = _mapping(details.get("plan"))
    targets = _mapping(event.get("targets"))
    facts = []
    _fact(facts, "Interface", targets.get("interface"))
    _fact(facts, "Frames sent", metrics.get("frames_sent"))
    _fact(facts, "Frames attempted", metrics.get("frames_attempted"))
    _fact(facts, "Total bytes", metrics.get("total_bytes"))
    _fact(facts, "Elapsed", _unit(metrics.get("elapsed_seconds"), "seconds"))
    _fact(facts, "Protocol", plan.get("protocol"))
    _fact(facts, "Source MAC", plan.get("source_mac"))
    _fact(facts, "Destination MAC", plan.get("destination_mac"))
    _fact(facts, "VLAN action", parameters.get("vlan_action"))
    _fact(facts, "Repeat count", parameters.get("repeat_count"))
    rows = [
        [_text(index), _text(detail)]
        for index, detail in enumerate(_sequence(plan.get("details")), start=1)
    ]
    return {
        "facts": facts,
        "detail": _table(["#", "Frame detail"], rows) if rows else None,
    }


def _lldp_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    targets = _mapping(event.get("targets"))
    facts = []
    _fact(facts, "Interface", targets.get("interface"))
    _fact(facts, "Persona", parameters.get("persona"))
    _fact(facts, "Preset", parameters.get("preset"))
    _fact(facts, "Interval", _unit(parameters.get("interval_seconds"), "seconds"))
    _fact(facts, "Duration limit", _unit(parameters.get("duration_minutes"), "minutes"))
    _fact(facts, "Frames sent", metrics.get("frames_sent"))
    _fact(facts, "Neighbors", metrics.get("neighbor_count"))
    rows = []
    for raw_neighbor in _sequence(details.get("neighbors")):
        neighbor = _mapping(raw_neighbor)
        rows.append(
            [
                _text(neighbor.get("interface")),
                _text(neighbor.get("system_name") or neighbor.get("chassis_id")),
                _text(neighbor.get("port_description") or neighbor.get("port_id")),
                ", ".join(_text(value) for value in _sequence(neighbor.get("management_addresses"))),
                ", ".join(_text(value) for value in _sequence(neighbor.get("capabilities"))),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Interface", "Neighbor", "Port", "Management", "Capabilities"], rows
        )
        if rows
        else None,
    }


def _packet_capture_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    targets = _mapping(event.get("targets"))
    facts = []
    _fact(facts, "Interface", targets.get("interface"))
    _fact(facts, "Filter", parameters.get("capture_filter") or "No capture filter")
    _fact(facts, "Duration limit", _unit(parameters.get("duration_limit_seconds"), "seconds"))
    _fact(facts, "Packet limit", parameters.get("packet_limit"))
    _fact(facts, "Size limit", _unit(parameters.get("size_limit_mib"), "MiB"))
    if event.get("event_type") == "packet_capture.started":
        return {"facts": facts, "detail": None}
    _fact(facts, "Packets captured", metrics.get("packet_count"))
    _fact(facts, "Capture size", _unit(metrics.get("size_bytes"), "bytes"))
    _fact(facts, "Elapsed", _unit(metrics.get("elapsed_seconds"), "seconds"))
    _fact(facts, "Termination", details.get("termination_reason"))
    _fact(facts, "PCAP evidence", _mapping(details.get("evidence")).get("filename"))
    return {"facts": facts, "detail": None}


def _ssh_presentation(event: dict[str, Any]) -> ReportPresentation:
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    facts = []
    _fact(facts, "Hosts", metrics.get("host_count"))
    _fact(facts, "Successful", metrics.get("successful_hosts"))
    _fact(facts, "Failed", metrics.get("failed_hosts"))
    _fact(facts, "Rendered commands", metrics.get("rendered_command_count"))
    _fact(facts, "Command output", _mapping(details.get("evidence")).get("filename"))
    rows = []
    for raw_result in _sequence(details.get("results")):
        result = _mapping(raw_result)
        rows.append(
            [
                _named_target(result, "host_label", "host"),
                _text(result.get("status")),
                _text(result.get("timed_out_command")),
                _text(result.get("error")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(["Host", "Status", "Timed-out command", "Error"], rows)
        if rows
        else None,
    }


def _remote_terminal_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    targets = _mapping(event.get("targets"))
    facts = []
    _fact(facts, "Session", parameters.get("title"))
    _fact(
        facts,
        "Remote",
        _host_port(targets.get("host"), targets.get("port")),
    )
    _fact(facts, "Protocol", parameters.get("protocol"))
    _fact(facts, "Remote user", parameters.get("remote_username"))
    if event.get("event_type") == "remote_terminal.session.started":
        _fact(
            facts,
            "Transcript",
            "Enabled" if parameters.get("transcript_enabled") else "Not retained",
        )
        return {"facts": facts, "detail": None}
    _fact(facts, "Duration", _duration(parameters.get("duration_seconds")))
    _fact(facts, "Ended by", _termination(parameters.get("termination")))
    _fact(facts, "Output", _unit(metrics.get("output_bytes"), "bytes"))
    if metrics.get("output_truncated"):
        _fact(facts, "Retention limit", "Transcript was truncated")
    _fact(facts, "Transcript evidence", _mapping(details.get("evidence")).get("filename"))
    _fact(facts, "Error", details.get("error"))
    return {"facts": facts, "detail": None}


def _transfer_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    facts = []
    _fact(facts, "Protocol", parameters.get("protocol"))
    _fact(facts, "Output", parameters.get("output_mode"))
    _fact(facts, "Transfers", metrics.get("transfer_count"))
    _fact(facts, "Successful", metrics.get("successful_transfers"))
    _fact(facts, "Failed", metrics.get("failed_transfers"))
    _fact(facts, "Transferred", _unit(metrics.get("transferred_bytes"), "bytes"))
    _fact(facts, "Result manifest", _mapping(details.get("evidence")).get("filename"))
    rows = []
    for raw_result in _sequence(details.get("results")):
        result = _mapping(raw_result)
        rows.append(
            [
                _named_target(result, "host_label", "host"),
                _text(result.get("remote_path")),
                _text(result.get("status")),
                _text(result.get("filename") or result.get("stored_path")),
                _unit(result.get("size"), "bytes"),
                _text(result.get("error")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["Host", "Remote path", "Status", "Retained as", "Size", "Error"], rows
        )
        if rows
        else None,
    }


def _wireless_history_presentation(event: dict[str, Any]) -> ReportPresentation:
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    result = _mapping(_mapping(event.get("details")).get("result"))
    facts = []
    _fact(facts, "Profile", parameters.get("profile"))
    _fact(facts, "VDOM", parameters.get("VDOM"))
    _fact(facts, "Time window", _unit(parameters.get("hours"), "hours"))
    _fact(facts, "Matching events", metrics.get("matching_events"))
    _fact(facts, "AP transitions", metrics.get("AP_transitions"))
    _fact(facts, "Currently visible", metrics.get("live_clients"))
    _fact(facts, "AP path", " → ".join(_text(item) for item in _sequence(result.get("ap_path"))))
    rows = []
    for raw_item in _sequence(result.get("timeline")):
        item = _mapping(raw_item)
        rows.append(
            [
                _text(item.get("first_time")),
                _text(item.get("last_time")),
                _text(item.get("ap")),
                _text(item.get("event_count")),
                f"{_text(item.get('ssid'))}\n{_text(item.get('ip'))}",
                _text(item.get("details") or item.get("event")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(
            ["First seen", "Last seen", "AP", "#", "Network / client IP", "Detail"],
            rows,
        )
        if rows
        else None,
    }


def _ip_snapshot_presentation(event: dict[str, Any]) -> ReportPresentation:
    targets = _mapping(event.get("targets"))
    families = _mapping(event.get("parameters"))
    labels = {
        "toolkit_facing": "Address seen by toolkit",
        "browser_public": "Browser public address",
        "server_public": "Toolkit server public address",
    }
    rows = [
        [labels[key], _text(value), _text(families.get(key))]
        for key, value in targets.items()
        if key in labels
    ]
    return {
        "facts": [],
        "detail": _table(["Observation", "Address", "Family"], rows) if rows else None,
    }


def _subnet_presentation(event: dict[str, Any]) -> ReportPresentation:
    targets = _mapping(event.get("targets"))
    details = _mapping(event.get("details"))
    metrics = _mapping(event.get("metrics"))
    facts = []
    _fact(facts, "Parent networks", "\n".join(_text(item) for item in _sequence(targets.get("parent_networks"))))
    _fact(facts, "Excluded networks", "\n".join(_text(item) for item in _sequence(targets.get("excluded_networks"))))
    _fact(facts, "Remaining networks", metrics.get("remaining_network_count"))
    rows = [
        [_text(index), _text(network)]
        for index, network in enumerate(_sequence(details.get("remaining_networks")), start=1)
    ]
    return {
        "facts": facts,
        "detail": _table(["#", "Remaining network"], rows) if rows else None,
    }


def _external_action_presentation(event: dict[str, Any]) -> ReportPresentation:
    targets = _mapping(event.get("targets"))
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    evidence = _mapping(_mapping(event.get("details")).get("evidence"))
    facts = []
    _fact(facts, "Resource", targets.get("resource_name"))
    _fact(facts, "Profile", targets.get("profile"))
    _fact(facts, "External action", parameters.get("external_action"))
    _fact(facts, "Format", parameters.get("format"))
    for label, key in (
        ("Outcome", "outcome"),
        ("Records", "record count"),
        ("Records", "record_count"),
        ("Requested", "requested object count"),
        ("Successful", "successful object count"),
        ("Failed", "failed object count"),
        ("Completed moves", "completed move count"),
        ("Export size", "export_size_bytes"),
    ):
        _fact(facts, label, metrics.get(key))
    _fact(facts, "Evidence", evidence.get("filename"))
    rows = []
    for raw_change in _sequence(metrics.get("changes")):
        change = _mapping(raw_change)
        rows.append(
            [
                _text(change.get("field")),
                _text(change.get("before")),
                _text(change.get("after")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(["Changed field", "Before", "After"], rows) if rows else None,
    }


def _automation_run_presentation(event: dict[str, Any]) -> ReportPresentation:
    targets = _mapping(event.get("targets"))
    parameters = _mapping(event.get("parameters"))
    metrics = _mapping(event.get("metrics"))
    details = _mapping(event.get("details"))
    evidence = _mapping(details.get("evidence"))
    facts = []
    _fact(facts, "Automation", targets.get("automation"))
    _fact(facts, "Trigger", parameters.get("trigger"))
    _fact(facts, "Results", metrics.get("result_count"))
    _fact(facts, "Successful", metrics.get("successful_results"))
    _fact(facts, "Failed", metrics.get("failed_results"))
    _fact(facts, "Collected ZIP", evidence.get("filename"))
    rows = []
    for raw_result in _sequence(details.get("results")):
        result = _mapping(raw_result)
        rows.append(
            [
                _text(result.get("stage")),
                _text(result.get("action")),
                _text(result.get("status")),
                _text(result.get("summary")),
            ]
        )
    return {
        "facts": facts,
        "detail": _table(["Stage", "Action", "Status", "Summary"], rows) if rows else None,
    }


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


def _host_port(host: Any, port: Any) -> str:
    if host in (None, ""):
        return ""
    return f"{_text(host)}:{_text(port)}" if port not in (None, "") else _text(host)


def _validity(value: Any) -> str:
    if value is None or value == "":
        return ""
    return "Valid" if bool(value) else "Needs attention"


def _rate(value: Any) -> str:
    if value is None or value == "":
        return "—"
    try:
        rate = float(value)
    except (TypeError, ValueError):
        return _text(value)
    for scale, unit in (
        (1_000_000_000_000, "Tbps"),
        (1_000_000_000, "Gbps"),
        (1_000_000, "Mbps"),
        (1_000, "Kbps"),
    ):
        if rate >= scale:
            return f"{rate / scale:.2f} {unit}"
    return f"{rate:.0f} bps"


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
        "remote_closed": "Remote host closed the shell",
        "idle_timeout": "Eight-hour inactivity limit",
        "toolkit_restart": "Toolkit restart",
        "connection_error": "Connection error",
    }.get(str(value or ""), _text(value))


_PRESENTATION_BUILDERS: dict[str, PresentationBuilder] = {
    "tools.ping": _ping_presentation,
    "tools.dns_response": _dns_presentation,
    "tools.port_scanner": _port_scan_presentation,
    "tools.traceroute": _traceroute_presentation,
    "tools.ntp_test": _ntp_presentation,
    "tools.path_mtu": _path_mtu_presentation,
    "tools.speed_test": _speed_test_presentation,
    "tools.snmp_test": _snmp_presentation,
    "tools.certificate_inspector": _certificate_presentation,
    "tools.dhcp_discover": _dhcp_presentation,
    "tools.radius_test": _radius_presentation,
    "tools.wake_on_lan": _wol_presentation,
    "tools.iperf3": _iperf_presentation,
    "tools.multicast": _multicast_presentation,
    "tools.syslog_receiver": _syslog_presentation,
    "tools.api_request": _api_presentation,
    "tools.packet_replay": _packet_replay_presentation,
    "tools.lldp_lab": _lldp_presentation,
    "tools.packet_capture": _packet_capture_presentation,
    "tools.multi_ssh": _ssh_presentation,
    "tools.remote_terminal": _remote_terminal_presentation,
    "tools.multi_sftp": _transfer_presentation,
    "fortigate.wireless_client_history": _wireless_history_presentation,
    "fortigate.rename_aps": _external_action_presentation,
    "fortigate.export_aps": _external_action_presentation,
    "fortigate.export_wireless_clients": _external_action_presentation,
    "fortigate.switch_order": _external_action_presentation,
    "fortigate.rename_switches": _external_action_presentation,
    "fortigate.export_switches": _external_action_presentation,
    "fortigate.export_fortiswitch_clients": _external_action_presentation,
    "fortiauthenticator.mac_devices": _external_action_presentation,
    "fortiauthenticator.group_memberships": _external_action_presentation,
    "fortiauthenticator.mac_cleanup": _external_action_presentation,
    "tools.certificate_automation": _external_action_presentation,
    "tools.whats_my_ip": _ip_snapshot_presentation,
    "tools.subnet_excluder": _subnet_presentation,
    "automation.home": _automation_run_presentation,
}

REPORT_PRESENTATION_TOOL_IDS = frozenset(_PRESENTATION_BUILDERS)
