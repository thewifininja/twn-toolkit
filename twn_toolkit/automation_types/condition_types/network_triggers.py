from __future__ import annotations

"""ICMP, DNS, TCP, manual, and calendar condition implementations."""

import json
import statistics
from typing import Any, Mapping

from ...network_tools import (
    ToolInputError,
    dns_lookup_matrix,
    parse_dns_hosts,
    parse_dns_servers,
    parse_ping_targets,
    parse_tcp_ports,
    ping_hosts,
    scan_tcp_checks,
)
from ...schedule_tools import schedule_occurrence, validate_schedule_config
from ..models import ConditionResult

def _validate_ping(config: dict[str, Any]) -> dict[str, Any]:
    targets = parse_ping_targets(str(config.get("targets", "")), limit=100)
    try:
        timeout = int(config.get("timeout", 1))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Ping timeout must be a whole number.") from exc
    if not 1 <= timeout <= 10:
        raise ToolInputError("Ping timeout must be between 1 and 10 seconds.")
    try:
        probe_count = int(config.get("probe_count", 1))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Ping probes per target must be a whole number.") from exc
    if not 1 <= probe_count <= 10:
        raise ToolInputError("Ping probes per target must be between 1 and 10.")
    quality_limits = {
        "max_packet_loss_pct": _optional_number(
            config.get("max_packet_loss_pct"),
            "Maximum packet loss",
            minimum=0,
            maximum=100,
        ),
        "max_latency_ms": _optional_number(
            config.get("max_latency_ms"),
            "Maximum average latency",
            minimum=0.1,
            maximum=60000,
        ),
        "max_jitter_ms": _optional_number(
            config.get("max_jitter_ms"),
            "Maximum jitter",
            minimum=0,
            maximum=60000,
        ),
    }
    failure_mode = str(config.get("failure_mode", "all"))
    if failure_mode not in {"all", "at_least"}:
        raise ToolInputError("Select a valid ping failure threshold.")
    try:
        failure_count = int(config.get("failure_count", len(targets)))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Required failed targets must be a whole number.") from exc
    if failure_mode == "all":
        failure_count = len(targets)
    if not 1 <= failure_count <= len(targets):
        raise ToolInputError(
            f"Required failed targets must be between 1 and {len(targets)}."
        )
    return {
        "targets": "\n".join(
            f"{target['label']} = {target['host']}" if target["label"] else target["host"]
            for target in targets
        ),
        "timeout": timeout,
        "probe_count": probe_count,
        **quality_limits,
        "failure_mode": failure_mode,
        "failure_count": failure_count,
    }


def _evaluate_ping(config: dict[str, Any]) -> ConditionResult:
    normalized = _validate_ping(config)
    targets = parse_ping_targets(normalized["targets"], limit=100)
    rounds = [
        ping_hosts(
            [target["host"] for target in targets],
            timeout=normalized["timeout"],
        )
        for _probe in range(normalized["probe_count"])
    ]
    results: list[dict[str, Any]] = []
    for index, target in enumerate(targets):
        samples = [round_results[index] for round_results in rounds]
        latencies = [
            float(sample["latency_ms"])
            for sample in samples
            if sample.get("reachable") and sample.get("latency_ms") is not None
        ]
        received = len(latencies)
        packet_loss_pct = round(
            ((normalized["probe_count"] - received) / normalized["probe_count"]) * 100,
            1,
        )
        average_latency_ms = round(statistics.fmean(latencies), 1) if latencies else None
        jitter_ms = (
            round(
                statistics.fmean(
                    abs(current - previous)
                    for previous, current in zip(latencies, latencies[1:])
                ),
                1,
            )
            if len(latencies) > 1
            else 0.0 if latencies else None
        )
        reasons: list[str] = []
        if not latencies:
            reasons.append("No ICMP replies received.")
        if (
            normalized["max_packet_loss_pct"] is not None
            and packet_loss_pct > normalized["max_packet_loss_pct"]
        ):
            reasons.append(
                f"Packet loss {packet_loss_pct:g}% exceeds "
                f"{normalized['max_packet_loss_pct']:g}%."
            )
        if (
            normalized["max_latency_ms"] is not None
            and average_latency_ms is not None
            and average_latency_ms > normalized["max_latency_ms"]
        ):
            reasons.append(
                f"Average latency {average_latency_ms:g} ms exceeds "
                f"{normalized['max_latency_ms']:g} ms."
            )
        if (
            normalized["max_jitter_ms"] is not None
            and jitter_ms is not None
            and jitter_ms > normalized["max_jitter_ms"]
        ):
            reasons.append(
                f"Jitter {jitter_ms:g} ms exceeds "
                f"{normalized['max_jitter_ms']:g} ms."
            )
        results.append(
            {
                "host": target["host"],
                "label": target["label"],
                "reachable": bool(latencies),
                "failed": bool(reasons),
                "reason": " ".join(reasons),
                "sent": normalized["probe_count"],
                "received": received,
                "packet_loss_pct": packet_loss_pct,
                "latency_ms": average_latency_ms,
                "average_latency_ms": average_latency_ms,
                "jitter_ms": jitter_ms,
                "samples": samples,
                "elapsed_ms": max(
                    (float(sample.get("elapsed_ms", 0)) for sample in samples),
                    default=0,
                ),
            }
        )
    failed = [result for result in results if result["failed"]]
    required = normalized["failure_count"]
    met = len(failed) >= required
    summary = (
        f"{len(failed)} of {len(results)} targets breached the ping policy; "
        f"threshold is {required}."
    )
    return ConditionResult(
        met=met,
        status="met" if met else "clear",
        summary=summary,
        evidence={
            "targets": results,
            "failed": len(failed),
            "reachable": sum(bool(result["reachable"]) for result in results),
            "healthy": len(results) - len(failed),
            "required_failed": required,
            "probe_count": normalized["probe_count"],
            "quality_limits": {
                key: normalized[key]
                for key in (
                    "max_packet_loss_pct",
                    "max_latency_ms",
                    "max_jitter_ms",
                )
            },
        },
    )


def _optional_number(
    value: Any,
    label: str,
    *,
    minimum: float,
    maximum: float,
) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ToolInputError(f"{label} must be a number.") from exc
    if not minimum <= parsed <= maximum:
        raise ToolInputError(
            f"{label} must be between {minimum:g} and {maximum:g}."
        )
    return parsed


def _validate_dns(config: dict[str, Any]) -> dict[str, Any]:
    hosts = parse_dns_hosts(str(config.get("hosts", "")), limit=50)
    servers = parse_dns_servers(str(config.get("servers", "")), limit=10)
    record_type = str(config.get("record_type", "A")).upper()
    if record_type not in {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"}:
        raise ToolInputError("Select a supported DNS record type.")
    try:
        timeout = float(config.get("timeout", 3))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("DNS timeout must be a number.") from exc
    if not 0.2 <= timeout <= 30:
        raise ToolInputError("DNS timeout must be between 0.2 and 30 seconds.")
    expected_answers = [
        line.strip()
        for line in str(config.get("expected_answers", "")).splitlines()
        if line.strip()
    ]
    if len(expected_answers) > 50:
        raise ToolInputError("A maximum of 50 expected DNS answers is allowed.")
    if any(len(answer) > 500 for answer in expected_answers):
        raise ToolInputError("Each expected DNS answer must be 500 characters or fewer.")
    answer_mode = str(config.get("answer_mode", "any"))
    if answer_mode not in {"any", "all"}:
        raise ToolInputError("Select a valid expected-answer matching mode.")
    failure_mode = str(config.get("failure_mode", "at_least"))
    if failure_mode not in {"all", "at_least"}:
        raise ToolInputError("Select a valid DNS failure threshold.")
    check_count = len(hosts) * len(servers)
    try:
        failure_count = int(config.get("failure_count", 1))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Required failed DNS checks must be a whole number.") from exc
    if failure_mode == "all":
        failure_count = check_count
    if not 1 <= failure_count <= check_count:
        raise ToolInputError(
            f"Required failed DNS checks must be between 1 and {check_count}."
        )
    return {
        "hosts": "\n".join(
            f"{host['label']} = {host['host']}" if host["label"] else host["host"]
            for host in hosts
        ),
        "servers": "\n".join(
            f"{server['label']} = {server['address']}"
            if server["label"]
            else server["address"]
            for server in servers
        ),
        "record_type": record_type,
        "timeout": timeout,
        "expected_answers": "\n".join(expected_answers),
        "answer_mode": answer_mode,
        "failure_mode": failure_mode,
        "failure_count": failure_count,
    }


def _canonical_dns_answer(value: str) -> str:
    value = str(value).strip().lower()
    return value[:-1] if value.endswith(".") else value


def _evaluate_dns(config: dict[str, Any]) -> ConditionResult:
    normalized = _validate_dns(config)
    hosts = parse_dns_hosts(normalized["hosts"], limit=50)
    servers = parse_dns_servers(normalized["servers"], limit=10)
    results = dns_lookup_matrix(
        hosts,
        servers,
        record_type=normalized["record_type"],
        timeout=normalized["timeout"],
    )
    expected = {
        _canonical_dns_answer(answer)
        for answer in normalized["expected_answers"].splitlines()
        if answer.strip()
    }
    evaluated: list[dict[str, Any]] = []
    for result in results:
        returned = {
            _canonical_dns_answer(answer) for answer in result.get("answers", [])
        }
        resolved = result.get("status") == "success" and bool(returned)
        answers_match = (
            not expected
            or (bool(expected & returned) if normalized["answer_mode"] == "any" else expected <= returned)
        )
        failed = not resolved or not answers_match
        reason = str(result.get("error", "")) if not resolved else (
            "DNS answer did not match the expected value set." if not answers_match else ""
        )
        evaluated.append({**result, "failed": failed, "matches_expected": answers_match, "reason": reason})
    failed_results = [result for result in evaluated if result["failed"]]
    required = normalized["failure_count"]
    met = len(failed_results) >= required
    expectation = " or returned an unexpected answer" if expected else ""
    return ConditionResult(
        met=met,
        status="met" if met else "clear",
        summary=(
            f"{len(failed_results)} of {len(evaluated)} DNS checks failed{expectation}; "
            f"threshold is {required}."
        ),
        evidence={
            "checks": evaluated,
            "failed": len(failed_results),
            "successful": len(evaluated) - len(failed_results),
            "required_failed": required,
            "record_type": normalized["record_type"],
            "expected_answers": sorted(expected),
        },
    )


def _validate_dns_performance(config: dict[str, Any]) -> dict[str, Any]:
    hosts = parse_dns_hosts(str(config.get("hosts", "")), limit=50)
    servers = parse_dns_servers(str(config.get("servers", "")), limit=10)
    record_type = str(config.get("record_type", "A")).upper()
    if record_type not in {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"}:
        raise ToolInputError("Select a supported DNS record type.")
    timeout = _optional_number(
        config.get("timeout", 3),
        "DNS timeout",
        minimum=0.2,
        maximum=30,
    )
    if timeout is None:
        raise ToolInputError("DNS timeout is required.")
    response_limit_ms = _optional_number(
        config.get("response_limit_ms", 250),
        "DNS response-time limit",
        minimum=1,
        maximum=30000,
    )
    if response_limit_ms is None:
        raise ToolInputError("DNS response-time limit is required.")
    failure_mode = str(config.get("failure_mode", "at_least"))
    if failure_mode not in {"all", "at_least"}:
        raise ToolInputError("Select a valid DNS performance threshold.")
    check_count = len(hosts) * len(servers)
    try:
        failure_count = int(config.get("failure_count", 1))
    except (TypeError, ValueError) as exc:
        raise ToolInputError(
            "Required slow or failed DNS checks must be a whole number."
        ) from exc
    if failure_mode == "all":
        failure_count = check_count
    if not 1 <= failure_count <= check_count:
        raise ToolInputError(
            f"Required slow or failed DNS checks must be between 1 and {check_count}."
        )
    return {
        "hosts": "\n".join(
            f"{host['label']} = {host['host']}" if host["label"] else host["host"]
            for host in hosts
        ),
        "servers": "\n".join(
            f"{server['label']} = {server['address']}"
            if server["label"]
            else server["address"]
            for server in servers
        ),
        "record_type": record_type,
        "timeout": timeout,
        "response_limit_ms": response_limit_ms,
        "failure_mode": failure_mode,
        "failure_count": failure_count,
        "check_count": check_count,
    }


def _evaluate_dns_performance(config: dict[str, Any]) -> ConditionResult:
    normalized = _validate_dns_performance(config)
    results = dns_lookup_matrix(
        parse_dns_hosts(normalized["hosts"], limit=50),
        parse_dns_servers(normalized["servers"], limit=10),
        record_type=normalized["record_type"],
        timeout=normalized["timeout"],
    )
    evaluated: list[dict[str, Any]] = []
    for result in results:
        response_ms = float(result.get("response_ms", 0))
        resolved = result.get("status") == "success" and bool(result.get("answers"))
        slow = resolved and response_ms > normalized["response_limit_ms"]
        reason = (
            str(result.get("error") or result.get("status"))
            if not resolved
            else (
                f"Response time {response_ms:g} ms exceeds "
                f"{normalized['response_limit_ms']:g} ms."
                if slow
                else ""
            )
        )
        evaluated.append(
            {
                **result,
                "failed": not resolved or slow,
                "slow": slow,
                "reason": reason,
                "response_limit_ms": normalized["response_limit_ms"],
            }
        )
    failed = [result for result in evaluated if result["failed"]]
    required = normalized["failure_count"]
    met = len(failed) >= required
    return ConditionResult(
        met=met,
        status="met" if met else "clear",
        summary=(
            f"{len(failed)} of {len(evaluated)} DNS checks were slow or failed; "
            f"threshold is {required} at {normalized['response_limit_ms']:g} ms."
        ),
        evidence={
            "checks": evaluated,
            "failed": len(failed),
            "successful": len(evaluated) - len(failed),
            "required_failed": required,
            "response_limit_ms": normalized["response_limit_ms"],
            "record_type": normalized["record_type"],
        },
    )


def _validate_tcp(config: dict[str, Any]) -> dict[str, Any]:
    target_text = str(config.get("targets", "")).strip()
    target_specs: list[dict[str, Any]] = []
    if target_text:
        for raw_line in target_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if "|" not in line:
                raise ToolInputError(
                    f"TCP target '{line}' needs a port list after |."
                )
            host_text, ports_text = (part.strip() for part in line.rsplit("|", 1))
            parsed_hosts = parse_ping_targets(host_text, limit=1)
            ports = parse_tcp_ports(ports_text, limit=200)
            target_specs.append({**parsed_hosts[0], "ports": ports})
    else:
        # Legacy global host/port definitions are normalized on their next edit/test.
        hosts = parse_ping_targets(str(config.get("hosts", "")), limit=50)
        ports = parse_tcp_ports(str(config.get("ports", "")), limit=200)
        target_specs = [{**host, "ports": ports} for host in hosts]
    if not target_specs:
        raise ToolInputError("Enter at least one TCP target and port list.")
    if len(target_specs) > 50:
        raise ToolInputError("A maximum of 50 TCP target lines is allowed.")
    check_count = sum(len(target["ports"]) for target in target_specs)
    if check_count > 5000:
        raise ToolInputError("A TCP condition is limited to 5,000 host/port checks.")
    try:
        timeout = float(config.get("timeout", 1))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("TCP connection timeout must be a number.") from exc
    if not 0.1 <= timeout <= 10:
        raise ToolInputError("TCP connection timeout must be between 0.1 and 10 seconds.")
    expected_state = str(config.get("expected_state", "open"))
    if expected_state not in {"open", "closed"}:
        raise ToolInputError("Select a valid expected TCP port state.")
    failure_mode = str(config.get("failure_mode", "at_least"))
    if failure_mode not in {"all", "at_least"}:
        raise ToolInputError("Select a valid TCP failure threshold.")
    try:
        failure_count = int(config.get("failure_count", 1))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Required failed TCP checks must be a whole number.") from exc
    if failure_mode == "all":
        failure_count = check_count
    if not 1 <= failure_count <= check_count:
        raise ToolInputError(
            f"Required failed TCP checks must be between 1 and {check_count}."
        )
    return {
        "targets": "\n".join(
            f"{target['label']} = {target['host']} | {', '.join(str(port) for port in target['ports'])}"
            if target["label"]
            else f"{target['host']} | {', '.join(str(port) for port in target['ports'])}"
            for target in target_specs
        ),
        "target_count": len(target_specs),
        "check_count": check_count,
        "timeout": timeout,
        "expected_state": expected_state,
        "failure_mode": failure_mode,
        "failure_count": failure_count,
    }


def _evaluate_tcp(config: dict[str, Any]) -> ConditionResult:
    normalized = _validate_tcp(config)
    checks: list[tuple[dict[str, str], int]] = []
    for line in normalized["targets"].splitlines():
        host_text, ports_text = (part.strip() for part in line.rsplit("|", 1))
        host = parse_ping_targets(host_text, limit=1)[0]
        checks.extend((host, port) for port in parse_tcp_ports(ports_text, limit=200))
    results = scan_tcp_checks(checks, timeout=normalized["timeout"])
    expected = normalized["expected_state"]
    evaluated = [
        {
            **result,
            "failed": result.get("status") != expected,
            "expected_state": expected,
        }
        for result in results
    ]
    failed_results = [result for result in evaluated if result["failed"]]
    required = normalized["failure_count"]
    met = len(failed_results) >= required
    return ConditionResult(
        met=met,
        status="met" if met else "clear",
        summary=(
            f"{len(failed_results)} of {len(evaluated)} TCP checks were not {expected}; "
            f"threshold is {required}."
        ),
        evidence={
            "checks": evaluated,
            "failed": len(failed_results),
            "successful": len(evaluated) - len(failed_results),
            "required_failed": required,
            "expected_state": expected,
        },
    )


def _validate_manual(_config: dict[str, Any]) -> dict[str, Any]:
    return {}


def _evaluate_manual(_config: dict[str, Any]) -> ConditionResult:
    return ConditionResult(
        met=True,
        status="manual",
        summary="Started manually by a toolkit user.",
        evidence={"trigger": "manual"},
    )


def _validate_schedule(config: dict[str, Any]) -> dict[str, Any]:
    return validate_schedule_config(config)


def _evaluate_schedule(config: dict[str, Any]) -> ConditionResult:
    import time

    normalized = validate_schedule_config(config)
    occurrence = schedule_occurrence(normalized, time.time())
    if occurrence is None:
        return ConditionResult(
            met=False,
            status="completed",
            summary="No future calendar occurrences remain.",
            evidence={"trigger": "schedule", "next_occurrence": None},
        )
    return ConditionResult(
        met=False,
        status="scheduled",
        summary=f"Next occurrence: {occurrence['display']}.",
        evidence={"trigger": "schedule", "next_occurrence": occurrence},
    )

def _parse_ping_form(form: Mapping[str, Any]) -> dict[str, Any]:
    return {"targets": form.get("condition_targets", ""), "timeout": form.get("condition_timeout", "1"), "probe_count": form.get("condition_probe_count", "3"), "max_packet_loss_pct": form.get("condition_max_packet_loss_pct", ""), "max_latency_ms": form.get("condition_max_latency_ms", ""), "max_jitter_ms": form.get("condition_max_jitter_ms", ""), "failure_mode": form.get("condition_failure_mode", "all"), "failure_count": form.get("condition_failure_count", "1")}


def _parse_dns_form(form: Mapping[str, Any]) -> dict[str, Any]:
    return {"hosts": form.get("dns_hosts", ""), "servers": form.get("dns_servers", ""), "record_type": form.get("dns_record_type", "A"), "expected_answers": form.get("dns_expected_answers", ""), "answer_mode": form.get("dns_answer_mode", "any"), "failure_mode": form.get("dns_failure_mode", "at_least"), "failure_count": form.get("dns_failure_count", "1"), "timeout": form.get("dns_timeout", "3")}


def _parse_dns_performance_form(form: Mapping[str, Any]) -> dict[str, Any]:
    return {"hosts": form.get("dns_performance_hosts", ""), "servers": form.get("dns_performance_servers", ""), "record_type": form.get("dns_performance_record_type", "A"), "timeout": form.get("dns_performance_timeout", "3"), "response_limit_ms": form.get("dns_performance_response_limit_ms", "250"), "failure_mode": form.get("dns_performance_failure_mode", "at_least"), "failure_count": form.get("dns_performance_failure_count", "1")}


def _parse_tcp_form(form: Mapping[str, Any]) -> dict[str, Any]:
    return {"targets": form.get("tcp_targets", ""), "timeout": form.get("tcp_timeout", "1"), "expected_state": form.get("tcp_expected_state", "open"), "failure_mode": form.get("tcp_failure_mode", "at_least"), "failure_count": form.get("tcp_failure_count", "1")}


def _parse_schedule_form(form: Mapping[str, Any]) -> dict[str, Any]:
    try:
        rules = json.loads(str(form.get("schedule_rules_json", "[]")))
    except json.JSONDecodeError as exc:
        raise ToolInputError("Schedule rules could not be decoded.") from exc
    return {"timezone": form.get("schedule_timezone", ""), "missed_policy": form.get("schedule_missed_policy", "grace"), "grace_minutes": form.get("schedule_grace_minutes", "30"), "rules": rules}


def _parse_manual_form(_form: Mapping[str, Any]) -> dict[str, Any]:
    return {}
