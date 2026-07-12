from __future__ import annotations

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Mapping

from flask import current_app, has_app_context

from ..network_tools import (
    ToolInputError,
    dns_lookup_matrix,
    parse_dns_hosts,
    parse_dns_servers,
    parse_ping_targets,
    parse_tcp_ports,
    ping_hosts,
    scan_tcp_checks,
)
from ..certificate_tools import (
    CertificateInspectionError,
    inspect_certificate_chain,
    normalize_certificate_target,
)
from ..schedule_tools import schedule_occurrence, validate_schedule_config
from ..profiles import SNMPCredentialProfileStore, SNMPHostProfileStore, SNMPOidProfileStore
from ..snmp_tools import parse_oid_profile, resolve_oid_selection, run_snmp_tests
from .models import ConditionResult, ConditionType

def _validate_ping(config: dict[str, Any]) -> dict[str, Any]:
    targets = parse_ping_targets(str(config.get("targets", "")), limit=100)
    try:
        timeout = int(config.get("timeout", 1))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Ping timeout must be a whole number.") from exc
    if not 1 <= timeout <= 10:
        raise ToolInputError("Ping timeout must be between 1 and 10 seconds.")
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
        "failure_mode": failure_mode,
        "failure_count": failure_count,
    }


def _evaluate_ping(config: dict[str, Any]) -> ConditionResult:
    normalized = _validate_ping(config)
    targets = parse_ping_targets(normalized["targets"], limit=100)
    raw_results = ping_hosts(
        [target["host"] for target in targets], timeout=normalized["timeout"]
    )
    results = [
        {**result, "label": targets[index]["label"]}
        for index, result in enumerate(raw_results)
    ]
    failed = [result for result in results if not result.get("reachable")]
    required = normalized["failure_count"]
    met = len(failed) >= required
    summary = (
        f"{len(failed)} of {len(results)} targets failed; "
        f"threshold is {required}."
    )
    return ConditionResult(
        met=met,
        status="met" if met else "clear",
        summary=summary,
        evidence={
            "targets": results,
            "failed": len(failed),
            "reachable": len(results) - len(failed),
            "required_failed": required,
        },
    )


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


SNMP_COMPARISONS = {
    "unavailable", "equals", "not_equals", "contains", "not_contains",
    "greater_than", "at_least", "less_than", "at_most",
}
SNMP_NUMERIC_COMPARISONS = {"greater_than", "at_least", "less_than", "at_most"}


def _validate_snmp(config: dict[str, Any]) -> dict[str, Any]:
    host_names = list(dict.fromkeys(str(value).strip() for value in config.get("host_names", []) if str(value).strip()))
    if not 1 <= len(host_names) <= 20:
        raise ToolInputError("Select between 1 and 20 saved SNMP hosts.")

    raw_rules = config.get("rules")
    if not isinstance(raw_rules, list):
        # Normalize the first SNMP condition format into one rule per selected
        # OID profile. The comparison is inverted because the old format
        # described health while rules describe the state that triggers.
        inverse = {
            "responds": "unavailable", "equals": "not_equals",
            "not_equals": "equals", "contains": "not_contains",
            "not_contains": "contains", "greater_than": "at_most",
            "at_least": "less_than", "less_than": "at_least",
            "at_most": "greater_than",
        }
        raw_rules = [
            {
                "id": f"legacy-{index}", "name": profile_name,
                "oid_profile_name": profile_name, "oid": "*",
                "comparison": inverse.get(str(config.get("comparison", "responds")), "unavailable"),
                "expected_value": str(config.get("expected_value", "")),
                "case_sensitive": bool(config.get("case_sensitive", False)),
            }
            for index, profile_name in enumerate(config.get("oid_profile_names", []), start=1)
        ]
    if not 1 <= len(raw_rules) <= 20:
        raise ToolInputError("Add between 1 and 20 SNMP rules.")
    rules: list[dict[str, Any]] = []
    for index, raw_rule in enumerate(raw_rules, start=1):
        if not isinstance(raw_rule, dict):
            raise ToolInputError(f"SNMP rule {index} is invalid.")
        name = str(raw_rule.get("name", "")).strip()
        profile_name = str(raw_rule.get("oid_profile_name", "")).strip()
        oid = str(raw_rule.get("oid", "")).strip().lstrip(".")
        comparison = str(raw_rule.get("comparison", "unavailable"))
        expected_value = str(raw_rule.get("expected_value", "")).strip()
        if not name or len(name) > 100:
            raise ToolInputError(f"SNMP rule {index} needs a name of 100 characters or fewer.")
        if not profile_name or not oid:
            raise ToolInputError(f"SNMP rule '{name}' needs an OID selection.")
        if oid != "*" and not oid.startswith("calc:") and not re.fullmatch(r"\d+(?:\.\d+)+", oid):
            raise ToolInputError(f"SNMP rule '{name}' has an invalid numeric OID.")
        if comparison not in SNMP_COMPARISONS:
            raise ToolInputError(f"SNMP rule '{name}' has an invalid comparison.")
        if comparison != "unavailable" and not expected_value:
            raise ToolInputError(f"SNMP rule '{name}' needs a comparison value.")
        if len(expected_value) > 500:
            raise ToolInputError(f"SNMP rule '{name}' comparison value is too long.")
        if comparison in SNMP_NUMERIC_COMPARISONS:
            try:
                float(expected_value)
            except ValueError as exc:
                raise ToolInputError(f"SNMP rule '{name}' requires a numeric comparison value.") from exc
        rules.append({
            "id": str(raw_rule.get("id", "")).strip() or f"rule-{index}",
            "name": name, "oid_profile_name": profile_name, "oid": oid,
            "comparison": comparison, "expected_value": expected_value,
            "case_sensitive": bool(raw_rule.get("case_sensitive", False)),
        })
    host_failure_mode = str(config.get("host_failure_mode", config.get("failure_mode", "at_least")))
    if host_failure_mode not in {"all", "at_least"}:
        raise ToolInputError("Select a valid SNMP host threshold.")
    try:
        host_failure_count = int(config.get("host_failure_count", config.get("failure_count", 1)))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Required matching SNMP hosts must be a whole number.") from exc
    if host_failure_mode == "all":
        host_failure_count = len(host_names)
    if not 1 <= host_failure_count <= len(host_names):
        raise ToolInputError(f"Required matching SNMP hosts must be between 1 and {len(host_names)}.")
    return {
        "host_names": host_names, "rules": rules,
        "host_failure_mode": host_failure_mode,
        "host_failure_count": host_failure_count,
    }


def _automation_instance_path() -> str:
    if has_app_context():
        return current_app.instance_path
    value = os.environ.get("TWN_TOOLKIT_INSTANCE_PATH", "").strip()
    if not value:
        raise ToolInputError("The automation worker has no toolkit instance path.")
    return value


def _snmp_numeric_value(value: str) -> float | None:
    text = str(value).strip()
    candidates = (text, re.match(r"^\(([-+]?\d+(?:\.\d+)?)\)", text).group(1) if re.match(r"^\(([-+]?\d+(?:\.\d+)?)\)", text) else "")
    for candidate in candidates:
        try:
            return float(candidate)
        except ValueError:
            continue
    return None


def _snmp_value_matches(value: str, rule: dict[str, Any]) -> tuple[bool, str]:
    comparison = rule["comparison"]
    expected = rule["expected_value"]
    if comparison in SNMP_NUMERIC_COMPARISONS:
        actual_number = _snmp_numeric_value(value)
        if actual_number is None:
            return False, "Returned value is not numeric"
        expected_number = float(expected)
        matches = {
            "greater_than": actual_number > expected_number,
            "at_least": actual_number >= expected_number,
            "less_than": actual_number < expected_number,
            "at_most": actual_number <= expected_number,
        }[comparison]
        return matches, f"Observed {actual_number:g}; expected {comparison.replace('_', ' ')} {expected_number:g}"
    actual_text, expected_text = str(value), expected
    if not rule["case_sensitive"]:
        actual_text, expected_text = actual_text.casefold(), expected_text.casefold()
    matches = {
        "equals": actual_text == expected_text,
        "not_equals": actual_text != expected_text,
        "contains": expected_text in actual_text,
        "not_contains": expected_text not in actual_text,
    }[comparison]
    return matches, f"Expected value to {comparison.replace('_', ' ')} '{expected}'"


def _evaluate_snmp(config: dict[str, Any]) -> ConditionResult:
    normalized = _validate_snmp(config)
    instance_path = _automation_instance_path()
    host_store = SNMPHostProfileStore(instance_path)
    oid_store = SNMPOidProfileStore(instance_path)
    credential_store = SNMPCredentialProfileStore(instance_path)
    hosts = [host_store.get(name) for name in normalized["host_names"]]
    if any(host is None for host in hosts):
        raise ToolInputError("One or more selected SNMP hosts no longer exist.")
    credential_names = {host["credential_name"] for host in hosts if host}
    credentials = {name: credential_store.get(name) for name in credential_names}
    if any(profile is None for profile in credentials.values()):
        raise ToolInputError("One or more SNMP hosts reference a missing credential profile.")
    prepared_profiles: list[dict[str, Any]] = []
    for rule in normalized["rules"]:
        profile = oid_store.get(rule["oid_profile_name"])
        if not profile:
            raise ToolInputError(f"OID profile '{rule['oid_profile_name']}' no longer exists.")
        entries = parse_oid_profile(profile["source"])
        selected = entries if rule["oid"] == "*" else resolve_oid_selection(entries, rule["oid"])
        if not selected:
            raise ToolInputError(f"OID selected by SNMP rule '{rule['name']}' no longer exists.")
        prepared_profiles.append({"name": rule["id"], "entries": selected})
    raw_results = run_snmp_tests(
        [host for host in hosts if host],
        {name: profile for name, profile in credentials.items() if profile},
        prepared_profiles,
    )
    rule_by_id = {rule["id"]: rule for rule in normalized["rules"]}
    host_results: dict[str, dict[str, Any]] = {
        host["name"]: {"host_name": host["name"], "host": host["host"], "matched": False, "rules": []}
        for host in hosts if host
    }
    for result in raw_results:
        rule = rule_by_id[result["profile_name"]]
        rule_result = {
            "rule_id": rule["id"], "rule_name": rule["name"],
            "comparison": rule["comparison"], "expected_value": rule["expected_value"],
            "matched": False, "values": [], "error": "",
            "response_ms": result.get("elapsed_ms", 0),
        }
        if result.get("status") != "success" or not result.get("rows"):
            rule_result["error"] = result.get("error") or "No SNMP values were returned."
            rule_result["matched"] = rule["comparison"] == "unavailable"
        elif rule["comparison"] == "unavailable":
            rule_result["values"] = result["rows"]
        else:
            selected_rows = (
                result["rows"] if rule["oid"] == "*"
                else [row for row in result["rows"] if row["oid"] == rule["oid"]]
            )
            for row in selected_rows:
                matches, reason = _snmp_value_matches(str(row.get("value", "")), rule)
                rule_result["values"].append({**row, "matched": matches, "reason": reason})
            rule_result["matched"] = any(value["matched"] for value in rule_result["values"])
        host_results[result["host_name"]]["rules"].append(rule_result)
    evaluated_hosts = list(host_results.values())
    for host_result in evaluated_hosts:
        host_result["matched"] = (
            len(host_result["rules"]) == len(normalized["rules"])
            and all(rule["matched"] for rule in host_result["rules"])
        )
    matched_hosts = sum(1 for host in evaluated_hosts if host["matched"])
    required = normalized["host_failure_count"]
    met = matched_hosts >= required
    return ConditionResult(
        met=met, status="met" if met else "clear",
        summary=f"{matched_hosts} of {len(evaluated_hosts)} hosts matched all {len(normalized['rules'])} SNMP rules; threshold is {required}.",
        evidence={"hosts": evaluated_hosts, "matched_hosts": matched_hosts, "required_hosts": required, "rule_count": len(normalized["rules"])},
    )


def _validate_certificate(config: dict[str, Any]) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    for raw_line in str(config.get("targets", "")).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "|" in line:
            target_text, port_text = (part.strip() for part in line.rsplit("|", 1))
        else:
            target_text, port_text = line, "443"
        if "=" in target_text:
            label, address = (part.strip() for part in target_text.split("=", 1))
            if not label or len(label) > 100:
                raise ToolInputError("Certificate target names must be 1 to 100 characters.")
        else:
            label, address = "", target_text
        try:
            host, port = normalize_certificate_target(address, port_text)
        except ValueError as exc:
            raise ToolInputError(f"Invalid certificate target '{line}': {exc}") from exc
        targets.append({"label": label, "host": host, "port": port})
    if not 1 <= len(targets) <= 20:
        raise ToolInputError("Enter between 1 and 20 certificate targets.")
    try:
        timeout = float(config.get("timeout", 8))
        expiry_days = int(config.get("expiry_days", 30))
        failure_count = int(config.get("failure_count", 1))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Enter valid certificate timeout, expiry, and threshold values.") from exc
    if not 0.2 <= timeout <= 30:
        raise ToolInputError("Certificate timeout must be between 0.2 and 30 seconds.")
    if not 0 <= expiry_days <= 3650:
        raise ToolInputError("Certificate expiry warning must be between 0 and 3650 days.")
    failure_mode = str(config.get("failure_mode", "at_least"))
    if failure_mode not in {"all", "at_least"}:
        raise ToolInputError("Select a valid certificate failure threshold.")
    if failure_mode == "all":
        failure_count = len(targets)
    if not 1 <= failure_count <= len(targets):
        raise ToolInputError(f"Required certificate failures must be between 1 and {len(targets)}.")
    return {
        "targets": "\n".join(
            f"{target['label']} = {target['host']} | {target['port']}"
            if target["label"] else f"{target['host']} | {target['port']}"
            for target in targets
        ),
        "target_count": len(targets), "timeout": timeout,
        "expiry_days": expiry_days,
        "check_hostname": bool(config.get("check_hostname", True)),
        "check_trust": bool(config.get("check_trust", True)),
        "check_chain": bool(config.get("check_chain", True)),
        "failure_mode": failure_mode, "failure_count": failure_count,
    }


def _inspect_certificate_target(target: dict[str, Any], timeout: float) -> dict[str, Any]:
    try:
        result = inspect_certificate_chain(target["host"], target["port"], timeout)
        return {"target": target, "result": result, "error": ""}
    except (CertificateInspectionError, ValueError, OSError) as exc:
        return {"target": target, "result": None, "error": str(exc)}


def _evaluate_certificate(config: dict[str, Any]) -> ConditionResult:
    normalized = _validate_certificate(config)
    targets = []
    for line in normalized["targets"].splitlines():
        target_text, port_text = (part.strip() for part in line.rsplit("|", 1))
        if "=" in target_text:
            label, host = (part.strip() for part in target_text.split("=", 1))
        else:
            label, host = "", target_text
        targets.append({"label": label, "host": host, "port": int(port_text)})
    with ThreadPoolExecutor(max_workers=min(10, len(targets))) as executor:
        inspected = list(executor.map(
            lambda target: _inspect_certificate_target(target, normalized["timeout"]),
            targets,
        ))
    checks: list[dict[str, Any]] = []
    for inspection in inspected:
        target = inspection["target"]
        result = inspection["result"]
        reasons: list[str] = []
        if not result:
            reasons.append(inspection["error"] or "TLS connection failed.")
            checks.append({**target, "failed": True, "reasons": reasons, "error": reasons[0]})
            continue
        leaf = result["certificates"][0]
        if not leaf["time_valid"]:
            reasons.append("Certificate is expired or not yet valid.")
        elif leaf["days_remaining"] <= normalized["expiry_days"]:
            reasons.append(f"Certificate expires in {leaf['days_remaining']} day(s).")
        if normalized["check_hostname"] and not result["hostname"]["valid"]:
            reasons.append(result["hostname"]["error"] or "Hostname does not match.")
        if normalized["check_trust"] and not result["trust"]["valid"]:
            reasons.append(result["trust"]["error"] or "System trust validation failed.")
        if normalized["check_chain"]:
            if not result["chain_order_valid"]:
                reasons.append("Presented certificate chain order is invalid.")
            if result["likely_missing_intermediate"]:
                reasons.append("Certificate chain likely has a missing intermediate.")
        checks.append({
            **target, "failed": bool(reasons), "reasons": reasons, "error": "",
            "common_name": leaf["common_name"], "issuer": leaf["issuer"],
            "not_after": leaf["not_after"].isoformat(),
            "days_remaining": leaf["days_remaining"],
            "fingerprint": leaf["sha256_fingerprint"],
            "hostname_valid": result["hostname"]["valid"],
            "trust_valid": result["trust"]["valid"],
            "chain_valid": result["chain_order_valid"] and not result["likely_missing_intermediate"],
            "tls_version": result["tls"]["version"], "elapsed_ms": result["elapsed_ms"],
        })
    failed = sum(1 for check in checks if check["failed"])
    required = normalized["failure_count"]
    met = failed >= required
    return ConditionResult(
        met=met, status="met" if met else "clear",
        summary=f"{failed} of {len(checks)} certificate targets failed policy; threshold is {required}.",
        evidence={"checks": checks, "failed": failed, "healthy": len(checks) - failed, "required_failed": required, "expiry_days": normalized["expiry_days"]},
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
    return {"targets": form.get("condition_targets", ""), "timeout": form.get("condition_timeout", "1"), "failure_mode": form.get("condition_failure_mode", "all"), "failure_count": form.get("condition_failure_count", "1")}


def _parse_dns_form(form: Mapping[str, Any]) -> dict[str, Any]:
    return {"hosts": form.get("dns_hosts", ""), "servers": form.get("dns_servers", ""), "record_type": form.get("dns_record_type", "A"), "expected_answers": form.get("dns_expected_answers", ""), "answer_mode": form.get("dns_answer_mode", "any"), "failure_mode": form.get("dns_failure_mode", "at_least"), "failure_count": form.get("dns_failure_count", "1"), "timeout": form.get("dns_timeout", "3")}


def _parse_tcp_form(form: Mapping[str, Any]) -> dict[str, Any]:
    return {"targets": form.get("tcp_targets", ""), "timeout": form.get("tcp_timeout", "1"), "expected_state": form.get("tcp_expected_state", "open"), "failure_mode": form.get("tcp_failure_mode", "at_least"), "failure_count": form.get("tcp_failure_count", "1")}


def _parse_snmp_form(form: Mapping[str, Any]) -> dict[str, Any]:
    getlist = getattr(form, "getlist", lambda key: form.get(key, []))
    try:
        rules = json.loads(str(form.get("snmp_rules_json", "[]")))
    except json.JSONDecodeError as exc:
        raise ToolInputError("SNMP rules could not be decoded.") from exc
    return {
        "host_names": getlist("snmp_host_name"),
        "rules": rules,
        "host_failure_mode": form.get("snmp_host_failure_mode", "at_least"),
        "host_failure_count": form.get("snmp_host_failure_count", "1"),
    }


def _parse_certificate_form(form: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "targets": form.get("certificate_targets", ""),
        "timeout": form.get("certificate_timeout", "8"),
        "expiry_days": form.get("certificate_expiry_days", "30"),
        "check_hostname": str(form.get("certificate_check_hostname", "")) == "1",
        "check_trust": str(form.get("certificate_check_trust", "")) == "1",
        "check_chain": str(form.get("certificate_check_chain", "")) == "1",
        "failure_mode": form.get("certificate_failure_mode", "at_least"),
        "failure_count": form.get("certificate_failure_count", "1"),
    }


def _parse_schedule_form(form: Mapping[str, Any]) -> dict[str, Any]:
    try:
        rules = json.loads(str(form.get("schedule_rules_json", "[]")))
    except json.JSONDecodeError as exc:
        raise ToolInputError("Schedule rules could not be decoded.") from exc
    return {"timezone": form.get("schedule_timezone", ""), "missed_policy": form.get("schedule_missed_policy", "grace"), "grace_minutes": form.get("schedule_grace_minutes", "30"), "rules": rules}


def _parse_manual_form(_form: Mapping[str, Any]) -> dict[str, Any]:
    return {}


def registered_conditions() -> tuple[ConditionType, ...]:
    return (
        ConditionType("schedule.calendar", "Calendar schedule", "Trigger from one or more one-time or recurring calendar rules.", _validate_schedule, _evaluate_schedule, _parse_schedule_form),
        ConditionType("manual.trigger", "Manual trigger", "Run attached actions only when a user explicitly starts the automation.", _validate_manual, _evaluate_manual, _parse_manual_form),
        ConditionType("ping.multi", "Multi-host ping", "Trigger when a selected number of ICMP targets are unreachable.", _validate_ping, _evaluate_ping, _parse_ping_form),
        ConditionType("dns.lookup", "DNS lookup", "Trigger when DNS queries fail or return unexpected answers.", _validate_dns, _evaluate_dns, _parse_dns_form),
        ConditionType("tcp.reachability", "TCP service reachability", "Trigger when TCP services do not match their expected open or closed state.", _validate_tcp, _evaluate_tcp, _parse_tcp_form),
        ConditionType("snmp.value", "SNMP OID value", "Trigger when saved SNMP hosts fail to return expected OID values.", _validate_snmp, _evaluate_snmp, _parse_snmp_form),
        ConditionType("certificate.health", "Certificate health", "Trigger when TLS certificates are unavailable, expiring, untrusted, mismatched, or incorrectly chained.", _validate_certificate, _evaluate_certificate, _parse_certificate_form),
    )
