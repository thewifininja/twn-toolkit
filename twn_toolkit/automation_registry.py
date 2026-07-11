from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Callable

from .network_tools import (
    ToolInputError,
    dns_lookup_matrix,
    parse_dns_hosts,
    parse_dns_servers,
    parse_ping_targets,
    parse_ssh_commands,
    parse_ssh_targets,
    parse_tcp_ports,
    ping_hosts,
    run_ssh_hosts,
    scan_tcp_checks,
    validate_hosts,
)
from .diagnostic_tools import send_syslog
from .schedule_tools import schedule_occurrence, validate_schedule_config


@dataclass(frozen=True)
class ConditionResult:
    met: bool
    status: str
    summary: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class ActionResult:
    status: str
    summary: str
    output: dict[str, Any]


@dataclass(frozen=True)
class ConditionType:
    id: str
    label: str
    description: str
    validate: Callable[[dict[str, Any]], dict[str, Any]]
    evaluate: Callable[[dict[str, Any]], ConditionResult]


@dataclass(frozen=True)
class ActionType:
    id: str
    label: str
    description: str
    validate: Callable[[dict[str, Any]], dict[str, Any]]
    execute: Callable[[dict[str, Any], ConditionResult], ActionResult]


class AutomationRegistry:
    """Internal registry for trusted condition and action implementations."""

    def __init__(self) -> None:
        self.conditions: dict[str, ConditionType] = {}
        self.actions: dict[str, ActionType] = {}

    def add_condition(self, condition: ConditionType) -> None:
        if condition.id in self.conditions:
            raise ValueError(f"Duplicate automation condition type: {condition.id}")
        self.conditions[condition.id] = condition

    def add_action(self, action: ActionType) -> None:
        if action.id in self.actions:
            raise ValueError(f"Duplicate automation action type: {action.id}")
        self.actions[action.id] = action

    def validate_condition(self, type_id: str, config: dict[str, Any]) -> dict[str, Any]:
        try:
            condition = self.conditions[type_id]
        except KeyError as exc:
            raise ToolInputError(f"Unknown condition type: {type_id}") from exc
        return condition.validate(config)

    def validate_action(self, type_id: str, config: dict[str, Any]) -> dict[str, Any]:
        try:
            action = self.actions[type_id]
        except KeyError as exc:
            raise ToolInputError(f"Unknown action type: {type_id}") from exc
        return action.validate(config)


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
def _validate_ssh(config: dict[str, Any]) -> dict[str, Any]:
    targets = parse_ssh_targets(str(config.get("hosts", "")), limit=50)
    username = str(config.get("username", "")).strip()
    password = str(config.get("password", ""))
    commands = [
        command.strip()
        for command in str(config.get("commands", "")).splitlines()
        if command.strip()
    ]
    try:
        port = int(config.get("port", 22))
        command_timeout = int(config.get("command_timeout", 300))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("SSH port and command timeout must be whole numbers.") from exc
    # Reuse the execution helper's complete validation without opening a connection.
    if not username:
        raise ToolInputError("Enter an SSH username.")
    if not password:
        raise ToolInputError("Enter an SSH password.")
    if not commands:
        raise ToolInputError("Enter at least one SSH command.")
    if len(commands) > 50:
        raise ToolInputError("A maximum of 50 SSH commands is allowed per action.")
    if any(len(command) > 500 for command in commands):
        raise ToolInputError("Each SSH command must be 500 characters or fewer.")
    if not 1 <= port <= 65535:
        raise ToolInputError("SSH port must be between 1 and 65535.")
    if not 1 <= command_timeout <= 3600:
        raise ToolInputError("Default command timeout must be between 1 and 3600 seconds.")
    parse_ssh_commands(commands, command_timeout)
    return {
        "hosts": "\n".join(
            f"{target['label']} = {target['host']}" if target["label"] else target["host"]
            for target in targets
        ),
        "username": username,
        "password": password,
        "commands": "\n".join(commands),
        "port": port,
        "command_timeout": command_timeout,
        "allow_unknown_hosts": bool(config.get("allow_unknown_hosts", False)),
        "send_ctrl_y": bool(config.get("send_ctrl_y", False)),
    }


def _execute_ssh(config: dict[str, Any], trigger: ConditionResult) -> ActionResult:
    normalized = _validate_ssh(config)
    hosts = parse_ssh_targets(normalized["hosts"], limit=50)
    commands = normalized["commands"].splitlines()
    results = run_ssh_hosts(
        hosts=hosts,
        username=normalized["username"],
        password=normalized["password"],
        commands=commands,
        port=normalized["port"],
        allow_unknown_hosts=normalized["allow_unknown_hosts"],
        send_ctrl_y=normalized["send_ctrl_y"],
        default_command_timeout=normalized["command_timeout"],
    )
    successes = sum(result.get("status") == "success" for result in results)
    status = "success" if successes == len(results) else "partial" if successes else "error"
    return ActionResult(
        status=status,
        summary=f"SSH collection succeeded on {successes} of {len(results)} hosts.",
        output={
            "trigger": trigger.evidence,
            "hosts": results,
            "command_count": len(commands),
        },
    )


def _validate_syslog(config: dict[str, Any]) -> dict[str, Any]:
    destinations: list[dict[str, Any]] = []
    for raw_line in str(config.get("destinations", "")).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "|" not in line:
            raise ToolInputError(
                f"Syslog destination '{line}' needs a port after |."
            )
        target_text, port_text = (part.strip() for part in line.rsplit("|", 1))
        if "=" in target_text:
            label, host = (part.strip() for part in target_text.split("=", 1))
            if not label:
                raise ToolInputError("Syslog destination friendly names cannot be empty.")
        else:
            label, host = "", target_text
        validate_hosts(host, limit=1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ToolInputError(f"Syslog port '{port_text}' must be a whole number.") from exc
        if not 1 <= port <= 65535:
            raise ToolInputError("Syslog ports must be between 1 and 65535.")
        destinations.append({"label": label, "host": host, "port": port})
    if not destinations:
        raise ToolInputError("Enter at least one syslog destination.")
    if len(destinations) > 20:
        raise ToolInputError("A maximum of 20 syslog destinations is allowed.")
    protocol = str(config.get("protocol", "udp")).lower()
    if protocol not in {"udp", "tcp"}:
        raise ToolInputError("Syslog protocol must be UDP or TCP.")
    try:
        facility = int(config.get("facility", 16))
        severity = int(config.get("severity", 6))
        timeout = float(config.get("timeout", 3))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Syslog facility, severity, and timeout must be numbers.") from exc
    if not 0 <= facility <= 23:
        raise ToolInputError("Syslog facility must be between 0 and 23.")
    if not 0 <= severity <= 7:
        raise ToolInputError("Syslog severity must be between 0 and 7.")
    if not 0.2 <= timeout <= 10:
        raise ToolInputError("Syslog send timeout must be between 0.2 and 10 seconds.")
    hostname = str(config.get("hostname", "twn-toolkit")).strip() or "twn-toolkit"
    app_name = str(config.get("app_name", "twn-automation")).strip() or "twn-automation"
    for value, label, maximum in ((hostname, "Host name", 255), (app_name, "Application name", 48)):
        if len(value) > maximum or not re.fullmatch(r"[\x21-\x7e]+", value):
            raise ToolInputError(f"{label} must be printable ASCII without spaces and at most {maximum} characters.")
    message = str(config.get("message", "")).strip()
    if not message:
        raise ToolInputError("Enter a syslog message.")
    if len(message.encode("utf-8")) > 8192:
        raise ToolInputError("Syslog message must be 8,192 UTF-8 bytes or fewer.")
    return {
        "destinations": "\n".join(
            f"{item['label']} = {item['host']} | {item['port']}"
            if item["label"] else f"{item['host']} | {item['port']}"
            for item in destinations
        ),
        "protocol": protocol,
        "facility": facility,
        "severity": severity,
        "hostname": hostname,
        "app_name": app_name,
        "message": message,
        "timeout": timeout,
    }


def _render_syslog_message(template: str, trigger: ConditionResult) -> str:
    replacements = {
        "{{trigger.status}}": trigger.status,
        "{{trigger.summary}}": trigger.summary,
        "{{trigger.met}}": "true" if trigger.met else "false",
        "{{timestamp}}": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    rendered = template
    for token, value in replacements.items():
        rendered = rendered.replace(token, str(value))
    return rendered


def _execute_syslog(config: dict[str, Any], trigger: ConditionResult) -> ActionResult:
    normalized = _validate_syslog(config)
    message = _render_syslog_message(normalized["message"], trigger)
    results = []
    for line in normalized["destinations"].splitlines():
        target_text, port_text = (part.strip() for part in line.rsplit("|", 1))
        if "=" in target_text:
            label, host = (part.strip() for part in target_text.split("=", 1))
        else:
            label, host = "", target_text
        try:
            sent = send_syslog(
                normalized["protocol"], host, int(port_text),
                facility=normalized["facility"], severity=normalized["severity"],
                hostname=normalized["hostname"], app_name=normalized["app_name"],
                message=message, timeout=normalized["timeout"],
            )
        except (ToolInputError, OSError) as exc:
            results.append({"status": "error", "label": label, "host": host, "port": int(port_text), "protocol": normalized["protocol"].upper(), "error": str(exc)})
        else:
            results.append({"status": "success", "label": label, **sent})
    successes = sum(item["status"] == "success" for item in results)
    status = "success" if successes == len(results) else "partial" if successes else "error"
    return ActionResult(
        status=status,
        summary=f"Syslog message sent to {successes} of {len(results)} destinations.",
        output={"destinations": results, "message": message},
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


def build_automation_registry() -> AutomationRegistry:
    registry = AutomationRegistry()
    registry.add_condition(
        ConditionType(
            id="schedule.calendar",
            label="Calendar schedule",
            description="Trigger from one or more one-time or recurring calendar rules.",
            validate=_validate_schedule,
            evaluate=_evaluate_schedule,
        )
    )
    registry.add_condition(
        ConditionType(
            id="manual.trigger",
            label="Manual trigger",
            description="Run attached actions only when a user explicitly starts the automation.",
            validate=_validate_manual,
            evaluate=_evaluate_manual,
        )
    )
    registry.add_condition(
        ConditionType(
            id="ping.multi",
            label="Multi-host ping",
            description="Trigger when a selected number of ICMP targets are unreachable.",
            validate=_validate_ping,
            evaluate=_evaluate_ping,
        )
    )
    registry.add_condition(
        ConditionType(
            id="dns.lookup",
            label="DNS lookup",
            description="Trigger when DNS queries fail or return unexpected answers.",
            validate=_validate_dns,
            evaluate=_evaluate_dns,
        )
    )
    registry.add_condition(
        ConditionType(
            id="tcp.reachability",
            label="TCP service reachability",
            description="Trigger when TCP services do not match their expected open or closed state.",
            validate=_validate_tcp,
            evaluate=_evaluate_tcp,
        )
    )
    registry.add_action(
        ActionType(
            id="ssh.collect",
            label="SSH command collection",
            description="Run a command set on one or more SSH targets and retain the output.",
            validate=_validate_ssh,
            execute=_execute_ssh,
        )
    )
    registry.add_action(
        ActionType(
            id="syslog.send",
            label="Send syslog message",
            description="Send an RFC 5424 message to one or more UDP or TCP collectors.",
            validate=_validate_syslog,
            execute=_execute_syslog,
        )
    )
    return registry


AUTOMATION_REGISTRY = build_automation_registry()
