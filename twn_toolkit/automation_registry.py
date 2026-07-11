from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .network_tools import (
    ToolInputError,
    parse_ping_targets,
    parse_ssh_commands,
    parse_ssh_targets,
    ping_hosts,
    run_ssh_hosts,
)


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


def _validate_manual(_config: dict[str, Any]) -> dict[str, Any]:
    return {}


def _evaluate_manual(_config: dict[str, Any]) -> ConditionResult:
    return ConditionResult(
        met=True,
        status="manual",
        summary="Started manually by a toolkit user.",
        evidence={"trigger": "manual"},
    )


def build_automation_registry() -> AutomationRegistry:
    registry = AutomationRegistry()
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
    registry.add_action(
        ActionType(
            id="ssh.collect",
            label="SSH command collection",
            description="Run a command set on one or more SSH targets and retain the output.",
            validate=_validate_ssh,
            execute=_execute_ssh,
        )
    )
    return registry


AUTOMATION_REGISTRY = build_automation_registry()
