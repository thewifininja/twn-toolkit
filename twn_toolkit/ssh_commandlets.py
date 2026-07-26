from __future__ import annotations

import csv
import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from io import StringIO
from typing import Any

from .network_tools import (
    SSH_DEFAULT_COMMAND_TIMEOUT,
    ToolInputError,
    parse_ssh_commands,
    validate_ssh_target,
)
from .profiles import JsonListStore


SSH_MATRIX_ROW_LIMIT = 50
SSH_MATRIX_COLUMN_LIMIT = 20
SSH_MATRIX_VALUE_LIMIT = 500
SSH_COMMANDLET_DESCRIPTION_LIMIT = 500
SSH_COMMANDLET_PLATFORM_LIMIT = 80
SSH_PREVIEW_MAX_AGE_SECONDS = 30 * 60

_VARIABLE_REFERENCE = re.compile(r"\{\{\s*([A-Za-z][A-Za-z0-9 _/-]*?)\s*\}\}")
_ESCAPED_REFERENCE = re.compile(r"\\(\{\{.*?\}\})")
_HEADER_SEPARATOR = re.compile(r"[^a-z0-9]+")
_HOST_ALIASES = {"host", "ip_fqdn", "fqdn", "address", "target"}
_NAME_ALIASES = {"name", "friendly_name", "friendly_label", "label"}
_BUILT_IN_VARIABLES = ("name", "host", "row_number")


class SSHCommandletStore(JsonListStore):
    def __init__(self, instance_path: str) -> None:
        super().__init__(instance_path, "ssh_commandlets.json")

    def upsert(self, commandlet: dict[str, Any], original_name: str = "") -> None:
        self._upsert(
            normalize_ssh_commandlet(commandlet),
            original_name=original_name,
        )


def normalize_variable_name(value: str) -> str:
    normalized = _HEADER_SEPARATOR.sub("_", str(value).strip().lower()).strip("_")
    if not normalized or not normalized[0].isalpha():
        raise ToolInputError(
            f"Variable name '{value}' must begin with a letter and contain letters, numbers, or separators."
        )
    return normalized


def parse_ssh_target_matrix(
    matrix_text: str,
    *,
    row_limit: int = SSH_MATRIX_ROW_LIMIT,
    column_limit: int = SSH_MATRIX_COLUMN_LIMIT,
) -> dict[str, Any]:
    raw_lines = [line for line in str(matrix_text).splitlines() if line.strip()]
    if len(raw_lines) < 2:
        raise ToolInputError(
            "Enter a header row and at least one SSH target row."
        )
    delimiter = _matrix_delimiter(raw_lines[0])
    rows = [_parse_matrix_line(line, delimiter) for line in raw_lines]
    raw_headers = rows[0]
    if len(raw_headers) < 1:
        raise ToolInputError("Enter at least one target-matrix column.")
    if len(raw_headers) > column_limit:
        raise ToolInputError(
            f"A maximum of {column_limit} target-matrix columns is allowed."
        )

    headers: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_header in raw_headers:
        if len(raw_header) > 80:
            raise ToolInputError(
                "Target-matrix headings must be 80 characters or fewer."
            )
        key = _canonical_header(raw_header)
        if key == "row_number":
            raise ToolInputError(
                "'row_number' is built in and cannot be used as a target-matrix column."
            )
        if key in seen:
            raise ToolInputError(
                f"Target-matrix headings must be unique after normalization; '{raw_header}' duplicates '{key}'."
            )
        seen.add(key)
        headers.append({"label": raw_header.strip(), "key": key})
    if "host" not in seen:
        raise ToolInputError("The target matrix needs a Host column.")

    data_rows = rows[1:]
    if len(data_rows) > row_limit:
        raise ToolInputError(f"A maximum of {row_limit} SSH hosts is allowed per run.")
    targets: list[dict[str, Any]] = []
    for row_number, row in enumerate(data_rows, start=1):
        if len(row) != len(headers):
            raise ToolInputError(
                f"Target-matrix row {row_number + 1} has {len(row)} value(s); "
                f"the header has {len(headers)} column(s)."
            )
        variables: dict[str, str] = {}
        for header, raw_value in zip(headers, row):
            value = raw_value.strip()
            _validate_matrix_value(value, row_number + 1, header["label"])
            variables[header["key"]] = value

        host = variables["host"]
        name = variables.get("name", "") or host
        validate_ssh_target(host, name)
        variables["host"] = host
        variables["name"] = name
        variables["row_number"] = str(row_number)
        targets.append(
            {
                "host": host,
                "label": name if name != host else "",
                "variables": variables,
            }
        )

    variable_names = list(_BUILT_IN_VARIABLES)
    variable_names.extend(
        header["key"]
        for header in headers
        if header["key"] not in _BUILT_IN_VARIABLES
    )
    return {
        "headers": headers,
        "targets": targets,
        "variable_names": list(dict.fromkeys(variable_names)),
    }


def referenced_ssh_variables(commands: list[str] | str) -> list[str]:
    command_lines = (
        str(commands).splitlines() if isinstance(commands, str) else commands
    )
    found: list[str] = []
    for line_number, command in enumerate(command_lines, start=1):
        protected, _escaped = _protect_escaped_references(str(command))
        for match in _VARIABLE_REFERENCE.finditer(protected):
            key = normalize_variable_name(match.group(1))
            if key not in found:
                found.append(key)
        remainder = _VARIABLE_REFERENCE.sub("", protected)
        if "{{" in remainder or "}}" in remainder:
            raise ToolInputError(
                f"Command line {line_number} contains an invalid variable reference."
            )
    return found


def render_ssh_command(command: str, variables: dict[str, str]) -> str:
    protected, escaped = _protect_escaped_references(str(command))

    def replace(match: re.Match[str]) -> str:
        key = normalize_variable_name(match.group(1))
        if key not in variables:
            raise ToolInputError(f"Unknown SSH command variable '{{{{ {key} }}}}'.")
        return str(variables[key])

    rendered = _VARIABLE_REFERENCE.sub(replace, protected)
    if "{{" in rendered or "}}" in rendered:
        raise ToolInputError("A command contains an invalid variable reference.")
    for marker, literal in escaped.items():
        rendered = rendered.replace(marker, literal)
    return rendered


def build_ssh_command_plans(
    matrix_text: str,
    commands: list[str] | str,
    default_command_timeout: int = SSH_DEFAULT_COMMAND_TIMEOUT,
) -> dict[str, Any]:
    matrix = parse_ssh_target_matrix(matrix_text)
    command_lines = (
        str(commands).splitlines() if isinstance(commands, str) else list(commands)
    )
    available = set(matrix["variable_names"])
    referenced = referenced_ssh_variables(command_lines)
    unknown = [name for name in referenced if name not in available]
    if unknown:
        formatted = ", ".join(f"{{{{ {name} }}}}" for name in unknown)
        raise ToolInputError(f"Unknown SSH command variable(s): {formatted}.")

    plans: list[dict[str, Any]] = []
    for target in matrix["targets"]:
        missing = [
            name for name in referenced if not target["variables"].get(name, "")
        ]
        if missing:
            formatted = ", ".join(f"{{{{ {name} }}}}" for name in missing)
            identity = target["label"] or target["host"]
            raise ToolInputError(
                f"SSH target '{identity}' is missing value(s) for: {formatted}."
            )
        rendered_commands = [
            render_ssh_command(command, target["variables"])
            for command in command_lines
            if str(command).strip()
        ]
        command_specs = parse_ssh_commands(
            rendered_commands, default_command_timeout
        )
        plans.append(
            {
                "host": target["host"],
                "label": target["label"],
                "variables": target["variables"],
                "commands": rendered_commands,
                "command_specs": command_specs,
            }
        )
    return {
        **matrix,
        "plans": plans,
        "referenced_variables": referenced,
        "command_count": len(command_lines),
    }


def ssh_command_plan_digest(plans: list[dict[str, Any]]) -> str:
    preview = [
        {
            "host": plan["host"],
            "label": plan.get("label", ""),
            "commands": plan["commands"],
            "timeouts": [
                int(spec["timeout"]) for spec in plan.get("command_specs", [])
            ],
        }
        for plan in plans
    ]
    encoded = json.dumps(
        preview, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_ssh_commandlet(commandlet: dict[str, Any]) -> dict[str, Any]:
    name = " ".join(str(commandlet.get("name", "")).split())
    description = str(commandlet.get("description", "")).strip()
    platform = " ".join(str(commandlet.get("platform", "")).split())
    commands = str(commandlet.get("commands", "")).strip()
    target_matrix = str(commandlet.get("target_matrix", "")).strip()
    if not name:
        raise ToolInputError("Enter a Commandlet name.")
    if len(name) > 100:
        raise ToolInputError("Commandlet names must be 100 characters or fewer.")
    if len(description) > SSH_COMMANDLET_DESCRIPTION_LIMIT:
        raise ToolInputError(
            f"Commandlet descriptions must be {SSH_COMMANDLET_DESCRIPTION_LIMIT} characters or fewer."
        )
    if len(platform) > SSH_COMMANDLET_PLATFORM_LIMIT:
        raise ToolInputError(
            f"Commandlet platform labels must be {SSH_COMMANDLET_PLATFORM_LIMIT} characters or fewer."
        )
    try:
        default_timeout = int(
            commandlet.get("command_timeout", SSH_DEFAULT_COMMAND_TIMEOUT)
        )
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Default command timeout must be a whole number.") from exc
    command_lines = [line for line in commands.splitlines() if line.strip()]
    target_count = 0
    if target_matrix:
        plans = build_ssh_command_plans(
            target_matrix, command_lines, default_timeout
        )
        target_count = len(plans["targets"])
    else:
        parse_ssh_commands(command_lines, default_timeout)
    variables = referenced_ssh_variables(command_lines)
    now = datetime.now(timezone.utc).isoformat()
    created_at = str(commandlet.get("created_at", "")).strip() or now
    return {
        "name": name,
        "description": description,
        "platform": platform,
        "commands": commands,
        "command_timeout": default_timeout,
        "target_matrix": target_matrix,
        "target_count": target_count,
        "variables": variables,
        "created_at": created_at,
        "updated_at": now,
    }


def _canonical_header(value: str) -> str:
    normalized = normalize_variable_name(value)
    if normalized in _HOST_ALIASES:
        return "host"
    if normalized in _NAME_ALIASES:
        return "name"
    return normalized


def _matrix_delimiter(header: str) -> str:
    if "\t" in header:
        return "\t"
    if "|" in header:
        return "|"
    if "," in header:
        return ","
    raise ToolInputError(
        "Separate target-matrix columns with pipes, tabs, or commas."
    )


def _parse_matrix_line(line: str, delimiter: str) -> list[str]:
    try:
        row = next(
            csv.reader(
                StringIO(line),
                delimiter=delimiter,
                skipinitialspace=True,
                strict=True,
            )
        )
    except csv.Error as exc:
        raise ToolInputError(f"Could not parse the target matrix: {exc}") from exc
    if delimiter == "|" and row and not row[0].strip():
        row = row[1:]
    if delimiter == "|" and row and not row[-1].strip():
        row = row[:-1]
    return [value.strip() for value in row]


def _validate_matrix_value(value: str, row_number: int, column: str) -> None:
    if len(value) > SSH_MATRIX_VALUE_LIMIT:
        raise ToolInputError(
            f"Target-matrix row {row_number}, column '{column}' exceeds "
            f"{SSH_MATRIX_VALUE_LIMIT} characters."
        )
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ToolInputError(
            f"Target-matrix row {row_number}, column '{column}' contains a control character."
        )


def _protect_escaped_references(value: str) -> tuple[str, dict[str, str]]:
    escaped: dict[str, str] = {}

    def protect(match: re.Match[str]) -> str:
        marker = f"\x00SSH_LITERAL_{len(escaped)}\x00"
        escaped[marker] = match.group(1)
        return marker

    return _ESCAPED_REFERENCE.sub(protect, value), escaped
