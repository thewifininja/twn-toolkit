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
    SSH_TARGET_LIMIT,
    ToolInputError,
    parse_ssh_commands,
    parse_ssh_targets,
    validate_ssh_target,
)
from .profiles import JsonListStore


SSH_MATRIX_ROW_LIMIT = SSH_TARGET_LIMIT
SSH_MATRIX_COLUMN_LIMIT = 20
SSH_MATRIX_VALUE_LIMIT = 500
SSH_COMMANDLET_DESCRIPTION_LIMIT = 500
SSH_COMMANDLET_PLATFORM_LIMIT = 80
SSH_MATRIX_ACTION_LIMIT = 100
SSH_PROFILE_NAME_LIMIT = 100
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

    def all(self) -> list[dict[str, Any]]:
        _migrate_legacy_ssh_profiles(str(self.instance_path))
        matrices = {
            matrix["name"]: matrix
            for matrix in SSHHostMatrixStore(str(self.instance_path)).all()
        }
        return [
            _resolved_commandlet(commandlet, matrices)
            for commandlet in super().all()
        ]

    def get(self, name: str) -> dict[str, Any] | None:
        return next(
            (commandlet for commandlet in self.all() if commandlet["name"] == name),
            None,
        )

    def upsert(self, commandlet: dict[str, Any], original_name: str = "") -> None:
        _migrate_legacy_ssh_profiles(str(self.instance_path))
        commandlet = dict(commandlet)
        embedded = str(commandlet.get("target_matrix", "")).strip()
        if embedded:
            matrix_store = SSHHostMatrixStore(str(self.instance_path))
            matrices = matrix_store.all()
            fingerprint = _matrix_fingerprint(embedded)
            matrix_name = next(
                (
                    str(matrix["name"])
                    for matrix in matrices
                    if _matrix_fingerprint(str(matrix["matrix"])) == fingerprint
                ),
                "",
            )
            if not matrix_name:
                base = f"{str(commandlet.get('name', 'Command set')).strip()} targets"
                base = base[:SSH_PROFILE_NAME_LIMIT].strip() or "Saved targets"
                matrix_name = _unique_profile_name(
                    base, {str(matrix["name"]) for matrix in matrices}
                )
                matrix_store.upsert(
                    {
                        "name": matrix_name,
                        "description": (
                            f"Targets saved with the {commandlet.get('name', 'command')} command set."
                        ),
                        "matrix": embedded,
                        "created_at": commandlet.get("created_at", ""),
                    }
                )
            raw_matrix_names = commandlet.get("matrix_names", [])
            matrix_names = (
                [raw_matrix_names]
                if isinstance(raw_matrix_names, str)
                else list(raw_matrix_names)
                if isinstance(raw_matrix_names, list)
                else []
            )
            if matrix_name not in matrix_names:
                matrix_names.append(matrix_name)
            commandlet["matrix_names"] = matrix_names
        self._upsert(
            normalize_ssh_commandlet(commandlet),
            original_name=original_name,
        )


class SSHHostMatrixStore(JsonListStore):
    def __init__(self, instance_path: str) -> None:
        super().__init__(instance_path, "ssh_host_matrices.json")

    def all(self) -> list[dict[str, Any]]:
        _migrate_legacy_ssh_profiles(str(self.instance_path))
        _migrate_matrix_actions(str(self.instance_path))
        return super().all()

    def get(self, name: str) -> dict[str, Any] | None:
        return next(
            (matrix for matrix in self.all() if matrix["name"] == name),
            None,
        )

    def upsert(self, matrix: dict[str, Any], original_name: str = "") -> None:
        _migrate_legacy_ssh_profiles(str(self.instance_path))
        self._upsert(
            normalize_ssh_host_matrix(matrix),
            original_name=original_name,
        )


SSHCommandSetStore = SSHCommandletStore


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


def ssh_hosts_to_matrix(hosts_text: str) -> str:
    """Convert the legacy friendly-name target syntax into a target matrix."""
    targets = parse_ssh_targets(str(hosts_text), limit=SSH_MATRIX_ROW_LIMIT)
    output = StringIO()
    writer = csv.writer(
        output,
        delimiter="|",
        quotechar='"',
        lineterminator="\n",
    )
    writer.writerow(["Name", "Host"])
    for target in targets:
        writer.writerow([target["label"] or target["host"], target["host"]])
    return output.getvalue().strip()


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


def ssh_matrix_command_compatibility(
    matrix_text: str,
    commands: list[str] | str,
) -> dict[str, Any]:
    matrix = parse_ssh_target_matrix(matrix_text)
    referenced = referenced_ssh_variables(commands)
    available = list(matrix["variable_names"])
    missing_variables = [name for name in referenced if name not in available]
    incomplete_targets: list[dict[str, Any]] = []
    if not missing_variables:
        for target in matrix["targets"]:
            missing_values = [
                name
                for name in referenced
                if not str(target["variables"].get(name, "")).strip()
            ]
            if missing_values:
                incomplete_targets.append(
                    {
                        "host": target["host"],
                        "label": target["label"] or target["host"],
                        "missing_variables": missing_values,
                    }
                )
    return {
        "compatible": not missing_variables and not incomplete_targets,
        "required_variables": referenced,
        "available_variables": available,
        "missing_variables": missing_variables,
        "incomplete_targets": incomplete_targets,
        "target_count": len(matrix["targets"]),
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
    if not name:
        raise ToolInputError("Enter a command-set name.")
    if len(name) > SSH_PROFILE_NAME_LIMIT:
        raise ToolInputError(
            f"Command-set names must be {SSH_PROFILE_NAME_LIMIT} characters or fewer."
        )
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
    parse_ssh_commands(command_lines, default_timeout)
    variables = referenced_ssh_variables(command_lines)
    raw_matrix_names = commandlet.get("matrix_names", [])
    if isinstance(raw_matrix_names, str):
        raw_matrix_names = [raw_matrix_names]
    matrix_names: list[str] = []
    for raw_name in raw_matrix_names if isinstance(raw_matrix_names, list) else []:
        matrix_name = " ".join(str(raw_name).split())
        if matrix_name and matrix_name not in matrix_names:
            matrix_names.append(matrix_name[:SSH_PROFILE_NAME_LIMIT])
    now = datetime.now(timezone.utc).isoformat()
    created_at = str(commandlet.get("created_at", "")).strip() or now
    return {
        "name": name,
        "description": description,
        "platform": platform,
        "commands": commands,
        "command_timeout": default_timeout,
        "variables": variables,
        "matrix_names": matrix_names,
        "created_at": created_at,
        "updated_at": now,
    }


def normalize_ssh_matrix_action(action: dict[str, Any]) -> dict[str, Any]:
    if not " ".join(str(action.get("name", "")).split()):
        raise ToolInputError("Enter a CLI-action name.")
    normalized = normalize_ssh_commandlet(action)
    return {
        key: normalized[key]
        for key in (
            "name",
            "description",
            "platform",
            "commands",
            "command_timeout",
            "variables",
            "created_at",
            "updated_at",
        )
    }


def ssh_matrix_actions_to_commands(actions: list[dict[str, Any]]) -> str:
    if not actions:
        raise ToolInputError("Select at least one CLI action.")
    if len(actions) > SSH_MATRIX_ACTION_LIMIT:
        raise ToolInputError(
            f"A maximum of {SSH_MATRIX_ACTION_LIMIT} CLI actions is allowed per matrix."
        )
    command_lines: list[str] = []
    for action in actions:
        normalized = normalize_ssh_matrix_action(action)
        parsed = parse_ssh_commands(
            str(normalized["commands"]).splitlines(),
            int(normalized["command_timeout"]),
        )
        command_lines.extend(
            f"[timeout={int(spec['timeout'])}] {spec['command']}" for spec in parsed
        )
    return "\n".join(command_lines)


def normalize_ssh_host_matrix(matrix: dict[str, Any]) -> dict[str, Any]:
    name = " ".join(str(matrix.get("name", "")).split())
    description = str(matrix.get("description", "")).strip()
    matrix_text = str(matrix.get("matrix", "")).strip()
    if not name:
        raise ToolInputError("Enter a host-matrix name.")
    if len(name) > SSH_PROFILE_NAME_LIMIT:
        raise ToolInputError(
            f"Host-matrix names must be {SSH_PROFILE_NAME_LIMIT} characters or fewer."
        )
    if len(description) > SSH_COMMANDLET_DESCRIPTION_LIMIT:
        raise ToolInputError(
            f"Host-matrix descriptions must be {SSH_COMMANDLET_DESCRIPTION_LIMIT} characters or fewer."
        )
    parsed = parse_ssh_target_matrix(matrix_text)
    raw_actions = matrix.get("actions", [])
    actions = (
        [normalize_ssh_matrix_action(action) for action in raw_actions]
        if isinstance(raw_actions, list)
        else []
    )
    if len(actions) > SSH_MATRIX_ACTION_LIMIT:
        raise ToolInputError(
            f"A maximum of {SSH_MATRIX_ACTION_LIMIT} CLI actions is allowed per matrix."
        )
    action_names: set[str] = set()
    for action in actions:
        comparable = str(action["name"]).casefold()
        if comparable in action_names:
            raise ToolInputError("CLI-action names must be unique within a host matrix.")
        action_names.add(comparable)
    now = datetime.now(timezone.utc).isoformat()
    created_at = str(matrix.get("created_at", "")).strip() or now
    action_schema_version = 1 if "actions" in matrix else int(
        matrix.get("action_schema_version", 0) or 0
    )
    return {
        "name": name,
        "description": description,
        "matrix": matrix_text,
        "target_count": len(parsed["targets"]),
        "variables": list(parsed["variable_names"]),
        "actions": actions,
        "action_schema_version": action_schema_version,
        "created_at": created_at,
        "updated_at": now,
    }


def _resolved_commandlet(
    commandlet: dict[str, Any],
    matrices: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    normalized = dict(commandlet)
    normalized["matrix_names"] = list(normalized.get("matrix_names", []))
    related = [
        matrices[name]
        for name in normalized.get("matrix_names", [])
        if name in matrices
    ]
    return {
        **normalized,
        "target_matrix": related[0]["matrix"] if related else "",
        "target_count": int(related[0]["target_count"]) if related else 0,
        "related_matrix_count": len(related),
    }


def _migrate_legacy_ssh_profiles(instance_path: str) -> None:
    command_store = JsonListStore(instance_path, "ssh_commandlets.json")
    raw_commandlets = command_store.all()
    if not any(str(item.get("target_matrix", "")).strip() for item in raw_commandlets):
        return

    matrix_store = JsonListStore(instance_path, "ssh_host_matrices.json")
    matrices = [normalize_ssh_host_matrix(item) for item in matrix_store.all()]
    fingerprints = {
        _matrix_fingerprint(matrix["matrix"]): matrix["name"] for matrix in matrices
    }
    known_names = {str(matrix["name"]) for matrix in matrices}
    migrated_commandlets: list[dict[str, Any]] = []
    for raw in raw_commandlets:
        embedded = str(raw.get("target_matrix", "")).strip()
        raw_matrix_names = raw.get("matrix_names", [])
        matrix_names = (
            [str(raw_matrix_names)]
            if isinstance(raw_matrix_names, str)
            else [str(name) for name in raw_matrix_names]
            if isinstance(raw_matrix_names, list)
            else []
        )
        if embedded:
            fingerprint = _matrix_fingerprint(embedded)
            matrix_name = fingerprints.get(fingerprint)
            if not matrix_name:
                base = f"{str(raw.get('name', 'Command set')).strip()} targets"
                base = base[:SSH_PROFILE_NAME_LIMIT].strip() or "Migrated targets"
                matrix_name = _unique_profile_name(base, known_names)
                migrated_matrix = normalize_ssh_host_matrix(
                    {
                        "name": matrix_name,
                        "description": (
                            f"Targets migrated from the {raw.get('name', 'legacy')} command set."
                        ),
                        "matrix": embedded,
                        "created_at": raw.get("created_at", ""),
                    }
                )
                matrices.append(migrated_matrix)
                fingerprints[fingerprint] = matrix_name
                known_names.add(matrix_name)
            if matrix_name not in matrix_names:
                matrix_names.append(matrix_name)
        migrated_commandlets.append(
            normalize_ssh_commandlet({**raw, "matrix_names": matrix_names})
        )
    matrix_store.replace_all(matrices)
    command_store.replace_all(migrated_commandlets)


def _migrate_matrix_actions(instance_path: str) -> None:
    matrix_store = JsonListStore(instance_path, "ssh_host_matrices.json")
    matrices = matrix_store.all()
    pending = [
        matrix
        for matrix in matrices
        if int(matrix.get("action_schema_version", 0) or 0) < 1
    ]
    if not pending:
        return

    command_store = JsonListStore(instance_path, "ssh_commandlets.json")
    commandlets = command_store.all()
    migrated: list[dict[str, Any]] = []
    for raw_matrix in matrices:
        if int(raw_matrix.get("action_schema_version", 0) or 0) >= 1:
            migrated.append(raw_matrix)
            continue
        matrix_name = str(raw_matrix.get("name", ""))
        related_actions = [
            normalize_ssh_matrix_action(commandlet)
            for commandlet in commandlets
            if matrix_name
            in (
                [str(commandlet.get("matrix_names", ""))]
                if isinstance(commandlet.get("matrix_names"), str)
                else [str(name) for name in commandlet.get("matrix_names", [])]
                if isinstance(commandlet.get("matrix_names"), list)
                else []
            )
        ]
        migrated.append(
            normalize_ssh_host_matrix(
                {
                    **raw_matrix,
                    "actions": related_actions,
                    "action_schema_version": 1,
                }
            )
        )
    matrix_store.replace_all(migrated)


def _matrix_fingerprint(matrix_text: str) -> str:
    parsed = parse_ssh_target_matrix(matrix_text)
    payload = {
        "headers": parsed["headers"],
        "targets": [target["variables"] for target in parsed["targets"]],
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _unique_profile_name(base: str, existing: set[str]) -> str:
    if base not in existing:
        return base
    suffix = 2
    while True:
        ending = f" ({suffix})"
        candidate = f"{base[: SSH_PROFILE_NAME_LIMIT - len(ending)]}{ending}"
        if candidate not in existing:
            return candidate
        suffix += 1


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
