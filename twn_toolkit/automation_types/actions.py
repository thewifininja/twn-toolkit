from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Mapping
from urllib.parse import urlsplit

from ..diagnostic_tools import parse_http_headers, send_api_request, send_syslog
from ..network_tools import (
    ToolInputError,
    parse_ssh_commands,
    parse_ssh_targets,
    run_ssh_hosts,
    validate_hosts,
)
from ..datastore import DatastoreError, LocalDatastore
from ..transfer_tools import (
    DEFAULT_TRANSFER_FILENAME_PATTERN as SFTP_DEFAULT_FILENAME_PATTERN,
    fetch_transfer_files as fetch_ssh_files,
    parse_remote_paths as parse_sftp_paths,
    validate_transfer_filename_pattern as validate_sftp_filename_pattern,
)
from .models import ActionResult, ActionType, ConditionResult

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


def _validate_sftp(config: dict[str, Any]) -> dict[str, Any]:
    targets = parse_ssh_targets(str(config.get("hosts", "")), limit=50)
    paths = parse_sftp_paths(str(config.get("remote_paths", "")))
    username = str(config.get("username", "")).strip()
    password = str(config.get("password", ""))
    try:
        port = int(config.get("port", 22))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("SFTP port must be a whole number.") from exc
    if not username or not password:
        raise ToolInputError("Enter a transfer username and password.")
    if not 1 <= port <= 65535:
        raise ToolInputError("SFTP port must be between 1 and 65535.")
    if len(targets) * len(paths) > 200:
        raise ToolInputError("An SFTP action may contain no more than 200 host/file transfers.")
    destination_mode = str(config.get("destination_mode", "run"))
    if destination_mode not in {"run", "datastore"}:
        raise ToolInputError("Choose retained-run or datastore file-transfer output.")
    protocol = str(config.get("protocol", "sftp")).lower()
    if protocol not in {"sftp", "scp", "ftp"}:
        raise ToolInputError("Choose SFTP, SCP, or FTP.")
    datastore_folder = str(config.get("datastore_folder", "")).replace("\\", "/").strip("/")
    if any(part == ".." for part in Path(datastore_folder).parts):
        raise ToolInputError("The SFTP datastore destination is invalid.")
    return {
        "hosts": "\n".join(f"{item['label']} = {item['host']}" if item["label"] else item["host"] for item in targets),
        "remote_paths": "\n".join(paths), "username": username, "password": password,
        "port": port, "allow_unknown_hosts": bool(config.get("allow_unknown_hosts", False)),
        "destination_mode": destination_mode, "datastore_folder": datastore_folder,
        "per_host_folders": bool(config.get("per_host_folders", False)),
        "protocol": protocol,
        "filename_pattern": validate_sftp_filename_pattern(str(config.get("filename_pattern", SFTP_DEFAULT_FILENAME_PATTERN))),
    }


def _execute_sftp(config: dict[str, Any], trigger: ConditionResult) -> ActionResult:
    normalized = _validate_sftp(config)
    instance_path = str(config.get("_instance_path", ""))
    staging = Path(tempfile.mkdtemp(prefix="twn-automation-sftp-"))
    keep_staging = False
    try:
        results = fetch_ssh_files(
            hosts=parse_ssh_targets(normalized["hosts"], limit=50),
            remote_paths=normalized["remote_paths"].splitlines(),
            username=normalized["username"], password=normalized["password"],
            port=normalized["port"], allow_unknown_hosts=normalized["allow_unknown_hosts"],
            output_dir=staging, filename_pattern=normalized["filename_pattern"],
            protocol=normalized["protocol"],
        )
        successes = [item for item in results if item["status"] == "success"]
        artifacts: list[dict[str, Any]] = []
        if normalized["destination_mode"] == "datastore":
            if not instance_path:
                raise ToolInputError("Automation datastore context is unavailable.")
            store = LocalDatastore(instance_path)
            store.list(normalized["datastore_folder"])
            for item in successes:
                destination = normalized["datastore_folder"]
                if normalized["per_host_folders"]:
                    folder = _safe_sftp_folder(str(item.get("host_label") or item["host"]))
                    destination = f"{destination}/{folder}".strip("/")
                    try:
                        store.list(destination)
                    except DatastoreError:
                        store.create_folder(normalized["datastore_folder"], folder)
                with (staging / str(item["filename"])).open("rb") as source:
                    saved = _save_sftp_datastore_file(
                        store, destination, str(item["filename"]), source
                    )
                item["stored_path"] = store.relative(saved)
        else:
            artifacts = [
                {"source_path": str(staging / str(item["filename"])), "filename": item["filename"],
                 "host": item["host"], "host_label": item.get("host_label", ""),
                 "remote_path": item["remote_path"], "size": item["size"]}
                for item in successes
            ]
            keep_staging = bool(artifacts)
        count = len(successes)
        status = "success" if count == len(results) else "partial" if count else "error"
        output = {"trigger": trigger.evidence, "transfers": results, "destination_mode": normalized["destination_mode"], "protocol": normalized["protocol"]}
        if artifacts:
            output["_artifact_sources"] = artifacts
        return ActionResult(status, f"SFTP collection succeeded for {count} of {len(results)} transfers.", output)
    finally:
        if not keep_staging:
            shutil.rmtree(staging, ignore_errors=True)


def _safe_sftp_folder(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-_")
    return (cleaned or "host")[:120]


def _save_sftp_datastore_file(
    store: LocalDatastore, destination: str, filename: str, source: Any
) -> Path:
    stem, suffix = Path(filename).stem, Path(filename).suffix
    candidate = filename
    for index in range(1, 1001):
        try:
            saved, _size = store.save_upload(destination, candidate, source)
            return saved
        except DatastoreError as exc:
            if "already exists" not in str(exc):
                raise
            source.seek(0)
            candidate = f"{stem}-{index + 1}{suffix}"
    raise DatastoreError("Unable to choose an unused datastore filename.")


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


def _parse_webhook_statuses(value: str) -> set[int]:
    statuses: set[int] = set()
    for token in re.split(r"[\s,]+", value.strip()):
        if not token:
            continue
        if "-" in token:
            if token.count("-") != 1:
                raise ToolInputError(f"Invalid HTTP status range: {token}")
            start_text, end_text = token.split("-", 1)
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ToolInputError(f"Invalid HTTP status range: {token}") from exc
            if start > end:
                raise ToolInputError(f"HTTP status range must be ascending: {token}")
            statuses.update(range(start, end + 1))
        else:
            try:
                statuses.add(int(token))
            except ValueError as exc:
                raise ToolInputError(f"Invalid HTTP status: {token}") from exc
    if not statuses or any(not 100 <= status <= 599 for status in statuses):
        raise ToolInputError("Expected HTTP statuses must be between 100 and 599.")
    return statuses


def _validate_webhook(config: dict[str, Any]) -> dict[str, Any]:
    endpoints = []
    for raw_line in str(config.get("endpoints", "")).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=" in line:
            label, url = (part.strip() for part in line.split("=", 1))
            if not label:
                raise ToolInputError("Webhook endpoint friendly names cannot be empty.")
        else:
            label, url = "", line
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
            raise ToolInputError("Webhook endpoints must be HTTP/HTTPS URLs without embedded credentials.")
        endpoints.append({"label": label, "url": url})
    if not endpoints:
        raise ToolInputError("Enter at least one webhook endpoint.")
    if len(endpoints) > 10:
        raise ToolInputError("A maximum of 10 webhook endpoints is allowed.")
    method = str(config.get("method", "POST")).upper()
    if method not in {"POST", "PUT", "PATCH"}:
        raise ToolInputError("Webhook method must be POST, PUT, or PATCH.")
    headers_text = str(config.get("headers", "")).strip()
    parse_http_headers(headers_text)
    body_format = str(config.get("body_format", "json"))
    if body_format not in {"json", "text"}:
        raise ToolInputError("Webhook body format must be JSON or text.")
    body = str(config.get("body", "")).strip()
    if not body:
        raise ToolInputError("Enter a webhook request body.")
    if len(body.encode("utf-8")) > 65536:
        raise ToolInputError("Webhook request body must be 65,536 UTF-8 bytes or fewer.")
    if body_format == "json":
        try:
            json.loads(body)
        except json.JSONDecodeError as exc:
            raise ToolInputError(f"Webhook JSON template is invalid: {exc.msg} at line {exc.lineno} column {exc.colno}.") from exc
    try:
        timeout = float(config.get("timeout", 10))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Webhook timeout must be a number.") from exc
    if not 0.2 <= timeout <= 30:
        raise ToolInputError("Webhook timeout must be between 0.2 and 30 seconds.")
    expected_statuses = str(config.get("expected_statuses", "200-299")).strip()
    _parse_webhook_statuses(expected_statuses)
    return {
        "endpoints": "\n".join(
            f"{item['label']} = {item['url']}" if item["label"] else item["url"]
            for item in endpoints
        ),
        "method": method,
        "headers": headers_text,
        "has_headers": bool(headers_text),
        "body_format": body_format,
        "body": body,
        "timeout": timeout,
        "verify_tls": bool(config.get("verify_tls", True)),
        "expected_statuses": expected_statuses,
    }


def _webhook_values(trigger: ConditionResult) -> dict[str, Any]:
    actions = trigger.evidence.get("actions", {})
    return {
        "{{trigger.status}}": trigger.status,
        "{{trigger.summary}}": trigger.summary,
        "{{trigger.met}}": trigger.met,
        "{{trigger.evidence}}": trigger.evidence,
        "{{actions.results}}": actions.get("results", []),
        "{{actions.successful}}": actions.get("successful", []),
        "{{actions.partial}}": actions.get("partial", []),
        "{{actions.failed}}": actions.get("failed", []),
        "{{timestamp}}": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def _replace_webhook_json(value: Any, replacements: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: _replace_webhook_json(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_webhook_json(item, replacements) for item in value]
    if not isinstance(value, str):
        return value
    if value in replacements:
        return replacements[value]
    rendered = value
    for token, replacement in replacements.items():
        if token in rendered:
            rendered = rendered.replace(token, json.dumps(replacement, ensure_ascii=False) if isinstance(replacement, (dict, list)) else str(replacement).lower() if isinstance(replacement, bool) else str(replacement))
    return rendered


def _render_webhook_body(config: dict[str, Any], trigger: ConditionResult) -> str:
    replacements = _webhook_values(trigger)
    if config["body_format"] == "json":
        parsed = json.loads(config["body"])
        return json.dumps(_replace_webhook_json(parsed, replacements), ensure_ascii=False, separators=(",", ":"))
    rendered = config["body"]
    for token, replacement in replacements.items():
        rendered = rendered.replace(token, json.dumps(replacement, ensure_ascii=False) if isinstance(replacement, (dict, list)) else str(replacement).lower() if isinstance(replacement, bool) else str(replacement))
    return rendered


def _execute_webhook(config: dict[str, Any], trigger: ConditionResult) -> ActionResult:
    normalized = _validate_webhook(config)
    headers = parse_http_headers(normalized["headers"])
    if normalized["body_format"] == "json" and not any(name.lower() == "content-type" for name in headers):
        headers["Content-Type"] = "application/json"
    body = _render_webhook_body(normalized, trigger)
    accepted = _parse_webhook_statuses(normalized["expected_statuses"])
    results = []
    for line in normalized["endpoints"].splitlines():
        if "=" in line:
            label, url = (part.strip() for part in line.split("=", 1))
        else:
            label, url = "", line.strip()
        try:
            response = send_api_request(
                normalized["method"], url, headers=headers, body=body,
                timeout=normalized["timeout"], verify_tls=normalized["verify_tls"],
            )
        except ToolInputError as exc:
            results.append({"status": "error", "label": label, "url": url, "error": str(exc)})
            continue
        success = response["status"] in accepted
        preview = str(response.get("body", ""))[:4096]
        results.append({
            "status": "success" if success else "error",
            "label": label, "url": url, "http_status": response["status"],
            "reason": response.get("reason", ""), "elapsed_ms": response.get("elapsed_ms"),
            "resolved_addresses": response.get("resolved_addresses", []),
            "redirect": response.get("redirect", ""), "response_preview": preview,
            "response_truncated": bool(response.get("truncated")) or len(str(response.get("body", ""))) > len(preview),
        })
    successes = sum(item["status"] == "success" for item in results)
    status = "success" if successes == len(results) else "partial" if successes else "error"
    return ActionResult(
        status=status,
        summary=f"Webhook delivered successfully to {successes} of {len(results)} endpoints.",
        output={"endpoints": results, "method": normalized["method"]},
    )

def _parse_ssh_form(form: Mapping[str, Any], existing: dict[str, Any]) -> dict[str, Any]:
    password = str(form.get("action_password", "")) or str(existing.get("password", ""))
    return {"hosts": form.get("action_hosts", ""), "username": form.get("action_username", ""), "password": password, "commands": form.get("action_commands", ""), "command_timeout": form.get("action_command_timeout", "300"), "port": form.get("action_port", "22"), "allow_unknown_hosts": "action_allow_unknown_hosts" in form, "send_ctrl_y": "action_send_ctrl_y" in form}


def _parse_sftp_form(form: Mapping[str, Any], existing: dict[str, Any]) -> dict[str, Any]:
    password = str(form.get("sftp_action_password", "")) or str(existing.get("password", ""))
    return {
        "hosts": form.get("sftp_action_hosts", ""), "username": form.get("sftp_action_username", ""),
        "password": password, "port": form.get("sftp_action_port", "22"),
        "remote_paths": form.get("sftp_action_remote_paths", ""),
        "filename_pattern": form.get("sftp_action_filename_pattern", SFTP_DEFAULT_FILENAME_PATTERN),
        "destination_mode": form.get("sftp_action_destination_mode", "run"),
        "datastore_folder": form.get("sftp_action_datastore_folder", ""),
        "per_host_folders": "sftp_action_per_host_folders" in form,
        "allow_unknown_hosts": "sftp_action_allow_unknown_hosts" in form,
        "protocol": form.get("sftp_action_protocol", "sftp"),
    }


def _parse_syslog_form(form: Mapping[str, Any], _existing: dict[str, Any]) -> dict[str, Any]:
    return {"destinations": form.get("syslog_destinations", ""), "protocol": form.get("syslog_protocol", "udp"), "facility": form.get("syslog_facility", "16"), "severity": form.get("syslog_severity", "6"), "hostname": form.get("syslog_hostname", "twn-toolkit"), "app_name": form.get("syslog_app_name", "twn-automation"), "message": form.get("syslog_message", ""), "timeout": form.get("syslog_timeout", "3")}


def _parse_webhook_form(form: Mapping[str, Any], existing: dict[str, Any]) -> dict[str, Any]:
    headers = str(form.get("webhook_headers", ""))
    if "webhook_clear_headers" in form:
        headers = ""
    elif not headers.strip():
        headers = str(existing.get("headers", ""))
    return {"endpoints": form.get("webhook_endpoints", ""), "method": form.get("webhook_method", "POST"), "headers": headers, "body_format": form.get("webhook_body_format", "json"), "body": form.get("webhook_body", ""), "timeout": form.get("webhook_timeout", "10"), "verify_tls": "webhook_verify_tls" in form, "expected_statuses": form.get("webhook_expected_statuses", "200-299")}


def registered_actions() -> tuple[ActionType, ...]:
    return (
        ActionType("ssh.collect", "SSH command collection", "Run a command set on one or more SSH targets and retain the output.", _validate_ssh, _execute_ssh, _parse_ssh_form, ("password",)),
        ActionType("sftp.fetch", "Remote file collection", "Fetch files from multiple hosts over SFTP, SCP, or FTP into retained run output or the datastore.", _validate_sftp, _execute_sftp, _parse_sftp_form, ("password",)),
        ActionType("syslog.send", "Send syslog message", "Send an RFC 5424 message to one or more UDP or TCP collectors.", _validate_syslog, _execute_syslog, _parse_syslog_form),
        ActionType("webhook.send", "Webhook / API notification", "Send a templated HTTP notification to one or more endpoints.", _validate_webhook, _execute_webhook, _parse_webhook_form, ("headers",)),
    )
