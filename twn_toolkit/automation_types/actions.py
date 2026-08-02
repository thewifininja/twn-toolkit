from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from ..auth import load_or_create_secret_key
from ..diagnostic_tools import parse_http_headers, send_api_request, send_syslog
from ..network_tools import (
    SSH_EXECUTION_BATCH_SIZE,
    ToolInputError,
    parse_ssh_targets,
    run_ssh_host_plans,
    validate_hosts,
)
from ..packet_capture import (
    DEFAULT_CAPTURE_FILENAME_PATTERN,
    format_capture_filename,
    run_packet_capture,
    validate_capture_config,
    validate_capture_filename_pattern,
)
from ..datastore import DatastoreError, LocalDatastore
from ..smtp_tools import (
    MAX_EMAIL_RECIPIENTS,
    SMTPSettingsStore,
    parse_email_recipients,
    send_smtp_message,
)
from ..ssh_commandlets import build_ssh_command_plans, ssh_hosts_to_matrix
from ..transfer_tools import (
    DEFAULT_TRANSFER_FILENAME_PATTERN as SFTP_DEFAULT_FILENAME_PATTERN,
    fetch_transfer_files as fetch_ssh_files,
    parse_remote_paths as parse_sftp_paths,
    validate_transfer_filename_pattern as validate_sftp_filename_pattern,
)
from .models import ActionResult, ActionType, ConditionResult

def _validate_ssh(config: dict[str, Any]) -> dict[str, Any]:
    matrix = str(config.get("matrix", "")).strip()
    if not matrix:
        matrix = ssh_hosts_to_matrix(str(config.get("hosts", "")))
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
    if not 1 <= port <= 65535:
        raise ToolInputError("SSH port must be between 1 and 65535.")
    if not 1 <= command_timeout <= 3600:
        raise ToolInputError("Default command timeout must be between 1 and 3600 seconds.")
    preview = build_ssh_command_plans(matrix, commands, command_timeout)
    return {
        "matrix": matrix,
        "hosts": "\n".join(
            f"{target['label']} = {target['host']}" if target["label"] else target["host"]
            for target in preview["targets"]
        ),
        "target_count": len(preview["targets"]),
        "variables": preview["referenced_variables"],
        "username": username,
        "password": password,
        "commands": "\n".join(commands),
        "port": port,
        "command_timeout": command_timeout,
        "allow_unknown_hosts": bool(config.get("allow_unknown_hosts", False)),
        "allow_legacy_algorithms": bool(config.get("allow_legacy_algorithms", False)),
        "send_ctrl_y": bool(config.get("send_ctrl_y", False)),
    }


def _execute_ssh(config: dict[str, Any], trigger: ConditionResult) -> ActionResult:
    normalized = _validate_ssh(config)
    preview = build_ssh_command_plans(
        normalized["matrix"],
        normalized["commands"],
        normalized["command_timeout"],
    )
    results = run_ssh_host_plans(
        preview["plans"],
        username=normalized["username"],
        password=normalized["password"],
        port=normalized["port"],
        allow_unknown_hosts=normalized["allow_unknown_hosts"],
        allow_legacy_algorithms=normalized["allow_legacy_algorithms"],
        send_ctrl_y=normalized["send_ctrl_y"],
    )
    successes = sum(result.get("status") == "success" for result in results)
    status = "success" if successes == len(results) else "partial" if successes else "error"
    return ActionResult(
        status=status,
        summary=f"SSH collection succeeded on {successes} of {len(results)} hosts.",
        output={
            "trigger": trigger.evidence,
            "hosts": results,
            "command_count": len(preview["plans"][0]["command_specs"]),
            "target_count": len(preview["plans"]),
            "execution_batch_count": (
                len(preview["plans"]) + SSH_EXECUTION_BATCH_SIZE - 1
            )
            // SSH_EXECUTION_BATCH_SIZE,
            "referenced_variables": preview["referenced_variables"],
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
        "allow_legacy_algorithms": bool(config.get("allow_legacy_algorithms", False)),
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
            allow_legacy_algorithms=(
                normalized["allow_legacy_algorithms"]
                if normalized["protocol"] in {"sftp", "scp"}
                else False
            ),
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
                        store,
                        destination,
                        str(item.get("preferred_filename") or item["filename"]),
                        source,
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
        protocol_label = normalized["protocol"].upper()
        return ActionResult(
            status,
            f"{protocol_label} collection succeeded for {count} of {len(results)} transfers.",
            output,
        )
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
    execution = trigger.evidence.get("execution", {})
    replacements = {
        "{{trigger.status}}": trigger.status,
        "{{trigger.summary}}": trigger.summary,
        "{{trigger.met}}": "true" if trigger.met else "false",
        "{{trigger.job_id}}": execution.get("job_id", ""),
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
    try:
        max_attempts = int(config.get("max_attempts", 1))
        retry_delay = float(config.get("retry_delay", 2))
    except (TypeError, ValueError) as exc:
        raise ToolInputError(
            "Webhook attempts and retry delay must be numbers."
        ) from exc
    if not 1 <= max_attempts <= 5:
        raise ToolInputError("Webhook attempts must be between 1 and 5.")
    if not 0 <= retry_delay <= 60:
        raise ToolInputError("Webhook retry delay must be between 0 and 60 seconds.")
    retry_statuses = str(
        config.get("retry_statuses", "408,425,429,500-599")
    ).strip()
    _parse_webhook_statuses(retry_statuses)
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
        "max_attempts": max_attempts,
        "retry_delay": retry_delay,
        "retry_statuses": retry_statuses,
    }


def _webhook_values(trigger: ConditionResult) -> dict[str, Any]:
    actions = trigger.evidence.get("actions", {})
    execution = trigger.evidence.get("execution", {})
    return {
        "{{trigger.status}}": trigger.status,
        "{{trigger.summary}}": trigger.summary,
        "{{trigger.met}}": trigger.met,
        "{{trigger.evidence}}": trigger.evidence,
        "{{trigger.job_id}}": execution.get("job_id", ""),
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


def _render_text_template(template: str, trigger: ConditionResult) -> str:
    rendered = template
    for token, replacement in _webhook_values(trigger).items():
        value = (
            json.dumps(replacement, ensure_ascii=False)
            if isinstance(replacement, (dict, list))
            else str(replacement).lower()
            if isinstance(replacement, bool)
            else str(replacement)
        )
        rendered = rendered.replace(token, value)
    return rendered


def _validate_email(config: dict[str, Any]) -> dict[str, Any]:
    to = parse_email_recipients(str(config.get("to", "")))
    cc = parse_email_recipients(str(config.get("cc", "")))
    bcc = parse_email_recipients(str(config.get("bcc", "")))
    if not to:
        raise ToolInputError("Enter at least one To recipient.")
    recipients = [*to, *cc, *bcc]
    unique_addresses = {item["address"].casefold() for item in recipients}
    if len(recipients) > MAX_EMAIL_RECIPIENTS:
        raise ToolInputError(
            f"A maximum of {MAX_EMAIL_RECIPIENTS} email recipients is allowed."
        )
    if len(unique_addresses) != len(recipients):
        raise ToolInputError("Each email recipient may appear only once.")
    subject = str(config.get("subject", "")).strip()
    if not subject:
        raise ToolInputError("Enter an email subject.")
    if len(subject) > 300 or any(character in subject for character in "\r\n"):
        raise ToolInputError("Email subjects must be one line and 300 characters or fewer.")
    body = str(config.get("body", "")).strip()
    if not body:
        raise ToolInputError("Enter an email message.")
    if len(body.encode("utf-8")) > 65536:
        raise ToolInputError("Email messages must be 65,536 UTF-8 bytes or fewer.")
    return {
        "to": ", ".join(item["display"] for item in to),
        "cc": ", ".join(item["display"] for item in cc),
        "bcc": ", ".join(item["display"] for item in bcc),
        "subject": subject,
        "body": body,
    }


def _execute_email(config: dict[str, Any], trigger: ConditionResult) -> ActionResult:
    normalized = _validate_email(config)
    instance_path = str(config.get("_instance_path", "")).strip()
    if not instance_path:
        raise ToolInputError("Automation SMTP context is unavailable.")
    settings = SMTPSettingsStore(
        instance_path, load_or_create_secret_key(instance_path)
    ).get(include_password=True)
    if not settings["configured"]:
        raise ToolInputError(
            "SMTP delivery is not configured. Save it under System Settings first."
        )
    subject = _render_text_template(normalized["subject"], trigger)
    subject = " ".join(subject.splitlines()).strip()[:300]
    body = _render_text_template(normalized["body"], trigger)
    to = parse_email_recipients(normalized["to"])
    cc = parse_email_recipients(normalized["cc"])
    bcc = parse_email_recipients(normalized["bcc"])
    result = send_smtp_message(
        settings, to=to, cc=cc, bcc=bcc, subject=subject, body=body
    )
    total = len(to) + len(cc) + len(bcc)
    accepted = int(result["accepted"])
    status = "success" if accepted == total else "partial" if accepted else "error"
    return ActionResult(
        status=status,
        summary=f"Email delivered to {accepted} of {total} recipients.",
        output={
            "deliveries": result["deliveries"],
            "message_id": result["message_id"],
            "subject": subject,
            "recipient_count": total,
        },
    )


def _execute_webhook(config: dict[str, Any], trigger: ConditionResult) -> ActionResult:
    normalized = _validate_webhook(config)
    headers = parse_http_headers(normalized["headers"])
    job_id = str(trigger.evidence.get("execution", {}).get("job_id", ""))
    if job_id and not any(name.lower() == "idempotency-key" for name in headers):
        headers["Idempotency-Key"] = job_id
    if normalized["body_format"] == "json" and not any(name.lower() == "content-type" for name in headers):
        headers["Content-Type"] = "application/json"
    body = _render_webhook_body(normalized, trigger)
    accepted = _parse_webhook_statuses(normalized["expected_statuses"])
    retryable = _parse_webhook_statuses(normalized["retry_statuses"])
    results = []
    for line in normalized["endpoints"].splitlines():
        if "=" in line:
            label, url = (part.strip() for part in line.split("=", 1))
        else:
            label, url = "", line.strip()
        attempts = []
        endpoint_result: dict[str, Any] | None = None
        for attempt in range(1, normalized["max_attempts"] + 1):
            try:
                response = send_api_request(
                    normalized["method"], url, headers=headers, body=body,
                    timeout=normalized["timeout"], verify_tls=normalized["verify_tls"],
                )
            except ToolInputError as exc:
                attempts.append({
                    "attempt": attempt,
                    "status": "error",
                    "error": str(exc),
                })
                if attempt < normalized["max_attempts"]:
                    _wait_for_webhook_retry(normalized["retry_delay"], attempt)
                    continue
                endpoint_result = {
                    "status": "error",
                    "label": label,
                    "url": url,
                    "error": str(exc),
                }
                break
            success = response["status"] in accepted
            attempts.append({
                "attempt": attempt,
                "status": "success" if success else "error",
                "http_status": response["status"],
                "reason": response.get("reason", ""),
                "elapsed_ms": response.get("elapsed_ms"),
            })
            if (
                not success
                and response["status"] in retryable
                and attempt < normalized["max_attempts"]
            ):
                _wait_for_webhook_retry(normalized["retry_delay"], attempt)
                continue
            preview = str(response.get("body", ""))[:4096]
            endpoint_result = {
                "status": "success" if success else "error",
                "label": label, "url": url, "http_status": response["status"],
                "reason": response.get("reason", ""), "elapsed_ms": response.get("elapsed_ms"),
                "resolved_addresses": response.get("resolved_addresses", []),
                "redirect": response.get("redirect", ""), "response_preview": preview,
                "response_truncated": bool(response.get("truncated")) or len(str(response.get("body", ""))) > len(preview),
            }
            break
        if endpoint_result is None:
            endpoint_result = {
                "status": "error",
                "label": label,
                "url": url,
                "error": "Webhook delivery ended without a result.",
            }
        endpoint_result["attempt_count"] = len(attempts)
        endpoint_result["attempts"] = attempts
        results.append(endpoint_result)
    successes = sum(item["status"] == "success" for item in results)
    status = "success" if successes == len(results) else "partial" if successes else "error"
    return ActionResult(
        status=status,
        summary=f"Webhook delivered successfully to {successes} of {len(results)} endpoints.",
        output={
            "endpoints": results,
            "method": normalized["method"],
            "expected_statuses": normalized["expected_statuses"],
            "max_attempts": normalized["max_attempts"],
            "retry_statuses": normalized["retry_statuses"],
        },
    )


def _wait_for_webhook_retry(base_delay: float, attempt: int) -> None:
    delay = min(60.0, float(base_delay) * (2 ** max(0, attempt - 1)))
    if delay > 0:
        time.sleep(delay)


def _packet_capture_destination(config: dict[str, Any]) -> dict[str, str]:
    destination_mode = str(config.get("destination_mode", "run"))
    if destination_mode not in {"run", "datastore"}:
        raise ToolInputError("Choose retained-run or datastore packet-capture output.")
    datastore_folder = str(config.get("datastore_folder", "")).replace("\\", "/").strip("/")
    if any(part == ".." for part in Path(datastore_folder).parts):
        raise ToolInputError("The packet-capture datastore destination is invalid.")
    return {
        "destination_mode": destination_mode,
        "datastore_folder": datastore_folder,
        "filename_pattern": validate_capture_filename_pattern(
            str(config.get("filename_pattern", DEFAULT_CAPTURE_FILENAME_PATTERN))
        ),
    }


def _validate_packet_capture(config: dict[str, Any]) -> dict[str, Any]:
    return {
        **validate_capture_config(config, require_runtime=False),
        **_packet_capture_destination(config),
    }


def _execute_packet_capture(
    config: dict[str, Any], trigger: ConditionResult
) -> ActionResult:
    normalized = {
        **validate_capture_config(config),
        **_packet_capture_destination(config),
    }
    instance_path = str(config.get("_instance_path", "")).strip()
    if not instance_path:
        raise ToolInputError("Automation packet-capture context is unavailable.")
    staging = Path(tempfile.mkdtemp(prefix="twn-automation-pcap-"))
    keep_staging = False
    try:
        timestamp = datetime.now().astimezone().strftime("%Y%m%d%H%M%S")
        interface = re.sub(
            r"[^A-Za-z0-9._-]+", "-", normalized["interface"]
        ).strip(".-_") or "interface"
        filename = format_capture_filename(
            normalized["filename_pattern"],
            timestamp=timestamp,
            action=str(config.get("_action_name", "packet-capture")),
            interface=interface,
        )
        output_path = staging / filename
        result = run_packet_capture(
            normalized,
            instance_path=instance_path,
            output_path=output_path,
        )
        output = {
            "trigger": trigger.evidence,
            "interface": normalized["interface"],
            "capture_filter": normalized["capture_filter"],
            "elapsed_seconds": result["elapsed_seconds"],
            "packet_count": result["packet_count_captured"],
            "size_bytes": result["size_bytes"],
            "termination_reason": result["termination_reason"],
            "destination_mode": normalized["destination_mode"],
        }
        if normalized["destination_mode"] == "datastore":
            store = LocalDatastore(instance_path)
            store.list(normalized["datastore_folder"])
            with output_path.open("rb") as source:
                saved = _save_sftp_datastore_file(
                    store, normalized["datastore_folder"], filename, source
                )
            output["stored_path"] = store.relative(saved)
        else:
            keep_staging = True
            output["_artifact_sources"] = [
                {
                    "source_path": str(output_path),
                    "filename": filename,
                    "interface": normalized["interface"],
                    "size": result["size_bytes"],
                }
            ]
        return ActionResult(
            status="success",
            summary=(
                f"Captured {result['packet_count_captured']:,} packet(s) "
                f"on {normalized['interface']} for {result['elapsed_seconds']:.1f} seconds."
            ),
            output=output,
        )
    finally:
        if not keep_staging:
            shutil.rmtree(staging, ignore_errors=True)


def _parse_ssh_form(form: Mapping[str, Any], existing: dict[str, Any]) -> dict[str, Any]:
    password = str(form.get("action_password", "")) or str(existing.get("password", ""))
    matrix = str(form.get("action_matrix", "")).strip()
    if not matrix and str(form.get("action_hosts", "")).strip():
        matrix = ssh_hosts_to_matrix(str(form.get("action_hosts", "")))
    return {
        "matrix": matrix,
        "username": form.get("action_username", ""),
        "password": password,
        "commands": form.get("action_commands", ""),
        "command_timeout": form.get("action_command_timeout", "300"),
        "port": form.get("action_port", "22"),
        "allow_unknown_hosts": "action_allow_unknown_hosts" in form,
        "allow_legacy_algorithms": "action_allow_legacy_algorithms" in form,
        "send_ctrl_y": "action_send_ctrl_y" in form,
    }


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
        "allow_legacy_algorithms": "sftp_action_allow_legacy_algorithms" in form,
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
    return {"endpoints": form.get("webhook_endpoints", ""), "method": form.get("webhook_method", "POST"), "headers": headers, "body_format": form.get("webhook_body_format", "json"), "body": form.get("webhook_body", ""), "timeout": form.get("webhook_timeout", "10"), "verify_tls": "webhook_verify_tls" in form, "expected_statuses": form.get("webhook_expected_statuses", "200-299"), "max_attempts": form.get("webhook_max_attempts", "1"), "retry_delay": form.get("webhook_retry_delay", "2"), "retry_statuses": form.get("webhook_retry_statuses", "408,425,429,500-599")}


def _parse_email_form(
    form: Mapping[str, Any], _existing: dict[str, Any]
) -> dict[str, Any]:
    return {
        "to": form.get("email_to", ""),
        "cc": form.get("email_cc", ""),
        "bcc": form.get("email_bcc", ""),
        "subject": form.get("email_subject", ""),
        "body": form.get("email_body", ""),
    }


def _parse_packet_capture_form(
    form: Mapping[str, Any], _existing: dict[str, Any]
) -> dict[str, Any]:
    return _validate_packet_capture(
        {
            "interface": form.get("capture_action_interface", ""),
            "capture_filter": form.get("capture_action_filter", ""),
            "duration_seconds": form.get("capture_action_duration", "60"),
            "packet_count": form.get("capture_action_packet_count", "0"),
            "max_size_mib": form.get("capture_action_max_size", "100"),
            "snap_length": form.get("capture_action_snap_length", "0"),
            "promiscuous": "capture_action_promiscuous" in form,
            "filename_pattern": form.get(
                "capture_action_filename_pattern",
                DEFAULT_CAPTURE_FILENAME_PATTERN,
            ),
            "destination_mode": form.get("capture_action_destination_mode", "run"),
            "datastore_folder": form.get("capture_action_datastore_folder", ""),
        }
    )


def registered_actions() -> tuple[ActionType, ...]:
    return (
        ActionType("ssh.collect", "SSH command collection", "Render a variable-aware command template across a target matrix and retain per-host output.", _validate_ssh, _execute_ssh, _parse_ssh_form, ("password",)),
        ActionType("sftp.fetch", "Remote file collection", "Fetch files from multiple hosts over SFTP, SCP, or FTP into retained run output or the datastore.", _validate_sftp, _execute_sftp, _parse_sftp_form, ("password",)),
        ActionType("syslog.send", "Send syslog message", "Send an RFC 5424 message to one or more UDP or TCP collectors.", _validate_syslog, _execute_syslog, _parse_syslog_form),
        ActionType("webhook.send", "Webhook / API notification", "Send a templated HTTP notification to one or more endpoints.", _validate_webhook, _execute_webhook, _parse_webhook_form, ("headers",)),
        ActionType("email.send", "Email notification", "Send a templated, metadata-only email through the installation-wide SMTP service.", _validate_email, _execute_email, _parse_email_form),
        ActionType("packet.capture", "Packet capture", "Capture a bounded PCAP from a local or SPAN-connected interface when an automation fires.", _validate_packet_capture, _execute_packet_capture, _parse_packet_capture_form),
    )
