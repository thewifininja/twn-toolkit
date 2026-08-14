from __future__ import annotations

import hmac
import re
import secrets
import time

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .activity_context import record_current_activity
from .audit import annotate_audit_event, annotate_tool_run, suppress_audit_event
from .network_tools import (
    SSH_DEFAULT_COMMAND_TIMEOUT,
    SSH_EXECUTION_BATCH_SIZE,
    SSH_EXECUTION_WORKERS,
    SSH_TARGET_LIMIT,
    ToolInputError,
    parse_ssh_targets,
    run_ssh_host_plans,
)
from .ssh_security import SSHKnownHostsError, forget_ssh_known_host
from .ssh_commandlets import (
    SSH_PREVIEW_MAX_AGE_SECONDS,
    SSHCommandletStore,
    build_ssh_command_plans,
    normalize_ssh_commandlet,
    ssh_command_plan_digest,
    ssh_hosts_to_matrix,
)
from .investigation_context import (
    add_current_investigation_generated_evidence_event,
    record_current_investigation_event,
)


_PREVIEW_TOKEN_SALT = "multi-ssh-advanced-preview-v1"
_HOST_KEY_RETRY_TOKEN_SALT = "multi-ssh-host-key-retry-v1"
_PREVIEW_DISPLAY_LIMIT = 100


def register_ssh_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/multi-ssh", methods=["GET", "POST"])
    def multi_ssh():
        legacy_mode = str(request.args.get("mode", "")).strip().lower()
        if request.method == "GET" and legacy_mode in {"basic", "advanced"}:
            preserved = {
                key: request.args[key]
                for key in ("commandlet", "duplicate")
                if request.args.get(key)
            }
            return redirect(url_for("tools.multi_ssh", **preserved))

        form = _default_form()
        results: list[dict[str, object]] | None = None
        preview: dict[str, object] | None = None
        preview_token = ""
        error = ""
        success = ""
        journal_event = None
        journal_operation_id = ""
        journal_started_at = 0.0

        if request.method == "GET":
            commandlet_name = str(request.args.get("commandlet", "")).strip()
            if commandlet_name:
                commandlet = _ssh_commandlet_store().get(commandlet_name)
                if commandlet:
                    duplicate = request.args.get("duplicate") == "1"
                    form.update(
                        {
                            "commands": commandlet["commands"],
                            "command_timeout": str(commandlet["command_timeout"]),
                            "matrix": commandlet.get("target_matrix", ""),
                            "commandlet_name": (
                                f"Copy of {commandlet['name']}"
                                if duplicate
                                else commandlet["name"]
                            ),
                            "commandlet_description": commandlet.get(
                                "description", ""
                            ),
                            "commandlet_platform": commandlet.get("platform", ""),
                            "commandlet_save_matrix": bool(
                                commandlet.get("target_matrix", "")
                            ),
                            "commandlet_original_name": (
                                "" if duplicate else commandlet["name"]
                            ),
                        }
                    )
                else:
                    error = "That Commandlet no longer exists."

        if request.method == "POST":
            form = _posted_form()
            action = str(request.form.get("action", "run")).strip().lower()
            if action == "run":
                journal_operation_id = f"multi-ssh:{secrets.token_hex(12)}"
                journal_started_at = time.time()
            if _is_legacy_basic_submission():
                try:
                    form["matrix"] = ssh_hosts_to_matrix(str(form["hosts"]))
                    preview = build_ssh_command_plans(
                        str(form["matrix"]),
                        str(form["commands"]),
                        int(str(form["command_timeout"])),
                    )
                    _annotate_preview_scale(preview)
                    preview_token = _preview_serializer().dumps(
                        {"digest": ssh_command_plan_digest(preview["plans"])}
                    )
                    success = (
                        "The legacy host list was imported. Review the rendered "
                        "commands, then enter credentials to run them."
                    )
                except (ToolInputError, TypeError, ValueError) as exc:
                    error = str(exc) if str(exc) else "Enter a valid SSH port."
                suppress_audit_event()
            elif action == "save_commandlet":
                try:
                    commandlet, existed = _save_commandlet(form)
                except (ToolInputError, ValueError) as exc:
                    error = str(exc)
                    suppress_audit_event()
                else:
                    success = (
                        f"Commandlet '{commandlet['name']}' "
                        f"{'updated' if existed else 'saved'}."
                    )
                    form["commandlet_name"] = commandlet["name"]
                    form["commandlet_original_name"] = commandlet["name"]
                    _annotate_commandlet_save(commandlet, existed)
            else:
                try:
                    preview = build_ssh_command_plans(
                        str(form["matrix"]),
                        str(form["commands"]),
                        int(str(form["command_timeout"])),
                    )
                    _annotate_preview_scale(preview)
                    if action == "preview":
                        preview_token = _preview_serializer().dumps(
                            {"digest": ssh_command_plan_digest(preview["plans"])}
                        )
                        suppress_audit_event()
                    elif action == "run":
                        _validate_preview_token(
                            request.form.get("preview_token", ""),
                            preview["plans"],
                        )
                        preview_token = request.form.get("preview_token", "")
                        if request.form.get("confirm_execution") != "on":
                            raise ToolInputError(
                                "Confirm that you intend to execute the previewed commands."
                            )
                        results = _run_plans(form, preview)
                        _attach_host_key_retry_tokens(results, preview, form)
                    else:
                        raise ToolInputError("Choose Preview commands or Run commands.")
                except (ToolInputError, TypeError, ValueError) as exc:
                    error = str(exc) if str(exc) else "Enter a valid SSH port."
                    if action == "run":
                        _record_failed_run(form, preview)
                        journal_event = _record_ssh_investigation(
                            form,
                            preview,
                            [],
                            error=str(exc),
                            operation_id=journal_operation_id,
                            started_at=journal_started_at,
                        )
                    else:
                        suppress_audit_event()
                else:
                    if action == "run":
                        _record_successful_run(form, preview, results or [])
                        journal_event = _record_ssh_investigation(
                            form,
                            preview,
                            results or [],
                            error="",
                            operation_id=journal_operation_id,
                            started_at=journal_started_at,
                        )

        return render_template(
            "tools/multi_ssh.html",
            error=error,
            success=success,
            form=form,
            results=results,
            preview=preview,
            preview_token=preview_token,
            commandlets=_ssh_commandlet_store().all(),
            ssh_target_limit=SSH_TARGET_LIMIT,
            ssh_target_limit_label=f"{SSH_TARGET_LIMIT:,}",
            ssh_batch_size=SSH_EXECUTION_BATCH_SIZE,
            ssh_execution_workers=SSH_EXECUTION_WORKERS,
            journal_event=journal_event,
        )

    @tools_bp.post("/multi-ssh/import-hosts")
    def import_ssh_hosts():
        try:
            targets = parse_ssh_targets(
                str(request.form.get("hosts", "")),
                limit=SSH_TARGET_LIMIT,
            )
        except (ToolInputError, ValueError) as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 400
        suppress_audit_event()
        return jsonify({"count": len(targets), "targets": targets})

    @tools_bp.post("/multi-ssh/host-keys/retry")
    def retry_multi_ssh_host_key():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            suppress_audit_event()
            return jsonify({"error": "Send a valid host-key retry request."}), 400
        try:
            preview = build_ssh_command_plans(
                str(payload.get("matrix", "")),
                str(payload.get("commands", "")),
                int(payload.get("command_timeout", SSH_DEFAULT_COMMAND_TIMEOUT)),
            )
            _validate_preview_token(
                str(payload.get("preview_token", "")),
                preview["plans"],
            )
            retry_context = _validate_host_key_retry_token(
                str(payload.get("retry_token", "")),
                preview["plans"],
            )
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))
            if not username:
                raise ToolInputError("Enter an SSH username.")
            if not password:
                raise ToolInputError("Enter an SSH password.")
        except (ToolInputError, TypeError, ValueError) as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc) or "Review the retry details."}), 400

        plan_index = int(retry_context["plan_index"])
        plan = dict(preview["plans"][plan_index])
        host = str(plan["host"])
        port = int(retry_context["port"])
        expected_fingerprint = str(retry_context["expected_fingerprint"])
        presented_fingerprint = str(retry_context["presented_fingerprint"])
        try:
            forgotten = forget_ssh_known_host(
                host,
                port,
                expected_fingerprint,
                allow_missing=True,
                allow_existing_fingerprint=presented_fingerprint,
            )
        except SSHKnownHostsError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 409

        plan["required_host_key_fingerprint"] = presented_fingerprint
        started_at = time.time()
        result = run_ssh_host_plans(
            [plan],
            username=username,
            password=password,
            port=port,
            allow_unknown_hosts=False,
            allow_legacy_algorithms=bool(retry_context["allow_legacy_algorithms"]),
            send_ctrl_y=bool(retry_context["send_ctrl_y"]),
        )[0]
        status = str(result.get("status", "error"))
        record_current_activity(
            "Automation",
            "Retried Bulk SSH host",
            f"{plan.get('label') or host} · {status}",
            counters={"ssh": {"hosts": 1, "commands": len(plan["commands"])}},
        )
        retry_form = {
            "port": str(port),
            "command_timeout": str(payload.get("command_timeout", "")),
            "allow_unknown_hosts": False,
            "allow_legacy_algorithms": bool(
                retry_context["allow_legacy_algorithms"]
            ),
        }
        _record_ssh_investigation(
            retry_form,
            {"plans": [plan]},
            [result],
            error="",
            operation_id=f"multi-ssh-retry:{secrets.token_hex(12)}",
            started_at=started_at,
        )
        annotate_audit_event(
            category="Network tools",
            action="ssh.host_key_recovery_run",
            summary=f"Processed verified SSH host-key recovery and retried {host}:{port}.",
            resource_type="ssh_host_key",
            resource_id=f"{host}:{port}",
            resource_name=host,
            details={
                "host": host,
                "port": port,
                "expected fingerprint": expected_fingerprint,
                "presented fingerprint": presented_fingerprint,
                "removed entries": int(forgotten["removed_entries"]),
                "command count": len(plan["commands"]),
                "outcome": status,
            },
        )
        return jsonify(
            {
                "forgotten": forgotten,
                "result": result,
                "message": (
                    "Saved key replaced and this host was rerun."
                    if status == "success"
                    else "The stale saved key was cleared, but this host's retry did not complete successfully."
                ),
            }
        )

    @tools_bp.post("/multi-ssh/commandlets/delete")
    def delete_ssh_commandlet():
        name = str(request.form.get("name", "")).strip()
        store = _ssh_commandlet_store()
        commandlet = store.get(name)
        if not commandlet:
            flash("That Commandlet no longer exists.", "error")
            suppress_audit_event()
        else:
            store.delete(name)
            flash(f"Commandlet '{name}' deleted.", "success")
            annotate_audit_event(
                category="Network tools",
                action="ssh.commandlet_deleted",
                summary=f"Deleted SSH Commandlet {name}.",
                resource_type="ssh_commandlet",
                resource_id=name,
                resource_name=name,
                details={
                    "command count": len(
                        [
                            line
                            for line in str(commandlet["commands"]).splitlines()
                            if line.strip()
                        ]
                    ),
                    "variables": commandlet.get("variables", []),
                    "saved target count": int(
                        commandlet.get("target_count", 0)
                    ),
                },
            )
        return redirect(url_for("tools.multi_ssh"))


def _default_form() -> dict[str, object]:
    return {
        "hosts": "",
        "matrix": "",
        "username": "",
        "port": "22",
        "commands": "",
        "command_timeout": str(SSH_DEFAULT_COMMAND_TIMEOUT),
        "allow_unknown_hosts": False,
        "allow_legacy_algorithms": False,
        "send_ctrl_y": False,
        "commandlet_name": "",
        "commandlet_description": "",
        "commandlet_platform": "",
        "commandlet_save_matrix": True,
        "commandlet_original_name": "",
    }


def _posted_form() -> dict[str, object]:
    return {
        "hosts": request.form.get("hosts", "").strip(),
        "matrix": request.form.get("matrix", "").strip(),
        "username": request.form.get("username", "").strip(),
        "port": request.form.get("port", "22").strip(),
        "commands": request.form.get("commands", "").strip(),
        "command_timeout": request.form.get(
            "command_timeout", str(SSH_DEFAULT_COMMAND_TIMEOUT)
        ).strip(),
        "allow_unknown_hosts": request.form.get("allow_unknown_hosts") == "on",
        "allow_legacy_algorithms": request.form.get("allow_legacy_algorithms") == "on",
        "send_ctrl_y": request.form.get("send_ctrl_y") == "on",
        "commandlet_name": request.form.get("commandlet_name", "").strip(),
        "commandlet_description": request.form.get(
            "commandlet_description", ""
        ).strip(),
        "commandlet_platform": request.form.get(
            "commandlet_platform", ""
        ).strip(),
        "commandlet_save_matrix": (
            request.form.get("commandlet_save_matrix") == "on"
        ),
        "commandlet_original_name": request.form.get(
            "commandlet_original_name", ""
        ).strip(),
    }


def _is_legacy_basic_submission() -> bool:
    requested_mode = str(request.form.get("mode", "")).strip().lower()
    return requested_mode == "basic" or (
        "hosts" in request.form and "matrix" not in request.form
    )


def _run_plans(
    form: dict[str, object], preview: dict[str, object]
) -> list[dict[str, object]]:
    return run_ssh_host_plans(
        preview["plans"],
        username=str(form["username"]),
        password=request.form.get("password", ""),
        port=int(str(form["port"])),
        allow_unknown_hosts=bool(form["allow_unknown_hosts"]),
        allow_legacy_algorithms=bool(form["allow_legacy_algorithms"]),
        send_ctrl_y=bool(form["send_ctrl_y"]),
    )


def _annotate_preview_scale(preview: dict[str, object]) -> None:
    plans = list(preview.get("plans", []))
    preview["display_plans"] = plans[:_PREVIEW_DISPLAY_LIMIT]
    preview["hidden_plan_count"] = max(0, len(plans) - _PREVIEW_DISPLAY_LIMIT)
    preview["execution_batch_size"] = SSH_EXECUTION_BATCH_SIZE
    preview["execution_batch_count"] = (
        (len(plans) + SSH_EXECUTION_BATCH_SIZE - 1)
        // SSH_EXECUTION_BATCH_SIZE
    )


def _record_successful_run(
    form: dict[str, object],
    preview: dict[str, object],
    results: list[dict[str, object]],
) -> None:
    host_count = len(preview["plans"])
    command_count = len(preview["plans"][0]["commands"]) if host_count else 0
    record_current_activity(
        "Automation",
        "Ran Bulk SSH",
        f"{host_count} host(s), {command_count} command(s)",
        counters={
            "ssh": {
                "hosts": host_count,
                "commands": host_count * command_count,
            }
        },
    )
    _annotate_run(
        "matrix",
        form,
        outcome="succeeded",
        host_count=host_count,
        command_count=command_count,
        successful_host_count=sum(
            1 for result in results if result.get("status") == "success"
        ),
        variable_count=len(preview["referenced_variables"]),
    )


def _record_failed_run(
    form: dict[str, object],
    preview: dict[str, object] | None,
) -> None:
    host_count = len(preview["plans"]) if preview else 0
    command_count = (
        len(preview["plans"][0]["commands"]) if preview and host_count else 0
    )
    record_current_activity("Automation", "Ran Bulk SSH", "Request failed")
    _annotate_run(
        "matrix",
        form,
        outcome="failed",
        host_count=host_count,
        command_count=command_count,
        successful_host_count=0,
        variable_count=len(preview["referenced_variables"]) if preview else 0,
    )


def _record_ssh_investigation(
    form: dict[str, object],
    preview: dict[str, object] | None,
    results: list[dict[str, object]],
    *,
    error: str,
    operation_id: str,
    started_at: float,
) -> dict[str, object] | None:
    plans = list((preview or {}).get("plans", []))
    safe_plans = [
        {
            "host": str(plan.get("host", "")),
            "label": str(plan.get("label", "")),
            "commands": [str(command) for command in plan.get("commands", [])],
        }
        for plan in plans
        if isinstance(plan, dict)
    ]
    safe_results = [
        {
            key: result.get(key)
            for key in (
                "host",
                "host_label",
                "status",
                "error",
                "timed_out_command",
                "command_timeout",
            )
        }
        for result in results
    ]
    successful = sum(result.get("status") == "success" for result in results)
    command_count = sum(len(plan.get("commands", [])) for plan in safe_plans)
    base_event = {
        "operation_id": operation_id,
        "event_type": "action.failed" if error else "action.completed",
        "tool_id": "tools.multi_ssh",
        "action": "Bulk SSH",
        "outcome": "failed" if error else "succeeded" if successful == len(results) else "incomplete",
        "summary": (
            f"Bulk SSH failed: {error}"
            if error
            else f"Ran {command_count} rendered SSH command(s) across {len(results)} host(s): {successful} succeeded."
        ),
        "targets": [
            {"host": plan["host"], "label": plan["label"]} for plan in safe_plans
        ],
        "parameters": {
            "port": form.get("port"),
            "command_timeout_seconds": form.get("command_timeout"),
            "unknown_hosts_allowed": bool(form.get("allow_unknown_hosts")),
            "legacy_algorithms_allowed": bool(form.get("allow_legacy_algorithms")),
            "plans": safe_plans,
        },
        "metrics": {
            "host_count": len(results),
            "successful_hosts": successful,
            "failed_hosts": len(results) - successful,
            "rendered_command_count": command_count,
        }
        if results
        else {},
        "details": {"error": error, "results": safe_results},
        "started_at": started_at,
        "completed_at": time.time(),
    }
    if error and not results:
        return record_current_investigation_event(**base_event)
    generated = add_current_investigation_generated_evidence_event(
        **base_event,
        filename=f"multi-ssh-{operation_id.rsplit(':', 1)[-1]}-output.txt",
        content_type="text/plain",
        content=_ssh_output(results).encode("utf-8"),
    )
    return generated["event"] if generated else None


def _ssh_output(results: list[dict[str, object]]) -> str:
    sections = []
    for result in results:
        identity = str(result.get("host_label") or result.get("host") or "Host")
        host = str(result.get("host") or "")
        heading = f"=== {identity}{f' ({host})' if host and host != identity else ''} · {result.get('status', '')} ==="
        body = str(result.get("output") or "No output captured.")
        if result.get("error"):
            body += f"\n\nError: {result['error']}"
        sections.append(f"{heading}\n{body.rstrip()}\n")
    return "\n".join(sections)
def _annotate_run(
    mode: str,
    form: dict[str, object],
    *,
    outcome: str,
    host_count: int,
    command_count: int,
    successful_host_count: int,
    variable_count: int = 0,
) -> None:
    annotate_tool_run(
        category="Network tools",
        action_namespace="ssh.multi_host_execution",
        tool_name="Bulk SSH",
        outcome=outcome,
        details={
            "mode": mode,
            "host count": host_count,
            "command count": command_count,
            "rendered command count": host_count * command_count,
            "variable count": variable_count,
            "successful host count": successful_host_count,
            "unknown hosts allowed": bool(form["allow_unknown_hosts"]),
            "legacy SSH compatibility": bool(form["allow_legacy_algorithms"]),
        },
    )


def _save_commandlet(
    form: dict[str, object],
) -> tuple[dict[str, object], bool]:
    store = _ssh_commandlet_store()
    original_name = str(form["commandlet_original_name"])
    requested_name = str(form["commandlet_name"])
    existed = bool(
        store.get(original_name) if original_name else store.get(requested_name)
    )
    commandlet = normalize_ssh_commandlet(
        {
            "name": requested_name,
            "description": form["commandlet_description"],
            "platform": form["commandlet_platform"],
            "commands": form["commands"],
            "command_timeout": form["command_timeout"],
            "target_matrix": (
                form["matrix"] if form["commandlet_save_matrix"] else ""
            ),
            "created_at": (
                (store.get(original_name) or {}).get("created_at", "")
                if original_name
                else (store.get(requested_name) or {}).get("created_at", "")
            ),
        }
    )
    store.upsert(commandlet, original_name=original_name)
    return commandlet, existed


def _annotate_commandlet_save(
    commandlet: dict[str, object], existed: bool
) -> None:
    operation = "updated" if existed else "created"
    annotate_audit_event(
        category="Network tools",
        action=f"ssh.commandlet_{operation}",
        summary=f"{operation.title()} SSH Commandlet {commandlet['name']}.",
        resource_type="ssh_commandlet",
        resource_id=str(commandlet["name"]),
        resource_name=str(commandlet["name"]),
        details={
            "command count": len(
                [
                    line
                    for line in str(commandlet["commands"]).splitlines()
                    if line.strip()
                ]
            ),
            "variables": commandlet["variables"],
            "target matrix stored": bool(commandlet["target_matrix"]),
            "saved target count": int(commandlet["target_count"]),
            "platform configured": bool(commandlet["platform"]),
            "description configured": bool(commandlet["description"]),
        },
    )


def _preview_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"], salt=_PREVIEW_TOKEN_SALT
    )


def _host_key_retry_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"], salt=_HOST_KEY_RETRY_TOKEN_SALT
    )


def _attach_host_key_retry_tokens(
    results: list[dict[str, object]],
    preview: dict[str, object],
    form: dict[str, object],
) -> None:
    plans = list(preview.get("plans", []))
    digest = ssh_command_plan_digest(plans)
    for plan_index, result in enumerate(results):
        mismatch = result.get("host_key_mismatch")
        if not isinstance(mismatch, dict) or plan_index >= len(plans):
            continue
        result["host_key_retry_token"] = _host_key_retry_serializer().dumps(
            {
                "digest": digest,
                "plan_index": plan_index,
                "host": str(plans[plan_index].get("host", "")),
                "port": int(str(form["port"])),
                "expected_fingerprint": str(
                    mismatch.get("expected_fingerprint", "")
                ),
                "presented_fingerprint": str(
                    mismatch.get("presented_fingerprint", "")
                ),
                "allow_legacy_algorithms": bool(
                    form.get("allow_legacy_algorithms")
                ),
                "send_ctrl_y": bool(form.get("send_ctrl_y")),
            }
        )


def _validate_host_key_retry_token(
    token: str,
    plans: list[dict[str, object]],
) -> dict[str, object]:
    if not token:
        raise ToolInputError("Run Bulk SSH again to create a host-key retry.")
    try:
        payload = _host_key_retry_serializer().loads(
            token,
            max_age=SSH_PREVIEW_MAX_AGE_SECONDS,
        )
    except SignatureExpired as exc:
        raise ToolInputError(
            "This host-key retry expired. Run Bulk SSH again."
        ) from exc
    except BadSignature as exc:
        raise ToolInputError(
            "This host-key retry is invalid. Run Bulk SSH again."
        ) from exc
    if not isinstance(payload, dict):
        raise ToolInputError("This host-key retry is invalid. Run Bulk SSH again.")
    expected_digest = ssh_command_plan_digest(plans)
    if not hmac.compare_digest(str(payload.get("digest", "")), expected_digest):
        raise ToolInputError(
            "The targets or commands changed. Run Bulk SSH again."
        )
    try:
        plan_index = int(payload.get("plan_index", -1))
        port = int(payload.get("port", 0))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("This host-key retry is invalid. Run Bulk SSH again.") from exc
    if not 0 <= plan_index < len(plans) or not 1 <= port <= 65535:
        raise ToolInputError("This host-key retry is invalid. Run Bulk SSH again.")
    if not hmac.compare_digest(
        str(payload.get("host", "")),
        str(plans[plan_index].get("host", "")),
    ):
        raise ToolInputError("This host-key retry is invalid. Run Bulk SSH again.")
    for field in ("expected_fingerprint", "presented_fingerprint"):
        if not re.fullmatch(
            r"SHA256:[A-Za-z0-9+/]{43}",
            str(payload.get(field, "")),
        ):
            raise ToolInputError(
                "This host-key retry is invalid. Run Bulk SSH again."
            )
    return payload


def _validate_preview_token(
    token: str, plans: list[dict[str, object]]
) -> None:
    if not token:
        raise ToolInputError(
            "Preview these commands before running them."
        )
    try:
        payload = _preview_serializer().loads(
            token, max_age=SSH_PREVIEW_MAX_AGE_SECONDS
        )
    except SignatureExpired as exc:
        raise ToolInputError(
            "This command preview expired. Preview the commands again."
        ) from exc
    except BadSignature as exc:
        raise ToolInputError(
            "The command preview is invalid. Preview the commands again."
        ) from exc
    expected = ssh_command_plan_digest(plans)
    if not hmac.compare_digest(str(payload.get("digest", "")), expected):
        raise ToolInputError(
            "The targets or commands changed. Preview the commands again."
        )


def _ssh_commandlet_store() -> SSHCommandletStore:
    return SSHCommandletStore(current_app.instance_path)
