from __future__ import annotations

import hmac
import json
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
    SSH_MATRIX_ACTION_LIMIT,
    SSHCommandletStore,
    SSHHostMatrixStore,
    build_ssh_command_plans,
    normalize_ssh_host_matrix,
    normalize_ssh_commandlet,
    normalize_ssh_matrix_action,
    ssh_matrix_actions_to_commands,
    ssh_matrix_command_compatibility,
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
                for key in ("commandlet", "duplicate", "host_matrix", "duplicate_matrix")
                if request.args.get(key)
            }
            return redirect(url_for("tools.multi_ssh", **preserved))

        if (
            request.method == "POST"
            and str(request.form.get("action", "")).strip().lower()
            == "load_profiles"
        ):
            return _load_ssh_profile_selection()

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
            host_matrix_name = str(request.args.get("host_matrix", "")).strip()
            if commandlet_name:
                commandlet = _ssh_commandlet_store().get(commandlet_name)
                if commandlet:
                    duplicate = request.args.get("duplicate") == "1"
                    form.update(
                        {
                            "commands": commandlet["commands"],
                            "command_timeout": str(commandlet["command_timeout"]),
                            "commandlet_name": (
                                f"Copy of {commandlet['name']}"
                                if duplicate
                                else commandlet["name"]
                            ),
                            "commandlet_description": commandlet.get(
                                "description", ""
                            ),
                            "commandlet_platform": commandlet.get("platform", ""),
                            "commandlet_original_name": (
                                "" if duplicate else commandlet["name"]
                            ),
                        }
                    )
                    if not host_matrix_name and commandlet.get("matrix_names"):
                        host_matrix_name = str(commandlet["matrix_names"][0])
                else:
                    error = "That command set no longer exists."
            if host_matrix_name:
                host_matrix = _ssh_host_matrix_store().get(host_matrix_name)
                if host_matrix:
                    duplicate_matrix = request.args.get("duplicate_matrix") == "1"
                    _load_host_matrix_form(
                        form,
                        host_matrix,
                        duplicate=duplicate_matrix,
                    )
                else:
                    error = "That host matrix no longer exists."

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
            elif action == "save_host_matrix":
                try:
                    host_matrix, existed = _save_host_matrix(form)
                except (ToolInputError, ValueError) as exc:
                    error = str(exc)
                    suppress_audit_event()
                else:
                    success = (
                        f"Host matrix '{host_matrix['name']}' "
                        f"{'updated' if existed else 'saved'}."
                    )
                    form["host_matrix_name"] = host_matrix["name"]
                    form["host_matrix_original_name"] = host_matrix["name"]
                    form["matrix_actions"] = host_matrix.get("actions", [])
                    _annotate_host_matrix_save(host_matrix, existed)
            elif action == "save_matrix_action":
                try:
                    host_matrix, matrix_action, existed = _save_matrix_action(form)
                except (ToolInputError, ValueError) as exc:
                    error = str(exc)
                    suppress_audit_event()
                else:
                    _load_host_matrix_form(form, host_matrix)
                    form["matrix_action_name"] = matrix_action["name"]
                    form["matrix_action_original_name"] = matrix_action["name"]
                    success = (
                        f"CLI action '{matrix_action['name']}' "
                        f"{'updated' if existed else 'added'} to '{host_matrix['name']}'."
                    )
                    _annotate_matrix_action_save(host_matrix, matrix_action, existed)
            elif action == "copy_matrix_action":
                try:
                    host_matrix, matrix_action = _copy_matrix_action(form)
                except (ToolInputError, ValueError, json.JSONDecodeError) as exc:
                    error = str(exc)
                    suppress_audit_event()
                else:
                    _load_host_matrix_form(form, host_matrix)
                    form["matrix_action_name"] = matrix_action["name"]
                    form["matrix_action_original_name"] = matrix_action["name"]
                    success = (
                        f"Copied CLI action '{matrix_action['name']}' into "
                        f"'{host_matrix['name']}' as an independent action."
                    )
                    _annotate_matrix_action_save(host_matrix, matrix_action, False)
            elif action == "duplicate_matrix_action":
                try:
                    host_matrix, matrix_action = _duplicate_matrix_action(form)
                except (ToolInputError, ValueError) as exc:
                    error = str(exc)
                    suppress_audit_event()
                else:
                    _load_host_matrix_form(form, host_matrix)
                    form["matrix_action_name"] = matrix_action["name"]
                    form["matrix_action_original_name"] = matrix_action["name"]
                    success = f"CLI action duplicated as '{matrix_action['name']}'."
                    _annotate_matrix_action_save(host_matrix, matrix_action, False)
            elif action == "delete_matrix_action":
                try:
                    host_matrix, deleted_name = _delete_matrix_action(form)
                except (ToolInputError, ValueError) as exc:
                    error = str(exc)
                    suppress_audit_event()
                else:
                    _load_host_matrix_form(form, host_matrix)
                    success = f"CLI action '{deleted_name}' deleted."
                    _annotate_matrix_action_delete(host_matrix, deleted_name)
            elif action == "move_matrix_action":
                try:
                    host_matrix = _move_matrix_action(form)
                except (ToolInputError, ValueError) as exc:
                    error = str(exc)
                    suppress_audit_event()
                else:
                    _load_host_matrix_form(form, host_matrix)
                    suppress_audit_event()
            elif action == "save_commandlet":
                try:
                    commandlet, existed = _save_commandlet(form)
                except (ToolInputError, ValueError) as exc:
                    error = str(exc)
                    suppress_audit_event()
                else:
                    success = (
                        f"Command set '{commandlet['name']}' "
                        f"{'updated' if existed else 'saved'}."
                    )
                    form["commandlet_name"] = commandlet["name"]
                    form["commandlet_original_name"] = commandlet["name"]
                    _annotate_commandlet_save(commandlet, existed)
            else:
                try:
                    preview = _build_ssh_preview(form)
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

        host_matrices, commandlets, current_compatibility = _ssh_profile_options(form)
        selected_matrix = _selected_host_matrix(form)
        matrix_actions = _annotated_matrix_actions(selected_matrix, form)
        selected_run_actions = _selected_run_actions(matrix_actions, form)
        selected_action = _selected_matrix_action(matrix_actions, form)
        action_editor = _matrix_action_editor(form, selected_action)
        active_workspace = _active_ssh_workspace(
            preview=preview,
            results=results,
        )
        return render_template(
            "tools/multi_ssh.html",
            error=error,
            success=success,
            form=form,
            results=results,
            preview=preview,
            preview_token=preview_token,
            commandlets=commandlets,
            host_matrices=host_matrices,
            current_compatibility=current_compatibility,
            selected_matrix=selected_matrix,
            matrix_actions=matrix_actions,
            selected_run_actions=selected_run_actions,
            selected_action=selected_action,
            action_editor=action_editor,
            action_sources=_ssh_action_sources(selected_matrix),
            active_workspace=active_workspace,
            ssh_matrix_action_limit=SSH_MATRIX_ACTION_LIMIT,
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
            flash("That command set no longer exists.", "error")
            suppress_audit_event()
        else:
            store.delete(name)
            flash(f"Command set '{name}' deleted.", "success")
            annotate_audit_event(
                category="Network tools",
                action="ssh.commandlet_deleted",
                summary=f"Deleted SSH command set {name}.",
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
                    "related host matrices": commandlet.get("matrix_names", []),
                },
            )
        return redirect(url_for("tools.multi_ssh"))

    @tools_bp.post("/multi-ssh/host-matrices/delete")
    def delete_ssh_host_matrix():
        name = str(request.form.get("name", "")).strip()
        store = _ssh_host_matrix_store()
        matrix = store.get(name)
        if not matrix:
            flash("That host matrix no longer exists.", "error")
            suppress_audit_event()
        else:
            store.delete(name)
            _remove_matrix_relationship(name)
            flash(f"Host matrix '{name}' deleted.", "success")
            annotate_audit_event(
                category="Network tools",
                action="ssh.host_matrix_deleted",
                summary=f"Deleted SSH host matrix {name}.",
                resource_type="ssh_host_matrix",
                resource_id=name,
                resource_name=name,
                details={
                    "target count": int(matrix.get("target_count", 0)),
                    "variables": matrix.get("variables", []),
                    "CLI action count": len(matrix.get("actions", [])),
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
        "host_matrix_name": "",
        "host_matrix_description": "",
        "host_matrix_original_name": "",
        "source_host_matrix": "",
        "matrix_actions": [],
        "selected_actions": [],
        "matrix_action_run": False,
        "matrix_action_name": "",
        "matrix_action_description": "",
        "matrix_action_platform": "",
        "matrix_action_original_name": "",
        "commandlet_name": "",
        "commandlet_description": "",
        "commandlet_platform": "",
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
        "host_matrix_name": request.form.get("host_matrix_name", "").strip(),
        "host_matrix_description": request.form.get(
            "host_matrix_description", ""
        ).strip(),
        "host_matrix_original_name": request.form.get(
            "host_matrix_original_name", ""
        ).strip(),
        "source_host_matrix": request.form.get("source_host_matrix", "").strip(),
        "matrix_actions": [],
        "selected_actions": [
            str(name).strip()
            for name in request.form.getlist("selected_actions")
            if str(name).strip()
        ],
        "matrix_action_run": request.form.get("matrix_action_run") == "on",
        "matrix_action_name": request.form.get("matrix_action_name", "").strip(),
        "matrix_action_description": request.form.get(
            "matrix_action_description", ""
        ).strip(),
        "matrix_action_platform": request.form.get(
            "matrix_action_platform", ""
        ).strip(),
        "matrix_action_original_name": request.form.get(
            "matrix_action_original_name", ""
        ).strip(),
        "commandlet_name": request.form.get("commandlet_name", "").strip(),
        "commandlet_description": request.form.get(
            "commandlet_description", ""
        ).strip(),
        "commandlet_platform": request.form.get(
            "commandlet_platform", ""
        ).strip(),
        "legacy_commandlet_save_matrix": (
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


def _load_host_matrix_form(
    form: dict[str, object],
    matrix: dict[str, object],
    *,
    duplicate: bool = False,
) -> None:
    form.update(
        {
            "matrix": matrix["matrix"],
            "host_matrix_name": (
                f"Copy of {matrix['name']}" if duplicate else matrix["name"]
            ),
            "host_matrix_description": matrix.get("description", ""),
            "host_matrix_original_name": "" if duplicate else matrix["name"],
            "source_host_matrix": str(matrix["name"]) if duplicate else "",
            "matrix_actions": list(matrix.get("actions", [])),
            # Loading or saving a matrix must never opt its action library into a
            # run. Operators assemble an explicit, ordered runbook on the Run tab.
            "selected_actions": [],
        }
    )


def _build_ssh_preview(form: dict[str, object]) -> dict[str, object]:
    if not bool(form.get("matrix_action_run")):
        preview = build_ssh_command_plans(
            str(form["matrix"]),
            str(form["commands"]),
            int(str(form["command_timeout"])),
        )
        preview["selected_actions"] = []
        return preview

    matrix_name = str(
        form.get("host_matrix_original_name") or form.get("host_matrix_name") or ""
    )
    matrix = _ssh_host_matrix_store().get(matrix_name) if matrix_name else None
    if not matrix:
        raise ToolInputError("Save or load a host matrix before running CLI actions.")
    requested = list(dict.fromkeys(str(name) for name in form["selected_actions"]))
    if not requested:
        raise ToolInputError("Select at least one CLI action.")
    actions_by_name = {
        str(action["name"]): action for action in matrix.get("actions", [])
    }
    actions = [actions_by_name[name] for name in requested if name in actions_by_name]
    missing = [
        name
        for name in requested
        if not any(str(action["name"]) == name for action in actions)
    ]
    if missing:
        raise ToolInputError(
            "One or more selected CLI actions no longer exist. Review the run queue."
        )
    commands = ssh_matrix_actions_to_commands(actions)
    form["matrix"] = str(matrix["matrix"])
    form["commands"] = commands
    form["command_timeout"] = str(SSH_DEFAULT_COMMAND_TIMEOUT)
    preview = build_ssh_command_plans(
        str(matrix["matrix"]),
        commands,
        SSH_DEFAULT_COMMAND_TIMEOUT,
    )
    preview["selected_actions"] = actions
    preview["action_count"] = len(actions)
    preview["action_execution_count"] = len(actions) * len(preview["plans"])
    preview["representative_plan"] = preview["plans"][0] if preview["plans"] else None
    return preview


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


def _save_matrix_action(
    form: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], bool]:
    store = _ssh_host_matrix_store()
    matrix_name = str(form.get("host_matrix_original_name", ""))
    matrix = store.get(matrix_name) if matrix_name else None
    if not matrix:
        raise ToolInputError("Save or load a host matrix before adding CLI actions.")
    original_name = str(form.get("matrix_action_original_name", ""))
    requested_name = str(form.get("matrix_action_name", ""))
    actions = list(matrix.get("actions", []))
    existing = next(
        (action for action in actions if str(action["name"]) == original_name),
        None,
    )
    if not original_name and any(
        str(action["name"]).casefold() == requested_name.casefold()
        for action in actions
    ):
        raise ToolInputError(
            "A CLI action with that name already exists in this host matrix."
        )
    matrix_action = normalize_ssh_matrix_action(
        {
            "name": requested_name,
            "description": form.get("matrix_action_description", ""),
            "platform": form.get("matrix_action_platform", ""),
            "commands": form.get("commands", ""),
            "command_timeout": form.get(
                "command_timeout", SSH_DEFAULT_COMMAND_TIMEOUT
            ),
            "created_at": (existing or {}).get("created_at", ""),
        }
    )
    for action in actions:
        if action is existing:
            continue
        if str(action["name"]).casefold() == str(matrix_action["name"]).casefold():
            raise ToolInputError(
                "CLI-action names must be unique within a host matrix."
            )
    _require_action_compatibility(matrix, matrix_action)
    if existing:
        actions[actions.index(existing)] = matrix_action
    else:
        if len(actions) >= SSH_MATRIX_ACTION_LIMIT:
            raise ToolInputError(
                f"A maximum of {SSH_MATRIX_ACTION_LIMIT} CLI actions is allowed per matrix."
            )
        actions.append(matrix_action)
    store.upsert({**matrix, "actions": actions}, original_name=matrix_name)
    saved = store.get(matrix_name)
    if not saved:
        raise ToolInputError("The host matrix could not be updated.")
    saved_action = next(
        action
        for action in saved.get("actions", [])
        if str(action["name"]) == str(matrix_action["name"])
    )
    return saved, saved_action, existing is not None


def _copy_matrix_action(
    form: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    store = _ssh_host_matrix_store()
    matrix_name = str(form.get("host_matrix_original_name", ""))
    matrix = store.get(matrix_name) if matrix_name else None
    if not matrix:
        raise ToolInputError("Save or load a host matrix before copying CLI actions.")
    raw_source = str(request.form.get("copy_action_source", "")).strip()
    if not raw_source:
        raise ToolInputError("Choose a CLI action to copy.")
    source = json.loads(raw_source)
    if not isinstance(source, dict):
        raise ToolInputError("Choose a valid CLI action to copy.")
    source_action: dict[str, object] | None = None
    if source.get("kind") == "matrix":
        source_matrix = store.get(str(source.get("matrix", "")))
        if source_matrix:
            source_action = next(
                (
                    action
                    for action in source_matrix.get("actions", [])
                    if str(action["name"]) == str(source.get("action", ""))
                ),
                None,
            )
    elif source.get("kind") == "legacy":
        source_action = _ssh_commandlet_store().get(str(source.get("action", "")))
    if not source_action:
        raise ToolInputError("That source CLI action no longer exists.")
    existing_names = {str(action["name"]) for action in matrix.get("actions", [])}
    copied_name = _unique_matrix_action_name(str(source_action["name"]), existing_names)
    copied = normalize_ssh_matrix_action(
        {
            **source_action,
            "name": copied_name,
            "created_at": "",
        }
    )
    _require_action_compatibility(matrix, copied)
    actions = [*matrix.get("actions", []), copied]
    if len(actions) > SSH_MATRIX_ACTION_LIMIT:
        raise ToolInputError(
            f"A maximum of {SSH_MATRIX_ACTION_LIMIT} CLI actions is allowed per matrix."
        )
    store.upsert({**matrix, "actions": actions}, original_name=matrix_name)
    saved = store.get(matrix_name)
    if not saved:
        raise ToolInputError("The host matrix could not be updated.")
    saved_action = next(
        action
        for action in saved.get("actions", [])
        if str(action["name"]) == copied_name
    )
    return saved, saved_action


def _duplicate_matrix_action(
    form: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    store = _ssh_host_matrix_store()
    matrix_name = str(form.get("host_matrix_original_name", ""))
    matrix = store.get(matrix_name) if matrix_name else None
    if not matrix:
        raise ToolInputError("That host matrix no longer exists.")
    action_name = str(
        form.get("matrix_action_original_name") or form.get("matrix_action_name") or ""
    )
    source = next(
        (
            action
            for action in matrix.get("actions", [])
            if str(action["name"]) == action_name
        ),
        None,
    )
    if not source:
        raise ToolInputError("That CLI action no longer exists.")
    existing_names = {str(action["name"]) for action in matrix.get("actions", [])}
    copied_name = _unique_matrix_action_name(str(source["name"]), existing_names)
    copied = normalize_ssh_matrix_action(
        {**source, "name": copied_name, "created_at": ""}
    )
    actions = [*matrix.get("actions", []), copied]
    if len(actions) > SSH_MATRIX_ACTION_LIMIT:
        raise ToolInputError(
            f"A maximum of {SSH_MATRIX_ACTION_LIMIT} CLI actions is allowed per matrix."
        )
    store.upsert({**matrix, "actions": actions}, original_name=matrix_name)
    saved = store.get(matrix_name)
    if not saved:
        raise ToolInputError("The host matrix could not be updated.")
    saved_action = next(
        action
        for action in saved.get("actions", [])
        if str(action["name"]) == copied_name
    )
    return saved, saved_action


def _delete_matrix_action(
    form: dict[str, object],
) -> tuple[dict[str, object], str]:
    store = _ssh_host_matrix_store()
    matrix_name = str(form.get("host_matrix_original_name", ""))
    matrix = store.get(matrix_name) if matrix_name else None
    if not matrix:
        raise ToolInputError("That host matrix no longer exists.")
    action_name = str(
        request.form.get("matrix_action_original_name", "")
        or request.form.get("matrix_action_name", "")
    ).strip()
    actions = [
        action
        for action in matrix.get("actions", [])
        if str(action["name"]) != action_name
    ]
    if len(actions) == len(matrix.get("actions", [])):
        raise ToolInputError("That CLI action no longer exists.")
    store.upsert({**matrix, "actions": actions}, original_name=matrix_name)
    saved = store.get(matrix_name)
    if not saved:
        raise ToolInputError("The host matrix could not be updated.")
    return saved, action_name


def _move_matrix_action(form: dict[str, object]) -> dict[str, object]:
    store = _ssh_host_matrix_store()
    matrix_name = str(form.get("host_matrix_original_name", ""))
    matrix = store.get(matrix_name) if matrix_name else None
    if not matrix:
        raise ToolInputError("That host matrix no longer exists.")
    action_name = str(request.form.get("move_action_name", "")).strip()
    direction = str(request.form.get("move_action_direction", "")).strip()
    actions = list(matrix.get("actions", []))
    index = next(
        (
            position
            for position, action in enumerate(actions)
            if str(action["name"]) == action_name
        ),
        -1,
    )
    if index < 0 or direction not in {"up", "down"}:
        raise ToolInputError("Choose a valid CLI action to move.")
    destination = index - 1 if direction == "up" else index + 1
    if 0 <= destination < len(actions):
        actions[index], actions[destination] = actions[destination], actions[index]
        store.upsert({**matrix, "actions": actions}, original_name=matrix_name)
    saved = store.get(matrix_name)
    if not saved:
        raise ToolInputError("The host matrix could not be updated.")
    return saved


def _require_action_compatibility(
    matrix: dict[str, object],
    action: dict[str, object],
) -> None:
    compatibility = ssh_matrix_command_compatibility(
        str(matrix["matrix"]),
        str(action["commands"]),
    )
    if compatibility["missing_variables"]:
        missing = ", ".join(str(name) for name in compatibility["missing_variables"])
        raise ToolInputError(
            f"CLI action '{action['name']}' requires missing matrix column(s): {missing}."
        )
    if compatibility["incomplete_targets"]:
        raise ToolInputError(
            f"CLI action '{action['name']}' has "
            f"{len(compatibility['incomplete_targets'])} target row(s) with missing values."
        )


def _unique_matrix_action_name(base: str, existing: set[str]) -> str:
    comparable = {name.casefold() for name in existing}
    if base.casefold() not in comparable:
        return base
    suffix = 2
    while True:
        ending = f" ({suffix})"
        candidate = f"{base[: 100 - len(ending)]}{ending}"
        if candidate.casefold() not in comparable:
            return candidate
        suffix += 1


def _annotate_matrix_action_save(
    matrix: dict[str, object],
    action: dict[str, object],
    existed: bool,
) -> None:
    operation = "updated" if existed else "created"
    annotate_audit_event(
        category="Network tools",
        action=f"ssh.matrix_action_{operation}",
        summary=(
            f"{operation.title()} SSH CLI action {action['name']} in host matrix "
            f"{matrix['name']}."
        ),
        resource_type="ssh_matrix_action",
        resource_id=f"{matrix['name']}:{action['name']}",
        resource_name=str(action["name"]),
        details={
            "host matrix": matrix["name"],
            "variables": action.get("variables", []),
            "command count": len(
                [
                    line
                    for line in str(action.get("commands", "")).splitlines()
                    if line.strip()
                ]
            ),
        },
    )


def _annotate_matrix_action_delete(
    matrix: dict[str, object],
    action_name: str,
) -> None:
    annotate_audit_event(
        category="Network tools",
        action="ssh.matrix_action_deleted",
        summary=f"Deleted SSH CLI action {action_name} from host matrix {matrix['name']}.",
        resource_type="ssh_matrix_action",
        resource_id=f"{matrix['name']}:{action_name}",
        resource_name=action_name,
        details={"host matrix": matrix["name"]},
    )


def _save_commandlet(
    form: dict[str, object],
) -> tuple[dict[str, object], bool]:
    store = _ssh_commandlet_store()
    matrix_store = _ssh_host_matrix_store()
    original_name = str(form["commandlet_original_name"])
    requested_name = str(form["commandlet_name"])
    existing = (
        store.get(original_name) if original_name else store.get(requested_name)
    )
    existed = bool(
        existing
    )
    matrix_names = []
    for matrix_name in list((existing or {}).get("matrix_names", [])):
        matrix = matrix_store.get(str(matrix_name))
        if matrix and _profiles_are_compatible(matrix, {**(existing or {}), "commands": form["commands"]}):
            matrix_names.append(str(matrix_name))
    selected_matrix_name = str(
        form.get("host_matrix_original_name") or form.get("host_matrix_name") or ""
    )
    selected_matrix = matrix_store.get(selected_matrix_name) if selected_matrix_name else None
    if selected_matrix and _profiles_are_compatible(
        selected_matrix, {"commands": form["commands"]}
    ):
        if selected_matrix_name not in matrix_names:
            matrix_names.append(selected_matrix_name)
    payload = {
        "name": requested_name,
        "description": form["commandlet_description"],
        "platform": form["commandlet_platform"],
        "commands": form["commands"],
        "command_timeout": form["command_timeout"],
        "matrix_names": matrix_names,
        "target_matrix": (
            form["matrix"] if form.get("legacy_commandlet_save_matrix") else ""
        ),
        "created_at": (existing or {}).get("created_at", ""),
    }
    store.upsert(payload, original_name=original_name)
    commandlet = store.get(requested_name)
    if commandlet is None:
        raise ToolInputError("The command set could not be saved.")
    return commandlet, existed


def _load_ssh_profile_selection():
    matrix_name = str(request.form.get("host_matrix", "")).strip()
    commandlet_name = str(request.form.get("commandlet", "")).strip()
    destination: dict[str, str] = {}
    if matrix_name:
        destination["host_matrix"] = matrix_name
    if commandlet_name:
        destination["commandlet"] = commandlet_name

    matrix = _ssh_host_matrix_store().get(matrix_name) if matrix_name else None
    store = _ssh_commandlet_store()
    commandlet = store.get(commandlet_name) if commandlet_name else None
    if matrix and commandlet and _profiles_are_compatible(matrix, commandlet):
        matrix_names = [
            str(name) for name in commandlet.get("matrix_names", [])
        ]
        if matrix_name not in matrix_names:
            matrix_names.append(matrix_name)
            store.upsert(
                {
                    **commandlet,
                    "target_matrix": "",
                    "matrix_names": matrix_names,
                },
                original_name=str(commandlet["name"]),
            )
            flash(
                f"'{matrix_name}' and '{commandlet_name}' are now a remembered pairing.",
                "success",
            )
            annotate_audit_event(
                category="Network tools",
                action="ssh.profile_pairing_remembered",
                summary=(
                    f"Related SSH host matrix {matrix_name} to command set "
                    f"{commandlet_name}."
                ),
                resource_type="ssh_commandlet",
                resource_id=commandlet_name,
                resource_name=commandlet_name,
                details={"host matrix": matrix_name},
            )
        else:
            suppress_audit_event()
    else:
        suppress_audit_event()
    return redirect(url_for("tools.multi_ssh", **destination))


def _save_host_matrix(
    form: dict[str, object],
) -> tuple[dict[str, object], bool]:
    store = _ssh_host_matrix_store()
    original_name = str(form["host_matrix_original_name"])
    requested_name = str(form["host_matrix_name"])
    existing = store.get(original_name) if original_name else store.get(requested_name)
    source_name = str(form.get("source_host_matrix", ""))
    source = existing or (store.get(source_name) if source_name else None)
    matrix = normalize_ssh_host_matrix(
        {
            "name": requested_name,
            "description": form["host_matrix_description"],
            "matrix": form["matrix"],
            "actions": list((source or {}).get("actions", [])),
            "created_at": (existing or {}).get("created_at", ""),
        }
    )
    for matrix_action in matrix.get("actions", []):
        _require_action_compatibility(matrix, matrix_action)
    store.upsert(matrix, original_name=original_name)
    _reconcile_matrix_relationships(
        original_name=original_name,
        matrix=matrix,
        selected_commandlet_name=str(
            form.get("commandlet_original_name") or form.get("commandlet_name") or ""
        ),
    )
    return matrix, bool(existing)


def _annotate_commandlet_save(
    commandlet: dict[str, object], existed: bool
) -> None:
    operation = "updated" if existed else "created"
    annotate_audit_event(
        category="Network tools",
        action=f"ssh.commandlet_{operation}",
        summary=f"{operation.title()} SSH command set {commandlet['name']}.",
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
            "related host matrices": commandlet.get("matrix_names", []),
            "platform configured": bool(commandlet["platform"]),
            "description configured": bool(commandlet["description"]),
        },
    )


def _annotate_host_matrix_save(
    matrix: dict[str, object], existed: bool
) -> None:
    operation = "updated" if existed else "created"
    annotate_audit_event(
        category="Network tools",
        action=f"ssh.host_matrix_{operation}",
        summary=f"{operation.title()} SSH host matrix {matrix['name']}.",
        resource_type="ssh_host_matrix",
        resource_id=str(matrix["name"]),
        resource_name=str(matrix["name"]),
        details={
            "target count": int(matrix["target_count"]),
            "variables": matrix["variables"],
            "CLI action count": len(matrix.get("actions", [])),
            "description configured": bool(matrix["description"]),
        },
    )


def _selected_host_matrix(form: dict[str, object]) -> dict[str, object] | None:
    name = str(
        form.get("host_matrix_original_name") or form.get("host_matrix_name") or ""
    )
    return _ssh_host_matrix_store().get(name) if name else None


def _annotated_matrix_actions(
    matrix: dict[str, object] | None,
    form: dict[str, object],
) -> list[dict[str, object]]:
    actions = list(
        matrix.get("actions", []) if matrix else form.get("matrix_actions", [])
    )
    matrix_text = str(form.get("matrix") or (matrix or {}).get("matrix", ""))
    annotated: list[dict[str, object]] = []
    for index, action in enumerate(actions, start=1):
        annotated.append(
            {
                **action,
                "order": index,
                "compatibility": _compatibility_or_none(
                    matrix_text,
                    str(action.get("commands", "")),
                ),
            }
        )
    return annotated


def _selected_matrix_action(
    actions: list[dict[str, object]],
    form: dict[str, object],
) -> dict[str, object] | None:
    if request.args.get("new_action") == "1":
        return None
    requested = str(
        request.args.get("matrix_action", "")
        or form.get("matrix_action_original_name")
        or form.get("matrix_action_name")
        or ""
    ).strip()
    if requested:
        selected = next(
            (action for action in actions if str(action["name"]) == requested),
            None,
        )
        if selected:
            return selected
    return actions[0] if actions else None


def _selected_run_actions(
    actions: list[dict[str, object]],
    form: dict[str, object],
) -> list[dict[str, object]]:
    """Return the temporary runbook in the operator-selected order."""
    actions_by_name = {str(action["name"]): action for action in actions}
    requested = list(
        dict.fromkeys(str(name) for name in form.get("selected_actions", []))
    )
    return [actions_by_name[name] for name in requested if name in actions_by_name]


def _matrix_action_editor(
    form: dict[str, object],
    selected: dict[str, object] | None,
) -> dict[str, object]:
    posted_action = str(request.form.get("action", "")).strip().lower()
    if request.method == "POST" and posted_action == "save_matrix_action":
        return {
            "name": form.get("matrix_action_name", ""),
            "description": form.get("matrix_action_description", ""),
            "platform": form.get("matrix_action_platform", ""),
            "commands": form.get("commands", ""),
            "command_timeout": form.get(
                "command_timeout", str(SSH_DEFAULT_COMMAND_TIMEOUT)
            ),
            "original_name": form.get("matrix_action_original_name", ""),
        }
    if selected:
        return {
            **selected,
            "original_name": selected["name"],
        }
    return {
        "name": "",
        "description": "",
        "platform": "",
        "commands": "",
        "command_timeout": SSH_DEFAULT_COMMAND_TIMEOUT,
        "original_name": "",
    }


def _ssh_action_sources(
    selected_matrix: dict[str, object] | None,
) -> list[dict[str, object]]:
    selected_name = str((selected_matrix or {}).get("name", ""))
    sources: list[dict[str, object]] = []

    def append_source(
        *,
        group: str,
        label: str,
        value: str,
        action: dict[str, object],
    ) -> None:
        compatibility = _compatibility_or_none(
            str((selected_matrix or {}).get("matrix", "")),
            str(action.get("commands", "")),
        )
        missing = list((compatibility or {}).get("missing_variables", []))
        incomplete = list((compatibility or {}).get("incomplete_targets", []))
        if missing:
            reason = f"missing {', '.join(str(name) for name in missing)}"
        elif incomplete:
            reason = f"{len(incomplete)} host row(s) need values"
        else:
            reason = ""
        sources.append(
            {
                "group": group,
                "label": label,
                "value": value,
                "compatible": bool(compatibility and compatibility["compatible"]),
                "reason": reason,
            }
        )

    for matrix in _ssh_host_matrix_store().all():
        if str(matrix["name"]) == selected_name:
            continue
        for action in matrix.get("actions", []):
            append_source(
                group=str(matrix["name"]),
                label=str(action["name"]),
                value=json.dumps(
                    {
                        "kind": "matrix",
                        "matrix": matrix["name"],
                        "action": action["name"],
                    },
                    separators=(",", ":"),
                ),
                action=action,
            )
    for commandlet in _ssh_commandlet_store().all():
        append_source(
            group="Imported command sets (pre-v0.22)",
            label=str(commandlet["name"]),
            value=json.dumps(
                {"kind": "legacy", "action": commandlet["name"]},
                separators=(",", ":"),
            ),
            action=commandlet,
        )
    return sources


def _active_ssh_workspace(
    *,
    preview: dict[str, object] | None,
    results: list[dict[str, object]] | None,
) -> str:
    requested = str(request.values.get("workspace", "")).strip().lower()
    if requested in {"hosts", "actions", "run"}:
        return requested
    posted_action = str(request.form.get("action", "")).strip().lower()
    if preview is not None or results is not None or posted_action in {"preview", "run"}:
        return "run"
    if "matrix_action" in request.args or request.args.get("new_action") == "1":
        return "actions"
    if posted_action in {
        "save_matrix_action",
        "copy_matrix_action",
        "duplicate_matrix_action",
        "delete_matrix_action",
        "move_matrix_action",
    }:
        return "actions"
    return "hosts"


def _ssh_profile_options(
    form: dict[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, object] | None]:
    matrices = _ssh_host_matrix_store().all()
    commandlets = _ssh_commandlet_store().all()
    commands = str(form.get("commands", ""))
    matrix_text = str(form.get("matrix", ""))
    selected_matrix_name = str(
        form.get("host_matrix_original_name") or form.get("host_matrix_name") or ""
    )
    annotated_matrices: list[dict[str, object]] = []
    for matrix in matrices:
        compatibility = _compatibility_or_none(str(matrix["matrix"]), commands)
        annotated_matrices.append({**matrix, "compatibility": compatibility})
    annotated_commandlets: list[dict[str, object]] = []
    for commandlet in commandlets:
        compatibility = _compatibility_or_none(matrix_text, str(commandlet["commands"]))
        annotated_commandlets.append(
            {
                **commandlet,
                "compatibility": compatibility,
                "related_to_selected": selected_matrix_name
                in commandlet.get("matrix_names", []),
            }
        )
    annotated_commandlets.sort(
        key=lambda item: (
            not bool(item.get("related_to_selected")),
            not bool((item.get("compatibility") or {}).get("compatible")),
            str(item["name"]).lower(),
        )
    )
    current = _compatibility_or_none(matrix_text, commands)
    return annotated_matrices, annotated_commandlets, current


def _compatibility_or_none(
    matrix_text: str, commands: str
) -> dict[str, object] | None:
    if not matrix_text.strip() or not commands.strip():
        return None
    try:
        return ssh_matrix_command_compatibility(matrix_text, commands)
    except (ToolInputError, ValueError):
        return None


def _profiles_are_compatible(
    matrix: dict[str, object], commandlet: dict[str, object]
) -> bool:
    compatibility = _compatibility_or_none(
        str(matrix.get("matrix", "")), str(commandlet.get("commands", ""))
    )
    return bool(compatibility and compatibility["compatible"])


def _reconcile_matrix_relationships(
    *,
    original_name: str,
    matrix: dict[str, object],
    selected_commandlet_name: str,
) -> None:
    store = _ssh_commandlet_store()
    matrix_store = _ssh_host_matrix_store()
    for commandlet in store.all():
        names = [
            str(name)
            for name in commandlet.get("matrix_names", [])
            if matrix_store.get(str(name))
        ]
        if original_name and original_name != matrix["name"]:
            names = [
                str(matrix["name"]) if name == original_name else name
                for name in names
            ]
        names = [
            name
            for name in dict.fromkeys(names)
            if (saved := matrix_store.get(name))
            and _profiles_are_compatible(saved, commandlet)
        ]
        if (
            commandlet["name"] == selected_commandlet_name
            and _profiles_are_compatible(matrix, commandlet)
            and matrix["name"] not in names
        ):
            names.append(str(matrix["name"]))
        if names != commandlet.get("matrix_names", []):
            store.upsert({**commandlet, "matrix_names": names})


def _remove_matrix_relationship(name: str) -> None:
    store = _ssh_commandlet_store()
    for commandlet in store.all():
        names = [
            str(matrix_name)
            for matrix_name in commandlet.get("matrix_names", [])
            if str(matrix_name) != name
        ]
        if names != commandlet.get("matrix_names", []):
            store.upsert({**commandlet, "matrix_names": names})


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


def _ssh_host_matrix_store() -> SSHHostMatrixStore:
    return SSHHostMatrixStore(current_app.instance_path)
