from __future__ import annotations

import hmac

from flask import (
    Blueprint,
    current_app,
    flash,
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
    ToolInputError,
    parse_ssh_targets,
    run_ssh_host_plans,
    run_ssh_hosts,
)
from .ssh_commandlets import (
    SSH_PREVIEW_MAX_AGE_SECONDS,
    SSHCommandletStore,
    build_ssh_command_plans,
    normalize_ssh_commandlet,
    ssh_command_plan_digest,
)


_PREVIEW_TOKEN_SALT = "multi-ssh-advanced-preview-v1"


def register_ssh_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/multi-ssh", methods=["GET", "POST"])
    def multi_ssh():
        mode = _requested_mode()
        form = _default_form(mode)
        results: list[dict[str, object]] | None = None
        preview: dict[str, object] | None = None
        preview_token = ""
        error = ""
        success = ""

        if request.method == "GET" and mode == "advanced":
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
            form = _posted_form(mode)
            action = str(request.form.get("action", "run")).strip().lower()
            if mode == "advanced" and action == "save_commandlet":
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
            elif mode == "advanced":
                try:
                    preview = build_ssh_command_plans(
                        str(form["matrix"]),
                        str(form["commands"]),
                        int(str(form["command_timeout"])),
                    )
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
                        results = _run_advanced(form, preview)
                    else:
                        raise ToolInputError("Choose Preview commands or Run commands.")
                except (ToolInputError, TypeError, ValueError) as exc:
                    error = str(exc) if str(exc) else "Enter a valid SSH port."
                    if action == "run":
                        _record_failed_run("advanced", form, preview)
                    else:
                        suppress_audit_event()
                else:
                    if action == "run":
                        _record_successful_run("advanced", form, preview, results or [])
            else:
                try:
                    results, host_count, command_count = _run_basic(form)
                except (ToolInputError, ValueError) as exc:
                    error = str(exc) if str(exc) else "Enter a valid SSH port."
                    record_current_activity("Automation", "Ran Multi-SSH", "Request failed")
                    _annotate_run(
                        "basic",
                        form,
                        outcome="failed",
                        host_count=0,
                        command_count=0,
                        successful_host_count=0,
                    )
                else:
                    _record_basic_success(
                        form, results, host_count, command_count
                    )

        return render_template(
            "tools/multi_ssh.html",
            error=error,
            success=success,
            form=form,
            mode=mode,
            results=results,
            preview=preview,
            preview_token=preview_token,
            commandlets=_ssh_commandlet_store().all(),
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
        return redirect(url_for("tools.multi_ssh", mode="advanced"))


def _default_form(mode: str) -> dict[str, object]:
    return {
        "mode": mode,
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


def _posted_form(mode: str) -> dict[str, object]:
    return {
        "mode": mode,
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


def _requested_mode() -> str:
    mode = str(
        request.form.get("mode", request.args.get("mode", "basic"))
    ).strip().lower()
    return mode if mode in {"basic", "advanced"} else "basic"


def _run_basic(
    form: dict[str, object],
) -> tuple[list[dict[str, object]], int, int]:
    if request.form.get("confirm_execution") != "on":
        raise ToolInputError("Confirm that you intend to execute these commands.")
    hosts = parse_ssh_targets(str(form["hosts"]), limit=50)
    commands = [
        command
        for command in str(form["commands"]).splitlines()
        if command.strip()
    ]
    results = run_ssh_hosts(
        hosts=hosts,
        username=str(form["username"]),
        password=request.form.get("password", ""),
        commands=commands,
        port=int(str(form["port"])),
        allow_unknown_hosts=bool(form["allow_unknown_hosts"]),
        allow_legacy_algorithms=bool(form["allow_legacy_algorithms"]),
        send_ctrl_y=bool(form["send_ctrl_y"]),
        default_command_timeout=int(str(form["command_timeout"])),
    )
    return results, len(hosts), len(commands)


def _run_advanced(
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


def _record_basic_success(
    form: dict[str, object],
    results: list[dict[str, object]],
    host_count: int,
    command_count: int,
) -> None:
    record_current_activity(
        "Automation",
        "Ran Multi-SSH",
        f"{len(results)} host(s), {command_count} command(s)",
        counters={
            "ssh": {
                "hosts": len(results),
                "commands": len(results) * command_count,
            }
        },
    )
    _annotate_run(
        "basic",
        form,
        outcome="succeeded",
        host_count=host_count,
        command_count=command_count,
        successful_host_count=sum(
            1 for result in results if result.get("status") == "success"
        ),
    )


def _record_successful_run(
    mode: str,
    form: dict[str, object],
    preview: dict[str, object],
    results: list[dict[str, object]],
) -> None:
    host_count = len(preview["plans"])
    command_count = len(preview["plans"][0]["commands"]) if host_count else 0
    record_current_activity(
        "Automation",
        "Ran Multi-SSH",
        f"{host_count} host(s), {command_count} command(s), Advanced",
        counters={
            "ssh": {
                "hosts": host_count,
                "commands": host_count * command_count,
            }
        },
    )
    _annotate_run(
        mode,
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
    mode: str,
    form: dict[str, object],
    preview: dict[str, object] | None,
) -> None:
    host_count = len(preview["plans"]) if preview else 0
    command_count = (
        len(preview["plans"][0]["commands"]) if preview and host_count else 0
    )
    record_current_activity("Automation", "Ran Multi-SSH", "Request failed")
    _annotate_run(
        mode,
        form,
        outcome="failed",
        host_count=host_count,
        command_count=command_count,
        successful_host_count=0,
        variable_count=len(preview["referenced_variables"]) if preview else 0,
    )


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
        tool_name="Multi-SSH",
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
