from __future__ import annotations

from flask import Blueprint, render_template, request

from .activity_context import record_current_activity
from .network_tools import (
    SSH_DEFAULT_COMMAND_TIMEOUT,
    ToolInputError,
    run_ssh_hosts,
    validate_hosts,
)


def register_ssh_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/multi-ssh", methods=["GET", "POST"])
    def multi_ssh():
        form = {
            "hosts": "",
            "username": "",
            "port": "22",
            "commands": "",
            "command_timeout": str(SSH_DEFAULT_COMMAND_TIMEOUT),
            "allow_unknown_hosts": False,
            "send_ctrl_y": False,
        }
        results: list[dict[str, object]] | None = None
        error = ""
        if request.method == "POST":
            form = {
                "hosts": request.form.get("hosts", "").strip(),
                "username": request.form.get("username", "").strip(),
                "port": request.form.get("port", "22").strip(),
                "commands": request.form.get("commands", "").strip(),
                "command_timeout": request.form.get(
                    "command_timeout", str(SSH_DEFAULT_COMMAND_TIMEOUT)
                ).strip(),
                "allow_unknown_hosts": request.form.get("allow_unknown_hosts") == "on",
                "send_ctrl_y": request.form.get("send_ctrl_y") == "on",
            }
            try:
                if request.form.get("confirm_execution") != "on":
                    raise ToolInputError("Confirm that you intend to execute these commands.")
                hosts = validate_hosts(str(form["hosts"]), limit=50)
                commands = [command for command in str(form["commands"]).splitlines() if command.strip()]
                port = int(str(form["port"]))
                results = run_ssh_hosts(
                    hosts=hosts,
                    username=str(form["username"]),
                    password=request.form.get("password", ""),
                    commands=commands,
                    port=port,
                    allow_unknown_hosts=bool(form["allow_unknown_hosts"]),
                    send_ctrl_y=bool(form["send_ctrl_y"]),
                    default_command_timeout=int(str(form["command_timeout"])),
                )
            except (ToolInputError, ValueError) as exc:
                error = str(exc) if str(exc) else "Enter a valid SSH port."
                record_current_activity("Automation", "Ran Multi-SSH", "Request failed")
            else:
                record_current_activity(
                    "Automation",
                    "Ran Multi-SSH",
                    f"{len(results)} host(s), {len(commands)} command(s)",
                    counters={
                        "ssh": {
                            "hosts": len(results),
                            "commands": len(results) * len(commands),
                        }
                    },
                )
        return render_template("tools/multi_ssh.html", error=error, form=form, results=results)
