from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from .network_tools import (
    ToolInputError,
    parse_ping_targets,
    ping_hosts,
    run_ssh_hosts,
    split_values,
    subtract_subnets,
    validate_hosts,
)
from .profiles import PingProfileStore


tools_bp = Blueprint("tools", __name__, url_prefix="/tools")


@tools_bp.get("/")
def index():
    return render_template("tools/index.html")


@tools_bp.route("/subnet-excluder", methods=["GET", "POST"])
def subnet_excluder():
    supernets = ""
    exclusions = ""
    results: list[str] | None = None
    error = ""
    if request.method == "POST":
        supernets = request.form.get("supernets", "").strip()
        exclusions = request.form.get("exclusions", "").strip()
        try:
            results = subtract_subnets(supernets, exclusions)
        except ToolInputError as exc:
            error = str(exc)
    return render_template(
        "tools/subnet_excluder.html",
        error=error,
        exclusions=exclusions,
        results=results,
        supernets=supernets,
    )


@tools_bp.get("/ping")
def ping_tool():
    return render_template("tools/ping.html", profiles=_ping_profile_store().all())


@tools_bp.post("/ping/run")
def ping_run():
    payload = request.get_json(silent=True) or {}
    try:
        targets = parse_ping_targets(str(payload.get("hosts", "")), limit=100)
        results = ping_hosts([target["host"] for target in targets])
    except ToolInputError as exc:
        return jsonify({"error": str(exc)}), 400
    for target, result in zip(targets, results):
        result["label"] = target["label"]
    return jsonify({"results": results})


@tools_bp.post("/ping/profiles")
def save_ping_profile():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    original_name = str(payload.get("original_name", "")).strip()
    if not name:
        return jsonify({"error": "Enter a profile name."}), 400
    if len(name) > 100:
        return jsonify({"error": "Profile names must be 100 characters or fewer."}), 400
    try:
        targets = parse_ping_targets(str(payload.get("hosts", "")), limit=100)
        interval = int(payload.get("interval", 2))
        if not 1 <= interval <= 60:
            raise ToolInputError("Interval must be between 1 and 60 seconds.")
    except (ToolInputError, TypeError, ValueError) as exc:
        return jsonify({"error": str(exc) or "Enter a valid interval."}), 400

    profile = {"name": name, "targets": targets, "interval": interval}
    _ping_profile_store().upsert(profile, original_name=original_name)
    return jsonify({"profile": profile})


@tools_bp.post("/ping/profiles/delete")
def delete_ping_profile():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    if not name:
        return jsonify({"error": "Select a profile to delete."}), 400
    if not _ping_profile_store().delete(name):
        return jsonify({"error": "Profile not found."}), 404
    return jsonify({"deleted": name})


def _ping_profile_store() -> PingProfileStore:
    return PingProfileStore(current_app.instance_path)


@tools_bp.route("/multi-ssh", methods=["GET", "POST"])
def multi_ssh():
    form = {
        "hosts": "",
        "username": "",
        "port": "22",
        "commands": "",
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
            )
        except (ToolInputError, ValueError) as exc:
            error = str(exc) if str(exc) else "Enter a valid SSH port."
    return render_template("tools/multi_ssh.html", error=error, form=form, results=results)
