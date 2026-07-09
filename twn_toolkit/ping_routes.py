from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from .network_tools import ToolInputError, parse_ping_targets, ping_hosts
from .profiles import PingProfileStore


def register_ping_routes(tools_bp: Blueprint) -> None:
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
