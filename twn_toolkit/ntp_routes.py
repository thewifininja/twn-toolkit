from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_profile_deleted, annotate_profile_saved
from .network_tools import ToolInputError, parse_ping_targets
from .ntp_tools import test_ntp_servers
from .profiles import NTPHostProfileStore


def register_ntp_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/ntp-test", methods=["GET", "POST"])
    def ntp_test():
        form = {"hosts": "", "port": "123", "timeout": "3", "samples": "4"}
        results = None
        error = ""
        if request.method == "POST":
            submitted_host = request.form.get("hosts", "").strip() or request.form.get("host", "").strip()
            form = {
                "hosts": submitted_host,
                "port": request.form.get("port", "123").strip(),
                "timeout": request.form.get("timeout", "3").strip(),
                "samples": request.form.get("samples", "4").strip(),
            }
            try:
                targets = parse_ping_targets(form["hosts"], limit=20)
                results = test_ntp_servers(
                    targets,
                    port=int(form["port"]),
                    timeout=float(form["timeout"]),
                    samples=int(form["samples"]),
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid NTP test settings."
                record_current_activity("Time", "Ran NTP test", "Request failed")
            else:
                query_count = sum(int(result.get("total_samples", 0)) for result in results)
                record_current_activity(
                    "Time",
                    "Ran NTP test",
                    f"{len(targets)} server(s), {query_count} sample(s)",
                    counters={"ntp": {"queries": query_count}},
                )
        return render_template(
            "tools/ntp_test.html",
            error=error,
            form=form,
            profiles=NTPHostProfileStore(current_app.instance_path).all(),
            results=results,
        )

    @tools_bp.post("/ntp-test/profiles")
    def save_ntp_profile():
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        values = request.form.get("values", "").strip()
        if not name or len(name) > 100:
            return jsonify({"error": "Enter a profile name of 100 characters or fewer."}), 400
        try:
            targets = parse_ping_targets(values, limit=20)
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 400
        profile = {"name": name, "values": values, "targets": targets, "count": len(targets)}
        store = NTPHostProfileStore(current_app.instance_path)
        before = store.get(original_name or name)
        store.upsert(profile, original_name=original_name)
        annotate_profile_saved(
            category="Network tools",
            action_namespace="ntp",
            profile_type="NTP host profile",
            before=before,
            after=profile,
        )
        return jsonify({"profile": profile})

    @tools_bp.post("/ntp-test/profiles/delete")
    def delete_ntp_profile():
        name = request.form.get("name", "").strip()
        store = NTPHostProfileStore(current_app.instance_path)
        profile = store.get(name)
        if not profile or not store.delete(name):
            return jsonify({"error": "Profile not found."}), 404
        annotate_profile_deleted(
            category="Network tools",
            action_namespace="ntp",
            profile_type="NTP host profile",
            profile=profile,
        )
        return jsonify({"deleted": name})
