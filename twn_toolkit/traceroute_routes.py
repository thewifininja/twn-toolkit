from __future__ import annotations

import json

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    render_template,
    request,
    stream_with_context,
)

from .activity_context import record_current_activity
from .network_tools import ToolInputError, parse_ping_targets
from .profiles import TracerouteHostProfileStore
from .traceroute_tools import prepare_traceroute, run_traceroute, stream_traceroute


def _record_traceroute_activity(
    title: str,
    detail: str = "",
    *,
    completed: int = 0,
    hops: int = 0,
    count_action: bool = False,
) -> None:
    record_current_activity(
        "Pathing",
        title,
        detail,
        counters={"traceroute": {"completed": completed, "hops": hops}},
        count_action=count_action,
    )


def register_traceroute_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/traceroute", methods=["GET", "POST"])
    def traceroute():
        form = {
            "host": "",
            "family": "auto",
            "method": "udp",
            "max_hops": "30",
            "probes": "3",
            "timeout": "2",
        }
        result = None
        error = ""
        if request.method == "POST":
            form = {
                "host": request.form.get("host", "").strip(),
                "family": request.form.get("family", "auto"),
                "method": request.form.get("method", "udp"),
                "max_hops": request.form.get("max_hops", "30").strip(),
                "probes": request.form.get("probes", "3").strip(),
                "timeout": request.form.get("timeout", "2").strip(),
            }
            try:
                result = run_traceroute(
                    form["host"],
                    family=form["family"],
                    method=form["method"],
                    max_hops=int(form["max_hops"]),
                    probes=int(form["probes"]),
                    timeout=float(form["timeout"]),
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                _record_traceroute_activity(
                    "Ran traceroute",
                    f"{form['host']}: failed",
                    count_action=True,
                )
                error = str(exc) or "Enter valid traceroute settings."
            else:
                _record_traceroute_activity(
                    "Ran traceroute",
                    f"{result['host']}: {result['hop_count']} hops"
                    + (" · destination reached" if result.get("reached") else " · incomplete"),
                    completed=1,
                    hops=int(result.get("hop_count", 0)),
                    count_action=True,
                )
        return render_template(
            "tools/traceroute.html",
            error=error,
            form=form,
            result=result,
            profiles=TracerouteHostProfileStore(current_app.instance_path).all(),
        )

    @tools_bp.post("/traceroute/profiles")
    def save_traceroute_profile():
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        values = request.form.get("values", "").strip()
        if not name or len(name) > 100:
            return jsonify({"error": "Enter a profile name of 100 characters or fewer."}), 400
        try:
            targets = parse_ping_targets(values, limit=10)
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 400
        profile = {"name": name, "values": values, "targets": targets, "count": len(targets)}
        TracerouteHostProfileStore(current_app.instance_path).upsert(
            profile, original_name=original_name
        )
        return jsonify({"profile": profile})

    @tools_bp.post("/traceroute/profiles/delete")
    def delete_traceroute_profile():
        name = request.form.get("name", "").strip()
        if not TracerouteHostProfileStore(current_app.instance_path).delete(name):
            return jsonify({"error": "Profile not found."}), 404
        return jsonify({"deleted": name})

    @tools_bp.post("/traceroute/run")
    def traceroute_run():
        payload = request.get_json(silent=True) or {}
        try:
            prepared = prepare_traceroute(
                str(payload.get("host", "")),
                family=str(payload.get("family", "auto")),
                method=str(payload.get("method", "udp")),
                max_hops=int(payload.get("max_hops", 30)),
                probes=int(payload.get("probes", 3)),
                timeout=float(payload.get("timeout", 2)),
            )
        except (ToolInputError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc) or "Enter valid traceroute settings."}), 400

        @stream_with_context
        def generate():
            try:
                for event in stream_traceroute(prepared):
                    if event.get("type") == "complete":
                        _record_traceroute_activity(
                            "Ran traceroute",
                            f"{prepared['host']}: {event.get('hop_count', 0)} hops"
                            + (
                                " · destination reached"
                                if event.get("reached")
                                else " · incomplete"
                            ),
                            completed=1,
                            hops=int(event.get("hop_count", 0)),
                            count_action=True,
                        )
                    yield json.dumps(event, separators=(",", ":")) + "\n"
            except ToolInputError as exc:
                _record_traceroute_activity(
                    "Ran traceroute",
                    f"{prepared['host']}: failed",
                    count_action=True,
                )
                yield json.dumps({"type": "error", "error": str(exc)}, separators=(",", ":")) + "\n"

        response = Response(generate(), mimetype="application/x-ndjson")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Accel-Buffering"] = "no"
        return response
