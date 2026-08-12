from __future__ import annotations

import json
import secrets
import time

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
from .audit import (
    annotate_profile_deleted,
    annotate_profile_duplicated,
    annotate_profile_saved,
    annotate_tool_run,
)
from .investigation_context import record_current_investigation_event
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
        journal_event = None
        error = ""
        if request.method == "POST":
            operation_id = f"traceroute:{secrets.token_hex(12)}"
            journal_started_at = time.time()
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
            annotate_tool_run(
                category="Network tools",
                action_namespace="traceroute",
                tool_name="traceroute",
                outcome="failed" if error else "succeeded",
                details={
                    "address family": form["family"],
                    "method": form["method"],
                    "hop count": int(result.get("hop_count", 0)) if result else 0,
                    "destination reached": bool(result and result.get("reached")),
                },
            )
            if error:
                journal_summary = f"Traceroute failed: {error}"
                journal_metrics = {}
            else:
                reached = bool(result and result.get("reached"))
                journal_summary = (
                    f"Traced the path to {result['host']} across "
                    f"{result['hop_count']} hop(s); the destination was "
                    f"{'reached' if reached else 'not reached'}."
                )
                journal_metrics = {
                    "hop_count": result.get("hop_count", 0),
                    "responding_hops": result.get("responding_hops", 0),
                    "reached": reached,
                }
            journal_event = record_current_investigation_event(
                operation_id=operation_id,
                event_type="diagnostic.failed" if error else "diagnostic.completed",
                tool_id="tools.traceroute",
                action="Traceroute",
                outcome="failed" if error else "succeeded",
                summary=journal_summary,
                targets={"host": result.get("host") if result else ""},
                parameters={
                    "family": form["family"],
                    "method": form["method"],
                    "maximum_hops": form["max_hops"],
                    "probes_per_hop": form["probes"],
                    "timeout_seconds": form["timeout"],
                },
                metrics=journal_metrics,
                details={"error": error, "result": result or {}},
                started_at=journal_started_at,
                completed_at=time.time(),
            )
        return render_template(
            "tools/traceroute.html",
            error=error,
            form=form,
            result=result,
            profiles=TracerouteHostProfileStore(current_app.instance_path).all(),
            journal_event=journal_event,
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
        store = TracerouteHostProfileStore(current_app.instance_path)
        before = store.get(original_name or name)
        store.upsert(profile, original_name=original_name)
        annotate_profile_saved(
            category="Network tools",
            action_namespace="traceroute",
            profile_type="Traceroute host profile",
            before=before,
            after=profile,
        )
        return jsonify({"profile": profile})

    @tools_bp.post("/traceroute/profiles/delete")
    def delete_traceroute_profile():
        name = request.form.get("name", "").strip()
        store = TracerouteHostProfileStore(current_app.instance_path)
        profile = store.get(name)
        if not profile or not store.delete(name):
            return jsonify({"error": "Profile not found."}), 404
        annotate_profile_deleted(
            category="Network tools",
            action_namespace="traceroute",
            profile_type="Traceroute host profile",
            profile=profile,
        )
        return jsonify({"deleted": name})

    @tools_bp.post("/traceroute/profiles/duplicate")
    def duplicate_traceroute_profile():
        name = request.form.get("name", "").strip()
        store = TracerouteHostProfileStore(current_app.instance_path)
        source = store.get(name)
        if not source:
            return jsonify({"error": "Profile not found."}), 404
        copied = store.duplicate(name)
        annotate_profile_duplicated(
            category="Network tools", action_namespace="traceroute",
            profile_type="Traceroute host profile", source=source, copied=copied,
        )
        return jsonify({"profile": {"name": copied["name"]}})

    @tools_bp.post("/traceroute/run")
    def traceroute_run():
        operation_id = f"traceroute-stream:{secrets.token_hex(12)}"
        journal_started_at = time.time()
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
            annotate_tool_run(
                category="Network tools",
                action_namespace="traceroute.stream",
                tool_name="streamed traceroute",
                outcome="failed",
            )
            return jsonify({"error": str(exc) or "Enter valid traceroute settings."}), 400

        annotate_tool_run(
            category="Network tools",
            action_namespace="traceroute.stream",
            tool_name="streamed traceroute",
            outcome="started",
            details={
                "address family": str(payload.get("family", "auto")),
                "method": prepared["method"],
                "maximum hops": prepared["max_hops"],
                "probe count per hop": prepared["probes"],
            },
        )

        @stream_with_context
        def generate():
            hops: list[dict[str, object]] = []
            try:
                for event in stream_traceroute(prepared):
                    if event.get("type") == "hop" and isinstance(
                        event.get("hop"), dict
                    ):
                        hops.append(dict(event["hop"]))
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
                        reached = bool(event.get("reached"))
                        journal_event = record_current_investigation_event(
                            operation_id=operation_id,
                            event_type="diagnostic.completed",
                            tool_id="tools.traceroute",
                            action="Traceroute",
                            outcome="succeeded",
                            summary=(
                                f"Traced the path to {prepared['host']} across "
                                f"{event.get('hop_count', 0)} hop(s); the destination "
                                f"was {'reached' if reached else 'not reached'}."
                            ),
                            targets={"host": prepared["host"]},
                            parameters={
                                "family": str(payload.get("family", "auto")),
                                "method": prepared["method"],
                                "maximum_hops": prepared["max_hops"],
                                "probes_per_hop": prepared["probes"],
                                "timeout_seconds": prepared["timeout"],
                            },
                            metrics={
                                "hop_count": int(event.get("hop_count", 0)),
                                "responding_hops": int(
                                    event.get("responding_hops", 0)
                                ),
                                "reached": reached,
                            },
                            details={
                                "result": {
                                    "host": prepared["host"],
                                    "family": str(payload.get("family", "auto")),
                                    "method": prepared["method"],
                                    "hops": hops,
                                }
                            },
                            started_at=journal_started_at,
                            completed_at=time.time(),
                        )
                        event["case_recorded"] = bool(journal_event)
                    yield json.dumps(event, separators=(",", ":")) + "\n"
            except ToolInputError as exc:
                _record_traceroute_activity(
                    "Ran traceroute",
                    f"{prepared['host']}: failed",
                    count_action=True,
                )
                journal_event = record_current_investigation_event(
                    operation_id=operation_id,
                    event_type="diagnostic.failed",
                    tool_id="tools.traceroute",
                    action="Traceroute",
                    outcome="failed",
                    summary=f"Traceroute failed: {exc}",
                    targets={"host": prepared["host"]},
                    parameters={
                        "family": str(payload.get("family", "auto")),
                        "method": prepared["method"],
                        "maximum_hops": prepared["max_hops"],
                        "probes_per_hop": prepared["probes"],
                        "timeout_seconds": prepared["timeout"],
                    },
                    metrics={"hop_count": len(hops)},
                    details={"error": str(exc), "hops": hops},
                    started_at=journal_started_at,
                    completed_at=time.time(),
                )
                yield json.dumps(
                    {
                        "type": "error",
                        "error": str(exc),
                        "case_recorded": bool(journal_event),
                    },
                    separators=(",", ":"),
                ) + "\n"

        response = Response(generate(), mimetype="application/x-ndjson")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Accel-Buffering"] = "no"
        return response
