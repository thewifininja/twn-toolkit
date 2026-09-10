from __future__ import annotations

import secrets
import time

from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, url_for

from .mso_ui import save_profile, delete_profile, mutation
from .audit import (
    annotate_profile_deleted,
    annotate_profile_duplicated,
    annotate_profile_saved,
    annotate_tool_run,
)
from .investigations import InvestigationStore
from .diagnostic_routes import diagnostic_store as _diagnostic_store, owned_diagnostic
from .diagnostic_worker import record_unsuccessful_scan
from .investigation_context import record_current_investigation_event
from .automation_heartbeat import read_automation_heartbeat
from .network_tools import (
    ToolInputError,
    parse_ping_targets,
    parse_tcp_ports,
)
from .profiles import PortScanProfileStore


def register_port_scanner_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/port-scanner", methods=["GET", "POST"])
    def port_scanner():
        store = _diagnostic_store()
        user = g.current_user
        form = {"hosts": "", "ports": "22, 53, 80, 443", "timeout": "1",
                "concurrency": "100", "open_only": True}
        error = ""
        job = None
        results = stats = journal_event = None
        page, total = 1, 0
        if request.method == "POST":
            form = {key: request.form.get(key, str(value)).strip() for key, value in form.items() if key != "open_only"}
            form["open_only"] = request.form.get("open_only") == "on"
            try:
                targets = parse_ping_targets(form["hosts"], limit=50)
                ports = parse_tcp_ports(form["ports"], limit=200)
                timeout, concurrency = float(form["timeout"]), int(form["concurrency"])
                if len(targets) * len(ports) > 5000:
                    raise ToolInputError("A scan is limited to 5,000 host/port combinations.")
                if not 0.1 <= timeout <= 10:
                    raise ToolInputError("Connection timeout must be between 0.1 and 10 seconds.")
                if not 1 <= concurrency <= 200:
                    raise ToolInputError("Concurrency must be between 1 and 200.")
                investigation = InvestigationStore(current_app.instance_path).active_for_user(user["id"])
                job_id = store.enqueue(user_id=user["id"], config={
                    "form": form, "targets": targets, "ports": ports,
                    "username": user["username"],
                    "investigation_id": investigation["id"] if investigation and investigation.get("is_recording") else "",
                })
                annotate_tool_run(category="Network tools", action_namespace="tcp_scanner",
                                  tool_name="TCP port scan", outcome="queued",
                                  details={"operation id": job_id, "host count": len(targets), "port count": len(ports)})
                return redirect(url_for("tools.port_scanner", job=job_id), code=303)
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid scanner settings."
                record_current_investigation_event(
                    operation_id="port-scan-rejected:" + secrets.token_hex(12),
                    event_type="diagnostic.failed", tool_id="tools.port_scanner",
                    action="TCP port scan", outcome="failed", summary="TCP port scan rejected: " + error,
                    targets={"hosts": form["hosts"]}, parameters=form, metrics={},
                    details={"error": error}, started_at=time.time(), completed_at=time.time(),
                )
                annotate_tool_run(category="Network tools", action_namespace="tcp_scanner",
                                  tool_name="TCP port scan", outcome="failed")
        elif request.args.get("job"):
            job = owned_diagnostic(request.args["job"], "tcp_scan")
            form = job["config"]["form"]
            if request.args.get("open_only") in {"0", "1"}:
                form["open_only"] = request.args["open_only"] == "1"
            try:
                page = max(1, min(50, int(request.args.get("page", 1))))
            except ValueError:
                page = 1
            if job["state"] == "succeeded":
                stats = job["summary"]["stats"]
                journal_event = job["summary"].get("journal_event")
                results, total = store.page(job["id"], user["id"], page, open_only=form["open_only"])
        return render_template(
            "tools/port_scanner.html", error=error, form=form,
            host_profiles=_port_scan_profile_store("hosts").all(),
            port_profiles=_port_scan_profile_store("ports").all(),
            results=results, stats=stats, journal_event=journal_event,
            diagnostic_job=job, diagnostic_recent=store.recent(user["id"]),
            result_page=page, result_total=total,
            diagnostic_scheduler=read_automation_heartbeat(store.instance / "automation-heartbeat.json"),
        )

    @tools_bp.get("/port-scanner/jobs/<job_id>/status")
    def port_scanner_job_status(job_id):
        job = owned_diagnostic(job_id, "tcp_scan")
        response = jsonify({"state": job["state"], "error": job["error"]})
        response.headers["Cache-Control"] = "no-store"
        return response

    @tools_bp.post("/port-scanner/jobs/<job_id>/cancel")
    def cancel_port_scanner_job(job_id):
        store = _diagnostic_store()
        owned_diagnostic(job_id, "tcp_scan")
        cancelled = store.cancel(job_id, g.current_user["id"])
        if cancelled:
            record_unsuccessful_scan(store, cancelled, "cancelled", "Cancelled before execution started.")
        annotate_tool_run(category="Network tools", action_namespace="tcp_scanner.cancel",
                          tool_name="TCP port scan", outcome="requested", details={"operation id": job_id})
        return redirect(url_for("tools.port_scanner", job=job_id), code=303)

    @tools_bp.post("/port-scanner/profiles/<kind>")
    @mutation
    def save_port_scan_profile(kind: str):
        if kind not in {"hosts", "ports"}:
            return jsonify({"error": "Unknown port scanner profile type."}), 404
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        values = request.form.get("values", "").strip()
        if not name or len(name) > 100:
            return jsonify({"error": "Enter a profile name of 100 characters or fewer."}), 400
        try:
            if kind == "hosts":
                parsed = parse_ping_targets(values, limit=50)
                profile = {"name": name, "values": values, "count": len(parsed)}
            else:
                parsed = parse_tcp_ports(values, limit=200)
                profile = {"name": name, "values": values, "count": len(parsed)}
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 400
        store = _port_scan_profile_store(kind)
        before = store.get(original_name or name)
        save_profile(store, profile, original_name=original_name)
        annotate_profile_saved(
            category="Network tools",
            action_namespace=f"tcp_scanner.{kind}",
            profile_type=f"TCP scanner {kind[:-1]} profile",
            before=before,
            after=profile,
        )
        return jsonify({"profile": profile})

    @tools_bp.post("/port-scanner/profiles/<kind>/delete")
    @mutation
    def delete_port_scan_profile(kind: str):
        if kind not in {"hosts", "ports"}:
            return jsonify({"error": "Unknown port scanner profile type."}), 404
        name = request.form.get("name", "").strip()
        store = _port_scan_profile_store(kind)
        profile = store.get(name)
        if not profile or not delete_profile(store, name):
            return jsonify({"error": "Profile not found."}), 404
        annotate_profile_deleted(
            category="Network tools",
            action_namespace=f"tcp_scanner.{kind}",
            profile_type=f"TCP scanner {kind[:-1]} profile",
            profile=profile,
        )
        return jsonify({"deleted": name})

    @tools_bp.post("/port-scanner/profiles/<kind>/duplicate")
    def duplicate_port_scan_profile(kind: str):
        if kind not in {"hosts", "ports"}:
            return jsonify({"error": "Unknown port scanner profile type."}), 404
        name = request.form.get("name", "").strip()
        store = _port_scan_profile_store(kind)
        source = store.get(name)
        if not source:
            return jsonify({"error": "Profile not found."}), 404
        copied = store.duplicate(name)
        annotate_profile_duplicated(
            category="Network tools", action_namespace=f"tcp_scanner.{kind}",
            profile_type=f"TCP scanner {kind[:-1]} profile", source=source, copied=copied,
        )
        return jsonify({"profile": {"name": copied["name"]}})


def _port_scan_profile_store(kind: str) -> PortScanProfileStore:
    return PortScanProfileStore(current_app.instance_path, kind)
