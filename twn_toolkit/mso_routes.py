"""Shared MSO review workspace; permission-filtered across registered saved lists."""
from flask import abort, current_app, flash, redirect, render_template, request, url_for

from .audit import annotate_audit_event
from .mso import MsoConflict, MsoStore
from .mso_types import LIST_TYPES
from .mso_ui import allowed
from .mso_secrets import redact
from .distributed_agents import DistributedSettingsStore


def register_mso_routes(tools_bp):
    @tools_bp.get("/mso/conflicts")
    def mso_conflicts():
        if DistributedSettingsStore(current_app.instance_path).get()["role"] == "standalone":
            abort(404)
        kinds = [kind for kind in LIST_TYPES if allowed(kind)]
        if not kinds:
            abort(403)
        profiles = [p for kind in kinds for p in MsoStore(current_app.instance_path, kind).profiles(metadata=True)]
        conflicts = [redact(p) for p in profiles if p["mso"]["conflict"]]
        page = max(1, request.args.get("page", 1, type=int))
        return render_template("tools/mso_conflicts.html", conflicts=conflicts[(page-1)*25:page*25],
                               page=page, more=len(conflicts) > page*25, list_types=LIST_TYPES,
                               credential_names={p["mso"]["id"]: p["name"] for p in profiles if p["mso"]["kind"] == "snmp.credentials"})

    @tools_bp.post("/mso/conflicts/resolve")
    def resolve_mso_conflict():
        if DistributedSettingsStore(current_app.instance_path).get()["role"] == "standalone":
            abort(404)
        kind = request.form.get("kind", "ping.profile")
        if not allowed(kind):
            abort(403)
        try:
            store = MsoStore(current_app.instance_path, kind)
            if not store.profile(request.form.get("object_id")):
                abort(404)
            store.resolve(request.form.get("object_id"), request.form.get("choice"), request.form.get("version", type=int))
        except (MsoConflict, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("tools.mso_conflicts"))
        annotate_audit_event(category="Network tools", action="mso.resolve", summary="Resolved shared saved-list conflict",
                             resource_type="MSO", resource_id=request.form.get("object_id", ""), details={"choice": request.form.get("choice")})
        flash("Conflict resolved. Changes will sync in the background.", "success")
        return redirect(url_for("tools.mso_conflicts"))
