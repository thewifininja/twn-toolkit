"""Shared MSO review workspace; only the Ping adapter participates in the pilot."""
from flask import current_app, flash, redirect, render_template, request, url_for

from .audit import annotate_audit_event
from .mso import MsoConflict, MsoStore


def register_mso_routes(tools_bp):
    @tools_bp.get("/mso/conflicts")
    def mso_conflicts():
        # Ping is the pilot type; future adapters must filter by their tool permission.
        profiles = MsoStore(current_app.instance_path).profiles(metadata=True)
        conflicts = [p for p in profiles if p["mso"]["conflict"]]
        page = max(1, request.args.get("page", 1, type=int))
        return render_template("tools/mso_conflicts.html", conflicts=conflicts[(page-1)*25:page*25],
                               page=page, more=len(conflicts) > page*25)

    @tools_bp.post("/mso/conflicts/resolve")
    def resolve_mso_conflict():
        try:
            store = MsoStore(current_app.instance_path)
            store.resolve(request.form.get("object_id"), request.form.get("choice"), request.form.get("version", type=int))
        except (MsoConflict, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("tools.mso_conflicts"))
        annotate_audit_event(category="Network tools", action="mso.resolve", summary="Resolved shared Ping profile conflict",
                             resource_type="MSO", resource_id=request.form.get("object_id", ""), details={"choice": request.form.get("choice")})
        flash("Conflict resolved. Changes will sync in the background.", "success")
        return redirect(url_for("tools.mso_conflicts"))
