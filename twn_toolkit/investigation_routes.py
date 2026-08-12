from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from .audit import annotate_audit_event
from .datastore import DatastoreError, format_bytes
from .investigations import InvestigationError, InvestigationStore


def register_investigation_routes(
    app: Flask, store: InvestigationStore
) -> None:
    def user() -> dict[str, object]:
        return getattr(g, "current_user", {}) or {}

    def user_id() -> str:
        return str(user().get("id", ""))

    def investigation_or_404(investigation_id: str) -> dict[str, object]:
        try:
            return store.get_for_user(investigation_id, user_id())
        except InvestigationError:
            abort(404)

    def tabs(investigation_id: str, active: str) -> list[dict[str, object]]:
        return [
            {
                "label": "Journal",
                "href": url_for("investigation_detail", investigation_id=investigation_id),
                "active": active == "journal",
            },
            {
                "label": "Evidence",
                "href": url_for("investigation_evidence", investigation_id=investigation_id),
                "active": active == "evidence",
            },
            {
                "label": "Report",
                "href": url_for("investigation_report", investigation_id=investigation_id),
                "active": active == "report",
            },
        ]

    def render_workspace(
        investigation_id: str, *, active_tab: str
    ) -> str:
        investigation = investigation_or_404(investigation_id)
        events = store.events_for_user(investigation_id, user_id())
        artifacts = store.artifacts_for_user(investigation_id, user_id())
        return render_template(
            "investigations/detail.html",
            investigation=investigation,
            investigation_events=events,
            investigation_artifacts=artifacts,
            investigation_tabs=tabs(investigation_id, active_tab),
            active_investigation_tab=active_tab,
            format_bytes=format_bytes,
        )

    @app.get("/investigations")
    def investigations():
        investigations = store.list_for_user(user_id())
        return render_template(
            "investigations/index.html",
            investigations=investigations,
            open_investigation=next(
                (item for item in investigations if item["is_open"]), None
            ),
        )

    @app.post("/investigations")
    def create_investigation():
        try:
            investigation = store.create(
                owner_user_id=user_id(),
                owner_username=str(user().get("username", "")),
                title=request.form.get("title", ""),
                description=request.form.get("description", ""),
            )
        except InvestigationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("investigations"))
        annotate_audit_event(
            category="Investigations",
            action="investigation.created",
            summary=f"Started investigation {investigation['title']}.",
            resource_type="investigation",
            resource_id=str(investigation["id"]),
            resource_name=str(investigation["title"]),
        )
        flash(f"Started investigation {investigation['title']}.", "success")
        return redirect(
            url_for("investigation_detail", investigation_id=investigation["id"])
        )

    @app.get("/investigations/<investigation_id>")
    def investigation_detail(investigation_id: str):
        return render_workspace(investigation_id, active_tab="journal")

    @app.post("/investigations/<investigation_id>/notes")
    def add_investigation_note(investigation_id: str):
        investigation = investigation_or_404(investigation_id)
        try:
            store.add_note(
                investigation_id,
                user_id(),
                str(user().get("username", "")),
                request.form.get("note", ""),
            )
        except InvestigationError as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Investigations",
                action="investigation.note_added",
                summary=f"Added a note to investigation {investigation['title']}.",
                resource_type="investigation",
                resource_id=investigation_id,
                resource_name=str(investigation["title"]),
            )
            flash("Added the note to the investigation journal.", "success")
        return redirect(url_for("investigation_detail", investigation_id=investigation_id))

    @app.post("/investigations/<investigation_id>/state")
    def update_investigation_state(investigation_id: str):
        investigation = investigation_or_404(investigation_id)
        state = request.form.get("state", "").strip()
        try:
            updated = store.set_state(
                investigation_id,
                user_id(),
                str(user().get("username", "")),
                state,
            )
        except InvestigationError as exc:
            flash(str(exc), "error")
        else:
            action_labels = {
                "recording": "resumed",
                "paused": "paused",
                "completed": "completed",
            }
            action = action_labels[state]
            annotate_audit_event(
                category="Investigations",
                action=f"investigation.{action}",
                summary=f"{action.title()} investigation {investigation['title']}.",
                resource_type="investigation",
                resource_id=investigation_id,
                resource_name=str(investigation["title"]),
                details={"state": updated["state"]},
            )
            flash(f"Investigation {action}.", "success")
        return redirect(_safe_next(url_for("investigation_detail", investigation_id=investigation_id)))

    @app.get("/investigations/<investigation_id>/evidence")
    def investigation_evidence(investigation_id: str):
        return render_workspace(investigation_id, active_tab="evidence")

    @app.post("/investigations/<investigation_id>/evidence")
    def upload_investigation_evidence(investigation_id: str):
        investigation = investigation_or_404(investigation_id)
        uploads = [item for item in request.files.getlist("files") if item.filename]
        if not uploads:
            flash("Choose at least one evidence file.", "error")
            return redirect(url_for("investigation_evidence", investigation_id=investigation_id))
        if len(uploads) > 20:
            flash("Upload no more than 20 evidence files at once.", "error")
            return redirect(url_for("investigation_evidence", investigation_id=investigation_id))
        saved = []
        try:
            for upload in uploads:
                saved.append(
                    store.add_evidence(
                        investigation_id=investigation_id,
                        user_id=user_id(),
                        username=str(user().get("username", "")),
                        filename=str(upload.filename),
                        content_type=str(upload.mimetype or "application/octet-stream"),
                        stream=upload.stream,
                    )
                )
        except (DatastoreError, InvestigationError, OSError) as exc:
            if saved:
                annotate_audit_event(
                    category="Investigations",
                    action="investigation.evidence_uploaded",
                    summary=(
                        f"Added {len(saved)} evidence file(s) to investigation "
                        f"{investigation['title']} before the upload stopped."
                    ),
                    resource_type="investigation",
                    resource_id=investigation_id,
                    resource_name=str(investigation["title"]),
                    details={"file count": len(saved), "partial": True},
                )
                flash(
                    f"Added {len(saved)} file(s), then stopped: {exc}",
                    "warning",
                )
            else:
                flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Investigations",
                action="investigation.evidence_uploaded",
                summary=f"Added {len(saved)} evidence file(s) to investigation {investigation['title']}.",
                resource_type="investigation",
                resource_id=investigation_id,
                resource_name=str(investigation["title"]),
                details={"file count": len(saved)},
            )
            flash(f"Added {len(saved)} evidence file(s).", "success")
        return redirect(url_for("investigation_evidence", investigation_id=investigation_id))

    @app.get("/investigations/<investigation_id>/evidence/<artifact_id>/download")
    def download_investigation_evidence(investigation_id: str, artifact_id: str):
        investigation = investigation_or_404(investigation_id)
        try:
            artifact = store.artifact_for_user(investigation_id, artifact_id, user_id())
            path = store.datastore.file(str(artifact["relative_path"]))
        except (DatastoreError, InvestigationError):
            abort(404)
        annotate_audit_event(
            category="Investigations",
            action="investigation.evidence_downloaded",
            summary=f"Downloaded evidence from investigation {investigation['title']}.",
            resource_type="investigation_artifact",
            resource_id=artifact_id,
            resource_name=str(artifact["display_name"]),
            details={"investigation": investigation_id},
        )
        return send_file(
            Path(path),
            as_attachment=True,
            download_name=str(artifact["display_name"]),
        )

    @app.get("/investigations/<investigation_id>/report")
    def investigation_report(investigation_id: str):
        return render_workspace(investigation_id, active_tab="report")


def _safe_next(default: str) -> str:
    value = request.form.get("next", "").strip()
    parsed = urlsplit(value)
    if value.startswith("/") and not value.startswith("//") and not parsed.netloc:
        return value
    return default
