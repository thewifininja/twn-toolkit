from __future__ import annotations

import io
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
from .investigation_exports import (
    InvestigationExportError,
    build_case_package,
    build_case_report_pdf,
    case_package_filename,
    case_report_filename,
)
from .investigations import InvestigationError, InvestigationStore
from .investigation_reporting import case_report_contents


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
        investigation, events, artifacts, report = load_report(investigation_id)
        return render_template(
            "investigations/detail.html",
            investigation=investigation,
            investigation_events=events,
            investigation_artifacts=artifacts,
            **report,
            investigation_tabs=tabs(investigation_id, active_tab),
            active_investigation_tab=active_tab,
            format_bytes=format_bytes,
        )

    def load_report(
        investigation_id: str,
    ) -> tuple[
        dict[str, object],
        list[dict[str, object]],
        list[dict[str, object]],
        dict[str, object],
    ]:
        investigation = investigation_or_404(investigation_id)
        events = store.events_for_user(investigation_id, user_id())
        artifacts = store.artifacts_for_user(investigation_id, user_id())
        return (
            investigation,
            events,
            artifacts,
            case_report_contents(events, artifacts),
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
            summary=f"Opened case {investigation['title']}.",
            resource_type="investigation",
            resource_id=str(investigation["id"]),
            resource_name=str(investigation["title"]),
        )
        flash(f"Opened case {investigation['title']}.", "success")
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
                summary=f"Added a note to case {investigation['title']}.",
                resource_type="investigation",
                resource_id=investigation_id,
                resource_name=str(investigation["title"]),
            )
            flash("Added the note to the case journal.", "success")
        return redirect(
            url_for("investigation_detail", investigation_id=investigation_id)
        )

    @app.post("/investigations/<investigation_id>/state")
    def update_investigation_state(investigation_id: str):
        investigation = investigation_or_404(investigation_id)
        state = request.form.get("state", "").strip()
        reopening = investigation["state"] == "completed" and state == "paused"
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
            if reopening:
                action, label = "reopened", "reopened"
            else:
                actions = {
                    "recording": ("resumed", "resumed"),
                    "paused": ("paused", "paused"),
                    "completed": ("completed", "closed"),
                }
                action, label = actions[state]
            annotate_audit_event(
                category="Investigations",
                action=f"investigation.{action}",
                summary=f"{label.title()} case {investigation['title']}.",
                resource_type="investigation",
                resource_id=investigation_id,
                resource_name=str(investigation["title"]),
                details={
                    "previous_state": investigation["state"],
                    "state": updated["state"],
                },
            )
            if reopening:
                flash("Case reopened with automatic recording paused.", "success")
            else:
                flash(f"Case {label}.", "success")
        default_destination = (
            url_for("investigations")
            if state == "completed"
            else url_for("investigation_detail", investigation_id=investigation_id)
        )
        return redirect(_safe_next(default_destination))

    @app.get("/investigations/<investigation_id>/evidence")
    def investigation_evidence(investigation_id: str):
        return render_workspace(investigation_id, active_tab="evidence")

    @app.post("/investigations/<investigation_id>/evidence")
    def upload_investigation_evidence(investigation_id: str):
        investigation = investigation_or_404(investigation_id)
        uploads = [item for item in request.files.getlist("files") if item.filename]
        if not uploads:
            flash("Choose at least one evidence file.", "error")
            return redirect(
                url_for("investigation_evidence", investigation_id=investigation_id)
            )
        if len(uploads) > 20:
            flash("Upload no more than 20 evidence files at once.", "error")
            return redirect(
                url_for("investigation_evidence", investigation_id=investigation_id)
            )
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
                        f"Added {len(saved)} evidence file(s) to case "
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
                summary=(
                    f"Added {len(saved)} evidence file(s) to case "
                    f"{investigation['title']}."
                ),
                resource_type="investigation",
                resource_id=investigation_id,
                resource_name=str(investigation["title"]),
                details={"file count": len(saved)},
            )
            flash(f"Added {len(saved)} evidence file(s).", "success")
        return redirect(
            url_for("investigation_evidence", investigation_id=investigation_id)
        )

    @app.get("/investigations/<investigation_id>/evidence/<artifact_id>/download")
    def download_investigation_evidence(investigation_id: str, artifact_id: str):
        investigation = investigation_or_404(investigation_id)
        try:
            artifact = store.artifact_for_user(
                investigation_id, artifact_id, user_id()
            )
            path = store.datastore.file(str(artifact["relative_path"]))
        except (DatastoreError, InvestigationError):
            abort(404)
        annotate_audit_event(
            category="Investigations",
            action="investigation.evidence_downloaded",
            summary=f"Downloaded evidence from case {investigation['title']}.",
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

    @app.get("/investigations/<investigation_id>/report.pdf")
    def download_investigation_report_pdf(investigation_id: str):
        investigation, _, _, report = load_report(investigation_id)
        pdf = build_case_report_pdf(investigation, report)
        annotate_audit_event(
            category="Investigations",
            action="investigation.report_pdf_downloaded",
            summary=f"Downloaded the PDF report for case {investigation['title']}.",
            resource_type="investigation",
            resource_id=investigation_id,
            resource_name=str(investigation["title"]),
            details={
                "included event count": len(report["report_events"]),
                "included evidence count": len(report["report_artifacts"]),
                "PDF byte count": len(pdf),
            },
        )
        return send_file(
            io.BytesIO(pdf),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=case_report_filename(investigation),
        )

    @app.get("/investigations/<investigation_id>/package.zip")
    def download_investigation_package(investigation_id: str):
        investigation, _, _, report = load_report(investigation_id)
        try:
            archive, manifest = build_case_package(
                store=store,
                investigation=investigation,
                report=report,
            )
        except (DatastoreError, InvestigationExportError, OSError) as exc:
            abort(409, str(exc) or "The case package could not be built.")
        annotate_audit_event(
            category="Investigations",
            action="investigation.package_downloaded",
            summary=f"Downloaded the selected package for case {investigation['title']}.",
            resource_type="investigation",
            resource_id=investigation_id,
            resource_name=str(investigation["title"]),
            details={
                "included event count": len(report["report_events"]),
                "included evidence count": len(report["report_artifacts"]),
                "PDF SHA-256": manifest["report"]["sha256"],
            },
        )
        return send_file(
            archive,
            mimetype="application/zip",
            as_attachment=True,
            download_name=case_package_filename(investigation),
        )

    @app.post("/investigations/<investigation_id>/report/contents")
    def update_investigation_report_contents(investigation_id: str):
        investigation = investigation_or_404(investigation_id)
        try:
            counts = store.set_report_contents(
                investigation_id,
                user_id(),
                event_ids=request.form.getlist("event_id"),
                artifact_ids=request.form.getlist("artifact_id"),
            )
        except InvestigationError as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Investigations",
                action="investigation.report_contents_updated",
                summary=f"Updated report contents for case {investigation['title']}.",
                resource_type="investigation",
                resource_id=investigation_id,
                resource_name=str(investigation["title"]),
                details={
                    "included event count": counts["included_events"],
                    "included evidence count": counts["included_artifacts"],
                },
            )
            flash("Saved the case report contents.", "success")
        return redirect(
            url_for("investigation_report", investigation_id=investigation_id)
        )


def _safe_next(default: str) -> str:
    value = request.form.get("next", "").strip()
    parsed = urlsplit(value)
    if value.startswith("/") and not value.startswith("//") and not parsed.netloc:
        return value
    return default
