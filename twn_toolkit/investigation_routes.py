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
from .auth import AuthStore
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
from .investigation_portability import (
    PortableCaseError,
    build_portable_case_archive,
    load_portable_case_archive,
    portable_case_filename,
)
from .live_tools import LiveToolStore
from .packet_capture import PacketCaptureStore
from .ping_investigation import (
    PingInvestigationError,
    stop_and_finalize_case_ping_sessions,
)
from .snmp_investigation import (
    SnmpInvestigationError,
    stop_and_finalize_case_snmp_sessions,
)
from .packet_capture_investigation import (
    PacketCaptureInvestigationError,
    stop_and_finalize_case_packet_captures,
)
from .iperf_investigation import (
    IperfInvestigationError,
    stop_and_finalize_case_iperf_servers,
)
from .iperf_server import IperfServerStore
from .remote_sessions import RemoteSessionError, RemoteSessionManager


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
        participants = list(investigation.get("participants", []))
        participant_user_ids = [str(item["user_id"]) for item in participants]
        auth_store = AuthStore(app.instance_path)
        participant_ids = {str(item["user_id"]) for item in participants}
        collaborator_candidates = []
        if investigation.get("can_manage_case") and investigation.get("is_open"):
            for candidate in auth_store.users():
                candidate_id = str(candidate.get("id", ""))
                allowed = auth_store.effective_tool_ids(candidate)
                if (
                    candidate_id
                    and candidate_id not in participant_ids
                    and candidate.get("enabled", True)
                    and (
                        candidate.get("is_admin")
                        or allowed is None
                        or "investigations.workspace" in allowed
                    )
                ):
                    collaborator_candidates.append(candidate)
        live_store = LiveToolStore(app.instance_path)
        remote_manager = app.extensions.get("remote_session_manager")
        active_remote_session_count = (
            sum(
                len(
                    remote_manager.sessions_for_investigation(
                        investigation_id, user_id=participant_user_id
                    )
                )
                for participant_user_id in participant_user_ids
            )
            if isinstance(remote_manager, RemoteSessionManager)
            else 0
        )
        return render_template(
            "investigations/detail.html",
            investigation=investigation,
            investigation_events=events,
            investigation_artifacts=artifacts,
            **report,
            investigation_tabs=tabs(investigation_id, active_tab),
            active_investigation_tab=active_tab,
            investigation_participants=participants,
            collaborator_candidates=collaborator_candidates,
            active_ping_session_count=sum(
                live_store.ping_session_count_for_investigation(
                    investigation_id,
                    user_id=participant_user_id,
                )
                for participant_user_id in participant_user_ids
            ),
            active_snmp_session_count=sum(
                live_store.snmp_session_count_for_investigation(
                    investigation_id,
                    user_id=participant_user_id,
                )
                for participant_user_id in participant_user_ids
            ),
            active_packet_capture_count=sum(
                len(
                    PacketCaptureStore(app.instance_path).active_for_investigation(
                        investigation_id,
                        user_id=participant_user_id,
                    )
                )
                for participant_user_id in participant_user_ids
            ),
            active_iperf_server_count=sum(
                len(
                    IperfServerStore(app.instance_path).active_for_investigation(
                        investigation_id,
                        user_id=participant_user_id,
                    )
                )
                for participant_user_id in participant_user_ids
            ),
            active_remote_session_count=active_remote_session_count,
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
        participants = store.participants_for_user(investigation_id, user_id())
        investigation["participants"] = participants
        events = store.events_for_user(investigation_id, user_id())
        operator_names: list[str] = []
        for item in (
            investigation.get("source_operators")
            if investigation.get("is_imported")
            else participants
        ):
            name = str(item.get("username", "")).strip()
            if name and name not in operator_names:
                operator_names.append(name)
        for event in events:
            name = str(event.get("created_by_username", "")).strip()
            if name and name not in operator_names:
                operator_names.append(name)
        investigation["operator_names"] = ", ".join(operator_names)
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

    @app.post("/investigations/import")
    def import_investigation_case():
        upload = request.files.get("case_archive")
        if not upload or not upload.filename:
            flash("Choose a TWN portable case archive.", "error")
            return redirect(url_for("investigations"))
        try:
            with load_portable_case_archive(upload.stream) as portable:
                imported = store.import_portable_case(
                    payload=portable.payload,
                    archive_sha256=portable.sha256,
                    owner_user_id=user_id(),
                    owner_username=str(user().get("username", "")),
                    open_evidence=portable.open_evidence,
                )
        except (DatastoreError, InvestigationError, PortableCaseError, OSError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("investigations"))
        annotate_audit_event(
            category="Investigations",
            action="investigation.portable_case_imported",
            summary=f"Imported portable case {imported['title']}.",
            resource_type="investigation",
            resource_id=str(imported["id"]),
            resource_name=str(imported["title"]),
            details={
                "source case ID": imported.get("import_source_case_id", ""),
                "source owner": imported.get("import_source_owner_username", ""),
                "event count": imported.get("event_count", 0),
                "evidence count": imported.get("artifact_count", 0),
            },
        )
        flash(
            "Imported a verified closed copy. Original operators were preserved "
            "as attribution, not granted local access.",
            "success",
        )
        return redirect(
            url_for("investigation_detail", investigation_id=imported["id"])
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
            _safe_next(
                url_for("investigation_detail", investigation_id=investigation_id)
            )
        )

    @app.post("/investigations/<investigation_id>/participants")
    def add_investigation_participant(investigation_id: str):
        investigation = investigation_or_404(investigation_id)
        if not investigation.get("can_manage_case"):
            abort(403)
        auth_store = AuthStore(app.instance_path)
        participant_id = request.form.get("user_id", "").strip()
        participant = next(
            (
                item
                for item in auth_store.users()
                if str(item.get("id", "")) == participant_id
            ),
            None,
        )
        if not participant or not participant.get("enabled", True):
            flash("Choose an active toolkit user.", "error")
        else:
            allowed = auth_store.effective_tool_ids(participant)
            if not (
                participant.get("is_admin")
                or allowed is None
                or "investigations.workspace" in allowed
            ):
                flash("That user does not have access to Investigations.", "error")
            else:
                try:
                    store.add_participant(
                        investigation_id,
                        user_id(),
                        str(user().get("username", "")),
                        participant_id,
                        str(participant.get("username", "")),
                    )
                except InvestigationError as exc:
                    flash(str(exc), "error")
                else:
                    annotate_audit_event(
                        category="Investigations",
                        action="investigation.participant_added",
                        summary=(
                            f"Added {participant['username']} to case "
                            f"{investigation['title']}."
                        ),
                        resource_type="investigation",
                        resource_id=investigation_id,
                        resource_name=str(investigation["title"]),
                        details={
                            "participant user ID": participant_id,
                            "participant username": participant["username"],
                        },
                    )
                    flash(
                        f"Added {participant['username']} to the case.", "success"
                    )
        return redirect(
            url_for("investigation_detail", investigation_id=investigation_id)
        )

    @app.post(
        "/investigations/<investigation_id>/participants/<participant_user_id>/remove"
    )
    def remove_investigation_participant(
        investigation_id: str, participant_user_id: str
    ):
        investigation = investigation_or_404(investigation_id)
        if not investigation.get("can_manage_case"):
            abort(403)
        participant = next(
            (
                item
                for item in store.participants_for_user(
                    investigation_id, user_id()
                )
                if str(item["user_id"]) == participant_user_id
            ),
            None,
        )
        if not participant:
            flash("That collaborator is not on this case.", "error")
            return redirect(
                url_for("investigation_detail", investigation_id=investigation_id)
            )
        try:
            stop_and_finalize_case_ping_sessions(
                app.instance_path,
                investigation_id=investigation_id,
                user_id=participant_user_id,
            )
            stop_and_finalize_case_snmp_sessions(
                app.instance_path,
                investigation_id=investigation_id,
                user_id=participant_user_id,
            )
            stop_and_finalize_case_packet_captures(
                app.instance_path,
                investigation_id=investigation_id,
                user_id=participant_user_id,
            )
            stop_and_finalize_case_iperf_servers(
                app.instance_path,
                investigation_id=investigation_id,
                user_id=participant_user_id,
            )
            remote_manager = app.extensions.get("remote_session_manager")
            if isinstance(remote_manager, RemoteSessionManager):
                remote_manager.stop_case_sessions(
                    investigation_id=investigation_id,
                    user_id=participant_user_id,
                )
            store.remove_participant(
                investigation_id,
                user_id(),
                str(user().get("username", "")),
                participant_user_id,
            )
        except (
            InvestigationError,
            PingInvestigationError,
            SnmpInvestigationError,
            PacketCaptureInvestigationError,
            IperfInvestigationError,
            RemoteSessionError,
        ) as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Investigations",
                action="investigation.participant_removed",
                summary=(
                    f"Removed {(participant or {}).get('username', participant_user_id)} "
                    f"from case {investigation['title']}."
                ),
                resource_type="investigation",
                resource_id=investigation_id,
                resource_name=str(investigation["title"]),
                details={
                    "participant user ID": participant_user_id,
                    "participant username": (participant or {}).get("username", ""),
                },
            )
            flash("Removed the collaborator from the case.", "success")
        return redirect(
            url_for("investigation_detail", investigation_id=investigation_id)
        )

    @app.post("/investigations/<investigation_id>/state")
    def update_investigation_state(investigation_id: str):
        investigation = investigation_or_404(investigation_id)
        if not investigation.get("can_manage_case"):
            abort(403)
        state = request.form.get("state", "").strip()
        reopening = investigation["state"] == "completed" and state == "paused"
        ping_result = {"stopped": 0, "finalized": 0}
        snmp_result = {"stopped": 0, "finalized": 0}
        capture_result = {"stopped": 0, "finalized": 0}
        iperf_result = {"stopped": 0, "finalized": 0}
        remote_result = {"stopped": 0, "finalized": 0}
        try:
            if state == "completed":
                for participant in store.participants_for_user(
                    investigation_id, user_id()
                ):
                    participant_user_id = str(participant["user_id"])
                    for aggregate, result in (
                        (
                            ping_result,
                            stop_and_finalize_case_ping_sessions(
                                app.instance_path,
                                investigation_id=investigation_id,
                                user_id=participant_user_id,
                            ),
                        ),
                        (
                            snmp_result,
                            stop_and_finalize_case_snmp_sessions(
                                app.instance_path,
                                investigation_id=investigation_id,
                                user_id=participant_user_id,
                            ),
                        ),
                        (
                            capture_result,
                            stop_and_finalize_case_packet_captures(
                                app.instance_path,
                                investigation_id=investigation_id,
                                user_id=participant_user_id,
                            ),
                        ),
                        (
                            iperf_result,
                            stop_and_finalize_case_iperf_servers(
                                app.instance_path,
                                investigation_id=investigation_id,
                                user_id=participant_user_id,
                            ),
                        ),
                    ):
                        aggregate["stopped"] += result["stopped"]
                        aggregate["finalized"] += result["finalized"]
                    remote_manager = app.extensions.get("remote_session_manager")
                    if isinstance(remote_manager, RemoteSessionManager):
                        result = remote_manager.stop_case_sessions(
                            investigation_id=investigation_id,
                            user_id=participant_user_id,
                        )
                        remote_result["stopped"] += result["stopped"]
                        remote_result["finalized"] += result["finalized"]
            updated = store.set_state(
                investigation_id,
                user_id(),
                str(user().get("username", "")),
                state,
            )
        except (
            InvestigationError,
            PingInvestigationError,
            SnmpInvestigationError,
            PacketCaptureInvestigationError,
            IperfInvestigationError,
            RemoteSessionError,
        ) as exc:
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
                    "multi-ping sessions stopped": ping_result["stopped"],
                    "multi-ping results finalized": ping_result["finalized"],
                    "SNMP monitors stopped": snmp_result["stopped"],
                    "SNMP monitor results finalized": snmp_result["finalized"],
                    "packet captures stopped": capture_result["stopped"],
                    "packet capture results finalized": capture_result["finalized"],
                    "iPerf3 servers stopped": iperf_result["stopped"],
                    "iPerf3 server results finalized": iperf_result["finalized"],
                    "remote sessions stopped": remote_result["stopped"],
                    "remote transcripts finalized": remote_result["finalized"],
                },
            )
            if reopening:
                flash("Case reopened with automatic recording paused.", "success")
            else:
                message = f"Case {label}."
                if state == "completed" and ping_result["stopped"]:
                    count = ping_result["stopped"]
                    message += (
                        f" Stopped and retained {count} attached Ping "
                        f"session{'s' if count != 1 else ''}."
                    )
                if state == "completed" and snmp_result["stopped"]:
                    count = snmp_result["stopped"]
                    message += (
                        f" Stopped and retained {count} attached SNMP monitor"
                        f"{'s' if count != 1 else ''}."
                    )
                if state == "completed" and capture_result["stopped"]:
                    count = capture_result["stopped"]
                    message += (
                        f" Stopped and retained {count} attached packet capture"
                        f"{'s' if count != 1 else ''}."
                    )
                if state == "completed" and iperf_result["stopped"]:
                    count = iperf_result["stopped"]
                    message += (
                        f" Stopped and retained {count} attached iPerf3 server"
                        f"{'s' if count != 1 else ''}."
                    )
                flash(message, "success")
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

    @app.get("/investigations/<investigation_id>/portable.twncase")
    def download_portable_investigation_case(investigation_id: str):
        portable = store.portable_case_for_user(investigation_id, user_id())
        investigation = portable["investigation"]
        try:
            archive, payload = build_portable_case_archive(
                store=store,
                investigation=investigation,
                operators=portable["operators"],
                events=portable["events"],
                artifacts=portable["artifacts"],
                origin=portable["origin"],
            )
        except (DatastoreError, PortableCaseError, OSError) as exc:
            abort(409, str(exc) or "The portable case could not be built.")
        annotate_audit_event(
            category="Investigations",
            action="investigation.portable_case_downloaded",
            summary=f"Exported a portable copy of case {investigation['title']}.",
            resource_type="investigation",
            resource_id=investigation_id,
            resource_name=str(investigation["title"]),
            details={
                "portable schema": payload["schema"],
                "event count": len(payload["events"]),
                "evidence count": len(payload["artifacts"]),
            },
        )
        return send_file(
            archive,
            mimetype="application/zip",
            as_attachment=True,
            download_name=portable_case_filename(investigation),
        )

    @app.post("/investigations/<investigation_id>/report/contents")
    def update_investigation_report_contents(investigation_id: str):
        investigation = investigation_or_404(investigation_id)
        if not investigation.get("can_manage_case"):
            abort(403)
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
