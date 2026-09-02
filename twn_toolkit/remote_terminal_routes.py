from __future__ import annotations

import csv
import io

from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    jsonify,
    render_template,
    request,
    url_for,
)

from .activity_context import record_current_activity
from .audit import annotate_audit_event, suppress_audit_event
from .datastore import DatastoreError, LocalDatastore
from .investigations import InvestigationError, InvestigationStore
from .remote_connections import RemoteConnectionError, RemoteConnectionStore
from .remote_sessions import (
    ACTIVE_REMOTE_SESSION_STATES,
    REMOTE_SESSION_CHECKPOINT_LIMIT_BYTES,
    REMOTE_SESSION_INPUT_LIMIT_BYTES,
    REMOTE_SESSION_OUTPUT_LIMIT_BYTES,
    RemoteSessionError,
    RemoteSessionManager,
    public_remote_session,
    safe_filename,
)
from .serial_console import (
    SERIAL_BAUD_RATES,
    SERIAL_DATA_BITS,
    SERIAL_FLOW_CONTROLS,
    SERIAL_PARITIES,
    SERIAL_STOP_BITS,
    SerialConsoleError,
    list_serial_devices,
    resolve_serial_device,
    serial_settings,
)


def register_remote_terminal_routes(tools_bp: Blueprint) -> None:
    @tools_bp.get("/remote-terminal")
    def remote_terminal():
        user = _current_user()
        sessions = _manager().sessions_for_user(
            user["id"], include_finished=True
        )
        return render_template(
            "tools/remote_terminal.html",
            remote_sessions=[_public_session(item) for item in sessions],
            remote_connection_library=_connection_library(user["id"]),
            serial_console_options=_serial_console_options(),
            can_save_remote_scrollback=_can_use_datastore(),
            datastore_folders=_datastore_folders(),
            requested_session=str(request.args.get("session", "")).strip()[:80],
        )

    @tools_bp.get("/remote-terminal/library")
    def remote_terminal_library():
        suppress_audit_event()
        user = _current_user()
        return jsonify({"library": _connection_library(user["id"])})

    @tools_bp.get("/remote-terminal/devices")
    def remote_terminal_devices():
        suppress_audit_event()
        return jsonify(
            {
                "devices": _serial_devices(),
                "options": _serial_console_options(),
            }
        )

    @tools_bp.get("/remote-terminal/sessions/<session_id>/popout")
    def remote_terminal_popout(session_id: str):
        suppress_audit_event()
        session = _manager().get_session(
            session_id, user_id=_current_user()["id"]
        )
        if not session:
            return jsonify({"error": "Remote session not found."}), 404
        public_session = _public_session(session)
        return render_template(
            "tools/remote_terminal_popout.html",
            remote_sessions=[public_session],
            requested_session=session_id,
            popout_session=public_session,
            can_save_remote_scrollback=_can_use_datastore(),
            datastore_folders=_datastore_folders(),
        )

    @tools_bp.post("/remote-terminal/sessions")
    def start_remote_terminal_session():
        payload = request.get_json(silent=True) or {}
        try:
            user = _current_user()
            console_device_id = ""
            console_device_path = ""
            console_device_label = ""
            console = serial_settings()
            source_host_id = str(payload.get("host_id", "")).strip()
            if source_host_id:
                saved_host = _connection_store().get_host(
                    source_host_id, user_id=user["id"],
                    is_admin=bool(user.get("is_admin")),
                )
                if not saved_host:
                    raise RemoteSessionError("Saved host not found.")
                host = str(saved_host["host"])
                port = int(saved_host["port"])
                protocol = _protocol(saved_host.get("protocol", "ssh"))
                if protocol == "console":
                    device = resolve_serial_device(
                        str(saved_host.get("console_device_id", ""))
                    )
                    console_device_id = str(device["id"])
                    console_device_path = str(device["path"])
                    console_device_label = str(
                        saved_host.get("console_device_label", "")
                        or device["label"]
                    )
                    console = serial_settings(
                        baud_rate=saved_host.get("console_baud_rate", 9600),
                        data_bits=saved_host.get("console_data_bits", 8),
                        parity=saved_host.get("console_parity", "none"),
                        stop_bits=saved_host.get("console_stop_bits", 1),
                        flow_control=saved_host.get("console_flow_control", "none"),
                    )
                    host = console_device_path
                    port = 0
                    remote_username = ""
                    password = ""
                else:
                    credential_id = str(
                        saved_host.get("effective_credential_id", "")
                    )
                    if credential_id:
                        credential = _connection_store().resolve_credential(
                            credential_id,
                            user_id=user["id"],
                            is_admin=bool(user.get("is_admin")),
                            host_id=source_host_id,
                        )
                        remote_username = credential["username"]
                        password = credential["password"]
                    elif protocol == "telnet":
                        remote_username = ""
                        password = ""
                    else:
                        raise RemoteSessionError(
                            "Assign a credential to this host or one of its parent folders."
                        )
                default_title = str(saved_host["name"])
                allow_unknown_hosts = bool(saved_host["allow_unknown_hosts"])
                allow_legacy_algorithms = bool(
                    saved_host["allow_legacy_algorithms"]
                )
            else:
                protocol = _protocol(payload.get("protocol", "ssh"))
                if protocol == "console":
                    device = resolve_serial_device(
                        str(payload.get("console_device_id", "")).strip()
                    )
                    console_device_id = str(device["id"])
                    console_device_path = str(device["path"])
                    console_device_label = str(device["label"])
                    console = serial_settings(
                        baud_rate=payload.get("console_baud_rate", 9600),
                        data_bits=payload.get("console_data_bits", 8),
                        parity=payload.get("console_parity", "none"),
                        stop_bits=payload.get("console_stop_bits", 1),
                        flow_control=payload.get("console_flow_control", "none"),
                    )
                    host = console_device_path
                    port = 0
                    remote_username = ""
                    password = ""
                    default_title = console_device_label
                else:
                    host = _host(payload.get("host", ""))
                    default_port = 23 if protocol == "telnet" else 22
                    port = _integer(payload.get("port", default_port), "Port", 1, 65535)
                    credential_id = str(payload.get("credential_id", "")).strip()
                    if credential_id:
                        credential = _connection_store().resolve_credential(
                            credential_id,
                            user_id=user["id"],
                            is_admin=bool(user.get("is_admin")),
                        )
                        remote_username = credential["username"]
                        password = credential["password"]
                    else:
                        password = str(payload.get("password", ""))
                        if protocol == "telnet":
                            remote_username = _optional_remote_username(
                                payload.get("username", "")
                            )
                        else:
                            remote_username = _text(
                                payload.get("username", ""), "Username", 128
                            )
                            if not password:
                                raise RemoteSessionError("Enter the password.")
                    if len(password.encode("utf-8")) > REMOTE_SESSION_INPUT_LIMIT_BYTES:
                        raise RemoteSessionError("The password is too large.")
                    default_title = (
                        f"{remote_username}@{host}" if remote_username else host
                    )
                allow_unknown_hosts = protocol == "ssh" and bool(
                    payload.get("allow_unknown_hosts", False)
                )
                allow_legacy_algorithms = protocol == "ssh" and bool(
                    payload.get("allow_legacy_algorithms", False)
                )
            title = " ".join(str(payload.get("title", "")).strip().split())
            if len(title) > 100:
                raise RemoteSessionError(
                    "Remote session names must be 100 characters or fewer."
                )
            columns = _integer(payload.get("columns", 120), "Columns", 40, 300)
            rows = _integer(payload.get("rows", 32), "Rows", 10, 120)
            investigation_id = _recording_case_id(user["id"])
            record_transcript = bool(investigation_id)
            session = _manager().start_session(
                protocol=protocol,
                user_id=user["id"],
                username=user["username"],
                title=title or default_title,
                host=host,
                port=port,
                remote_username=remote_username,
                password=password,
                record_transcript=record_transcript,
                investigation_id=investigation_id,
                allow_unknown_hosts=allow_unknown_hosts,
                allow_legacy_algorithms=allow_legacy_algorithms,
                source_host_id=source_host_id,
                columns=columns,
                rows=rows,
                console_device_id=console_device_id,
                console_device_path=console_device_path,
                console_device_label=console_device_label,
                console_baud_rate=int(console["baud_rate"]),
                console_data_bits=int(console["data_bits"]),
                console_parity=str(console["parity"]),
                console_stop_bits=str(console["stop_bits"]),
                console_flow_control=str(console["flow_control"]),
            )
        except (RemoteSessionError, SerialConsoleError, TypeError, ValueError) as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 400
        annotate_audit_event(
            category="Network tools",
            action="remote_terminal.session_started",
            summary=f"Started a persistent remote {protocol.upper()} session.",
            resource_type="remote_session",
            resource_id=str(session["id"]),
            resource_name=str(session["title"]),
            details={
                "protocol": protocol.upper(),
                "host": host if protocol != "console" else "",
                "port": port if protocol != "console" else "",
                "console device": console_device_label if protocol == "console" else "",
                "console path": console_device_path if protocol == "console" else "",
                "remote username": remote_username,
                "connection source": "saved host" if source_host_id else "quick connect",
                "case attached": bool(investigation_id),
                "transcript evidence enabled": bool(session["record_transcript"]),
            },
        )
        record_current_activity(
            "Network tools",
            f"Started persistent {protocol.upper()} session",
            console_device_label if protocol == "console" else f"{host}:{port}",
            count_action=True,
        )
        return jsonify({"session": _public_session(session)}), 201

    @tools_bp.post("/remote-terminal/folders")
    def create_remote_terminal_folder():
        payload = request.get_json(silent=True) or {}
        user = _current_user()
        parent_id = str(payload.get("parent_id", ""))
        visibility = str(
            payload.get("visibility", "inherit" if parent_id else "private")
        )
        try:
            RemoteConnectionStore._clean_visibility(
                visibility, allow_inherit=True
            )
            folder = _connection_store().create_folder(
                user_id=user["id"],
                name=str(payload.get("name", "")),
                parent_id=parent_id,
                credential_mode=str(payload.get("credential_mode", "inherit")),
                credential_id=str(payload.get("credential_id", "")),
            )
            _connection_store().set_visibility(
                "folder",
                str(folder["id"]),
                user_id=user["id"],
                visibility=visibility,
            )
            folder = _connection_store().get_folder(
                str(folder["id"]), user_id=user["id"]
            )
        except RemoteConnectionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 400
        _annotate_library_change("folder_created", "Created saved-host folder.", folder)
        return _library_response(user["id"], 201)

    @tools_bp.patch("/remote-terminal/folders/<folder_id>")
    def update_remote_terminal_folder(folder_id: str):
        payload = request.get_json(silent=True) or {}
        user = _current_user()
        try:
            folder = _connection_store().update_folder(
                folder_id,
                user_id=user["id"],
                name=str(payload.get("name", "")),
                parent_id=str(payload.get("parent_id", "")),
                credential_mode=(
                    str(payload.get("credential_mode", ""))
                    if "credential_mode" in payload
                    else None
                ),
                credential_id=str(payload.get("credential_id", "")),
            )
            if "visibility" in payload:
                _connection_store().set_visibility(
                    "folder",
                    folder_id,
                    user_id=user["id"],
                    visibility=str(payload["visibility"]),
                )
                folder = _connection_store().get_folder(
                    folder_id, user_id=user["id"]
                )
        except RemoteConnectionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 400
        _annotate_library_change("folder_updated", "Updated saved-host folder.", folder)
        return _library_response(user["id"])

    @tools_bp.post("/remote-terminal/folders/<folder_id>/duplicate")
    def duplicate_remote_terminal_folder(folder_id: str):
        user = _current_user()
        try:
            folder = _connection_store().duplicate_folder(
                folder_id, user_id=user["id"]
            )
        except RemoteConnectionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 400
        _annotate_library_change(
            "folder_duplicated", "Duplicated saved-host folder.", folder
        )
        return _library_response(user["id"], 201)

    @tools_bp.delete("/remote-terminal/folders/<folder_id>")
    def delete_remote_terminal_folder(folder_id: str):
        user = _current_user()
        existing = _connection_store().get_folder(folder_id, user_id=user["id"])
        if not existing:
            suppress_audit_event()
            return jsonify({"error": "Saved folder not found."}), 404
        try:
            _connection_store().delete_folder(folder_id, user_id=user["id"])
        except RemoteConnectionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 409
        _annotate_library_change(
            "folder_deleted", "Deleted saved-host folder.", existing
        )
        return _library_response(user["id"])

    @tools_bp.post("/remote-terminal/credentials")
    def create_remote_terminal_credential():
        return _save_remote_terminal_credential()

    @tools_bp.patch("/remote-terminal/credentials/<credential_id>")
    def update_remote_terminal_credential(credential_id: str):
        return _save_remote_terminal_credential(credential_id)

    @tools_bp.post("/remote-terminal/credentials/<credential_id>/duplicate")
    def duplicate_remote_terminal_credential(credential_id: str):
        user = _current_user()
        try:
            credential = _connection_store().duplicate_credential(
                credential_id, user_id=user["id"]
            )
        except RemoteConnectionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 404
        _annotate_library_change(
            "credential_duplicated",
            "Duplicated encrypted remote credential.",
            credential,
            resource_type="remote_credential",
        )
        return _library_response(user["id"], 201)

    @tools_bp.delete("/remote-terminal/credentials/<credential_id>")
    def delete_remote_terminal_credential(credential_id: str):
        user = _current_user()
        existing = next(
            (
                item
                for item in _connection_store().library_for_user(user["id"])[
                    "credentials"
                ]
                if item["id"] == credential_id
            ),
            None,
        )
        if not existing:
            suppress_audit_event()
            return jsonify({"error": "Saved credential not found."}), 404
        try:
            _connection_store().delete_credential(
                credential_id, user_id=user["id"]
            )
        except RemoteConnectionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 409
        _annotate_library_change(
            "credential_deleted",
            "Deleted encrypted remote credential.",
            existing,
            resource_type="remote_credential",
        )
        return _library_response(user["id"])

    @tools_bp.post("/remote-terminal/hosts")
    def create_remote_terminal_host():
        return _save_remote_terminal_host()

    @tools_bp.post("/remote-terminal/hosts/import/preview")
    def preview_remote_terminal_host_import():
        suppress_audit_event()
        payload = request.get_json(silent=True) or {}
        preview = _remote_host_import_preview(payload, _current_user()["id"])
        return jsonify({"preview": preview})

    @tools_bp.post("/remote-terminal/hosts/import")
    def import_remote_terminal_hosts():
        payload = request.get_json(silent=True) or {}
        user = _current_user()
        preview = _remote_host_import_preview(payload, user["id"])
        if preview["errors"]:
            suppress_audit_event()
            return jsonify(
                {
                    "error": "Fix the highlighted import rows before saving.",
                    "preview": preview,
                }
            ), 400
        try:
            imported = _connection_store().import_hosts(
                user_id=user["id"],
                folder_id=str(payload.get("folder_id", "")),
                hosts=list(preview["rows"]),
            )
        except (RemoteConnectionError, TypeError, ValueError) as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 400
        protocols = sorted(
            {str(item["protocol"]).upper() for item in preview["rows"]}
        )
        _annotate_library_change(
            "hosts_imported",
            f"Imported {imported} saved remote host{'s' if imported != 1 else ''}.",
            {"id": "host-import", "name": "Imported saved hosts"},
            resource_type="remote_host_collection",
            details={
                "hosts": imported,
                "folder assigned": bool(payload.get("folder_id")),
                "protocols": ", ".join(protocols),
                "credential mode": "inherited",
            },
        )
        return _library_response(user["id"], 201)

    @tools_bp.post("/remote-terminal/library/bulk")
    def bulk_update_remote_terminal_library():
        payload = request.get_json(silent=True) or {}
        user = _current_user()
        destination_id = (
            str(payload.get("destination_id", ""))
            if bool(payload.get("change_location"))
            else None
        )
        credential_mode = (
            str(payload.get("credential_mode", ""))
            if bool(payload.get("change_credential"))
            else None
        )
        try:
            changed = _connection_store().bulk_update(
                user_id=user["id"],
                host_ids=list(payload.get("host_ids", [])),
                folder_ids=list(payload.get("folder_ids", [])),
                destination_id=destination_id,
                credential_mode=credential_mode,
                credential_id=str(payload.get("credential_id", "")),
            )
        except (RemoteConnectionError, TypeError, ValueError) as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 400
        _annotate_library_change(
            "library_bulk_updated",
            "Updated selected Remote Terminal library items.",
            {"id": "bulk-selection", "name": "Selected connection items"},
            details={
                "hosts": changed["hosts"],
                "folders": changed["folders"],
                "location changed": destination_id is not None,
                "credential changed": credential_mode is not None,
            },
        )
        return _library_response(user["id"])

    @tools_bp.patch("/remote-terminal/hosts/<host_id>")
    def update_remote_terminal_host(host_id: str):
        return _save_remote_terminal_host(host_id)

    @tools_bp.post("/remote-terminal/hosts/<host_id>/duplicate")
    def duplicate_remote_terminal_host(host_id: str):
        user = _current_user()
        existing = _connection_store().get_host(host_id, user_id=user["id"])
        if not existing or not existing.get("owned"):
            suppress_audit_event()
            return jsonify({"error": "Saved host not found."}), 404
        try:
            host = _connection_store().duplicate_host(host_id, user_id=user["id"])
        except RemoteConnectionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 404
        _annotate_library_change(
            "host_duplicated", "Duplicated saved remote host.", host,
            resource_type="remote_host",
        )
        return _library_response(user["id"], 201)

    @tools_bp.delete("/remote-terminal/hosts/<host_id>")
    def delete_remote_terminal_host(host_id: str):
        user = _current_user()
        existing = _connection_store().get_host(host_id, user_id=user["id"])
        if not existing or not existing.get("owned"):
            suppress_audit_event()
            return jsonify({"error": "Saved host not found."}), 404
        _connection_store().delete_host(host_id, user_id=user["id"])
        _annotate_library_change(
            "host_deleted", "Deleted saved remote host.", existing,
            resource_type="remote_host",
        )
        return _library_response(user["id"])

    @tools_bp.get("/remote-terminal/sessions/<session_id>")
    def remote_terminal_session(session_id: str):
        suppress_audit_event()
        session = _manager().get_session(
            session_id, user_id=_current_user()["id"]
        )
        if not session:
            return jsonify({"error": "Remote session not found."}), 404
        return jsonify({"session": _public_session(session)})

    @tools_bp.get("/remote-terminal/sessions/<session_id>/output")
    def remote_terminal_output(session_id: str):
        suppress_audit_event()
        try:
            after_id = int(request.args.get("after", "0"))
        except ValueError:
            return jsonify({"error": "Output cursor must be an integer."}), 400
        manager = _manager()
        if not manager.get_session(session_id, user_id=_current_user()["id"]):
            return jsonify({"error": "Remote session not found."}), 404
        page = manager.store.output_page(
            session_id,
            user_id=_current_user()["id"],
            after_id=after_id,
            include_checkpoint=request.args.get("bootstrap") == "1",
        )
        if page is None:
            return jsonify({"error": "Remote session not found."}), 404
        page["session"] = _public_session(page["session"])
        return jsonify(page)

    @tools_bp.post("/remote-terminal/sessions/<session_id>/checkpoint")
    def save_remote_terminal_checkpoint(session_id: str):
        suppress_audit_event()
        if (
            request.content_length is not None
            and request.content_length > REMOTE_SESSION_CHECKPOINT_LIMIT_BYTES + 64 * 1024
        ):
            return jsonify({"error": "Terminal checkpoint is too large."}), 413
        data = request.get_json(silent=True) or {}
        try:
            output_cursor = int(data.get("cursor", 0))
        except (TypeError, ValueError):
            return jsonify({"error": "Terminal checkpoint cursor must be an integer."}), 400
        snapshot = data.get("snapshot")
        if not isinstance(snapshot, dict):
            return jsonify({"error": "Terminal checkpoint is invalid."}), 400
        try:
            saved = _manager().store.save_checkpoint(
                session_id,
                user_id=_current_user()["id"],
                output_cursor=output_cursor,
                snapshot=snapshot,
            )
        except RemoteSessionError as exc:
            return jsonify({"error": str(exc)}), 400
        if not saved and not _manager().get_session(
            session_id, user_id=_current_user()["id"]
        ):
            return jsonify({"error": "Remote session not found."}), 404
        return jsonify({"saved": saved, "cursor": output_cursor})

    @tools_bp.get("/remote-terminal/sessions/<session_id>/download")
    def download_remote_terminal_scrollback(session_id: str):
        user = _current_user()
        manager = _manager()
        session = manager.get_session(session_id, user_id=user["id"])
        if not session:
            suppress_audit_event()
            return jsonify({"error": "Remote session not found."}), 404
        filename = (
            f"{safe_filename(str(session['title']))}-{session_id[:8]}-scrollback.txt"
        )
        response = current_app.response_class(
            manager.store.transcript(session_id),
            content_type="text/plain; charset=utf-8",
        )
        disposition = "inline" if request.args.get("view") == "1" else "attachment"
        response.headers["Content-Disposition"] = f'{disposition}; filename="{filename}"'
        response.headers["X-Content-Type-Options"] = "nosniff"
        annotate_audit_event(
            category="Network tools",
            action=(
                "remote_terminal.scrollback_viewed"
                if disposition == "inline"
                else "remote_terminal.scrollback_downloaded"
            ),
            summary=(
                "Viewed the retained remote-terminal transcript."
                if disposition == "inline"
                else "Downloaded retained remote-terminal scrollback."
            ),
            resource_type="remote_session",
            resource_id=session_id,
            resource_name=str(session["title"]),
            details={
                "host": session["host"],
                "port": session["port"],
                "output bytes": session["output_bytes"],
            },
        )
        return response

    @tools_bp.post("/remote-terminal/sessions/<session_id>/case")
    def attach_remote_terminal_case(session_id: str):
        user = _current_user()
        investigation_store = current_app.extensions.get("investigation_store")
        if not isinstance(investigation_store, InvestigationStore):  # pragma: no cover
            return jsonify({"error": "Case recording is unavailable."}), 503
        investigation = investigation_store.active_for_user(user["id"])
        if not investigation:
            suppress_audit_event()
            return jsonify({"error": "Open or reopen a case before attaching this session."}), 409
        payload = request.get_json(silent=True) or {}
        requested_id = str(payload.get("investigation_id", "")).strip()
        if requested_id and requested_id != str(investigation["id"]):
            suppress_audit_event()
            return jsonify({"error": "The selected case is no longer active."}), 409
        existing = _manager().get_session(session_id, user_id=user["id"])
        if not existing:
            suppress_audit_event()
            return jsonify({"error": "Remote session not found."}), 404
        try:
            session = _manager().attach_to_case(
                session_id,
                user_id=user["id"],
                username=user["username"],
                investigation_id=str(investigation["id"]),
            )
        except (InvestigationError, RemoteSessionError) as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 409
        annotate_audit_event(
            category="Network tools",
            action="remote_terminal.session_attached_to_case",
            summary="Attached retained remote-terminal output to a case.",
            resource_type="remote_session",
            resource_id=session_id,
            resource_name=str(session["title"]),
            details={
                "case": investigation["id"],
                "case title": investigation["title"],
                "session state": session["state"],
                "output bytes": session["output_bytes"],
            },
        )
        return jsonify({"session": _public_session(session)})

    @tools_bp.post("/remote-terminal/sessions/<session_id>/datastore")
    def save_remote_terminal_scrollback(session_id: str):
        user = _current_user()
        manager = _manager()
        if not _can_use_datastore():
            abort(403)
        session = manager.get_session(session_id, user_id=user["id"])
        if not session:
            suppress_audit_event()
            return jsonify({"error": "Remote session not found."}), 404
        transcript = manager.store.transcript(session_id)
        if not transcript:
            suppress_audit_event()
            return jsonify({"error": "This session has no retained output to save."}), 409
        payload = request.get_json(silent=True) or {}
        destination = str(payload.get("folder", "")).strip()
        datastore = LocalDatastore(current_app.instance_path)
        kind = (
            "live snapshot"
            if session["state"] in ACTIVE_REMOTE_SESSION_STATES
            else "completed scrollback"
        )
        suffix = "snapshot" if kind == "live snapshot" else "scrollback"
        base_filename = (
            f"{safe_filename(str(session['title']))}-{session_id[:8]}-{suffix}.txt"
        )
        try:
            filename = _available_datastore_filename(
                datastore, destination, base_filename
            )
            path, byte_count = datastore.save_upload(
                destination,
                filename,
                io.BytesIO(transcript.encode("utf-8")),
                max_bytes=REMOTE_SESSION_OUTPUT_LIMIT_BYTES + 1024,
            )
        except (DatastoreError, OSError) as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 409
        relative_path = datastore.relative(path)
        annotate_audit_event(
            category="Local storage",
            action="remote_terminal.scrollback_saved_to_datastore",
            summary=f"Saved remote-terminal {kind} to the Datastore.",
            resource_type="datastore_file",
            resource_id=relative_path,
            resource_name=filename,
            details={
                "session": session_id,
                "session title": session["title"],
                "host": session["host"],
                "kind": kind,
                "bytes": byte_count,
            },
        )
        record_current_activity(
            "Local storage",
            "Saved remote-terminal output",
            relative_path,
        )
        return jsonify(
            {
                "saved": {
                    "name": filename,
                    "path": relative_path,
                    "byte_count": byte_count,
                    "kind": kind,
                    "folder_url": url_for("local_datastore", path=destination),
                }
            }
        )

    @tools_bp.delete("/remote-terminal/sessions/<session_id>")
    def delete_remote_terminal_scrollback(session_id: str):
        user = _current_user()
        manager = _manager()
        session = manager.get_session(session_id, user_id=user["id"])
        if not session:
            suppress_audit_event()
            return jsonify({"error": "Remote session not found."}), 404
        try:
            deleted = manager.store.delete_session(session_id, user_id=user["id"])
        except RemoteSessionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 409
        annotate_audit_event(
            category="Network tools",
            action="remote_terminal.scrollback_deleted",
            summary="Deleted retained remote-terminal scrollback.",
            resource_type="remote_session",
            resource_id=session_id,
            resource_name=str(session["title"]),
            details={
                "host": session["host"],
                "port": session["port"],
                "output bytes": session["output_bytes"],
                "case evidence retained": bool(session.get("investigation_id")),
            },
        )
        return jsonify({"deleted_id": str(deleted["id"])})

    @tools_bp.post("/remote-terminal/sessions/<session_id>/input")
    def remote_terminal_input(session_id: str):
        suppress_audit_event()
        payload = request.get_json(silent=True) or {}
        data = str(payload.get("data", ""))
        try:
            _manager().send_input(
                session_id, user_id=_current_user()["id"], data=data
            )
        except RemoteSessionError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify({"accepted_bytes": len(data.encode("utf-8"))})

    @tools_bp.post("/remote-terminal/sessions/<session_id>/credential")
    def remote_terminal_credential(session_id: str):
        suppress_audit_event()
        payload = request.get_json(silent=True) or {}
        try:
            accepted_bytes = _manager().send_telnet_credential(
                session_id,
                user_id=_current_user()["id"],
                field=str(payload.get("field", "")),
            )
        except RemoteSessionError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify({"accepted_bytes": accepted_bytes})

    @tools_bp.post("/remote-terminal/sessions/<session_id>/resize")
    def resize_remote_terminal_session(session_id: str):
        suppress_audit_event()
        payload = request.get_json(silent=True) or {}
        try:
            columns = _integer(payload.get("columns", 120), "Columns", 40, 300)
            rows = _integer(payload.get("rows", 32), "Rows", 10, 120)
            _manager().resize(
                session_id,
                user_id=_current_user()["id"],
                columns=columns,
                rows=rows,
            )
        except (RemoteSessionError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify({"columns": columns, "rows": rows})

    @tools_bp.post("/remote-terminal/sessions/<session_id>/stop")
    def stop_remote_terminal_session(session_id: str):
        user = _current_user()
        existing = _manager().get_session(session_id, user_id=user["id"])
        if not existing:
            suppress_audit_event()
            return jsonify({"error": "Remote session not found."}), 404
        try:
            session = _manager().stop_session(session_id, user_id=user["id"])
        except RemoteSessionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 409
        if not session:  # pragma: no cover - ownership was checked above
            return jsonify({"error": "Remote session not found."}), 404
        if existing["state"] not in ACTIVE_REMOTE_SESSION_STATES:
            suppress_audit_event()
        else:
            annotate_audit_event(
                category="Network tools",
                action="remote_terminal.session_stopped",
                summary="Stopped a persistent remote terminal session.",
                resource_type="remote_session",
                resource_id=str(session["id"]),
                resource_name=str(session["title"]),
                details={
                    "host": session["host"],
                    "port": session["port"],
                    "output bytes": session["output_bytes"],
                    "termination": session["termination"],
                },
            )
        return jsonify({"session": _public_session(session)})

    @tools_bp.post("/remote-terminal/sessions/<session_id>/rename")
    def rename_remote_terminal_session(session_id: str):
        payload = request.get_json(silent=True) or {}
        title = " ".join(str(payload.get("title", "")).strip().split())
        if not title:
            suppress_audit_event()
            return jsonify({"error": "Remote session names cannot be blank."}), 400
        if len(title) > 100:
            suppress_audit_event()
            return jsonify(
                {"error": "Remote session names must be 100 characters or fewer."}
            ), 400
        user = _current_user()
        existing = _manager().get_session(session_id, user_id=user["id"])
        if not existing:
            suppress_audit_event()
            return jsonify({"error": "Remote session not found."}), 404
        session = _manager().store.rename_session(
            session_id, user_id=user["id"], title=title
        )
        annotate_audit_event(
            category="Network tools",
            action="remote_terminal.session_renamed",
            summary="Renamed a remote terminal session.",
            resource_type="remote_session",
            resource_id=session_id,
            resource_name=title,
            details={"previous name": existing["title"], "new name": title},
        )
        return jsonify({"session": _public_session(session)})


def _save_remote_terminal_credential(credential_id: str = ""):
    payload = request.get_json(silent=True) or {}
    user = _current_user()
    existing = None
    scope_host_id = ""
    if credential_id:
        existing = next(
            (
                item
                for item in _connection_library(user["id"])["credentials"]
                if item["id"] == credential_id and item.get("owned")
            ),
            None,
        )
        if not existing:
            suppress_audit_event()
            return jsonify({"error": "Saved credential not found."}), 404
        scope_host_id = str(existing["scope_host_id"])
    visibility = str(
        payload.get(
            "visibility",
            existing.get("visibility", "private") if existing else "private",
        )
    )
    try:
        RemoteConnectionStore._clean_visibility(visibility)
        credential = _connection_store().save_credential(
            user_id=user["id"],
            credential_id=credential_id,
            name=str(payload.get("name", "")),
            remote_username=str(payload.get("username", "")),
            password=str(payload.get("password", "")),
            scope_host_id=scope_host_id,
        )
        _connection_store().set_visibility(
            "credential",
            str(credential["id"]),
            user_id=user["id"],
            visibility=visibility,
        )
        credential = next(
            item
            for item in _connection_library(user["id"])["credentials"]
            if item["id"] == credential["id"]
        )
    except RemoteConnectionError as exc:
        suppress_audit_event()
        return jsonify({"error": str(exc)}), 400
    _annotate_library_change(
        "credential_updated" if credential_id else "credential_created",
        (
            "Updated encrypted remote credential."
            if credential_id
            else "Created encrypted remote credential."
        ),
        credential,
        resource_type="remote_credential",
        details={
            "username": credential["username"],
            "host scoped": bool(credential["scope_host_id"]),
            "visibility": credential["visibility"],
            "secret replaced": bool(payload.get("password")),
        },
    )
    return _library_response(user["id"], 200 if credential_id else 201)

def _save_remote_terminal_host(host_id: str = ""):
    payload = request.get_json(silent=True) or {}
    user = _current_user()
    existing_host = (
        _connection_store().get_host(host_id, user_id=user["id"])
        if host_id
        else None
    )
    if host_id and (not existing_host or not existing_host.get("owned")):
        suppress_audit_event()
        return jsonify({"error": "Saved host not found."}), 404
    visibility = str(
        payload.get("visibility", existing_host.get("visibility", "inherit") if existing_host else "inherit")
    )
    protocol_value = str(payload.get("protocol", "ssh")).strip().lower()
    credential_mode = (
        "none"
        if protocol_value == "console"
        else str(payload.get("credential_mode", "saved"))
    )
    host_credential = None
    if credential_mode == "host":
        host_credential = {
            "name": str(payload.get("host_credential_name", "")),
            "username": str(payload.get("host_username", "")),
            "password": str(payload.get("host_password", "")),
        }
    elif credential_mode in {"none", "inherit"}:
        pass
    elif credential_mode != "saved":
        suppress_audit_event()
        return jsonify(
            {
                "error": (
                    "Choose inherited, saved, host-specific, or no credentials."
                )
            }
        ), 400
    try:
        RemoteConnectionStore._clean_visibility(visibility, allow_inherit=True)
        protocol = _protocol(protocol_value)
        console_device_id = ""
        console_device_path = ""
        console_device_label = ""
        console = serial_settings()
        if protocol == "console":
            requested_device_id = str(
                payload.get("console_device_id", "")
            ).strip()
            try:
                device = resolve_serial_device(requested_device_id)
            except SerialConsoleError:
                existing = (
                    _connection_store().get_host(host_id, user_id=user["id"])
                    if host_id
                    else None
                )
                if (
                    not existing
                    or str(existing.get("protocol", "")) != "console"
                    or str(existing.get("console_device_id", ""))
                    != requested_device_id
                ):
                    raise
                console_device_id = requested_device_id
                console_device_path = str(existing["console_device_path"])
                console_device_label = str(existing["console_device_label"])
            else:
                console_device_id = str(device["id"])
                console_device_path = str(device["path"])
                console_device_label = str(device["label"])
            console = serial_settings(
                baud_rate=payload.get("console_baud_rate", 9600),
                data_bits=payload.get("console_data_bits", 8),
                parity=payload.get("console_parity", "none"),
                stop_bits=payload.get("console_stop_bits", 1),
                flow_control=payload.get("console_flow_control", "none"),
            )
        host = _connection_store().save_host(
            user_id=user["id"],
            host_id=host_id,
            name=str(payload.get("name", "")),
            host=(
                console_device_path
                if protocol == "console"
                else str(payload.get("host", ""))
            ),
            port=(
                0
                if protocol == "console"
                else _integer(
                    payload.get("port", 23 if protocol == "telnet" else 22),
                    "Port",
                    1,
                    65535,
                )
            ),
            protocol=protocol,
            folder_id=str(payload.get("folder_id", "")),
            credential_id=(
                ""
                if credential_mode in {"none", "inherit"}
                else str(payload.get("credential_id", ""))
            ),
            credential_mode=(
                credential_mode
                if credential_mode in {"none", "inherit"}
                else "credential"
            ),
            allow_unknown_hosts=bool(payload.get("allow_unknown_hosts", False)),
            allow_legacy_algorithms=bool(
                payload.get("allow_legacy_algorithms", False)
            ),
            notes=str(payload.get("notes", "")),
            host_credential=host_credential,
            console_device_id=console_device_id,
            console_device_path=console_device_path,
            console_device_label=console_device_label,
            console_baud_rate=int(console["baud_rate"]),
            console_data_bits=int(console["data_bits"]),
            console_parity=str(console["parity"]),
            console_stop_bits=str(console["stop_bits"]),
            console_flow_control=str(console["flow_control"]),
        )
        _connection_store().set_visibility(
            "host",
            str(host["id"]),
            user_id=user["id"],
            visibility=visibility,
        )
        host = _connection_store().get_host(
            str(host["id"]), user_id=user["id"]
        )
        if host and host.get("credential_scope_host_id") == host.get("id"):
            _connection_store().set_visibility(
                "credential",
                str(host["credential_id"]),
                user_id=user["id"],
                visibility=str(host["effective_visibility"]),
            )
            host = _connection_store().get_host(
                str(host["id"]), user_id=user["id"]
            )

    except (RemoteConnectionError, SerialConsoleError, TypeError, ValueError) as exc:
        suppress_audit_event()
        return jsonify({"error": str(exc)}), 400
    _annotate_library_change(
        "host_updated" if host_id else "host_created",
        "Updated saved remote host." if host_id else "Created saved remote host.",
        host,
        resource_type="remote_host",
        details={
            "host": host["host"],
            "port": host["port"],
            "protocol": str(host["protocol"]).upper(),
            "folder assigned": bool(host["folder_id"]),
            "visibility": host["effective_visibility"],
            "credential mode": (
                "host-specific"
                if host["credential_scope_host_id"] == host["id"]
                else "inherited"
                if host["credential_mode"] == "inherit"
                else "shared"
                if host["credential_id"]
                else "none"
            ),
        },
    )
    return _library_response(user["id"], 200 if host_id else 201)


def _remote_host_import_preview(
    payload: dict[str, object], user_id: str
) -> dict[str, object]:
    folder_id = str(payload.get("folder_id", ""))
    errors: list[dict[str, object]] = []
    if folder_id and not _connection_store().get_folder(folder_id, user_id=user_id):
        errors.append({"row": 0, "message": "Choose a valid destination folder."})
    rows, parse_errors = _parse_remote_host_import(
        payload.get("text", ""), payload.get("default_protocol", "ssh")
    )
    errors.extend(parse_errors)

    existing_names = {
        str(item["name"]).casefold()
        for item in _connection_store().library_for_user(user_id)["hosts"]
        if str(item["folder_id"]) == folder_id
    }
    for item in rows:
        if str(item["name"]).casefold() in existing_names:
            errors.append(
                {
                    "row": item["row"],
                    "message": "That host name is already used in the destination folder.",
                }
            )
    return {
        "rows": rows,
        "errors": errors,
        "count": len(rows),
        "ready": bool(rows) and not errors,
    }


def _parse_remote_host_import(
    value: object, default_protocol: object = "ssh"
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    text = str(value)
    if len(text.encode("utf-8")) > 512 * 1024:
        return [], [{"row": 0, "message": "Host import text must be 512 KiB or smaller."}]
    protocol_default = str(default_protocol).strip().lower()
    if protocol_default not in {"ssh", "telnet"}:
        return [], [{"row": 0, "message": "Choose SSH or Telnet as the default protocol."}]

    source_rows: list[tuple[int, list[str]]] = []
    errors: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            parsed = next(csv.reader([line], skipinitialspace=True))
        except csv.Error as exc:
            errors.append({"row": line_number, "message": f"Invalid CSV: {exc}"})
            continue
        source_rows.append(
            (
                line_number,
                [
                    field.strip().lstrip("\ufeff") if index == 0 else field.strip()
                    for index, field in enumerate(parsed)
                ],
            )
        )
    if not source_rows:
        errors.append({"row": 0, "message": "Paste or choose at least one host."})
        return [], errors
    if len(source_rows) > 1000:
        errors.append({"row": 0, "message": "Import no more than 1,000 hosts at once."})
        return [], errors

    header_aliases = {
        "name": {"name", "display name", "label"},
        "host": {
            "host",
            "host/ip",
            "hostname",
            "ip",
            "ip address",
            "address",
        },
        "protocol": {"protocol", "type"},
        "port": {"port"},
    }
    first_values = [field.casefold() for field in source_rows[0][1]]
    has_header = any(field in header_aliases["host"] for field in first_values)
    header_map: dict[str, int] = {}
    if has_header:
        for index, field in enumerate(first_values):
            for key, aliases in header_aliases.items():
                if field in aliases and key not in header_map:
                    header_map[key] = index
        source_rows = source_rows[1:]

    parsed_rows: list[dict[str, object]] = []
    seen_names: set[str] = set()
    for line_number, values in source_rows:
        try:
            if has_header:
                def column(name: str) -> str:
                    index = header_map.get(name)
                    return values[index].strip() if index is not None and index < len(values) else ""

                host = column("host")
                name = column("name") or host
                protocol = column("protocol") or protocol_default
                raw_port = column("port")
            else:
                if len(values) == 1:
                    if "=" in values[0]:
                        name, host = [part.strip() for part in values[0].split("=", 1)]
                    else:
                        host = values[0]
                        name = host
                    protocol = protocol_default
                    raw_port = ""
                elif 2 <= len(values) <= 4:
                    name, host = values[:2]
                    name = name or host
                    protocol = values[2] if len(values) >= 3 and values[2] else protocol_default
                    raw_port = values[3] if len(values) == 4 else ""
                else:
                    raise RemoteConnectionError(
                        "Use host, name = host, or name,host,protocol,port."
                    )
            clean_protocol = str(protocol).strip().lower()
            if clean_protocol not in {"ssh", "telnet"}:
                raise RemoteConnectionError("Protocol must be SSH or Telnet.")
            clean_name = RemoteConnectionStore._name(name, "Host name")
            clean_host = RemoteConnectionStore._hostname(host)
            try:
                port = int(raw_port) if str(raw_port).strip() else (
                    23 if clean_protocol == "telnet" else 22
                )
            except (TypeError, ValueError) as exc:
                raise RemoteConnectionError("Port must be a whole number.") from exc
            if not 1 <= port <= 65535:
                raise RemoteConnectionError("Port must be between 1 and 65535.")
            if clean_name.casefold() in seen_names:
                raise RemoteConnectionError("That host name appears more than once in this import.")
            seen_names.add(clean_name.casefold())
            parsed_rows.append(
                {
                    "row": line_number,
                    "name": clean_name,
                    "host": clean_host,
                    "protocol": clean_protocol,
                    "port": port,
                    "credential_mode": "inherit",
                }
            )
        except (RemoteConnectionError, TypeError, ValueError) as exc:
            errors.append({"row": line_number, "message": str(exc)})
    return parsed_rows, errors


def _connection_store() -> RemoteConnectionStore:
    store = current_app.extensions.get("remote_connection_store")
    if not isinstance(store, RemoteConnectionStore):  # pragma: no cover
        raise RuntimeError("The remote-connection library is unavailable.")
    return store


def _library_response(user_id: str, status: int = 200):
    return (
        jsonify({"library": _connection_library(user_id)}),
        status,
    )


def _serial_devices() -> list[dict[str, object]]:
    try:
        devices = list_serial_devices()
    except SerialConsoleError:
        return []
    active_devices = {
        str(session.get("console_device_id", ""))
        for session in _manager().store.active_sessions()
        if str(session.get("protocol", "")) == "console"
        and str(session.get("state", "")) in ACTIVE_REMOTE_SESSION_STATES
    }
    for device in devices:
        device["in_use"] = str(device["id"]) in active_devices
    return devices


def _connection_library(user_id: str) -> dict[str, list[dict[str, object]]]:
    library = _connection_store().library_for_user(
        user_id,
        is_admin=bool(getattr(g, "current_user", {}).get("is_admin")),
    )
    devices = {str(item["id"]): item for item in _serial_devices()}
    for host in library["hosts"]:
        if str(host.get("protocol", "")) != "console":
            continue
        device = devices.get(str(host.get("console_device_id", "")))
        host["console_available"] = bool(device)
        host["console_accessible"] = bool(device and device.get("accessible"))
        host["console_in_use"] = bool(device and device.get("in_use"))
        host["console_current_path"] = str(device.get("path", "")) if device else ""
        if device:
            host["console_device_path"] = str(device["path"])
    return library


def _serial_console_options() -> dict[str, object]:
    return {
        "devices": _serial_devices(),
        "baud_rates": SERIAL_BAUD_RATES,
        "data_bits": SERIAL_DATA_BITS,
        "parities": SERIAL_PARITIES,
        "stop_bits": SERIAL_STOP_BITS,
        "flow_controls": SERIAL_FLOW_CONTROLS,
    }


def _annotate_library_change(
    action: str,
    summary: str,
    item: dict[str, object],
    *,
    resource_type: str = "remote_folder",
    details: dict[str, object] | None = None,
) -> None:
    audit_details = dict(details or {})
    for key in ("user_id", "visibility", "effective_visibility"):
        if key in item:
            audit_details[
                "owner id" if key == "user_id" else key.replace("_", " ")
            ] = item[key]

    annotate_audit_event(
        category="Network tools",
        action=f"remote_terminal.{action}",
        summary=summary,
        resource_type=resource_type,
        resource_id=str(item["id"]),
        resource_name=str(item["name"]),
        details=audit_details,
    )


def _public_session(session: dict[str, object]) -> dict[str, object]:
    result = public_remote_session(session)
    investigation_id = str(session.get("investigation_id", ""))
    if not investigation_id:
        return result
    store = current_app.extensions.get("investigation_store")
    if not isinstance(store, InvestigationStore):
        return result
    try:
        investigation = store.get_for_user(
            investigation_id, _current_user()["id"]
        )
    except (InvestigationError, OSError):
        return result
    result["investigation_title"] = investigation["title"]
    result["investigation_url"] = url_for(
        "investigation_detail", investigation_id=investigation_id
    )
    return result


def _can_use_datastore() -> bool:
    user = getattr(g, "current_user", {}) or {}
    allowed_tool_ids = getattr(g, "allowed_tool_ids", None)
    return bool(
        user.get("is_admin")
        or allowed_tool_ids is None
        or "local.datastore" in allowed_tool_ids
    )


def _datastore_folders() -> list[dict[str, str]]:
    if not _can_use_datastore():
        return []
    return LocalDatastore(current_app.instance_path).folders()


def _available_datastore_filename(
    store: LocalDatastore, folder: str, filename: str
) -> str:
    existing = {
        str(item["name"]).casefold() for item in store.list(folder)["entries"]
    }
    if filename.casefold() not in existing:
        return filename
    stem = filename[:-4] if filename.casefold().endswith(".txt") else filename
    for index in range(2, 10_002):
        candidate = f"{stem[:240]}-{index}.txt"
        if candidate.casefold() not in existing:
            return candidate
    raise DatastoreError("Unable to choose an unused transcript filename.")


def _manager() -> RemoteSessionManager:
    user = getattr(g, "current_user", {}) or {}
    allowed_tool_ids = getattr(g, "allowed_tool_ids", None)
    if (
        not user.get("is_admin")
        and allowed_tool_ids is not None
        and "tools.remote_terminal" not in allowed_tool_ids
    ):
        abort(403)
    manager = current_app.extensions.get("remote_session_manager")
    if not isinstance(manager, RemoteSessionManager):  # pragma: no cover
        raise RuntimeError("The remote-session manager is unavailable.")
    return manager


def _current_user() -> dict[str, str]:
    user = getattr(g, "current_user", {}) or {}
    return {
        "id": str(user.get("id", "")),
        "username": str(user.get("username", "")),
    }


def _recording_case_id(user_id: str) -> str:
    store = current_app.extensions.get("investigation_store")
    if not isinstance(store, InvestigationStore):
        return ""
    investigation = store.active_for_user(user_id)
    if not investigation or not investigation.get("is_recording"):
        return ""
    return str(investigation["id"])


def _host(value: object) -> str:
    host = str(value).strip()
    if (
        not host
        or len(host) > 255
        or any(character.isspace() for character in host)
        or "://" in host
    ):
        raise RemoteSessionError("Enter a valid host name or IP address.")
    return host


def _protocol(value: object) -> str:
    protocol = str(value).strip().lower()
    if protocol not in {"ssh", "telnet", "console"}:
        raise RemoteSessionError("Choose SSH, Telnet, or Console.")
    return protocol


def _text(value: object, label: str, maximum: int) -> str:
    clean = str(value).strip()
    if not clean:
        raise RemoteSessionError(f"Enter the {label.lower()}.")
    if len(clean) > maximum:
        raise RemoteSessionError(f"{label} must be {maximum} characters or fewer.")
    return clean


def _optional_remote_username(value: object) -> str:
    clean = str(value).strip()
    if len(clean) > 128 or any(character in "\r\n\x00" for character in clean):
        raise RemoteSessionError("Enter a valid username.")
    return clean


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise RemoteSessionError(f"{label} must be a whole number.") from exc
    if not minimum <= number <= maximum:
        raise RemoteSessionError(
            f"{label} must be between {minimum} and {maximum}."
        )
    return number


__all__ = ["register_remote_terminal_routes", "REMOTE_SESSION_INPUT_LIMIT_BYTES"]
