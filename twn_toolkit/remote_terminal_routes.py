from __future__ import annotations

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
    REMOTE_SESSION_INPUT_LIMIT_BYTES,
    REMOTE_SESSION_OUTPUT_LIMIT_BYTES,
    RemoteSessionError,
    RemoteSessionManager,
    public_remote_session,
    safe_filename,
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
            remote_connection_library=_connection_store().library_for_user(
                user["id"]
            ),
            can_save_remote_scrollback=_can_use_datastore(),
            datastore_folders=_datastore_folders(),
            requested_session=str(request.args.get("session", "")).strip()[:80],
        )

    @tools_bp.get("/remote-terminal/library")
    def remote_terminal_library():
        suppress_audit_event()
        user = _current_user()
        return jsonify(
            {"library": _connection_store().library_for_user(user["id"])}
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
            source_host_id = str(payload.get("host_id", "")).strip()
            if source_host_id:
                saved_host = _connection_store().get_host(
                    source_host_id, user_id=user["id"]
                )
                if not saved_host:
                    raise RemoteSessionError("Saved host not found.")
                credential = _connection_store().resolve_credential(
                    str(saved_host["credential_id"]),
                    user_id=user["id"],
                    host_id=source_host_id,
                )
                host = str(saved_host["host"])
                port = int(saved_host["port"])
                remote_username = credential["username"]
                password = credential["password"]
                default_title = str(saved_host["name"])
                allow_unknown_hosts = bool(saved_host["allow_unknown_hosts"])
                allow_legacy_algorithms = bool(
                    saved_host["allow_legacy_algorithms"]
                )
            else:
                host = _host(payload.get("host", ""))
                port = _integer(payload.get("port", 22), "SSH port", 1, 65535)
                credential_id = str(payload.get("credential_id", "")).strip()
                if credential_id:
                    credential = _connection_store().resolve_credential(
                        credential_id, user_id=user["id"]
                    )
                    remote_username = credential["username"]
                    password = credential["password"]
                else:
                    remote_username = _text(
                        payload.get("username", ""), "SSH username", 128
                    )
                    password = str(payload.get("password", ""))
                    if not password:
                        raise RemoteSessionError("Enter the SSH password.")
                default_title = f"{remote_username}@{host}"
                allow_unknown_hosts = bool(payload.get("allow_unknown_hosts", False))
                allow_legacy_algorithms = bool(
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
            record_transcript = bool(
                payload.get("record_transcript", bool(investigation_id))
            )
            session = _manager().start_ssh_session(
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
            )
        except (RemoteSessionError, TypeError, ValueError) as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 400
        annotate_audit_event(
            category="Network tools",
            action="remote_terminal.session_started",
            summary="Started a persistent remote SSH session.",
            resource_type="remote_session",
            resource_id=str(session["id"]),
            resource_name=str(session["title"]),
            details={
                "protocol": "SSH",
                "host": host,
                "port": port,
                "remote username": remote_username,
                "connection source": "saved host" if source_host_id else "quick connect",
                "case attached": bool(investigation_id),
                "transcript evidence enabled": bool(session["record_transcript"]),
            },
        )
        record_current_activity(
            "Network tools",
            "Started persistent SSH session",
            f"{host}:{port}",
            count_action=True,
        )
        return jsonify({"session": _public_session(session)}), 201

    @tools_bp.post("/remote-terminal/folders")
    def create_remote_terminal_folder():
        payload = request.get_json(silent=True) or {}
        user = _current_user()
        try:
            folder = _connection_store().create_folder(
                user_id=user["id"],
                name=str(payload.get("name", "")),
                parent_id=str(payload.get("parent_id", "")),
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
            "Duplicated encrypted SSH credential.",
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
            "Deleted encrypted SSH credential.",
            existing,
            resource_type="remote_credential",
        )
        return _library_response(user["id"])

    @tools_bp.post("/remote-terminal/hosts")
    def create_remote_terminal_host():
        return _save_remote_terminal_host()

    @tools_bp.patch("/remote-terminal/hosts/<host_id>")
    def update_remote_terminal_host(host_id: str):
        return _save_remote_terminal_host(host_id)

    @tools_bp.post("/remote-terminal/hosts/<host_id>/duplicate")
    def duplicate_remote_terminal_host(host_id: str):
        user = _current_user()
        try:
            host = _connection_store().duplicate_host(host_id, user_id=user["id"])
        except RemoteConnectionError as exc:
            suppress_audit_event()
            return jsonify({"error": str(exc)}), 404
        _annotate_library_change(
            "host_duplicated", "Duplicated saved SSH host.", host,
            resource_type="remote_host",
        )
        return _library_response(user["id"], 201)

    @tools_bp.delete("/remote-terminal/hosts/<host_id>")
    def delete_remote_terminal_host(host_id: str):
        user = _current_user()
        existing = _connection_store().get_host(host_id, user_id=user["id"])
        if not existing:
            suppress_audit_event()
            return jsonify({"error": "Saved host not found."}), 404
        _connection_store().delete_host(host_id, user_id=user["id"])
        _annotate_library_change(
            "host_deleted", "Deleted saved SSH host.", existing,
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
        )
        if page is None:
            return jsonify({"error": "Remote session not found."}), 404
        page["session"] = _public_session(page["session"])
        return jsonify(page)

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
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}"'
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        annotate_audit_event(
            category="Network tools",
            action="remote_terminal.scrollback_downloaded",
            summary="Downloaded retained remote-terminal scrollback.",
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
                summary="Stopped a persistent remote SSH session.",
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
            summary="Renamed a remote SSH session.",
            resource_type="remote_session",
            resource_id=session_id,
            resource_name=title,
            details={"previous name": existing["title"], "new name": title},
        )
        return jsonify({"session": _public_session(session)})


def _save_remote_terminal_credential(credential_id: str = ""):
    payload = request.get_json(silent=True) or {}
    user = _current_user()
    scope_host_id = ""
    if credential_id:
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
        scope_host_id = str(existing["scope_host_id"])
    try:
        credential = _connection_store().save_credential(
            user_id=user["id"],
            credential_id=credential_id,
            name=str(payload.get("name", "")),
            remote_username=str(payload.get("username", "")),
            password=str(payload.get("password", "")),
            scope_host_id=scope_host_id,
        )
    except RemoteConnectionError as exc:
        suppress_audit_event()
        return jsonify({"error": str(exc)}), 400
    _annotate_library_change(
        "credential_updated" if credential_id else "credential_created",
        (
            "Updated encrypted SSH credential."
            if credential_id
            else "Created encrypted SSH credential."
        ),
        credential,
        resource_type="remote_credential",
        details={
            "username": credential["username"],
            "host scoped": bool(credential["scope_host_id"]),
            "secret replaced": bool(payload.get("password")),
        },
    )
    return _library_response(user["id"], 200 if credential_id else 201)


def _save_remote_terminal_host(host_id: str = ""):
    payload = request.get_json(silent=True) or {}
    user = _current_user()
    credential_mode = str(payload.get("credential_mode", "saved"))
    host_credential = None
    if credential_mode == "host":
        host_credential = {
            "name": str(payload.get("host_credential_name", "")),
            "username": str(payload.get("host_username", "")),
            "password": str(payload.get("host_password", "")),
        }
    elif credential_mode != "saved":
        suppress_audit_event()
        return jsonify({"error": "Choose saved or host-specific credentials."}), 400
    try:
        host = _connection_store().save_host(
            user_id=user["id"],
            host_id=host_id,
            name=str(payload.get("name", "")),
            host=str(payload.get("host", "")),
            port=_integer(payload.get("port", 22), "SSH port", 1, 65535),
            folder_id=str(payload.get("folder_id", "")),
            credential_id=str(payload.get("credential_id", "")),
            allow_unknown_hosts=bool(payload.get("allow_unknown_hosts", False)),
            allow_legacy_algorithms=bool(
                payload.get("allow_legacy_algorithms", False)
            ),
            notes=str(payload.get("notes", "")),
            host_credential=host_credential,
        )
    except (RemoteConnectionError, TypeError, ValueError) as exc:
        suppress_audit_event()
        return jsonify({"error": str(exc)}), 400
    _annotate_library_change(
        "host_updated" if host_id else "host_created",
        "Updated saved SSH host." if host_id else "Created saved SSH host.",
        host,
        resource_type="remote_host",
        details={
            "host": host["host"],
            "port": host["port"],
            "folder assigned": bool(host["folder_id"]),
            "credential mode": (
                "host-specific"
                if host["credential_scope_host_id"] == host["id"]
                else "shared"
            ),
        },
    )
    return _library_response(user["id"], 200 if host_id else 201)


def _connection_store() -> RemoteConnectionStore:
    store = current_app.extensions.get("remote_connection_store")
    if not isinstance(store, RemoteConnectionStore):  # pragma: no cover
        raise RuntimeError("The remote-connection library is unavailable.")
    return store


def _library_response(user_id: str, status: int = 200):
    return (
        jsonify({"library": _connection_store().library_for_user(user_id)}),
        status,
    )


def _annotate_library_change(
    action: str,
    summary: str,
    item: dict[str, object],
    *,
    resource_type: str = "remote_folder",
    details: dict[str, object] | None = None,
) -> None:
    annotate_audit_event(
        category="Network tools",
        action=f"remote_terminal.{action}",
        summary=summary,
        resource_type=resource_type,
        resource_id=str(item["id"]),
        resource_name=str(item["name"]),
        details=details or {},
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


def _text(value: object, label: str, maximum: int) -> str:
    clean = str(value).strip()
    if not clean:
        raise RemoteSessionError(f"Enter the {label.lower()}.")
    if len(clean) > maximum:
        raise RemoteSessionError(f"{label} must be {maximum} characters or fewer.")
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
