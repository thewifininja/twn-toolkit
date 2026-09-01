from __future__ import annotations

import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from flask import (
    Flask,
    Response,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from .auth import APPEARANCE_PALETTES, AuthStore
from .automation import AutomationStore
from .profile_backup import (
    ConfigurationImportStore,
    apply_remote_connection_owner_mappings,
    backup_entry_count,
    build_profile_backup,
    decrypt_backup,
    encrypt_backup,
    import_backup_items,
    inspect_profile_backup,
    is_encrypted_backup,
    preview_import_items,
    remote_connection_owner_mappings,
    selected_backup_items,
    validate_profile_backup,
)
from .server_settings import (
    ServerSettingsStore,
    normalize_allowed_networks,
    normalize_instance_name,
    normalize_preferred_fqdn,
)
from .tls_tools import certificate_status, regenerate_self_signed_certificate
from .tool_catalog import TOOL_BY_ID, grouped_access_tools
from .audit import AuditStore, annotate_audit_event, audit_reference
from .operational import OperationalSettingsStore
from .raspberry_pi_networking import (
    MAX_CERTIFICATE_BYTES,
    PI_NETWORK_ROLLBACK_SECONDS,
    PiNetworkBrokerError,
    RaspberryPiNetworkStore,
    raspberry_pi_identity,
    raspberry_pi_network_status,
    request_pi_network_broker,
    validate_pi_network_configuration,
    validate_uploaded_tls_material,
)
from .smtp_tools import (
    SMTPSettingsStore,
    parse_email_recipients,
    send_smtp_message,
)
from .migrations import MigrationManager
from .network_tools import ToolInputError
from .service_cli import (
    service_runtime_status,
    systemd_network_capabilities_enabled,
)
from .system_diagnostics import (
    command_dependencies,
    platform_capabilities,
    readonly_sqlite_connection,
)
from .system_identity import collect_system_identity
from .tftp import tftp_process_status
from .time_settings import COMMON_TIMEZONES, TimeSettingsStore
from .ssh_transfer_server import ssh_transfer_process_status
from .ftp_server import ftp_process_status
from .iperf_server import iperf3_process_status
from .upgrade_manager import ReleaseClient, UpgradeError, UpgradeManager
from .version import APP_VERSION
from .distributed_agents import (
    DistributedAgentStore,
    DistributedIdentityStore,
    DistributedSettingsStore,
    split_mainframe_certificate_hosts,
)
from .distributed_pki import DistributedPkiStore, PairingSessionStore
from .distributed_transport import EnrollmentClient, EnrollmentTransportError
from .distributed_agents import DistributedEnrollmentWindow
from .distributed_jobs import DistributedJobStore


DATABASE_LIVE_CHECK_TIMEOUT_SECONDS = 0.25
DATABASE_LIVE_CHECK_MAX_BYTES = 64 * 1024 * 1024


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("bytes", "KiB", "MiB", "GiB"):
        if amount < 1024 or unit == "GiB":
            return f"{amount:.1f} {unit}" if unit != "bytes" else f"{int(amount)} bytes"
        amount /= 1024
    return f"{amount:.1f} GiB"


def _diagnostic_value(
    metric: str,
    label: str,
    collector: Callable[[], Any],
    fallback: Any,
    timings: list[tuple[str, float]],
    warnings: list[str],
) -> Any:
    started = time.perf_counter()
    try:
        return collector()
    except Exception as exc:
        detail = " ".join(str(exc).split())[:240]
        warnings.append(
            f"{label} could not be collected"
            f"{f': {detail}' if detail else '.'}"
        )
        return fallback
    finally:
        timings.append((metric, (time.perf_counter() - started) * 1000))


def _bounded_quick_check(
    connection: sqlite3.Connection,
    *,
    timeout_seconds: float = DATABASE_LIVE_CHECK_TIMEOUT_SECONDS,
) -> tuple[str, str]:
    """Run SQLite's quick check without letting it dominate a web request."""
    deadline = time.perf_counter() + max(0.0, float(timeout_seconds))
    interrupted_by_deadline = False
    deadline_reached = threading.Event()
    check_finished = threading.Event()

    def stop_after_deadline() -> int:
        nonlocal interrupted_by_deadline
        interrupted_by_deadline = time.perf_counter() >= deadline
        return int(interrupted_by_deadline)

    def interrupt_at_deadline() -> None:
        if check_finished.is_set():
            return
        deadline_reached.set()
        try:
            connection.interrupt()
        except sqlite3.Error:
            # The request may have completed and closed the connection between
            # the event check and the thread-safe interrupt call.
            pass

    connection.set_progress_handler(stop_after_deadline, 1000)
    watchdog = threading.Timer(
        max(0.0, float(timeout_seconds)),
        interrupt_at_deadline,
    )
    watchdog.daemon = True
    watchdog.start()
    try:
        row = connection.execute("PRAGMA quick_check(1)").fetchone()
    except sqlite3.OperationalError as exc:
        if (
            (interrupted_by_deadline or deadline_reached.is_set())
            and "interrupted" in str(exc).lower()
        ):
            milliseconds = max(1, round(timeout_seconds * 1000))
            return (
                "bounded",
                f"Live integrity scan stopped after {milliseconds} ms to keep this page responsive.",
            )
        raise
    finally:
        check_finished.set()
        watchdog.cancel()
        watchdog.join(timeout=0.05)
        connection.set_progress_handler(None, 0)
    return str(row[0]), ""


def _database_diagnostics(instance: Path) -> list[dict[str, str]]:
    databases = []
    for path in sorted(instance.glob("*.sqlite3")):
        size = path.stat().st_size
        if size > DATABASE_LIVE_CHECK_MAX_BYTES:
            databases.append(
                {
                    "name": path.name,
                    "size": _format_bytes(size),
                    "status": "manual",
                    "status_class": "warning",
                    "detail": (
                        "Live integrity scan skipped above 64 MiB; run a full "
                        "check during a maintenance window."
                    ),
                }
            )
            continue
        status = "ok"
        detail = ""
        status_class = "success"
        try:
            with readonly_sqlite_connection(path) as connection:
                status, detail = _bounded_quick_check(connection)
                if status == "bounded":
                    status_class = "warning"
                elif status != "ok":
                    status_class = "error"
        except sqlite3.Error as exc:
            status = f"unavailable: {' '.join(str(exc).split())[:160]}"
            status_class = "error"
        databases.append(
            {
                "name": path.name,
                "size": _format_bytes(size),
                "status": status,
                "status_class": status_class,
                "detail": detail,
            }
        )
    return databases


def _backup_audit_references(
    selected_items: list[dict[str, Any]],
) -> list[dict[str, str]]:
    return [
        audit_reference("backup item", item["id"], item["label"])
        for item in selected_items
    ]


def _format_audit_value(value: Any) -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if _is_audit_reference(value):
        return _format_audit_reference(value)
    if isinstance(value, list) and value and all(
        _is_audit_reference(item) for item in value
    ):
        return "\n".join(
            f"• {_format_audit_reference(item).replace(chr(10), ' · ')}"
            for item in value
        )
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    return str(value)


def _is_audit_reference(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"type", "name", "id"}
        and all(isinstance(value.get(key), str) for key in ("type", "name", "id"))
        and bool(value.get("name") or value.get("id"))
    )


def _format_audit_reference(reference: dict[str, str]) -> str:
    name = reference.get("name", "").strip()
    resource_id = reference.get("id", "").strip()
    resource_type = reference.get("type", "").strip()
    if name and resource_id:
        return f"{name}\nID: {resource_id}"
    if name:
        return name
    return f"{resource_type.capitalize()} ID: {resource_id}" if resource_type else resource_id


def _user_audit_snapshot(
    user: dict[str, Any] | None,
    access_profiles: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not user:
        return {}
    profile_names = {
        str(profile.get("id", "")): str(profile.get("name", ""))
        for profile in access_profiles or []
        if isinstance(profile, dict)
    }
    return {
        "username": user.get("username", ""),
        "system administrator": bool(user.get("is_admin")),
        "enabled": bool(user.get("enabled", True)),
        "access profiles": [
            audit_reference("access profile", profile_id, profile_names.get(profile_id, ""))
            for profile_id in user.get("access_profile_ids", [])
            if isinstance(profile_id, str)
        ],
    }


def _profile_audit_snapshot(profile: dict[str, Any] | None) -> dict[str, Any]:
    if not profile:
        return {}
    return {
        "name": profile.get("name", ""),
        "description": profile.get("description", ""),
        "tool access": list(profile.get("tool_ids", [])),
    }


def _resolve_legacy_audit_value(
    field: str,
    value: Any,
    access_profiles: list[dict[str, Any]],
) -> Any:
    """Add readable labels to older audit values that stored bare references."""
    if field != "access profiles" or not isinstance(value, list):
        return value
    profile_names = {
        str(profile.get("id", "")): str(profile.get("name", ""))
        for profile in access_profiles
        if isinstance(profile, dict)
    }
    resolved = []
    for item in value:
        if _is_audit_reference(item):
            resolved.append(item)
        elif isinstance(item, str):
            resolved.append(
                audit_reference("access profile", item, profile_names.get(item, ""))
            )
    return resolved


def _format_storage_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        **summary,
        "datastore_display": _format_bytes(int(summary["datastore_bytes"])),
        "artifact_display": _format_bytes(int(summary["artifact_bytes"])),
        "disk_free_display": _format_bytes(int(summary["disk_free_bytes"])),
        "disk_total_display": _format_bytes(int(summary["disk_total_bytes"])),
    }


def _process_health(instance: Path, name: str, pid_name: str, heartbeat_name: str) -> dict[str, Any]:
    pid = None; running = False
    try:
        pid = int((instance / pid_name).read_text(encoding="utf-8").strip()); os.kill(pid, 0); running = True
    except (OSError, ValueError): pass
    heartbeat_age = None
    if heartbeat_name:
        try:
            heartbeat = json.loads((instance / heartbeat_name).read_text(encoding="utf-8")); heartbeat_age = max(0, int(time.time() - float(heartbeat["updated_at"])))
        except (OSError, ValueError, KeyError): pass
    return {"name": name, "running": running, "pid": pid, "heartbeat_age": heartbeat_age}


def register_admin_routes(
    app: Flask,
    *,
    auth_store: AuthStore,
    automation_store: AutomationStore,
    server_settings_store: ServerSettingsStore,
    distributed_settings_store: DistributedSettingsStore,
    distributed_identity_store: DistributedIdentityStore,
    distributed_agent_store: DistributedAgentStore,
    distributed_pki_store: DistributedPkiStore,
    distributed_pairing_store: PairingSessionStore,
    distributed_job_store: DistributedJobStore,
    backup_catalog: list[dict[str, Any]],
    start_session: Callable[[dict[str, Any]], None],
    audit_store: AuditStore,
    operational_store: OperationalSettingsStore,
) -> None:
    project_root = Path(__file__).resolve().parent.parent
    upgrade_manager = UpgradeManager(project_root, Path(app.instance_path), APP_VERSION)
    smtp_store = SMTPSettingsStore(app.instance_path, app.config["SECRET_KEY"])
    time_store = TimeSettingsStore(app.instance_path)
    pi_network_store = RaspberryPiNetworkStore(
        app.instance_path, str(app.config["SECRET_KEY"])
    )
    configuration_import_store = ConfigurationImportStore(
        app.instance_path, str(app.config["SECRET_KEY"])
    )
    distributed_enrollment_window = DistributedEnrollmentWindow(app.instance_path)

    def _balanced_category_columns(
        values: list[dict[str, Any]],
    ) -> list[list[tuple[str, list[dict[str, Any]]]]]:
        categories: dict[str, list[dict[str, Any]]] = {}
        for value in values:
            categories.setdefault(str(value["category"]), []).append(value)
        category_groups = sorted(
            categories.items(),
            key=lambda category: (-len(category[1]), category[0].lower()),
        )
        columns: list[list[tuple[str, list[dict[str, Any]]]]] = [[], []]
        column_weights = [0, 0]
        for category in category_groups:
            column_index = column_weights.index(min(column_weights))
            columns[column_index].append(category)
            column_weights[column_index] += len(category[1]) + 1
        return columns

    def _configuration_backup_page(
        *,
        active_view: str = "export",
        preview_token: str = "",
        pending_import: dict[str, Any] | None = None,
    ) -> str:
        catalog_display: list[dict[str, Any]] = []
        for catalog_item in backup_catalog:
            catalog_display.append(
                {
                    **catalog_item,
                    "record_count": backup_entry_count(catalog_item["store"]),
                }
            )
        preview = None
        if pending_import:
            backup = pending_import["backup"]
            inspection = inspect_profile_backup(backup, backup_catalog)
            import_mode = str(pending_import.get("import_mode", "merge"))
            available_ids = {
                group["id"]
                for group in inspection["groups"]
                if group["available"]
            }
            selected = selected_backup_items(backup_catalog, available_ids)
            effects = {
                item["id"]: item
                for item in preview_import_items(backup["items"], selected, import_mode)
            }
            preview = {
                **inspection,
                "effects": effects,
                "category_columns": _balanced_category_columns(
                    inspection["groups"]
                ),
                "import_mode": import_mode,
                "encrypted_input": bool(pending_import.get("encrypted_input")),
                "owners": remote_connection_owner_mappings(
                    backup["items"], auth_store.users()
                ),
            }
        return render_template(
            "auth/backup.html",
            backup_catalog=backup_catalog,
            backup_category_columns=_balanced_category_columns(catalog_display),
            installed_version=APP_VERSION,
            active_view=active_view,
            preview_token=preview_token,
            import_preview=preview,
            local_users=auth_store.users(),
        )

    @app.post("/settings/theme")
    def update_theme():
        payload = request.get_json(silent=True) or {}
        theme = str(payload.get("theme", ""))
        try:
            auth_store.set_user_theme(g.current_user["id"], theme)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        g.current_user["theme"] = theme
        return jsonify({"theme": theme})

    @app.post("/settings/appearance")
    def update_appearance():
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "Appearance settings must be an object."}), 400
        try:
            appearance_context = (
                auth_store.execution_context(g.current_user["id"])
                if distributed_settings_store.get()["role"] == "mainframe"
                else "local"
            )
            appearance = auth_store.set_user_appearance(
                g.current_user["id"], payload, appearance_context
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        g.current_user["appearance"] = appearance
        g.current_user["theme"] = APPEARANCE_PALETTES[appearance["palette"]]
        return jsonify({"appearance": appearance})

    @app.get("/settings")
    def settings():
        requested_section = str(request.args.get("section", "system")).strip().lower()
        pi_identity = raspberry_pi_identity()
        available_sections = {"system", "email", "operations", "accounts"}
        if pi_identity["is_raspberry_pi"]:
            available_sections.add("raspberry-pi")
        settings_section = (
            requested_section
            if requested_section in available_sections
            else "system"
        )
        if not g.current_user.get("is_admin"):
            settings_section = "accounts"
        visible_users = (
            auth_store.users()
            if g.current_user.get("is_admin")
            else [g.current_user]
        )
        active_server_settings = server_settings_store.get()
        pi_network_status = (
            raspberry_pi_network_status()
            if settings_section == "raspberry-pi"
            else {
                **pi_identity,
                "supported": False,
                "broker_available": False,
                "interfaces": [],
                "wifi_interfaces": [],
                "wired_interfaces": [],
                "managed": {},
                "pending": {},
                "profile_status": [],
                "wireless_clients": [],
                "wired_clients": [],
                "limitations": [],
            }
        )
        pi_service_network_capabilities = bool(
            pi_identity["is_raspberry_pi"]
            and systemd_network_capabilities_enabled()
        )
        pi_service_install_command = "sudo ./twn service install"
        if pi_service_network_capabilities:
            pi_service_install_command += " --network-capabilities"
        pi_network_configuration = pi_network_store.get_configuration()
        local_pending = (
            pi_network_store.pending_configuration()
            or pi_network_store.pending()
        )
        if (
            local_pending
            and pi_network_status.get("broker_available")
            and not pi_network_status.get("pending")
        ):
            _cleanup_pi_network_material(
                pi_network_store,
                (
                    _pi_configuration_material(
                        dict(local_pending.get("configuration") or {})
                    )
                    if local_pending.get("configuration")
                    else dict(local_pending.get("material") or {})
                ),
                keep=_pi_configuration_material(pi_network_configuration),
            )
            pi_network_store.clear_pending()
            local_pending = {}
        pi_network_editor = _pi_profile_editor(
            pi_network_configuration,
            pi_network_status,
            profile_id=str(request.args.get("profile", "")).strip(),
            new_kind=str(request.args.get("new", "")).strip().lower(),
        )
        automation_storage = automation_store.storage_stats()
        automation_storage["database_size"] = _format_bytes(
            int(automation_storage["database_bytes"])
        )
        for source, target in (
            ("oldest_check_at", "oldest_check"),
            ("oldest_run_at", "oldest_run"),
            ("last_pruned_at", "last_pruned"),
        ):
            value = automation_storage[source]
            automation_storage[target] = (
                datetime.fromtimestamp(float(value)).astimezone().strftime("%b %-d, %Y %-I:%M %p")
                if value else "Never"
            )
        return render_template(
            "auth/settings.html",
            users=visible_users,
            access_profiles=auth_store.access_profiles(),
            tool_groups_for_access=grouped_access_tools(),
            idle_timeout_minutes=auth_store.idle_timeout_minutes(),
            min_password_length=auth_store.min_password_length(),
            password_policy=auth_store.password_policy(),
            server_settings=active_server_settings,
            tls_status=certificate_status(
                app.instance_path, active_server_settings["preferred_fqdn"]
            ),
            current_client_ip=request.remote_addr or "unknown",
            automation_storage=automation_storage,
            operational_settings=operational_store.get(),
            operational_storage=_format_storage_summary(operational_store.storage_summary()),
            smtp_settings=smtp_store.get(),
            time_settings=time_store.snapshot(),
            timezone_choices=COMMON_TIMEZONES,
            settings_section=settings_section,
            pi_network_identity=pi_identity,
            pi_network_status=pi_network_status,
            pi_network_settings=pi_network_store.get(),
            pi_network_configuration=pi_network_configuration,
            pi_network_editor=pi_network_editor,
            pi_network_pending=local_pending,
            pi_service_install_command=pi_service_install_command,
            pi_service_network_capabilities=pi_service_network_capabilities,
        )

    @app.get("/mainframe")
    def mainframe():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        distributed_settings = distributed_settings_store.get()
        pki_status = None
        if distributed_settings["role"] == "mainframe":
            certificate_addresses, certificate_names = split_mainframe_certificate_hosts(
                distributed_settings["mainframe_listen_interfaces"],
                distributed_settings["mainframe_advertised_hosts"],
            )
            pki_status = distributed_pki_store.ensure_mainframe_identity(
                certificate_addresses, dns_names=certificate_names
            )
        enrollment_client = (
            EnrollmentClient(
                app.instance_path,
                distributed_settings["agent_mainframe_url"],
                distributed_settings["agent_mainframe_fallback_url"],
            )
            if distributed_settings["role"] == "agent"
            else None
        )
        try:
            agent_runtime_status = json.loads(
                (Path(app.instance_path) / "distributed-status.json").read_text(
                    encoding="utf-8"
                )
            )
            if not isinstance(agent_runtime_status, dict):
                agent_runtime_status = {}
        except (OSError, json.JSONDecodeError):
            agent_runtime_status = {}
        agents = distributed_agent_store.list()
        return render_template(
            "auth/mainframe.html",
            distributed_settings=distributed_settings,
            distributed_identity=distributed_identity_store.load_or_create(),
            distributed_agents=agents,
            distributed_pki_status=pki_status,
            distributed_pairings={
                agent["id"]: distributed_pairing_store.active_for_agent(agent["id"])
                for agent in agents
            },
            agent_enrollment_pending=(
                enrollment_client.pending() if enrollment_client else None
            ),
            agent_enrolled=(enrollment_client.enrolled() if enrollment_client else False),
            agent_runtime_status=agent_runtime_status,
            distributed_jobs=distributed_job_store.recent(
                requester_id=g.current_user["id"]
            ),
            enrollment_window=distributed_enrollment_window.status(),
        )

    @app.post("/mainframe/enrollment-window")
    def update_mainframe_enrollment_window():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        if distributed_settings_store.get()["role"] != "mainframe":
            return Response("Enrollment windows require Mainframe mode.", status=409)
        action = request.form.get("action", "open")
        try:
            if action == "close":
                status = distributed_enrollment_window.close()
                summary = "Closed new agent enrollment."
                audit_action = "distributed.enrollment_window_closed"
            else:
                minutes = int(request.form.get("minutes", "15"))
                status = distributed_enrollment_window.open(minutes)
                summary = f"Opened new agent enrollment for {minutes} minute(s)."
                audit_action = "distributed.enrollment_window_opened"
        except (TypeError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("mainframe", _anchor="enrollment-window"))
        annotate_audit_event(
            category="Mainframe",
            action=audit_action,
            summary=summary,
            resource_type="distributed enrollment",
            resource_id="mainframe",
            resource_name="Agent enrollment window",
            details={"open until": status["open_until"]},
        )
        flash(summary, "success")
        return redirect(url_for("mainframe", _anchor="enrollment-window"))

    @app.post("/mainframe/system-identity")
    def run_distributed_system_identity():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        context_id = auth_store.execution_context(g.current_user["id"])
        if context_id == "local":
            identity = collect_system_identity(app.instance_path)["toolkit"]
            flash(
                f"This instance is {identity['hostname']} running toolkit {identity['version']}.",
                "success",
            )
            return redirect(url_for("mainframe", _anchor="distributed-jobs"))
        agent = distributed_agent_store.get(context_id)
        if not agent or agent["state"] != "approved" or not agent["online"]:
            flash("The selected execution agent is offline or unavailable.", "error")
            return redirect(url_for("mainframe", _anchor="distributed-jobs"))
        capabilities = {
            (item["id"], item["version"]) for item in agent["capabilities"]
        }
        if ("system.identity", "1") not in capabilities:
            flash("The selected agent does not support system identity version 1.", "error")
            return redirect(url_for("mainframe", _anchor="distributed-jobs"))
        job = distributed_job_store.enqueue(
            agent_id=agent["id"],
            requester_id=g.current_user["id"],
            capability_id="system.identity",
            capability_version="1",
        )
        annotate_audit_event(
            category="Mainframe",
            action="distributed.job_queued",
            summary=f"Queued system identity on {agent['name']}.",
            resource_type="distributed job",
            resource_id=job["id"],
            resource_name="System identity",
            details={"agent id": agent["id"], "capability": "system.identity@1"},
        )
        flash(f"System identity queued on {agent['name']}.", "success")
        return redirect(url_for("mainframe", _anchor="distributed-jobs"))

    @app.get("/agents/<agent_id>/")
    def agent_workspace(agent_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        if distributed_settings_store.get()["role"] != "mainframe":
            return Response("Agent workspaces require Mainframe mode.", status=409)
        agent = distributed_agent_store.get(agent_id)
        if not agent or agent["state"] != "approved":
            return Response("That agent workspace is unavailable.", status=404)
        if auth_store.execution_context(g.current_user["id"]) != agent_id:
            flash("Select that agent from the Instance menu before entering its workspace.", "error")
            return redirect(url_for("mainframe"))
        job = distributed_job_store.latest(
            agent_id=agent_id,
            requester_id=g.current_user["id"],
            capability_id="system.identity",
            capability_version="1",
        )
        identity = (
            job["output"]
            if job and job["state"] == "succeeded" and job["output"]
            else None
        )
        return render_template(
            "auth/agent_workspace.html",
            workspace_agent=agent,
            workspace_job=job,
            workspace_identity=identity,
        )

    @app.post("/agents/<agent_id>/system-information/refresh")
    def refresh_agent_workspace_identity(agent_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        agent = distributed_agent_store.get(agent_id)
        if (
            not agent
            or agent["state"] != "approved"
            or auth_store.execution_context(g.current_user["id"]) != agent_id
        ):
            return Response("That agent workspace is unavailable.", status=409)
        if not agent["online"]:
            flash(f"{agent['name']} is offline. The workspace remained selected.", "error")
            return redirect(url_for("agent_workspace", agent_id=agent_id))
        capabilities = {(item["id"], item["version"]) for item in agent["capabilities"]}
        if ("system.identity", "1") not in capabilities:
            flash("This agent does not support the System Information workspace.", "error")
            return redirect(url_for("agent_workspace", agent_id=agent_id))
        job = distributed_job_store.enqueue(
            agent_id=agent_id,
            requester_id=g.current_user["id"],
            capability_id="system.identity",
            capability_version="1",
            inputs={"workspace_snapshot": True},
        )
        annotate_audit_event(
            category="Mainframe",
            action="distributed.workspace_snapshot_queued",
            summary=f"Refreshed the remote workspace for {agent['name']}.",
            resource_type="distributed job",
            resource_id=job["id"],
            resource_name=agent["name"],
            details={"agent id": agent_id, "capability": "system.identity@1"},
        )
        flash(f"Refreshing the {agent['name']} workspace.", "success")
        return redirect(url_for("agent_workspace", agent_id=agent_id))

    @app.route("/agents/<agent_id>/tools/dns-response", methods=["GET", "POST"])
    def agent_dns_response(agent_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        agent = distributed_agent_store.get(agent_id)
        if (
            distributed_settings_store.get()["role"] != "mainframe"
            or not agent
            or agent["state"] != "approved"
            or auth_store.execution_context(g.current_user["id"]) != agent_id
        ):
            return Response("That agent workspace is unavailable.", status=409)
        capabilities = {(item["id"], item["version"]) for item in agent["capabilities"]}
        supported = ("tools.dns.lookup", "1") in capabilities
        if request.method == "POST":
            if not agent["online"]:
                flash(f"{agent['name']} is offline. DNS was not run locally.", "error")
                return redirect(url_for("agent_dns_response", agent_id=agent_id))
            if not supported:
                flash("This agent does not advertise remote DNS Lookup.", "error")
                return redirect(url_for("agent_dns_response", agent_id=agent_id))
            inputs = {
                "hosts": request.form.get("hosts", "").strip(),
                "servers": request.form.get("servers", "").strip(),
                "record_type": request.form.get("record_type", "A").strip(),
                "timeout": request.form.get("timeout", "3").strip(),
            }
            job = distributed_job_store.enqueue(
                agent_id=agent_id,
                requester_id=g.current_user["id"],
                capability_id="tools.dns.lookup",
                capability_version="1",
                inputs=inputs,
            )
            annotate_audit_event(
                category="Mainframe",
                action="distributed.remote_dns_queued",
                summary=f"Queued DNS Lookup on {agent['name']}.",
                resource_type="distributed job",
                resource_id=job["id"],
                resource_name="DNS Lookup",
                details={"agent id": agent_id, "capability": "tools.dns.lookup@1"},
            )
            return redirect(
                url_for("agent_dns_response", agent_id=agent_id, job=job["id"])
            )
        job_id = request.args.get("job", "").strip()
        job = (
            distributed_job_store.get(job_id)
            if job_id
            else distributed_job_store.latest(
                agent_id=agent_id,
                requester_id=g.current_user["id"],
                capability_id="tools.dns.lookup",
                capability_version="1",
            )
        )
        if job and (
            job["agent_id"] != agent_id
            or job["requester_id"] != g.current_user["id"]
            or job["capability_id"] != "tools.dns.lookup"
            or job["capability_version"] != "1"
        ):
            return Response("That remote DNS request is unavailable.", status=404)
        form = {
            "hosts": "example.com",
            "servers": "Cloudflare = 1.1.1.1\nGoogle = 8.8.8.8",
            "record_type": "A",
            "timeout": "3",
        }
        if job:
            form.update({key: str(job["inputs"].get(key, value)) for key, value in form.items()})
        return render_template(
            "auth/agent_dns_response.html",
            workspace_agent=agent,
            remote_dns_supported=supported,
            remote_dns_job=job,
            remote_dns_output=(job["output"] if job and job["state"] == "succeeded" else None),
            form=form,
        )

    @app.post("/mainframe/enroll")
    def begin_mainframe_enrollment():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        settings = distributed_settings_store.get()
        if settings["role"] != "agent":
            flash("Configure this instance as an Agent before requesting enrollment.", "error")
            return redirect(url_for("mainframe"))
        name = server_settings_store.get()["instance_name"] or "TWN Toolkit Agent"
        try:
            pending = EnrollmentClient(
                app.instance_path,
                settings["agent_mainframe_url"],
                settings["agent_mainframe_fallback_url"],
            ).begin(name)
        except (EnrollmentTransportError, ValueError) as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration",
                action="distributed.enrollment_requested",
                summary="Requested enrollment with a Mainframe.",
                resource_type="distributed enrollment",
                resource_id=pending["session_id"],
                resource_name=settings["agent_mainframe_url"],
                details={"pairing code": pending["pairing_code"]},
            )
            flash("Enrollment requested. Compare the pairing code on both instances.", "success")
        return redirect(url_for("mainframe"))

    @app.post("/mainframe/enroll/poll")
    def poll_mainframe_enrollment():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        settings = distributed_settings_store.get()
        if settings["role"] != "agent":
            return Response("This instance is not configured as an agent.", status=409)
        try:
            result = EnrollmentClient(
                app.instance_path,
                settings["agent_mainframe_url"],
                settings["agent_mainframe_fallback_url"],
            ).poll()
        except EnrollmentTransportError as exc:
            flash(str(exc), "error")
        else:
            flash(
                "Enrollment approved and credentials installed."
                if result["state"] == "approved"
                else f"Enrollment is {result['state']}.",
                "success" if result["state"] == "approved" else "info",
            )
        return redirect(url_for("mainframe"))

    @app.post("/settings/agents/configuration")
    def update_distributed_settings():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        before = distributed_settings_store.get()
        try:
            after = distributed_settings_store.save(
                {
                    "role": request.form.get("role", "standalone"),
                    "mainframe_listen_interfaces": request.form.get(
                        "mainframe_listen_interfaces", ""
                    ),
                    "mainframe_port": request.form.get("mainframe_port", ""),
                    "mainframe_advertised_hosts": request.form.get(
                        "mainframe_advertised_hosts", ""
                    ),
                    "agent_mainframe_url": request.form.get(
                        "agent_mainframe_url", ""
                    ),
                    "agent_mainframe_fallback_url": request.form.get(
                        "agent_mainframe_fallback_url", ""
                    ),
                }
            )
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            if after["role"] == "mainframe":
                certificate_addresses, certificate_names = split_mainframe_certificate_hosts(
                    after["mainframe_listen_interfaces"],
                    after["mainframe_advertised_hosts"],
                )
                distributed_pki_store.ensure_mainframe_identity(
                    certificate_addresses, dns_names=certificate_names
                )
            annotate_audit_event(
                category="Administration",
                action="distributed.configuration_updated",
                summary="Updated distributed toolkit configuration.",
                resource_type="settings",
                resource_id="distributed-agents",
                resource_name="Distributed agents",
                before=before,
                after=after,
            )
            flash(
                "Mainframe configuration saved. Restart the toolkit to apply listener-role changes.",
                "success",
            )
        return redirect(url_for("mainframe"))

    @app.post("/settings/agents/<agent_id>/<action>")
    def update_distributed_agent(agent_id: str, action: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        transitions = {"approve": "approved", "deny": "denied", "revoke": "revoked"}
        if action == "remove":
            before = distributed_agent_store.get(agent_id)
            if before is None:
                return Response("Agent enrollment does not exist.", status=404)
            try:
                removed = distributed_agent_store.remove_revoked(agent_id)
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                annotate_audit_event(
                    category="Administration",
                    action="distributed.agent_removed",
                    summary=f"Removed revoked agent {removed['name']}.",
                    resource_type="distributed agent",
                    resource_id=agent_id,
                    resource_name=removed["name"],
                    before={"state": removed["state"]},
                    after=None,
                )
                flash(f"Removed revoked agent {removed['name']}.", "success")
            return redirect(url_for("mainframe"))
        state = transitions.get(action)
        if state is None:
            return Response("Unknown agent action.", status=404)
        before = distributed_agent_store.get(agent_id)
        if before is None:
            return Response("Agent enrollment does not exist.", status=404)
        if action == "approve" and request.form.get("pairing_code_confirmed") != "on":
            flash("Confirm that the pairing codes match before approving the agent.", "error")
            return redirect(url_for("mainframe"))
        try:
            after = distributed_agent_store.set_state(agent_id, state)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration",
                action=f"distributed.agent_{state}",
                summary=f"{state.capitalize()} agent {after['name']}.",
                resource_type="distributed agent",
                resource_id=agent_id,
                resource_name=after["name"],
                before={"state": before["state"]},
                after={"state": after["state"]},
            )
            flash(f"Agent {after['name']} is now {state}.", "success")
        return redirect(url_for("mainframe"))

    def _pi_admin_required() -> Response | None:
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        if not raspberry_pi_identity()["is_raspberry_pi"]:
            return Response("Raspberry Pi hardware is required.", status=404)
        return None

    def _pi_settings_redirect(anchor: str = "raspberry-pi-networking"):
        return redirect(
            url_for("settings", section="raspberry-pi", _anchor=anchor)
        )

    def _pi_configuration_material(configuration: dict[str, Any]) -> dict[str, str]:
        material: dict[str, str] = {}
        for profile in configuration.get("profiles", []):
            if not isinstance(profile, dict):
                continue
            for key, path in dict(profile.get("material") or {}).items():
                if path:
                    material[f"{profile.get('id', '')}:{key}"] = str(path)
        return material

    def _pi_profile_editor(
        configuration: dict[str, Any],
        status: dict[str, Any],
        *,
        profile_id: str,
        new_kind: str,
    ) -> dict[str, Any]:
        for profile in configuration.get("profiles", []):
            if str(profile.get("id", "")) == profile_id:
                return json.loads(json.dumps(profile))
        if new_kind not in {"wifi-ap", "wifi-client", "wired"}:
            return {}
        interfaces = list(status.get("interfaces") or [])
        wifi = next(
            (item for item in interfaces if item.get("type") == "wifi"),
            next(iter(status.get("wifi_interfaces") or []), {}),
        )
        wired = next(
            (item for item in interfaces if item.get("type") == "ethernet"),
            next(iter(status.get("wired_interfaces") or []), {}),
        )
        common = {
            "id": "",
            "name": "",
            "kind": new_kind,
            "enabled": True,
            "autoconnect": True,
        }
        if new_kind == "wired":
            common.update(
                {
                    "name": "Wired connection",
                    "interface": str(wired.get("name", "eth0")),
                    "adapter_mac": str(
                        wired.get("mac_address") or wired.get("mac") or ""
                    ),
                    "ipv4_mode": "dhcp",
                    "ipv6_mode": "auto",
                    "dns_servers": [],
                    "mtu": 0,
                    "route_metric": 0,
                    "network": "192.168.60.0/24",
                    "gateway": "192.168.60.1",
                    "dhcp_start": "192.168.60.50",
                    "dhcp_end": "192.168.60.200",
                    "lease_time": 3600,
                }
            )
            return common
        common.update(
            {
                "name": "Access point" if new_kind == "wifi-ap" else "Wi-Fi client",
                "wifi_interface": str(wifi.get("name", "wlan0")),
                "adapter_mac": str(
                    wifi.get("mac_address") or wifi.get("mac") or ""
                ),
                "ssid": "",
                "hidden": False,
                "security": "wpa2-wpa3",
            }
        )
        if new_kind == "wifi-ap":
            common.update(
                {
                    "network_mode": "nat",
                    "uplink_interface": str(wired.get("name", "eth0")),
                    "uplink_mac": str(
                        wired.get("mac_address") or wired.get("mac") or ""
                    ),
                    "band": "auto",
                    "channel": 0,
                    "client_isolation": False,
                    "vlan_id": 0,
                    "network": "192.168.50.0/24",
                    "gateway": "192.168.50.1",
                    "dhcp_start": "192.168.50.50",
                    "dhcp_end": "192.168.50.200",
                    "lease_time": 3600,
                }
            )
        return common

    def _uploaded_pi_material(name: str) -> bytes:
        upload = request.files.get(name)
        if not upload or not upload.filename:
            return b""
        data = upload.stream.read(MAX_CERTIFICATE_BYTES + 1)
        if len(data) > MAX_CERTIFICATE_BYTES:
            raise ToolInputError(
                "Each uploaded certificate or key file must be 2 MiB or smaller."
            )
        return data

    def _existing_pi_material(
        store: RaspberryPiNetworkStore, material: dict[str, str], key: str
    ) -> bytes:
        raw_path = str(material.get(key, ""))
        if not raw_path:
            return b""
        try:
            path = Path(raw_path).resolve(strict=True)
            path.relative_to(store.material_root.resolve())
            data = path.read_bytes()
        except (OSError, ValueError):
            return b""
        return data if len(data) <= MAX_CERTIFICATE_BYTES else b""

    def _cleanup_pi_network_material(
        store: RaspberryPiNetworkStore,
        material: dict[str, str],
        *,
        keep: dict[str, str] | None = None,
    ) -> None:
        keep_paths = {
            str(Path(path).resolve())
            for path in (keep or {}).values()
            if path
        }
        def material_paths(values: dict[str, Any]):
            for value in values.values():
                if isinstance(value, dict):
                    yield from material_paths(value)
                elif value:
                    yield str(value)

        for raw_path in material_paths(material):
            try:
                path = Path(str(raw_path)).resolve()
                parent = path.parent
                parent.relative_to(store.material_root.resolve())
            except (OSError, ValueError):
                continue
            if str(path) not in keep_paths:
                path.unlink(missing_ok=True)
                try:
                    parent.rmdir()
                except OSError:
                    pass

    def _apply_pi_configuration(
        configuration: dict[str, Any], *, summary: str
    ) -> dict[str, Any]:
        validated = validate_pi_network_configuration(configuration)
        source_profiles = {
            str(profile.get("id", "")): profile
            for profile in configuration.get("profiles", [])
            if isinstance(profile, dict)
        }
        for profile in validated["profiles"]:
            source = source_profiles.get(str(profile.get("id", "")), {})
            for key in ("passphrase", "password", "private_key_password"):
                if not profile.get(key) and source.get(key):
                    profile[key] = str(source[key])
            profile["material"] = dict(source.get("material") or {})
            profile["certificate_summary"] = dict(
                source.get("certificate_summary") or {}
            )
        response = request_pi_network_broker(
            {
                "operation": "apply",
                "configuration": validated,
                "rollback_seconds": PI_NETWORK_ROLLBACK_SECONDS,
            },
            timeout=90,
        )
        pi_network_store.save_pending_configuration(
            kind="apply",
            token=str(response["token"]),
            expires_at=float(response["expires_at"]),
            configuration=validated,
            dormant_profiles=list(response.get("dormant_profiles") or []),
        )
        annotate_audit_event(
            category="Administration",
            action="settings.raspberry_pi_network_pending",
            summary=summary,
            resource_type="settings",
            resource_id="raspberry-pi-networking",
            resource_name="Raspberry Pi networking",
            details={
                "profiles": len(validated["profiles"]),
                "dormant profiles": len(response.get("dormant_profiles") or []),
                "rollback seconds": PI_NETWORK_ROLLBACK_SECONDS,
            },
        )
        return validated

    @app.post("/settings/raspberry-pi/network/apply")
    def apply_raspberry_pi_networking():
        denied = _pi_admin_required()
        if denied:
            return denied
        current = pi_network_store.get_configuration(include_secrets=True)
        old_identifier = str(request.form.get("profile_id", "")).strip()
        existing = next(
            (
                profile
                for profile in current.get("profiles", [])
                if str(profile.get("id", "")) == old_identifier
            ),
            {},
        )
        identifier = old_identifier or f"network-{secrets.token_hex(5)}"
        kind = str(request.form.get("kind", "")).strip().lower()
        profile: dict[str, Any] = {
            "id": identifier,
            "name": request.form.get("name", ""),
            "kind": kind,
            "enabled": request.form.get("enabled") == "on",
            "autoconnect": request.form.get("autoconnect") == "on",
        }
        if kind == "wired":
            profile.update(
                {
                    "interface": request.form.get("interface", ""),
                    "adapter_mac": request.form.get("adapter_mac", ""),
                    "ipv4_mode": request.form.get("ipv4_mode", "dhcp"),
                    "ipv6_mode": request.form.get("ipv6_mode", "auto"),
                    "address": request.form.get("address", ""),
                    "gateway": request.form.get("gateway", ""),
                    "dns_servers": request.form.get("dns_servers", ""),
                    "network": request.form.get("network", ""),
                    "dhcp_start": request.form.get("dhcp_start", ""),
                    "dhcp_end": request.form.get("dhcp_end", ""),
                    "lease_time": request.form.get("lease_time", "3600"),
                    "mtu": request.form.get("mtu", "0"),
                    "route_metric": request.form.get("route_metric", "0"),
                }
            )
        else:
            profile.update(
                {
                    "wifi_interface": request.form.get("wifi_interface", ""),
                    "adapter_mac": request.form.get("adapter_mac", ""),
                    "ssid": request.form.get("ssid", ""),
                    "hidden": request.form.get("hidden") == "on",
                    "security": request.form.get("security", ""),
                    "passphrase": request.form.get("passphrase", "")
                    or str(existing.get("passphrase", "")),
                    "has_passphrase": bool(existing.get("passphrase")),
                    "identity": request.form.get("identity", ""),
                    "anonymous_identity": request.form.get(
                        "anonymous_identity", ""
                    ),
                    "password": request.form.get("password", "")
                    or str(existing.get("password", "")),
                    "has_password": bool(existing.get("password")),
                    "verify_server_certificate": request.form.get(
                        "verify_server_certificate"
                    )
                    == "on",
                    "ca_source": request.form.get("ca_source", "system"),
                    "server_domain": request.form.get("server_domain", ""),
                    "tls_material_format": request.form.get(
                        "tls_material_format", "bundle"
                    ),
                    "private_key_password": request.form.get(
                        "private_key_password", ""
                    )
                    or str(existing.get("private_key_password", "")),
                }
            )
            if kind == "wifi-ap":
                profile.update(
                    {
                        "network_mode": request.form.get("network_mode", "nat"),
                        "uplink_interface": request.form.get(
                            "uplink_interface", ""
                        ),
                        "uplink_mac": request.form.get("uplink_mac", ""),
                        "band": request.form.get("band", "auto"),
                        "channel": request.form.get("channel", "0"),
                        "client_isolation": request.form.get("client_isolation")
                        == "on",
                        "vlan_id": request.form.get("vlan_id", ""),
                        "network": request.form.get("network", ""),
                        "gateway": request.form.get("gateway", ""),
                        "dhcp_start": request.form.get("dhcp_start", ""),
                        "dhcp_end": request.form.get("dhcp_end", ""),
                        "lease_time": request.form.get("lease_time", "3600"),
                    }
                )

        staged_material: dict[str, str] = {}
        try:
            if kind == "wifi-client":
                current_material = dict(existing.get("material") or {})
                material = dict(current_material)
                new_files: dict[str, bytes] = {}
                ca_data = _uploaded_pi_material("ca_certificate")
                client_data = _uploaded_pi_material("client_certificate")
                key_data = _uploaded_pi_material("private_key")
                bundle_data = _uploaded_pi_material("identity_bundle")
                security = profile.get("security")
                if security not in {"peap", "eap-tls"}:
                    material = {}
                elif security == "peap":
                    for unused_key in (
                        "bundle",
                        "client_certificate",
                        "private_key",
                    ):
                        material.pop(unused_key, None)
                    if profile.get("ca_source") != "upload":
                        material.pop("ca", None)
                if security in {"peap", "eap-tls"} and profile.get("ca_source") == "upload":
                    if ca_data:
                        new_files["ca"] = ca_data
                    elif material.get("ca"):
                        ca_data = _existing_pi_material(
                            pi_network_store, material, "ca"
                        )
                    else:
                        raise ToolInputError(
                            "Upload the trusted RADIUS CA certificate."
                        )
                if security == "eap-tls":
                    if profile["tls_material_format"] == "bundle":
                        if bundle_data:
                            new_files["bundle"] = bundle_data
                            material.pop("client_certificate", None)
                            material.pop("private_key", None)
                        elif material.get("bundle"):
                            bundle_data = _existing_pi_material(
                                pi_network_store, material, "bundle"
                            )
                        else:
                            raise ToolInputError(
                                "Upload a PKCS#12 client identity bundle."
                            )
                        client_data = key_data = b""
                    else:
                        if client_data:
                            new_files["client_certificate"] = client_data
                            material.pop("bundle", None)
                        elif material.get("client_certificate"):
                            client_data = _existing_pi_material(
                                pi_network_store, material, "client_certificate"
                            )
                        if key_data:
                            new_files["private_key"] = key_data
                        elif material.get("private_key"):
                            key_data = _existing_pi_material(
                                pi_network_store, material, "private_key"
                            )
                        bundle_data = b""
                        if not client_data or not key_data:
                            raise ToolInputError(
                                "Upload both the EAP-TLS client certificate and private key."
                            )
                certificate_summary = {}
                if ca_data or client_data or key_data or bundle_data:
                    certificate_summary = validate_uploaded_tls_material(
                        ca_data=ca_data,
                        client_certificate_data=client_data,
                        private_key_data=key_data,
                        bundle_data=bundle_data,
                        private_key_password=str(
                            profile.get("private_key_password", "")
                        ),
                    )
                if new_files:
                    staged_material = pi_network_store.stage_material(new_files)
                    material.update(staged_material)
                profile["material"] = material
                profile["certificate_summary"] = (
                    certificate_summary
                    or (
                        dict(existing.get("certificate_summary") or {})
                        if security in {"peap", "eap-tls"}
                        else {}
                    )
                )

            profiles = [
                item
                for item in current.get("profiles", [])
                if str(item.get("id", "")) != old_identifier
            ]
            profiles.append(profile)
            configuration = {
                "schema_version": 2,
                "country": request.form.get("country", "")
                or current.get("country", "")
                or "US",
                "profiles": profiles,
            }
            _apply_pi_configuration(
                configuration,
                summary=f"Applied provisional Raspberry Pi profile {profile['name']}.",
            )
        except (ToolInputError, PiNetworkBrokerError, OSError, RuntimeError) as exc:
            _cleanup_pi_network_material(pi_network_store, staged_material)
            flash(str(exc), "error")
            return redirect(
                url_for(
                    "settings",
                    section="raspberry-pi",
                    profile=old_identifier,
                    new=kind if not old_identifier else None,
                    _anchor="pi-network-profile-editor",
                )
            )
        flash(
            "The network configuration is provisional. Confirm it before the rollback timer expires.",
            "warning",
        )
        return _pi_settings_redirect("pi-network-pending")

    @app.post("/settings/raspberry-pi/network/profile/<profile_id>/toggle")
    def toggle_raspberry_pi_network_profile(profile_id: str):
        denied = _pi_admin_required()
        if denied:
            return denied
        configuration = pi_network_store.get_configuration(include_secrets=True)
        profile = next(
            (
                item
                for item in configuration.get("profiles", [])
                if str(item.get("id", "")) == profile_id
            ),
            None,
        )
        try:
            if profile is None:
                raise ToolInputError("That Raspberry Pi network profile no longer exists.")
            profile["enabled"] = not bool(profile.get("enabled", True))
            _apply_pi_configuration(
                configuration,
                summary=f"Provisionally {'enabled' if profile['enabled'] else 'disabled'} Raspberry Pi profile {profile.get('name', profile_id)}.",
            )
        except (ToolInputError, PiNetworkBrokerError, OSError, RuntimeError) as exc:
            flash(str(exc), "error")
        else:
            flash(
                "The profile change is provisional. Confirm it before automatic rollback.",
                "warning",
            )
        return _pi_settings_redirect("pi-network-pending")

    @app.post("/settings/raspberry-pi/network/profile/<profile_id>/delete")
    def delete_raspberry_pi_network_profile(profile_id: str):
        denied = _pi_admin_required()
        if denied:
            return denied
        configuration = pi_network_store.get_configuration(include_secrets=True)
        removed = next(
            (
                item
                for item in configuration.get("profiles", [])
                if str(item.get("id", "")) == profile_id
            ),
            None,
        )
        try:
            if removed is None:
                raise ToolInputError("That Raspberry Pi network profile no longer exists.")
            configuration["profiles"] = [
                item
                for item in configuration["profiles"]
                if str(item.get("id", "")) != profile_id
            ]
            _apply_pi_configuration(
                configuration,
                summary=f"Provisionally removed Raspberry Pi profile {removed.get('name', profile_id)}.",
            )
        except (ToolInputError, PiNetworkBrokerError, OSError, RuntimeError) as exc:
            flash(str(exc), "error")
        else:
            flash(
                "The profile removal is provisional. Confirm it before automatic rollback.",
                "warning",
            )
        return _pi_settings_redirect("pi-network-pending")

    @app.post("/settings/raspberry-pi/network/confirm")
    def confirm_raspberry_pi_networking():
        denied = _pi_admin_required()
        if denied:
            return denied
        pending = (
            pi_network_store.pending_configuration(include_secrets=True)
            or pi_network_store.pending(include_secrets=True)
        )
        token = str(pending.get("token", ""))
        try:
            if not token:
                raise PiNetworkBrokerError(
                    "The pending network change is no longer available."
                )
            request_pi_network_broker(
                {"operation": "confirm", "token": token}
            )
            before = pi_network_store.get_configuration()
            if pending.get("kind") == "apply" and pending.get("configuration"):
                old_material = _pi_configuration_material(before)
                after = pi_network_store.save_active_configuration(
                    dict(pending["configuration"])
                )
                new_material = _pi_configuration_material(after)
                _cleanup_pi_network_material(
                    pi_network_store,
                    old_material,
                    keep=new_material,
                )
            elif pending.get("kind") == "apply":
                legacy_before = pi_network_store.get()
                old_material = dict(legacy_before.get("material") or {})
                new_material = dict(pending.get("material") or {})
                after = pi_network_store.save_active(
                    dict(pending.get("settings") or {}),
                    material=new_material,
                    certificate_summary=dict(
                        pending.get("certificate_summary") or {}
                    ),
                )
                _cleanup_pi_network_material(
                    pi_network_store, old_material, keep=new_material
                )
            else:
                old_material = _pi_configuration_material(before)
                pi_network_store.clear()
                _cleanup_pi_network_material(pi_network_store, old_material)
                after = {}
            pi_network_store.clear_pending()
        except (PiNetworkBrokerError, OSError, RuntimeError) as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration",
                action="settings.raspberry_pi_network_confirmed",
                summary="Confirmed the Raspberry Pi network configuration.",
                resource_type="settings",
                resource_id="raspberry-pi-networking",
                resource_name="Raspberry Pi networking",
                before=before,
                after=after,
            )
            flash("Raspberry Pi networking is active and retained.", "success")
        return _pi_settings_redirect()

    @app.post("/settings/raspberry-pi/network/rollback")
    def rollback_raspberry_pi_networking():
        denied = _pi_admin_required()
        if denied:
            return denied
        pending = pi_network_store.pending_configuration() or pi_network_store.pending()
        try:
            request_pi_network_broker(
                {"operation": "rollback", "token": str(pending.get("token", ""))},
                timeout=90,
            )
        except (PiNetworkBrokerError, OSError) as exc:
            flash(str(exc), "error")
        else:
            _cleanup_pi_network_material(
                pi_network_store,
                (
                    _pi_configuration_material(
                        dict(pending.get("configuration") or {})
                    )
                    if pending.get("configuration")
                    else dict(pending.get("material") or {})
                ),
                keep=_pi_configuration_material(
                    pi_network_store.get_configuration()
                ),
            )
            pi_network_store.clear_pending()
            annotate_audit_event(
                category="Administration",
                action="settings.raspberry_pi_network_rolled_back",
                summary="Rolled back a provisional Raspberry Pi network configuration.",
                resource_type="settings",
                resource_id="raspberry-pi-networking",
                resource_name="Raspberry Pi networking",
            )
            flash("The previous network configuration was restored.", "success")
        return _pi_settings_redirect()

    @app.post("/settings/raspberry-pi/network/disable")
    def disable_raspberry_pi_networking():
        denied = _pi_admin_required()
        if denied:
            return denied
        try:
            response = request_pi_network_broker(
                {
                    "operation": "disable",
                    "rollback_seconds": PI_NETWORK_ROLLBACK_SECONDS,
                },
                timeout=90,
            )
            pi_network_store.save_pending_configuration(
                kind="disable",
                token=str(response["token"]),
                expires_at=float(response["expires_at"]),
            )
        except (PiNetworkBrokerError, OSError, RuntimeError) as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration",
                action="settings.raspberry_pi_network_disable_pending",
                summary="Provisionally disabled toolkit-managed Raspberry Pi networking.",
                resource_type="settings",
                resource_id="raspberry-pi-networking",
                resource_name="Raspberry Pi networking",
            )
            flash(
                "Toolkit-managed networking is provisionally disabled. Confirm that the previous network is reachable.",
                "warning",
            )
        return _pi_settings_redirect("pi-network-pending")

    @app.post("/settings/raspberry-pi/network/scan")
    def scan_raspberry_pi_wifi():
        denied = _pi_admin_required()
        if denied:
            return denied
        try:
            response = request_pi_network_broker(
                {
                    "operation": "scan",
                    "interface": request.form.get("wifi_interface", ""),
                }
            )
        except (PiNetworkBrokerError, OSError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"networks": response.get("networks") or []})

    @app.post("/settings/timezone")
    def update_time_settings():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        before = time_store.get()
        try:
            after = time_store.save(request.form.get("timezone", ""))
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration",
                action="settings.timezone_updated",
                summary="Updated the toolkit timezone.",
                resource_type="settings",
                resource_id="toolkit-timezone",
                resource_name="Toolkit timezone",
                before=before,
                after=after,
            )
            resolved = time_store.resolved_timezone()
            flash(
                f"Toolkit timezone saved as {resolved}. No restart is required.",
                "success",
            )
        return redirect(
            url_for("settings", section="system", _anchor="toolkit-timezone")
        )

    @app.post("/settings/smtp")
    def update_smtp_settings():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        before = smtp_store.get()
        try:
            after = smtp_store.save(
                {
                    "host": request.form.get("smtp_host", ""),
                    "port": request.form.get("smtp_port", "587"),
                    "security": request.form.get("smtp_security", "starttls"),
                    "verify_tls": request.form.get("smtp_verify_tls") == "on",
                    "username": request.form.get("smtp_username", ""),
                    "from_name": request.form.get("smtp_from_name", ""),
                    "from_address": request.form.get("smtp_from_address", ""),
                    "timeout": request.form.get("smtp_timeout", "10"),
                },
                password=request.form.get("smtp_password", ""),
                clear_password=request.form.get("smtp_clear_password") == "on",
            )
        except (RuntimeError, ToolInputError) as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration",
                action="settings.smtp_updated",
                summary="Updated SMTP delivery settings.",
                resource_type="settings",
                resource_id="smtp-delivery",
                resource_name="SMTP delivery",
                before=before,
                after=after,
            )
            flash("SMTP delivery settings saved.", "success")
        return redirect(url_for("settings", section="email", _anchor="smtp-delivery"))

    @app.post("/settings/smtp/test")
    def test_smtp_settings():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        try:
            settings_value = smtp_store.get(include_password=True)
            if not settings_value["configured"]:
                raise ToolInputError("Save SMTP delivery settings before testing.")
            recipients = parse_email_recipients(
                request.form.get("smtp_test_recipient", ""), limit=1
            )
            if not recipients:
                raise ToolInputError("Enter a test email recipient.")
            result = send_smtp_message(
                settings_value,
                to=recipients,
                subject="TWN Toolkit SMTP test",
                body=(
                    "This test message confirms that the toolkit can deliver "
                    "email through the saved SMTP settings."
                ),
            )
            if not result["accepted"]:
                raise ToolInputError(result["deliveries"][0]["error"])
        except (RuntimeError, ToolInputError) as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration",
                action="settings.smtp_tested",
                summary="Sent an SMTP test message.",
                resource_type="settings",
                resource_id="smtp-delivery",
                resource_name="SMTP delivery",
                details={"recipient count": 1},
            )
            flash("SMTP test message sent.", "success")
        return redirect(url_for("settings", section="email", _anchor="smtp-delivery"))

    @app.post("/settings/operations")
    def update_operational_settings():
        if not g.current_user.get("is_admin"): return Response("Administrator access is required.", status=403)
        before = operational_store.get()
        try:
            after = operational_store.save({
                "max_concurrent_automations": request.form.get("max_concurrent_automations", ""),
                "max_queued_automations": request.form.get("max_queued_automations", ""),
                "skip_overlapping_automations": request.form.get("skip_overlapping_automations") == "on",
                "datastore_quota_gib": request.form.get("datastore_quota_gib", ""),
                "automation_artifact_quota_gib": request.form.get("automation_artifact_quota_gib", ""),
                "minimum_free_gib": request.form.get("minimum_free_gib", ""),
            })
        except ValueError as exc: flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration", action="settings.operations_updated",
                summary="Updated operational limits.", resource_type="settings",
                resource_id="operational-limits", resource_name="Operational limits",
                before=before, after=after,
            )
            flash("Operational limits saved. Scheduler concurrency changes apply after toolkit restart.", "success")
        return redirect(url_for("settings", section="operations", _anchor="operational-limits"))

    @app.get("/settings/diagnostics")
    def diagnostics():
        if not g.current_user.get("is_admin"): return Response("Administrator access is required.", status=403)
        route_started = time.perf_counter()
        timings: list[tuple[str, float]] = []
        diagnostic_warnings: list[str] = []
        instance = Path(app.instance_path)
        processes = [
            _process_health(instance, "Web service", "twn-toolkit.pid", ""),
            _process_health(instance, "Worker supervisor", "twn-supervisor.pid", "supervisor-heartbeat.json"),
            _process_health(instance, "Automation scheduler", "twn-automation.pid", "automation-heartbeat.json"),
            {"name": "TFTP service", **tftp_process_status(app.instance_path)},
            {"name": "SFTP / SCP service", **ssh_transfer_process_status(app.instance_path)},
            {"name": "FTP service", **ftp_process_status(app.instance_path)},
        ]
        iperf_status = _diagnostic_value(
            "iperf",
            "Managed iPerf3 listener status",
            lambda: iperf3_process_status(app.instance_path),
            {"running": False, "pid": None, "count": 0, "error": "Status unavailable."},
            timings,
            diagnostic_warnings,
        )
        if iperf_status.get("error"):
            diagnostic_warnings.append(str(iperf_status["error"]))
        processes.append({"name": "Managed iPerf3 listeners", **iperf_status})
        databases = _diagnostic_value(
            "databases",
            "Database integrity",
            lambda: _database_diagnostics(instance),
            [],
            timings,
            diagnostic_warnings,
        )
        runtime = _diagnostic_value(
            "runtime",
            "Runtime mode",
            lambda: service_runtime_status(
                project_root,
                manager_timeout_seconds=0.5,
            ),
            {
                "mode": "Unavailable",
                "platform": os.name,
                "healthy": False,
                "state": "Unknown",
                "paused": False,
                "process_set_ready": False,
                "manages_this_checkout": False,
                "installed": False,
                "manager_state": "unavailable",
                "last_exit": "",
                "launcher_running": False,
                "service_user": "",
                "service_group": "",
                "definition_path": "",
            },
            timings,
            diagnostic_warnings,
        )
        dependencies = _diagnostic_value(
            "dependencies",
            "Command dependencies",
            command_dependencies,
            [],
            timings,
            diagnostic_warnings,
        )
        capabilities = _diagnostic_value(
            "capabilities",
            "Platform capabilities",
            platform_capabilities,
            [],
            timings,
            diagnostic_warnings,
        )
        audit_query = request.args.get("audit_q", "").strip()[:160]
        try:
            audit_page_number = max(1, int(request.args.get("audit_page", "1")))
        except ValueError:
            audit_page_number = 1
        empty_audit_page = {
            "events": [],
            "query": audit_query,
            "page": audit_page_number,
            "per_page": 40,
            "total": 0,
            "total_pages": 1,
            "first_item": 0,
            "last_item": 0,
        }
        audit_page = _diagnostic_value(
            "audit",
            "Toolkit audit history",
            lambda: audit_store.search(
                audit_query,
                page=audit_page_number,
                per_page=40,
                timeout_seconds=0.2,
            ),
            empty_audit_page,
            timings,
            diagnostic_warnings,
        )
        audit = audit_page["events"]
        access_profiles = _diagnostic_value(
            "access_profiles",
            "Access profile labels",
            auth_store.access_profiles,
            [],
            timings,
            diagnostic_warnings,
        )
        for event in audit:
            event["recorded_display"] = datetime.fromtimestamp(float(event["recorded_at"])).astimezone().strftime("%b %-d, %Y %-I:%M:%S %p")
            event["category"] = event.get("category") or "Administration"
            event["summary"] = event.get("summary") or str(event["endpoint"]).replace("_", " ").capitalize()
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            event["changes"] = []
            for change in details.get("changes", []):
                if not isinstance(change, dict):
                    continue
                field = str(change.get("field", ""))
                previous = _resolve_legacy_audit_value(
                    field, change.get("before"), access_profiles
                )
                current = _resolve_legacy_audit_value(
                    field, change.get("after"), access_profiles
                )
                event["changes"].append(
                    {
                        **change,
                        "before_display": _format_audit_value(previous),
                        "after_display": _format_audit_value(current),
                    }
                )
            event["detail_items"] = [
                {
                    "label": key.replace("_", " ").replace(".", " › "),
                    "value": _format_audit_value(value),
                }
                for key, value in details.items()
                if key != "changes"
            ]
        storage = _diagnostic_value(
            "storage",
            "Storage capacity",
            lambda: _format_storage_summary(operational_store.storage_summary()),
            {
                "disk_free_display": "Unavailable",
                "disk_total_display": "Unavailable",
                "datastore_display": "Unavailable",
                "artifact_display": "Unavailable",
                "datastore_quota_gib": "—",
                "automation_artifact_quota_gib": "—",
                "minimum_free_gib": "—",
            },
            timings,
            diagnostic_warnings,
        )
        automation_snapshot = _diagnostic_value(
            "automation",
            "Automation storage diagnostics",
            automation_store.diagnostics_snapshot,
            {
                "migrations": [],
                "storage": {
                    "eligible_check_count": 0,
                    "eligible_run_count": 0,
                },
                "orphan_artifacts": {"count": 0, "bytes": 0},
            },
            timings,
            diagnostic_warnings,
        )
        toolkit_migrations = _diagnostic_value(
            "migrations",
            "Toolkit migration history",
            lambda: MigrationManager(app.instance_path).applied(),
            [],
            timings,
            diagnostic_warnings,
        )
        render_started = time.perf_counter()
        body = render_template(
            "auth/diagnostics.html", processes=processes, databases=databases,
            runtime=runtime, dependencies=dependencies, capabilities=capabilities,
            audit_events=audit,
            storage=storage,
            migrations=[*toolkit_migrations, *automation_snapshot["migrations"]],
            automation_storage=automation_snapshot["storage"],
            orphan_artifacts=automation_snapshot["orphan_artifacts"],
            audit_page=audit_page,
            diagnostic_warnings=diagnostic_warnings,
        )
        timings.append(("render", (time.perf_counter() - render_started) * 1000))
        timings.append(("total", (time.perf_counter() - route_started) * 1000))
        response = app.make_response(body)
        response.headers["Server-Timing"] = ", ".join(
            f"{name};dur={duration:.1f}" for name, duration in timings
        )
        return response

    @app.get("/settings/updates")
    def updates():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        requested_section = str(request.args.get("section", "updates")).strip().lower()
        updates_section = (
            requested_section
            if requested_section in {"updates", "recovery"}
            else "updates"
        )
        release = None
        check_error = ""
        if request.args.get("check") == "1" and updates_section == "updates":
            try:
                release = ReleaseClient().release(APP_VERSION)
            except UpgradeError as exc:
                check_error = str(exc)
        backups = upgrade_manager.backups()
        for backup in backups:
            backup["created_display"] = datetime.fromtimestamp(
                float(backup.get("created_at", 0))
            ).astimezone().strftime("%b %-d, %Y %-I:%M %p")
        return render_template(
            "auth/updates.html",
            installed_version=APP_VERSION,
            release=release,
            check_error=check_error,
            upgrade_status=upgrade_manager.status(),
            recovery_points=backups,
            updates_section=updates_section,
        )

    @app.get("/settings/updates/status")
    def update_status():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        return jsonify(upgrade_manager.status())

    def upgrade_actor() -> dict[str, str]:
        return {
            "id": str(g.current_user.get("id", "")),
            "username": str(g.current_user.get("username", "")),
            "remote_ip": request.remote_addr or "",
        }

    def render_upgrade_started(request_data: dict[str, Any], message: str):
        annotate_audit_event(
            category="Administration", action=f"upgrade.{request_data['operation']}_requested",
            summary=message, resource_type="toolkit_release",
            resource_id=str(request_data.get("target_version", "")),
            resource_name=f"Toolkit v{request_data.get('target_version', '')}",
            details={"operation id": request_data["id"]},
        )
        return render_template(
            "auth/updating.html",
            operation_id=request_data["id"],
            operation=request_data["operation"],
        )

    @app.post("/settings/updates/install")
    def install_update():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        try:
            if request.form.get("confirm_upgrade") != "on":
                raise UpgradeError("Confirm that services will restart and an automatic recovery point will be created.")
            client = ReleaseClient()
            release = client.release(APP_VERSION, request.form.get("version", ""))
            bundle = upgrade_manager.download_release(release, client)
            operation = upgrade_manager.launch_upgrade(bundle, upgrade_actor())
        except UpgradeError as exc:
            flash(str(exc), "error")
            return redirect(url_for("updates", check=1))
        return render_upgrade_started(
            operation, f"Requested toolkit upgrade to v{operation['target_version']}.",
        )

    @app.post("/settings/updates/upload")
    def upload_update_bundle():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        try:
            if request.form.get("confirm_upgrade") != "on":
                raise UpgradeError("Confirm that services will restart and an automatic recovery point will be created.")
            upload = request.files.get("bundle")
            if not upload or not upload.filename:
                raise UpgradeError("Choose a toolkit release bundle.")
            bundle = upgrade_manager.save_upload(upload.stream)
            operation = upgrade_manager.launch_upgrade(bundle, upgrade_actor())
        except UpgradeError as exc:
            flash(str(exc), "error")
            return redirect(url_for("updates", section="updates"))
        return render_upgrade_started(
            operation, f"Requested manual toolkit upgrade to v{operation['target_version']}.",
        )

    @app.post("/settings/updates/backup")
    def create_recovery_point():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        try:
            if request.form.get("confirm_backup") != "on":
                raise UpgradeError("Confirm the brief service restart required for a consistent recovery point.")
            operation = upgrade_manager.launch_backup(upgrade_actor())
        except UpgradeError as exc:
            flash(str(exc), "error")
            return redirect(url_for("updates", section="recovery"))
        return render_upgrade_started(operation, "Requested a complete toolkit recovery point.")

    @app.post("/settings/updates/rollback")
    def rollback_update():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        try:
            if request.form.get("confirm_rollback") != "on":
                raise UpgradeError("Confirm that current code and instance data will be replaced by the selected recovery point.")
            operation = upgrade_manager.launch_rollback(
                request.form.get("backup_id", ""), upgrade_actor()
            )
        except UpgradeError as exc:
            flash(str(exc), "error")
            return redirect(url_for("updates", section="recovery"))
        return render_upgrade_started(
            operation, f"Requested rollback to recovery point {operation['backup_id']}.",
        )

    @app.post("/settings/diagnostics/cleanup-artifacts")
    def cleanup_orphan_artifacts():
        if not g.current_user.get("is_admin"): return Response("Administrator access is required.", status=403)
        cleaned = automation_store.cleanup_orphan_artifacts()
        annotate_audit_event(
            category="Administration", action="automation.artifacts_cleaned",
            summary="Cleaned orphaned automation artifacts.",
            resource_type="automation_storage", resource_id="orphan-artifacts",
            resource_name="Orphaned automation artifacts", details={
                "folders removed": cleaned["count"],
                "bytes reclaimed": cleaned["bytes"],
            },
        )
        flash(f"Removed {cleaned['count']} orphaned artifact folder(s), reclaiming {_format_bytes(cleaned['bytes'])}.", "success")
        return redirect(url_for("diagnostics", _anchor="storage-health"))

    @app.post("/settings/automation-retention")
    def update_automation_retention():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        before = automation_store.retention_settings()
        try:
            check_days = int(request.form.get("check_retention_days", ""))
            run_days = int(request.form.get("run_retention_days", ""))
            automation_store.update_retention_settings(
                check_retention_days=check_days,
                run_retention_days=run_days,
            )
        except (TypeError, ValueError) as exc:
            flash(str(exc) or "Enter whole numbers for retention days.", "error")
        else:
            after = automation_store.retention_settings()
            annotate_audit_event(
                category="Administration", action="automation.retention_updated",
                summary="Updated automation retention settings.",
                resource_type="settings", resource_id="automation-retention",
                resource_name="Automation retention", before=before, after=after,
            )
            flash("Automation retention settings updated.", "success")
        return redirect(url_for("settings", section="operations", _anchor="automation-retention"))

    @app.post("/settings/automation-retention/prune")
    def prune_automation_history():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        deleted = automation_store.prune_history()
        annotate_audit_event(
            category="Administration", action="automation.history_pruned",
            summary="Pruned retained automation history.",
            resource_type="automation_storage", resource_id="history",
            resource_name="Automation history", details={
                "checks removed": deleted["checks"],
                "runs removed": deleted["runs"],
            },
        )
        flash(
            f"Pruned {deleted['checks']} check record(s) and {deleted['runs']} collected action run(s).",
            "success",
        )
        return redirect(url_for("settings", section="operations", _anchor="automation-retention"))

    @app.post("/settings/automation-retention/optimize")
    def optimize_automation_database():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        try:
            automation_store.optimize_database()
        except Exception as exc:
            flash(f"Automation database optimization failed: {exc}", "error")
        else:
            annotate_audit_event(
                category="Administration", action="automation.database_optimized",
                summary="Optimized the automation database.",
                resource_type="database", resource_id="automation",
                resource_name="Automation database",
            )
            flash("Automation database optimized.", "success")
        return redirect(url_for("settings", section="operations", _anchor="automation-retention"))

    @app.post("/settings/users")
    def create_user():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        password = request.form.get("password", "")
        if password != request.form.get("confirm_password", ""):
            flash("Passwords do not match.", "error")
        else:
            try:
                created = auth_store.create_user(
                    request.form.get("username", ""),
                    password,
                    is_admin=request.form.get("builtin_profile") == "administrator",
                    access_profile_ids=request.form.getlist("access_profile_id"),
                )
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                annotate_audit_event(
                    category="Administration", action="user.created",
                    summary=f"Created user {created['username']}.", resource_type="user",
                    resource_id=created["id"], resource_name=created["username"],
                    after=_user_audit_snapshot(created, auth_store.access_profiles()),
                )
                flash("User created.", "success")
        return redirect(url_for("settings", section="accounts"))

    @app.post("/settings/users/<user_id>/access")
    def update_user_access(user_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        before = next((user for user in auth_store.users() if user["id"] == user_id), None)
        try:
            auth_store.update_user_access(
                user_id,
                is_admin=request.form.get("builtin_profile") == "administrator",
                access_profile_ids=request.form.getlist("access_profile_id"),
            )
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            after = next((user for user in auth_store.users() if user["id"] == user_id), None)
            annotate_audit_event(
                category="Administration", action="user.access_updated",
                summary=f"Updated access for {(after or before or {}).get('username', user_id)}.",
                resource_type="user", resource_id=user_id,
                resource_name=str((after or before or {}).get("username", "")),
                before=_user_audit_snapshot(before, auth_store.access_profiles()),
                after=_user_audit_snapshot(after, auth_store.access_profiles()),
            )
            flash("User access updated.", "success")
        return redirect(url_for("settings", section="accounts"))

    @app.post("/settings/access-profiles")
    def save_access_profile():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        profile_id = request.form.get("profile_id", "")
        before = auth_store.get_access_profile(profile_id) if profile_id else None
        try:
            saved = auth_store.save_access_profile(
                profile_id=profile_id,
                name=request.form.get("name", ""),
                description=request.form.get("description", ""),
                tool_ids=[
                    tool_id
                    for tool_id in request.form.getlist("tool_id")
                    if TOOL_BY_ID.get(tool_id) and TOOL_BY_ID[tool_id].grantable
                ],
            )
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration",
                action="access_profile.updated" if before else "access_profile.created",
                summary=f"{'Updated' if before else 'Created'} access profile {saved['name']}.",
                resource_type="access profile", resource_id=saved["id"],
                resource_name=saved["name"], before=_profile_audit_snapshot(before),
                after=_profile_audit_snapshot(saved),
            )
            flash("Access profile saved.", "success")
        return redirect(url_for("settings", section="accounts"))

    @app.post("/settings/access-profiles/<profile_id>/delete")
    def delete_access_profile(profile_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        profile = auth_store.get_access_profile(profile_id)
        try:
            auth_store.delete_access_profile(profile_id)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Administration", action="access_profile.deleted",
                summary=f"Deleted access profile {(profile or {}).get('name', profile_id)}.",
                resource_type="access profile", resource_id=profile_id,
                resource_name=str((profile or {}).get("name", "")),
                details={"deleted profile": _profile_audit_snapshot(profile)},
            )
            flash("Access profile deleted.", "success")
        return redirect(url_for("settings", section="accounts"))

    @app.post("/settings/access-profiles/<profile_id>/duplicate")
    def duplicate_access_profile(profile_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        source = auth_store.get_access_profile(profile_id)
        if not source:
            abort(404)
        copied = auth_store.duplicate_access_profile(profile_id)
        annotate_audit_event(
            category="Administration", action="access_profile.duplicated",
            summary=f"Duplicated access profile {source['name']} as {copied['name']}.",
            resource_type="access profile", resource_id=copied["id"],
            resource_name=copied["name"],
            details={"source profile id": profile_id},
            after=_profile_audit_snapshot(copied),
        )
        flash(f"Duplicated access profile as {copied['name']}.", "success")
        return redirect(url_for("settings", section="accounts", _anchor="access-profiles"))

    @app.post("/settings/users/<user_id>/password")
    def change_user_password(user_id: str):
        is_self = user_id == g.current_user["id"]
        if not (g.current_user.get("is_admin") or is_self):
            return Response("Permission denied.", status=403)
        password = request.form.get("password", "")
        target_user = next((user for user in auth_store.users() if user["id"] == user_id), None)
        if password != request.form.get("confirm_password", ""):
            flash("Passwords do not match.", "error")
        else:
            try:
                auth_store.update_password(user_id, password)
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                if is_self:
                    updated = next(
                        user for user in auth_store.users() if user["id"] == user_id
                    )
                    start_session(updated)
                annotate_audit_event(
                    category="Administration", action="user.password_changed",
                    summary=f"Changed the password for {(target_user or {}).get('username', user_id)}.",
                    resource_type="user", resource_id=user_id,
                    resource_name=str((target_user or {}).get("username", "")),
                    details={"existing sessions invalidated": True},
                )
                flash("Password updated. Existing sessions for that user were signed out.", "success")
        return redirect(url_for("settings", section="accounts"))

    @app.post("/settings/users/<user_id>/delete")
    def delete_user(user_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        target_user = next((user for user in auth_store.users() if user["id"] == user_id), None)
        if user_id == g.current_user["id"]:
            flash("You cannot delete your own signed-in account.", "error")
        else:
            try:
                auth_store.delete_user(user_id)
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                annotate_audit_event(
                    category="Administration", action="user.deleted",
                    summary=f"Deleted user {(target_user or {}).get('username', user_id)}.",
                    resource_type="user", resource_id=user_id,
                    resource_name=str((target_user or {}).get("username", "")),
                    details={
                        "deleted user": _user_audit_snapshot(
                            target_user, auth_store.access_profiles()
                        )
                    },
                )
                flash("User deleted.", "success")
        return redirect(url_for("settings", section="accounts"))

    @app.post("/settings/session")
    def update_session_settings():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        before = {
            "idle timeout minutes": auth_store.idle_timeout_minutes(),
            **auth_store.password_policy(),
        }
        try:
            minutes = int(request.form.get("idle_timeout_minutes", ""))
            min_password_length = int(request.form.get("min_password_length", ""))
        except (TypeError, ValueError):
            flash("Enter whole numbers for the authentication settings.", "error")
        else:
            try:
                auth_store.set_policy(
                    idle_timeout_minutes=minutes,
                    min_password_length=min_password_length,
                    require_uppercase=request.form.get("require_uppercase") == "on",
                    require_lowercase=request.form.get("require_lowercase") == "on",
                    require_number=request.form.get("require_number") == "on",
                    require_special=request.form.get("require_special") == "on",
                )
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                after = {
                    "idle timeout minutes": auth_store.idle_timeout_minutes(),
                    **auth_store.password_policy(),
                }
                annotate_audit_event(
                    category="Administration", action="settings.authentication_updated",
                    summary="Updated authentication and session policy.",
                    resource_type="settings", resource_id="authentication-policy",
                    resource_name="Authentication policy", before=before, after=after,
                )
                flash("Session settings updated.", "success")
        return redirect(url_for("settings", section="accounts"))

    @app.post("/settings/server")
    def update_server_settings():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        before = server_settings_store.get()
        listen_host = request.form.get("listen_host", "")
        allowed_networks = request.form.get("allowed_networks", "")
        instance_name = request.form.get("instance_name", "")
        preferred_fqdn = request.form.get("preferred_fqdn", "")
        settings_saved = False
        try:
            candidate = {
                "listen_host": listen_host,
                "allowed_networks": normalize_allowed_networks(allowed_networks),
                "instance_name": normalize_instance_name(instance_name),
                "preferred_fqdn": normalize_preferred_fqdn(preferred_fqdn),
            }
            # Validate without writing so a rejected current-client check changes nothing.
            if listen_host not in {"127.0.0.1", "0.0.0.0"}:
                raise ValueError("Choose localhost-only or all network interfaces.")
            if not server_settings_store.client_allowed(request.remote_addr, candidate):
                raise ValueError(
                    "These trusted hosts would exclude your current client address "
                    f"({request.remote_addr or 'unknown'}). Add it or its network before restarting."
                )
            server_settings_store.save(
                listen_host,
                candidate["allowed_networks"],
                candidate["instance_name"],
                candidate["preferred_fqdn"],
            )
            settings_saved = True
            if request.form.get("regenerate_tls") == "on":
                current_tls = certificate_status(
                    app.instance_path, candidate["preferred_fqdn"]
                )
                if not current_tls["enabled"] or not current_tls["present"]:
                    raise ValueError(
                        "The toolkit-managed HTTPS certificate is not enabled and cannot be regenerated here."
                    )
                regenerate_self_signed_certificate(
                    app.instance_path,
                    extra_names=[
                        candidate["instance_name"],
                        candidate["preferred_fqdn"],
                    ],
                )
        except (RuntimeError, ValueError) as exc:
            if settings_saved:
                server_settings_store.restore_previous()
            flash(str(exc), "error")
            return redirect(url_for("settings"))

        project_root = Path(__file__).resolve().parent.parent
        restart_log_path = Path(app.instance_path) / "twn-toolkit-restart.log"
        restart_log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with restart_log_path.open("a", encoding="utf-8") as restart_log:
                subprocess.Popen(
                    [str(project_root / "twn"), "web-restart"],
                    cwd=project_root,
                    stdin=subprocess.DEVNULL,
                    stdout=restart_log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
        except OSError as exc:
            server_settings_store.restore_previous()
            flash(f"Settings were saved, but automatic restart failed: {exc}", "error")
            return redirect(url_for("settings"))
        annotate_audit_event(
            category="Administration", action="settings.server_updated",
            summary="Updated server identity and network access settings.",
            resource_type="settings", resource_id="server-settings",
            resource_name="Server settings", before=before,
            after=server_settings_store.get(),
            details={"TLS certificate regenerated": request.form.get("regenerate_tls") == "on"},
        )
        return render_template(
            "auth/restarting.html",
            previous_boot_id=app.config["BOOT_ID"],
        )

    @app.get("/settings/backup")
    def backup_settings():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        active_view = (
            "import" if request.args.get("view") == "import" else "export"
        )
        preview_token = str(request.args.get("preview", ""))
        pending = None
        if preview_token:
            try:
                pending = configuration_import_store.get(
                    preview_token, user_id=str(g.current_user["id"])
                )
                active_view = "import"
            except ValueError as exc:
                flash(str(exc), "error")
                preview_token = ""
        return _configuration_backup_page(
            active_view=active_view,
            preview_token=preview_token,
            pending_import=pending,
        )

    @app.post("/settings/backup/export")
    def export_profile_backup():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        selected_ids = set(request.form.getlist("item"))
        selected_items = selected_backup_items(backup_catalog, selected_ids)
        if not selected_items:
            flash("Choose at least one profile group to export.", "error")
            return redirect(url_for("backup_settings"))

        has_sensitive_items = any(item["sensitive"] for item in selected_items)
        encrypt_requested = has_sensitive_items or request.form.get("encrypt_backup") == "on"
        password = request.form.get("backup_password", "")
        confirm_password = request.form.get("confirm_backup_password", "")
        if encrypt_requested:
            if not password:
                flash("Enter an encryption password for this backup.", "error")
                return redirect(url_for("backup_settings"))
            if password != confirm_password:
                flash("Backup encryption passwords do not match.", "error")
                return redirect(url_for("backup_settings"))

        backup = build_profile_backup(selected_items)
        payload = json.dumps(backup, indent=2).encode("utf-8")
        filename_prefix = "twn-toolkit-configuration-backup"
        if encrypt_requested:
            payload = json.dumps(encrypt_backup(payload, password), indent=2).encode("utf-8")
            filename_prefix = "twn-toolkit-encrypted-configuration-backup"
        annotate_audit_event(
            category="Backup and restore",
            action="backup.exported",
            summary=f"Exported {len(selected_items)} backup group(s).",
            resource_type="configuration_backup",
            resource_id="export",
            resource_name="Configuration backup export",
            details={
                "selected groups": _backup_audit_references(selected_items),
                "group count": len(selected_items),
                "encrypted": encrypt_requested,
                "contains sensitive groups": has_sensitive_items,
                "export size bytes": len(payload),
            },
        )
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return Response(
            payload,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename_prefix}-{stamp}.json"'
            },
        )

    @app.post("/settings/backup/inspect")
    def inspect_configuration_backup():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        upload = request.files.get("backup_file")
        if not upload or not upload.filename:
            flash("Choose a toolkit configuration backup to inspect.", "error")
            return redirect(url_for("backup_settings", view="import"))
        import_mode = request.form.get("import_mode", "merge")
        if import_mode not in {"merge", "replace"}:
            flash("Choose Combine or Replace for the import mode.", "error")
            return redirect(url_for("backup_settings", view="import"))
        encrypted_input = False
        try:
            raw = upload.read(64 * 1024 * 1024 + 1)
            if len(raw) > 64 * 1024 * 1024:
                raise ValueError("Configuration backups may not exceed 64 MiB.")
            backup = json.loads(raw.decode("utf-8"))
            if is_encrypted_backup(backup):
                encrypted_input = True
                backup_password = request.form.get("backup_password", "")
                if not backup_password:
                    raise ValueError("Enter the password for this encrypted backup.")
                backup = decrypt_backup(backup, backup_password)
            validate_profile_backup(backup)
            inspection = inspect_profile_backup(backup, backup_catalog)
            if inspection["unavailable_count"] == len(inspection["groups"]):
                raise ValueError("This backup does not contain any groups available in this toolkit version.")
            preview_token = configuration_import_store.create(
                backup,
                user_id=str(g.current_user["id"]),
                encrypted_input=encrypted_input,
                import_mode=import_mode,
            )
        except (OSError, TypeError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            annotate_audit_event(
                category="Backup and restore",
                action="backup.inspect_failed",
                summary="Configuration backup inspection failed.",
                resource_type="configuration_backup",
                resource_id="inspect",
                resource_name="Configuration backup inspection",
                details={
                    "import mode": import_mode,
                    "encrypted": encrypted_input,
                    "outcome": "failed",
                    "error": str(exc)[:500],
                },
            )
            flash(f"Backup inspection failed: {exc}", "error")
            return redirect(url_for("backup_settings", view="import"))
        return redirect(
            url_for("backup_settings", view="import", preview=preview_token)
        )

    @app.post("/settings/backup/import")
    def import_profile_backup():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        preview_token = str(request.form.get("preview_token", ""))
        selected_ids = set(request.form.getlist("item"))
        selected_items = selected_backup_items(backup_catalog, selected_ids)
        import_mode = request.form.get("import_mode", "merge")
        encrypted_input = False
        try:
            pending = configuration_import_store.get(
                preview_token, user_id=str(g.current_user["id"])
            )
            encrypted_input = bool(pending.get("encrypted_input"))
            backup = pending["backup"]
            if not selected_items:
                raise ValueError("Choose at least one configuration group to import.")
            if import_mode != pending.get("import_mode"):
                raise ValueError("The import mode changed. Inspect the backup again before importing.")
            owner_mappings = remote_connection_owner_mappings(
                backup["items"], auth_store.users()
            )
            if "remote_connection_library" in selected_ids:
                mapping_values = {
                    owner["index"]: str(
                        request.form.get(f"owner_map_{owner['index']}", "")
                    )
                    for owner in owner_mappings
                }
                backup_items = apply_remote_connection_owner_mappings(
                    backup["items"], mapping_values
                )
            else:
                backup_items = backup["items"]
            imported = import_backup_items(backup_items, selected_items, import_mode)
        except (OSError, TypeError, UnicodeError, sqlite3.Error, ValueError, RuntimeError) as exc:
            annotate_audit_event(
                category="Backup and restore",
                action="backup.import_failed",
                summary="Configuration backup import failed.",
                resource_type="configuration_backup",
                resource_id="import",
                resource_name="Configuration backup import",
                details={
                    "selected groups": _backup_audit_references(selected_items),
                    "group count": len(selected_items),
                    "import mode": import_mode,
                    "encrypted": encrypted_input,
                    "outcome": "failed",
                    "error": str(exc)[:500],
                },
            )
            flash(f"Backup import failed: {exc}", "error")
            return redirect(
                url_for("backup_settings", view="import", preview=preview_token)
            )
        else:
            configuration_import_store.delete(preview_token)
            imported_counts = [
                {"group": label, "record count": count}
                for label, count in imported
            ]
            annotate_audit_event(
                category="Backup and restore",
                action="backup.imported",
                summary=f"Imported {len(imported)} backup group(s) in {import_mode} mode.",
                resource_type="configuration_backup",
                resource_id="import",
                resource_name="Configuration backup import",
                details={
                    "selected groups": _backup_audit_references(selected_items),
                    "group count": len(selected_items),
                    "import mode": import_mode,
                    "encrypted": encrypted_input,
                    "outcome": "success",
                    "imported groups": imported_counts,
                    "imported record count": sum(count for _label, count in imported),
                },
            )
            action = "Combined" if import_mode == "merge" else "Imported"
            flash(
                action
                + " "
                + ", ".join(f"{count} {label}" for label, count in imported)
                + ".",
                "success",
            )
        return redirect(url_for("backup_settings", view="import"))
