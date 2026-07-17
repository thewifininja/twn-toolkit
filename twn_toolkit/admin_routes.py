from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
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

from .auth import AuthStore
from .automation import AutomationStore
from .profile_backup import (
    build_profile_backup,
    decrypt_backup,
    encrypt_backup,
    import_backup_items,
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
from .migrations import MigrationManager
from .network_tools import ping_engine_capability
from .tftp import tftp_process_status
from .ssh_transfer_server import ssh_transfer_process_status
from .ftp_server import ftp_process_status
from .upgrade_manager import ReleaseClient, UpgradeError, UpgradeManager
from .version import APP_VERSION


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("bytes", "KiB", "MiB", "GiB"):
        if amount < 1024 or unit == "GiB":
            return f"{amount:.1f} {unit}" if unit != "bytes" else f"{int(amount)} bytes"
        amount /= 1024
    return f"{amount:.1f} GiB"


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
    backup_catalog: list[dict[str, Any]],
    start_session: Callable[[dict[str, Any]], None],
    audit_store: AuditStore,
    operational_store: OperationalSettingsStore,
) -> None:
    project_root = Path(__file__).resolve().parent.parent
    upgrade_manager = UpgradeManager(project_root, Path(app.instance_path), APP_VERSION)

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

    @app.get("/settings")
    def settings():
        visible_users = (
            auth_store.users()
            if g.current_user.get("is_admin")
            else [g.current_user]
        )
        active_server_settings = server_settings_store.get()
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
        )

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
        return redirect(url_for("settings", _anchor="operational-limits"))

    @app.get("/settings/diagnostics")
    def diagnostics():
        if not g.current_user.get("is_admin"): return Response("Administrator access is required.", status=403)
        instance = Path(app.instance_path)
        processes = [
            _process_health(instance, "Web service", "twn-toolkit.pid", ""),
            _process_health(instance, "Worker supervisor", "twn-supervisor.pid", "supervisor-heartbeat.json"),
            _process_health(instance, "Automation scheduler", "twn-automation.pid", "automation-heartbeat.json"),
            {"name": "TFTP service", **tftp_process_status(app.instance_path)},
            {"name": "SFTP / SCP service", **ssh_transfer_process_status(app.instance_path)},
            {"name": "FTP service", **ftp_process_status(app.instance_path)},
        ]
        databases = []
        for path in sorted(instance.glob("*.sqlite3")):
            status = "ok"
            try:
                connection = sqlite3.connect(path, timeout=2)
                try: status = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                finally: connection.close()
            except sqlite3.Error as exc: status = str(exc)
            databases.append({"name": path.name, "size": _format_bytes(path.stat().st_size), "status": status})
        dependencies = [
            {"name": name, "available": bool(shutil.which(name)), "detail": ""}
            for name in ("ping", "traceroute", "tcpdump", "openssl")
        ]
        ping_capability = ping_engine_capability()
        dependencies.append(
            {
                "name": "fping high-capacity ICMP",
                "available": ping_capability["accelerated"],
                "detail": ping_capability["detail"],
            }
        )
        audit_query = request.args.get("audit_q", "").strip()[:160]
        try:
            audit_page_number = max(1, int(request.args.get("audit_page", "1")))
        except ValueError:
            audit_page_number = 1
        audit_page = audit_store.search(
            audit_query, page=audit_page_number, per_page=40
        )
        audit = audit_page["events"]
        access_profiles = auth_store.access_profiles()
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
        return render_template(
            "auth/diagnostics.html", processes=processes, databases=databases,
            dependencies=dependencies, audit_events=audit,
            storage=_format_storage_summary(operational_store.storage_summary()),
            migrations=[*MigrationManager(app.instance_path).applied(), *automation_store.migration_status()],
            automation_storage=automation_store.storage_stats(),
            orphan_artifacts=automation_store.orphan_artifact_stats(),
            audit_page=audit_page,
        )

    @app.get("/settings/updates")
    def updates():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        release = None
        check_error = ""
        if request.args.get("check") == "1":
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
            return redirect(url_for("updates"))
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
            return redirect(url_for("updates"))
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
            return redirect(url_for("updates"))
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
        return redirect(url_for("settings", _anchor="automation-retention"))

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
        return redirect(url_for("settings", _anchor="automation-retention"))

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
        return redirect(url_for("settings", _anchor="automation-retention"))

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
        return redirect(url_for("settings"))

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
        return redirect(url_for("settings"))

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
        return redirect(url_for("settings"))

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
        return redirect(url_for("settings"))

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
        return redirect(url_for("settings"))

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
        return redirect(url_for("settings"))

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
        return redirect(url_for("settings"))

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
        return render_template("auth/backup.html", backup_catalog=backup_catalog)

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
        filename_prefix = "twn-toolkit-backup"
        if encrypt_requested:
            payload = json.dumps(encrypt_backup(payload, password), indent=2).encode("utf-8")
            filename_prefix = "twn-toolkit-encrypted-backup"
        annotate_audit_event(
            category="Backup and restore",
            action="backup.exported",
            summary=f"Exported {len(selected_items)} backup group(s).",
            resource_type="profile_backup",
            resource_id="export",
            resource_name="Profile backup export",
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

    @app.post("/settings/backup/import")
    def import_profile_backup():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        upload = request.files.get("backup_file")
        if not upload or not upload.filename:
            flash("Choose a toolkit backup JSON file to import.", "error")
            return redirect(url_for("backup_settings"))

        selected_ids = set(request.form.getlist("item"))
        selected_items = selected_backup_items(backup_catalog, selected_ids)
        if not selected_items:
            flash("Choose at least one profile group to import.", "error")
            return redirect(url_for("backup_settings"))

        import_mode = request.form.get("import_mode", "merge")
        if import_mode not in {"merge", "replace"}:
            flash("Choose combine or replace for the import mode.", "error")
            return redirect(url_for("backup_settings"))

        encrypted_input = False
        try:
            backup = json.loads(upload.read().decode("utf-8"))
            if backup.get("format") == "twn-toolkit-encrypted-profile-backup":
                encrypted_input = True
                backup_password = request.form.get("backup_password", "")
                if not backup_password:
                    raise ValueError("Enter the password for this encrypted backup.")
                backup = decrypt_backup(backup, backup_password)
            validate_profile_backup(backup)
            imported = import_backup_items(backup["items"], selected_items, import_mode)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            annotate_audit_event(
                category="Backup and restore",
                action="backup.import_failed",
                summary="Profile backup import failed.",
                resource_type="profile_backup",
                resource_id="import",
                resource_name="Profile backup import",
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
        else:
            imported_counts = [
                {"group": label, "record count": count}
                for label, count in imported
            ]
            annotate_audit_event(
                category="Backup and restore",
                action="backup.imported",
                summary=f"Imported {len(imported)} backup group(s) in {import_mode} mode.",
                resource_type="profile_backup",
                resource_id="import",
                resource_name="Profile backup import",
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
        return redirect(url_for("backup_settings"))
