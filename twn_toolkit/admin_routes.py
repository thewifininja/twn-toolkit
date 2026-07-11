from __future__ import annotations

import json
import subprocess
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


def register_admin_routes(
    app: Flask,
    *,
    auth_store: AuthStore,
    server_settings_store: ServerSettingsStore,
    backup_catalog: list[dict[str, Any]],
    start_session: Callable[[dict[str, Any]], None],
) -> None:
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
        )

    @app.post("/settings/users")
    def create_user():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        password = request.form.get("password", "")
        if password != request.form.get("confirm_password", ""):
            flash("Passwords do not match.", "error")
        else:
            try:
                auth_store.create_user(
                    request.form.get("username", ""),
                    password,
                    is_admin=request.form.get("builtin_profile") == "administrator",
                    access_profile_ids=request.form.getlist("access_profile_id"),
                )
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash("User created.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/users/<user_id>/access")
    def update_user_access(user_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        try:
            auth_store.update_user_access(
                user_id,
                is_admin=request.form.get("builtin_profile") == "administrator",
                access_profile_ids=request.form.getlist("access_profile_id"),
            )
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("User access updated.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/access-profiles")
    def save_access_profile():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        try:
            auth_store.save_access_profile(
                profile_id=request.form.get("profile_id", ""),
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
            flash("Access profile saved.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/access-profiles/<profile_id>/delete")
    def delete_access_profile(profile_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        try:
            auth_store.delete_access_profile(profile_id)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("Access profile deleted.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/users/<user_id>/password")
    def change_user_password(user_id: str):
        is_self = user_id == g.current_user["id"]
        if not (g.current_user.get("is_admin") or is_self):
            return Response("Permission denied.", status=403)
        password = request.form.get("password", "")
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
                flash("Password updated. Existing sessions for that user were signed out.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/users/<user_id>/delete")
    def delete_user(user_id: str):
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        if user_id == g.current_user["id"]:
            flash("You cannot delete your own signed-in account.", "error")
        else:
            try:
                auth_store.delete_user(user_id)
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash("User deleted.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/session")
    def update_session_settings():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
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
                flash("Session settings updated.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/server")
    def update_server_settings():
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
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

        try:
            backup = json.loads(upload.read().decode("utf-8"))
            if backup.get("format") == "twn-toolkit-encrypted-profile-backup":
                backup_password = request.form.get("backup_password", "")
                if not backup_password:
                    raise ValueError("Enter the password for this encrypted backup.")
                backup = decrypt_backup(backup, backup_password)
            validate_profile_backup(backup)
            imported = import_backup_items(backup["items"], selected_items, import_mode)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            flash(f"Backup import failed: {exc}", "error")
        else:
            action = "Combined" if import_mode == "merge" else "Imported"
            flash(
                action
                + " "
                + ", ".join(f"{count} {label}" for label, count in imported)
                + ".",
                "success",
            )
        return redirect(url_for("backup_settings"))
