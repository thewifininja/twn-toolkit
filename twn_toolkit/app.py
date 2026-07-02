from __future__ import annotations

import csv
import io
import re
import secrets
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from flask import (
    Flask,
    Response,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .auth import AuthStore, load_or_create_secret_key
from .fortiauthenticator import (
    FortiAuthenticatorClient,
    FortiAuthenticatorError,
    normalize_host as normalize_fortiauthenticator_host,
)
from .fortigate import FortiGateClient, FortiGateError, normalize_api_key, normalize_host
from .profiles import (
    DNSProfileStore,
    FortiAuthenticatorProfileStore,
    PingProfileStore,
    PortScanProfileStore,
    NTPHostProfileStore,
    TracerouteHostProfileStore,
    ProfileStore,
    RadiusProfileStore,
    SNMPCredentialProfileStore,
    SNMPHostProfileStore,
    SNMPOidProfileStore,
)
from .server_settings import ServerSettingsStore, normalize_allowed_networks
from .tasks import TASKS, ExportTask, RenameTask, discover_export_fields, get_task, grouped_tasks
from .tools import tools_bp


def create_app(instance_path: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    app.config.from_mapping(
        BOOT_ID=secrets.token_hex(12),
        SECRET_KEY=load_or_create_secret_key(app.instance_path),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    app.register_blueprint(tools_bp)

    auth_store = AuthStore(app.instance_path)
    server_settings_store = ServerSettingsStore(app.instance_path)
    store = ProfileStore(app.instance_path)
    fortiauthenticator_store = FortiAuthenticatorProfileStore(app.instance_path)
    ping_profile_store = PingProfileStore(app.instance_path)

    @app.before_request
    def require_authentication():
        if app.testing:
            g.current_user = {
                "id": "test-user",
                "username": "test-user",
                "is_admin": True,
            }
            return None

        if not server_settings_store.client_allowed(request.remote_addr):
            return Response(
                "This client address is not included in the toolkit's trusted hosts.",
                status=403,
                mimetype="text/plain",
            )

        endpoint = request.endpoint or ""
        if endpoint == "static" or endpoint in {
            "favicon",
            "health",
            "login",
            "logout",
            "setup",
        }:
            return None

        if not auth_store.is_configured():
            session.clear()
            return redirect(url_for("setup"))

        user_id = session.get("user_id")
        user = next(
            (item for item in auth_store.users() if item["id"] == user_id),
            None,
        )
        now = int(time.time())
        idle_seconds = auth_store.idle_timeout_minutes() * 60
        last_seen = session.get("last_seen")
        valid_session = (
            user
            and user.get("enabled", True)
            and session.get("session_version") == user.get("session_version", 1)
            and isinstance(last_seen, int)
            and now - last_seen <= idle_seconds
        )
        if not valid_session:
            expired = bool(user_id and last_seen and now - int(last_seen) > idle_seconds)
            session.clear()
            if expired:
                flash("Your session expired due to inactivity.", "error")
            return redirect(url_for("login", next=_safe_next_url()))

        session["last_seen"] = now
        g.current_user = user
        return None

    @app.context_processor
    def authentication_context():
        password_policy = auth_store.password_policy()
        current_user = getattr(g, "current_user", None)
        return {
            "current_user": current_user,
            "user_theme": current_user.get("theme", "light") if current_user else "system",
            "min_password_length": password_policy["min_length"],
            "password_policy": password_policy,
        }

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

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if auth_store.is_configured():
            return redirect(url_for("login"))
        if request.method == "POST":
            password = request.form.get("password", "")
            if password != request.form.get("confirm_password", ""):
                flash("Passwords do not match.", "error")
            else:
                try:
                    user = auth_store.create_user(
                        request.form.get("username", ""), password, is_admin=True
                    )
                except ValueError as exc:
                    flash(str(exc), "error")
                else:
                    _start_session(user)
                    flash("Administrator account created.", "success")
                    return redirect(url_for("index"))
        return render_template("auth/setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_store.is_configured():
            return redirect(url_for("setup"))
        if request.method == "POST":
            user = auth_store.authenticate(
                request.form.get("username", ""),
                request.form.get("password", ""),
            )
            if user:
                _start_session(user)
                return redirect(_validated_next_url(request.form.get("next", "")))
            flash("Invalid username or password.", "error")
        return render_template("auth/login.html", next_url=_safe_next_url())

    @app.post("/logout")
    def logout():
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("login"))

    @app.get("/settings")
    def settings():
        visible_users = (
            auth_store.users()
            if g.current_user.get("is_admin")
            else [g.current_user]
        )
        return render_template(
            "auth/settings.html",
            users=visible_users,
            idle_timeout_minutes=auth_store.idle_timeout_minutes(),
            min_password_length=auth_store.min_password_length(),
            password_policy=auth_store.password_policy(),
            server_settings=server_settings_store.get(),
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
                    is_admin=request.form.get("is_admin") == "on",
                )
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash("User created.", "success")
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
                    _start_session(updated)
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
        try:
            candidate = {
                "listen_host": listen_host,
                "allowed_networks": normalize_allowed_networks(allowed_networks),
            }
            # Validate without writing so a rejected current-client check changes nothing.
            if listen_host not in {"127.0.0.1", "0.0.0.0"}:
                raise ValueError("Choose localhost-only or all network interfaces.")
            if not server_settings_store.client_allowed(request.remote_addr, candidate):
                raise ValueError(
                    "These trusted hosts would exclude your current client address "
                    f"({request.remote_addr or 'unknown'}). Add it or its network before restarting."
                )
            server_settings_store.save(listen_host, candidate["allowed_networks"])
        except (RuntimeError, ValueError) as exc:
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

    @app.get("/health")
    def health():
        return jsonify({"boot_id": app.config["BOOT_ID"]})

    def _start_session(user: dict[str, Any]) -> None:
        session.clear()
        session["user_id"] = user["id"]
        session["session_version"] = user.get("session_version", 1)
        session["last_seen"] = int(time.time())

    def _validated_next_url(candidate: str) -> str:
        if candidate.startswith("/") and not candidate.startswith("//"):
            return candidate
        return url_for("index")

    def _safe_next_url() -> str:
        return _validated_next_url(request.args.get("next", ""))

    @app.cli.command("reset-auth")
    @click.option("--yes", is_flag=True, help="Reset without an interactive confirmation.")
    def reset_auth(yes: bool) -> None:
        """Remove users and require first-run administrator setup again."""
        if not yes and not click.confirm(
            "Delete all toolkit users and authentication settings? Saved device profiles are not affected."
        ):
            click.echo("Reset cancelled.")
            return
        if auth_store.path.exists():
            auth_store.path.unlink()
        click.echo("Authentication reset. Open the toolkit to create a new administrator.")

    @app.cli.command("reset-data")
    @click.option("--yes", is_flag=True, help="Reset without an interactive confirmation.")
    def reset_data(yes: bool) -> None:
        """Remove all locally saved profiles and API keys."""
        if not yes and not click.confirm(
            "Delete all saved FortiGate, FortiAuthenticator, ping, DNS, RADIUS, SNMP, TCP scanner, NTP, and traceroute profiles and credentials?"
        ):
            click.echo("Reset cancelled.")
            return
        store.clear()
        fortiauthenticator_store.clear()
        ping_profile_store.clear()
        DNSProfileStore(app.instance_path, "hosts").clear()
        DNSProfileStore(app.instance_path, "servers").clear()
        RadiusProfileStore(app.instance_path, "servers").clear()
        RadiusProfileStore(app.instance_path, "credentials").clear()
        RadiusProfileStore(app.instance_path, "attributes").clear()
        PortScanProfileStore(app.instance_path, "hosts").clear()
        PortScanProfileStore(app.instance_path, "ports").clear()
        NTPHostProfileStore(app.instance_path).clear()
        TracerouteHostProfileStore(app.instance_path).clear()
        SNMPCredentialProfileStore(app.instance_path).clear()
        SNMPHostProfileStore(app.instance_path).clear()
        SNMPOidProfileStore(app.instance_path).clear()
        click.echo("The WiFi Ninja's Toolkit local profile data has been reset.")

    @app.get("/")
    def index():
        return render_template("home.html")

    @app.get("/fortigate")
    def fortigate_home():
        profiles = store.all()
        edit_profile = store.get(request.args.get("edit", ""))
        return render_template(
            "index.html",
            edit_profile=edit_profile,
            profiles=profiles,
            task_groups=grouped_tasks(),
        )

    @app.get("/fortigate/switch-order")
    def switch_order():
        return render_template("switch_order.html", profiles=store.all())

    @app.post("/fortigate/switch-order/objects")
    def switch_order_objects():
        profile = store.get(request.form.get("profile", ""))
        if not profile:
            return jsonify({"error": "Select a valid FortiGate profile."}), 400
        vdom = request.form.get("vdom", "").strip() or profile.get("default_vdom", "root")
        try:
            switches = _managed_switch_order(
                FortiGateClient.from_profile(profile).get_managed_switches(vdom)
            )
        except FortiGateError as exc:
            return jsonify({"error": str(exc)}), 502
        return jsonify({"switches": switches, "row_count": len(switches), "vdom": vdom})

    @app.post("/fortigate/switch-order/apply")
    def apply_switch_order():
        profile = store.get(request.form.get("profile", ""))
        desired_ids = list(dict.fromkeys(request.form.getlist("switch_id")))
        if not profile:
            return jsonify({"error": "Select a valid FortiGate profile."}), 400
        if len(desired_ids) < 2:
            return jsonify({"error": "Load and order at least two switches."}), 400

        vdom = request.form.get("vdom", "").strip() or profile.get("default_vdom", "root")
        client = FortiGateClient.from_profile(profile)
        try:
            current = _managed_switch_order(client.get_managed_switches(vdom))
        except FortiGateError as exc:
            return jsonify({"error": str(exc)}), 502

        current_ids = [item["id"] for item in current]
        if len(desired_ids) != len(current_ids) or set(desired_ids) != set(current_ids):
            return jsonify(
                {
                    "error": (
                        "The managed-switch list changed after it was loaded. "
                        "Reload the switches before applying an order."
                    )
                }
            ), 409

        moves = _switch_order_moves(current_ids, desired_ids)
        completed: list[dict[str, str]] = []
        try:
            for move in moves:
                client.move_managed_switch_after(move["switch_id"], move["after"], vdom)
                completed.append(move)
            verified = _managed_switch_order(client.get_managed_switches(vdom))
        except FortiGateError as exc:
            return jsonify(
                {
                    "error": str(exc),
                    "completed_moves": completed,
                    "message": (
                        f"FortiGate rejected the reorder after {len(completed)} "
                        "successful move(s). Reload to inspect its current order."
                    ),
                }
            ), 502

        verified_ids = [item["id"] for item in verified]
        if verified_ids != desired_ids:
            return jsonify(
                {
                    "error": "FortiGate accepted the moves but the verified order does not match.",
                    "completed_moves": completed,
                    "switches": verified,
                }
            ), 409
        return jsonify(
            {
                "message": f"Verified the new order of {len(verified)} FortiSwitches.",
                "moves": completed,
                "switches": verified,
            }
        )

    @app.get("/fortiauthenticator")
    def fortiauthenticator_home():
        profiles = fortiauthenticator_store.all()
        edit_profile = fortiauthenticator_store.get(request.args.get("edit", ""))
        return render_template(
            "fortiauthenticator/index.html",
            edit_profile=edit_profile,
            profiles=profiles,
        )

    @app.post("/fortiauthenticator/profiles")
    def save_fortiauthenticator_profile():
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        host = request.form.get("host", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        verify_tls = request.form.get("verify_tls") == "on"
        is_default = request.form.get("is_default") == "on"
        existing_profile = fortiauthenticator_store.get(original_name) if original_name else None

        try:
            timeout = int(request.form.get("timeout", "20"))
            if not 1 <= timeout <= 300:
                raise ValueError
        except ValueError:
            flash("Timeout must be a whole number from 1 to 300 seconds.", "error")
            return redirect(url_for("fortiauthenticator_home"))

        if not name or not host or not username or (not password and not existing_profile):
            flash("Profile name, FortiAuthenticator URL, username, and password are required.", "error")
            return redirect(url_for("fortiauthenticator_home"))

        try:
            host = normalize_fortiauthenticator_host(host)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("fortiauthenticator_home"))

        if existing_profile and original_name != name:
            fortiauthenticator_store.delete(original_name)

        fortiauthenticator_store.upsert(
            {
                "name": name,
                "host": host,
                "username": username,
                "password": password if password else existing_profile["password"],
                "verify_tls": verify_tls,
                "timeout": timeout,
                "is_default": is_default,
            }
        )
        flash(f"Saved FortiAuthenticator profile '{name}'.", "success")
        return redirect(url_for("fortiauthenticator_home"))

    @app.post("/fortiauthenticator/profiles/<name>/delete")
    def delete_fortiauthenticator_profile(name: str):
        fortiauthenticator_store.delete(name)
        flash(f"Deleted FortiAuthenticator profile '{name}'.", "success")
        return redirect(url_for("fortiauthenticator_home"))

    @app.post("/fortiauthenticator/profiles/<name>/test")
    def test_fortiauthenticator_profile(name: str):
        profile = fortiauthenticator_store.get(name)
        if not profile:
            flash("FortiAuthenticator profile not found.", "error")
            return redirect(url_for("fortiauthenticator_home"))

        try:
            result = FortiAuthenticatorClient.from_profile(profile).test_connection()
        except FortiAuthenticatorError as exc:
            flash(f"Connection failed: {exc}", "error")
        else:
            total = result.get("meta", {}).get("total_count")
            suffix = f" ({total} MAC devices available)." if total is not None else "."
            flash(f"Connection to '{name}' succeeded{suffix}", "success")
        return redirect(url_for("fortiauthenticator_home"))

    @app.route("/fortiauthenticator/mac-devices", methods=["GET", "POST"])
    def fortiauthenticator_mac_devices():
        profiles = fortiauthenticator_store.all()
        selected_name = request.form.get("profile", "") if request.method == "POST" else ""
        rows: list[dict[str, Any]] | None = None
        total_count = 0
        preview_limit = 500

        if request.method == "POST":
            profile = fortiauthenticator_store.get(selected_name)
            if not profile:
                flash("Select a valid FortiAuthenticator profile.", "error")
            else:
                try:
                    objects = FortiAuthenticatorClient.from_profile(profile).get_all_mac_devices()
                except FortiAuthenticatorError as exc:
                    flash(f"MAC device fetch failed: {exc}", "error")
                else:
                    total_count = len(objects)
                    rows = [_format_mac_device(item) for item in objects[:preview_limit]]

        return render_template(
            "fortiauthenticator/mac_devices.html",
            profiles=profiles,
            rows=rows,
            selected_name=selected_name,
            total_count=total_count,
            preview_limit=preview_limit,
        )

    @app.post("/fortiauthenticator/mac-devices.csv")
    def export_fortiauthenticator_mac_devices():
        profile = fortiauthenticator_store.get(request.form.get("profile", ""))
        if not profile:
            flash("Select a valid FortiAuthenticator profile.", "error")
            return redirect(url_for("fortiauthenticator_mac_devices"))

        try:
            objects = FortiAuthenticatorClient.from_profile(profile).get_all_mac_devices()
        except FortiAuthenticatorError as exc:
            flash(f"MAC device export failed: {exc}", "error")
            return redirect(url_for("fortiauthenticator_mac_devices"))

        output = io.StringIO()
        fieldnames = ["ID", "MAC Address", "Name", "Description", "Resource URI"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(_format_mac_device(item) for item in objects)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_profile_name = re.sub(r"[^A-Za-z0-9._-]+", "_", profile["name"]).strip("_") or "profile"
        filename = f"mac-devices-{safe_profile_name}-{stamp}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.route("/fortiauthenticator/mac-group-memberships", methods=["GET", "POST"])
    def fortiauthenticator_mac_group_memberships():
        profiles = fortiauthenticator_store.all()
        selected_name = request.form.get("profile", "") if request.method == "POST" else ""
        rows: list[dict[str, Any]] | None = None
        total_count = 0
        preview_limit = 500

        if request.method == "POST":
            profile = fortiauthenticator_store.get(selected_name)
            if not profile:
                flash("Select a valid FortiAuthenticator profile.", "error")
            else:
                try:
                    objects = (
                        FortiAuthenticatorClient.from_profile(profile).get_all_mac_group_memberships()
                    )
                except FortiAuthenticatorError as exc:
                    flash(f"MAC group-membership fetch failed: {exc}", "error")
                else:
                    total_count = len(objects)
                    rows = [_format_mac_group_membership(item) for item in objects[:preview_limit]]

        return render_template(
            "fortiauthenticator/mac_group_memberships.html",
            profiles=profiles,
            rows=rows,
            selected_name=selected_name,
            total_count=total_count,
            preview_limit=preview_limit,
        )

    @app.post("/fortiauthenticator/mac-group-memberships.csv")
    def export_fortiauthenticator_mac_group_memberships():
        profile = fortiauthenticator_store.get(request.form.get("profile", ""))
        if not profile:
            flash("Select a valid FortiAuthenticator profile.", "error")
            return redirect(url_for("fortiauthenticator_mac_group_memberships"))

        try:
            objects = FortiAuthenticatorClient.from_profile(
                profile
            ).get_all_mac_group_memberships()
        except FortiAuthenticatorError as exc:
            flash(f"MAC group-membership export failed: {exc}", "error")
            return redirect(url_for("fortiauthenticator_mac_group_memberships"))

        output = io.StringIO()
        fieldnames = [
            "Membership ID",
            "Device ID",
            "Device Name",
            "Device URI",
            "Group ID",
            "Group Name",
            "Group URI",
            "Expiry Time",
            "Resource URI",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(_format_mac_group_membership(item) for item in objects)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_profile_name = re.sub(r"[^A-Za-z0-9._-]+", "_", profile["name"]).strip("_") or "profile"
        filename = f"mac-group-memberships-{safe_profile_name}-{stamp}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.route("/fortiauthenticator/mac-cleanup", methods=["GET", "POST"])
    def fortiauthenticator_mac_cleanup():
        profiles = fortiauthenticator_store.all()
        selected_name = request.form.get("profile", "") if request.method == "POST" else ""
        selected_group_uri = request.form.get("group_uri", "") if request.method == "POST" else ""
        selected_action = request.form.get("action", "remove_memberships")
        groups: list[dict[str, Any]] = []
        preview: dict[str, Any] | None = None

        if request.method == "POST":
            profile = fortiauthenticator_store.get(selected_name)
            if not profile:
                flash("Select a valid FortiAuthenticator profile.", "error")
            else:
                client = FortiAuthenticatorClient.from_profile(profile)
                try:
                    memberships = client.get_all_mac_group_memberships()
                    groups = _mac_groups(memberships)
                    if request.form.get("intent") == "preview":
                        if selected_action not in {"remove_memberships", "delete_devices"}:
                            raise FortiAuthenticatorError("Select a valid cleanup action.")
                        if selected_group_uri not in {group["uri"] for group in groups}:
                            raise FortiAuthenticatorError("Select a valid MAC group.")
                        devices = client.get_all_mac_devices()
                        preview = _build_mac_cleanup_preview(
                            memberships,
                            devices,
                            selected_group_uri,
                            selected_action,
                        )
                except FortiAuthenticatorError as exc:
                    flash(f"Cleanup preview failed: {exc}", "error")

        return render_template(
            "fortiauthenticator/mac_cleanup.html",
            profiles=profiles,
            groups=groups,
            selected_name=selected_name,
            selected_group_uri=selected_group_uri,
            selected_action=selected_action,
            preview=preview,
            preview_limit=500,
        )

    @app.post("/fortiauthenticator/mac-cleanup/execute")
    def execute_fortiauthenticator_mac_cleanup():
        profile = fortiauthenticator_store.get(request.form.get("profile", ""))
        group_uri = request.form.get("group_uri", "")
        action = request.form.get("action", "")
        confirmation = request.form.get("confirmation", "").strip()
        requested_ids = list(
            dict.fromkeys(
                value.strip()
                for value in request.form.getlist("selected_id")
                if value.strip()
            )
        )
        if not profile or action not in {"remove_memberships", "delete_devices"}:
            flash("Cleanup request is invalid. Build a new preview.", "error")
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        client = FortiAuthenticatorClient.from_profile(profile)
        try:
            memberships = client.get_all_mac_group_memberships()
            if group_uri not in {group["uri"] for group in _mac_groups(memberships)}:
                raise FortiAuthenticatorError("The selected MAC group is no longer available.")
            devices = client.get_all_mac_devices()
            preview = _build_mac_cleanup_preview(memberships, devices, group_uri, action)
        except FortiAuthenticatorError as exc:
            flash(f"Cleanup validation failed: {exc}", "error")
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        if not preview["targets"]:
            flash("No matching records remain. Nothing was changed.", "error")
            return redirect(url_for("fortiauthenticator_mac_cleanup"))
        if not requested_ids:
            flash("Select at least one device. Nothing was changed.", "error")
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        id_key = "membership_id" if action == "remove_memberships" else "device_id"
        targets_by_id = {target[id_key]: target for target in preview["targets"]}
        stale_ids = [identifier for identifier in requested_ids if identifier not in targets_by_id]
        if stale_ids:
            flash(
                "The selected targets changed after the preview. Nothing was changed; build a new preview.",
                "error",
            )
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        targets = [targets_by_id[identifier] for identifier in requested_ids]
        expected_confirmation = _cleanup_confirmation(action, len(targets))
        if confirmation != expected_confirmation:
            flash(
                f"Confirmation did not match. Nothing was changed. Expected: {expected_confirmation}",
                "error",
            )
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        results = []
        for target in targets:
            try:
                if action == "remove_memberships":
                    client.delete_mac_group_membership(target["membership_id"])
                else:
                    client.delete_mac_device(target["device_id"])
            except FortiAuthenticatorError as exc:
                results.append({**target, "status": "error", "message": str(exc)})
            else:
                operation = (
                    "Group membership removed."
                    if action == "remove_memberships"
                    else "MAC device deleted globally."
                )
                results.append({**target, "status": "success", "message": operation})

        return render_template(
            "fortiauthenticator/mac_cleanup_results.html",
            action=action,
            group_name=preview["group_name"],
            profile=profile,
            results=results,
        )

    @app.get("/favicon.ico")
    def favicon():
        return app.send_static_file("brand/favicon-32.png")

    @app.post("/profiles")
    def save_profile():
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        host = request.form.get("host", "").strip()
        api_key = request.form.get("api_key", "").strip()
        verify_tls = request.form.get("verify_tls") == "on"
        is_default = request.form.get("is_default") == "on"
        default_vdom = request.form.get("default_vdom", "root").strip() or "root"
        existing_profile = store.get(original_name) if original_name else None

        if not name or not host or (not api_key and not existing_profile):
            flash("Profile name, FortiGate URL, and API key are required.", "error")
            return redirect(url_for("fortigate_home"))

        try:
            host = normalize_host(host)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("fortigate_home"))

        if existing_profile and original_name != name:
            store.delete(original_name)

        store.upsert(
            {
                "name": name,
                "host": host,
                "api_key": normalize_api_key(api_key) if api_key else existing_profile["api_key"],
                "verify_tls": verify_tls,
                "is_default": is_default,
                "default_vdom": default_vdom,
            }
        )
        flash(f"Saved profile '{name}'.", "success")
        return redirect(url_for("fortigate_home"))

    @app.post("/profiles/<name>/delete")
    def delete_profile(name: str):
        store.delete(name)
        flash(f"Deleted profile '{name}'.", "success")
        return redirect(url_for("fortigate_home"))

    @app.post("/profiles/<name>/test")
    def test_profile(name: str):
        profile = store.get(name)
        if not profile:
            flash("Profile not found.", "error")
            return redirect(url_for("fortigate_home"))

        client = FortiGateClient.from_profile(profile)
        try:
            result = client.test_connection()
        except FortiGateError as exc:
            flash(f"Connection failed: {_connection_error_message(exc)}", "error")
        else:
            version = result.get("version") or result.get("build") or "reachable"
            flash(f"Connection OK: {version}", "success")

        return redirect(url_for("fortigate_home"))

    @app.get("/tasks/<task_id>")
    def task_form(task_id: str):
        task = get_task(task_id)
        if not task:
            flash("Task not found.", "error")
            return redirect(url_for("fortigate_home"))
        return render_template("task.html", profiles=store.all(), task=task)

    @app.get("/tasks/<task_id>/template.csv")
    def task_csv_template(task_id: str):
        task = get_task(task_id)
        if not isinstance(task, RenameTask):
            return Response("CSV templates are only available for rename tasks.", status=404)
        return Response(
            task.csv_template(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={task.id}-template.csv"},
        )

    @app.post("/tasks/<task_id>/run")
    def run_task(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        upload = request.files.get("csv_file")
        dry_run = request.form.get("dry_run") == "on"
        endpoint_template = request.form.get("endpoint_template", "").strip()

        if not task or not profile:
            flash("Select a valid task and profile.", "error")
            return redirect(url_for("fortigate_home"))

        client = FortiGateClient.from_profile(profile)
        if isinstance(task, ExportTask):
            fields = request.form.get("fields", "").strip()
            try:
                csv_data = task.run(
                    client=client,
                    endpoint_template=endpoint_template or task.endpoint_template,
                    default_vdom=profile.get("default_vdom", "root"),
                    fields=fields,
                )
            except FortiGateError as exc:
                flash(f"Export failed: {exc}", "error")
                return redirect(url_for("task_form", task_id=task_id))

            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"{task.id}-{profile['name']}-{stamp}.csv".replace(" ", "_")
            return Response(
                csv_data,
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        if not isinstance(task, RenameTask):
            flash("Task type is not supported yet.", "error")
            return redirect(url_for("fortigate_home"))

        if not upload or upload.filename == "":
            flash("Choose a CSV file to import.", "error")
            return redirect(url_for("task_form", task_id=task_id))

        results, entries = task.run_with_entries(
            client=client,
            csv_stream=upload.stream,
            dry_run=dry_run,
            endpoint_template=endpoint_template or task.endpoint_template,
            default_vdom=profile.get("default_vdom", "root"),
        )

        return render_template(
            "results.html",
            entries=entries if dry_run else None,
            endpoint_template=endpoint_template or task.endpoint_template,
            profile=profile,
            task=task,
            results=results,
            dry_run=dry_run,
        )

    @app.post("/tasks/<task_id>/objects")
    def task_objects(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        endpoint_template = request.form.get("endpoint_template", "").strip()

        if not isinstance(task, RenameTask):
            return jsonify({"error": "Object discovery is only available for rename tasks."}), 400
        if not profile:
            return jsonify({"error": "Select a FortiGate profile first."}), 400

        client = FortiGateClient.from_profile(profile)
        try:
            objects = task.discover_objects(
                client=client,
                endpoint_template=endpoint_template or task.endpoint_template,
                default_vdom=profile.get("default_vdom", "root"),
            )
        except FortiGateError as exc:
            return jsonify({"error": str(exc)}), 502

        return jsonify({"objects": objects, "row_count": len(objects)})

    @app.post("/tasks/<task_id>/rename")
    def rename_objects(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        endpoint_template = request.form.get("endpoint_template", "").strip()
        dry_run = request.form.get("dry_run") == "on"

        if not isinstance(task, RenameTask) or not profile:
            flash("Select a valid rename task and profile.", "error")
            return redirect(url_for("task_form", task_id=task_id))

        identifiers = request.form.getlist("identifier")
        current_names = request.form.getlist("current_name")
        new_names = request.form.getlist("new_name")
        vdoms = request.form.getlist("vdom")
        if not identifiers or not (
            len(identifiers) == len(current_names) == len(new_names) == len(vdoms)
        ):
            flash("Select at least one device and enter its new name.", "error")
            return redirect(url_for("task_form", task_id=task_id))

        entries = [
            {
                "identifier": identifier,
                "current_name": current_name,
                "new_name": new_name,
                "vdom": vdom,
            }
            for identifier, current_name, new_name, vdom in zip(
                identifiers, current_names, new_names, vdoms
            )
        ]
        client = FortiGateClient.from_profile(profile)
        results = task.run_entries(
            client=client,
            entries=entries,
            dry_run=dry_run,
            endpoint_template=endpoint_template or task.endpoint_template,
            default_vdom=profile.get("default_vdom", "root"),
        )
        return render_template(
            "results.html",
            entries=entries if dry_run else None,
            endpoint_template=endpoint_template or task.endpoint_template,
            profile=profile,
            task=task,
            results=results,
            dry_run=dry_run,
        )

    @app.post("/tasks/<task_id>/fields")
    def task_fields(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        endpoint_template = request.form.get("endpoint_template", "").strip()

        if not isinstance(task, ExportTask):
            return jsonify({"error": "Field discovery is only available for export tasks."}), 400
        if not profile:
            return jsonify({"error": "Select a FortiGate profile first."}), 400

        client = FortiGateClient.from_profile(profile)
        try:
            rows, endpoint_used = task.preview_rows_with_endpoint(
                client=client,
                endpoint_template=endpoint_template or task.endpoint_template,
                default_vdom=profile.get("default_vdom", "root"),
            )
        except FortiGateError as exc:
            return jsonify({"error": str(exc)}), 502

        fields = discover_export_fields(task, rows)
        return jsonify({"endpoint_used": endpoint_used, "fields": fields, "row_count": len(rows)})

    @app.post("/tasks/<task_id>/preview")
    def task_preview(task_id: str):
        task = get_task(task_id)
        profile = store.get(request.form.get("profile", ""))
        endpoint_template = request.form.get("endpoint_template", "").strip()
        selected_fields = request.form.get("fields", "").strip()

        if not isinstance(task, ExportTask):
            return jsonify({"error": "Data preview is only available for export tasks."}), 400
        if not profile:
            return jsonify({"error": "Select a FortiGate profile first."}), 400

        client = FortiGateClient.from_profile(profile)
        try:
            rows, endpoint_used = task.preview_rows_with_endpoint(
                client=client,
                endpoint_template=endpoint_template or task.endpoint_template,
                default_vdom=profile.get("default_vdom", "root"),
            )
        except FortiGateError as exc:
            return jsonify({"error": str(exc)}), 502

        columns, formatted_rows = task.format_rows(rows, selected_fields)
        return jsonify(
            {
                "columns": columns,
                "endpoint_used": endpoint_used,
                "row_count": len(formatted_rows),
                "rows": formatted_rows,
            }
        )

    return app


def _format_mac_device(item: dict[str, Any]) -> dict[str, Any]:
    resource_uri = str(item.get("resource_uri") or "")
    return {
        "ID": _resource_id(resource_uri) or item.get("id", ""),
        "MAC Address": item.get("address", ""),
        "Name": item.get("name", ""),
        "Description": item.get("description", ""),
        "Resource URI": resource_uri,
    }


def _managed_switch_order(items: list[dict[str, Any]]) -> list[dict[str, str]]:
    switches: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        identifier = str(
            item.get("switch-id")
            or item.get("switch_id")
            or item.get("name")
            or item.get("serial")
            or item.get("sn")
            or ""
        ).strip()
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        display_name = str(
            item.get("name")
            or item.get("switch-id")
            or item.get("switch_id")
            or identifier
        ).strip()
        description = str(item.get("description") or "").strip()
        serial = str(item.get("sn") or item.get("serial") or "").strip()
        switches.append(
            {
                "id": identifier,
                "name": display_name,
                "description": description,
                "serial": serial,
            }
        )
    return switches


def _switch_order_moves(
    current_ids: list[str],
    desired_ids: list[str],
) -> list[dict[str, str]]:
    simulated = list(current_ids)
    moves: list[dict[str, str]] = []
    for index in range(1, len(desired_ids)):
        switch_id = desired_ids[index]
        after = desired_ids[index - 1]
        switch_index = simulated.index(switch_id)
        if switch_index > 0 and simulated[switch_index - 1] == after:
            continue
        simulated.remove(switch_id)
        after_index = simulated.index(after)
        simulated.insert(after_index + 1, switch_id)
        moves.append({"switch_id": switch_id, "after": after})
    return moves


def _format_mac_group_membership(item: dict[str, Any]) -> dict[str, Any]:
    device_uri = str(item.get("device") or "")
    group_uri = str(item.get("group") or "")
    resource_uri = str(item.get("resource_uri") or "")
    return {
        "Membership ID": item.get("id", "") or _resource_id(resource_uri),
        "Device ID": _resource_id(device_uri),
        "Device Name": item.get("device_name", ""),
        "Device URI": device_uri,
        "Group ID": _resource_id(group_uri),
        "Group Name": item.get("group_name", ""),
        "Group URI": group_uri,
        "Expiry Time": item.get("expiry_time") or "",
        "Resource URI": resource_uri,
    }


def _resource_id(resource_uri: str) -> str:
    match = re.search(r"/(\d+)/?$", resource_uri)
    return match.group(1) if match else ""


def _mac_groups(memberships: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for membership in memberships:
        uri = str(membership.get("group") or "")
        if not uri:
            continue
        group = groups.setdefault(
            uri,
            {
                "uri": uri,
                "id": _resource_id(uri),
                "name": str(membership.get("group_name") or uri),
                "count": 0,
            },
        )
        group["count"] += 1
    return sorted(groups.values(), key=lambda group: (group["name"].lower(), group["uri"]))


def _build_mac_cleanup_preview(
    memberships: list[dict[str, Any]],
    devices: list[dict[str, Any]],
    group_uri: str,
    action: str,
) -> dict[str, Any]:
    selected_memberships = [
        membership for membership in memberships if str(membership.get("group") or "") == group_uri
    ]
    device_lookup = {
        _resource_id(str(device.get("resource_uri") or "")) or str(device.get("id") or ""): device
        for device in devices
    }
    memberships_by_device: dict[str, list[dict[str, Any]]] = {}
    for membership in memberships:
        device_id = _resource_id(str(membership.get("device") or ""))
        if device_id:
            memberships_by_device.setdefault(device_id, []).append(membership)

    targets_by_device: dict[str, dict[str, Any]] = {}
    for membership in selected_memberships:
        device_id = _resource_id(str(membership.get("device") or ""))
        membership_id = str(membership.get("id") or "") or _resource_id(
            str(membership.get("resource_uri") or "")
        )
        if not device_id or not membership_id:
            continue
        device = device_lookup.get(device_id, {})
        other_groups = sorted(
            {
                str(item.get("group_name") or item.get("group") or "")
                for item in memberships_by_device.get(device_id, [])
                if str(item.get("group") or "") != group_uri
            }
        )
        targets_by_device.setdefault(
            device_id,
            {
                "membership_id": membership_id,
                "device_id": device_id,
                "mac_address": str(device.get("address") or ""),
                "device_name": str(
                    device.get("name") or membership.get("device_name") or ""
                ),
                "other_groups": other_groups,
            },
        )

    targets = sorted(
        targets_by_device.values(),
        key=lambda target: (
            target["device_name"].lower(),
            target["mac_address"].lower(),
            int(target["device_id"]),
        ),
    )
    count = len(targets)
    group_name = next(
        (
            str(membership.get("group_name") or group_uri)
            for membership in selected_memberships
        ),
        group_uri,
    )
    return {
        "action": action,
        "confirmation": _cleanup_confirmation(action, count),
        "group_name": group_name,
        "group_uri": group_uri,
        "overlap_count": sum(bool(target["other_groups"]) for target in targets),
        "targets": targets,
    }


def _cleanup_confirmation(action: str, count: int) -> str:
    if action == "remove_memberships":
        return f"REMOVE {count} {'MEMBERSHIP' if count == 1 else 'MEMBERSHIPS'}"
    return f"DELETE {count} {'DEVICE' if count == 1 else 'DEVICES'}"


def _connection_error_message(exc: FortiGateError) -> str:
    if exc.status_code == 401:
        return (
            "HTTP 401 Unauthorized. The FortiGate was reached, but the API token was rejected or the API user "
            "does not have permission to read the test endpoint (/api/v2/monitor/system/status). Make sure the "
            "profile URL includes your custom port, for example https://<fortigate>:8443, paste only the token "
            "value, and confirm the API admin trusted hosts/admin profile allow this request."
        )

    if exc.status_code == 403:
        return (
            "HTTP 403 Forbidden. The token appears valid, but the API admin profile is not allowed to read this "
            "endpoint."
        )

    return str(exc)
