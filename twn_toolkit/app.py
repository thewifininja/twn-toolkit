from __future__ import annotations

import os
import secrets
import time
from typing import Any

import click
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .activity import ActivityStore
from .automation import AutomationStore
from .automation_routes import register_automation_routes
from .datastore import LocalDatastore, MAX_UPLOAD_BYTES
from .datastore_routes import register_datastore_routes
from .tftp import TFTPHistoryStore, TFTPSettingsStore
from .ssh_transfer_server import SSHTransferHistoryStore, SSHTransferSettingsStore
from .ftp_server import FTPSettingsStore
from .auth import AuthStore, load_or_create_secret_key
from .admin_routes import register_admin_routes
from .dashboard_layout import DashboardLayoutStore
from .fortiauthenticator_routes import register_fortiauthenticator_routes
from .fortigate_routes import register_fortigate_routes
from .profiles import (
    FortiAuthenticatorProfileStore,
    ProfileStore,
)
from .profile_backup import build_backup_catalog, build_reset_stores
from .server_settings import ServerSettingsStore
from .tool_catalog import (
    TOOL_BY_ID,
    TOOL_CATEGORIES,
    NAVIGATION_SUBGROUPS,
    favorite_tools,
    grouped_visible_tools,
    tool_id_for_endpoint,
    visible_tools,
)
from .tools import tools_bp
from .version import APP_VERSION, RELEASE_NOTES
from .audit import AuditStore
from .migrations import run_toolkit_migrations
from .operational import OperationalSettingsStore


def create_app(instance_path: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    app.config.from_mapping(
        BOOT_ID=secrets.token_hex(12),
        SECRET_KEY=load_or_create_secret_key(app.instance_path),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("TWN_TOOLKIT_HTTPS") == "1",
        PREFERRED_URL_SCHEME=(
            "https" if os.environ.get("TWN_TOOLKIT_HTTPS") == "1" else "http"
        ),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 1024 * 1024,
    )
    app.register_blueprint(tools_bp)
    run_toolkit_migrations(app.instance_path)

    auth_store = AuthStore(app.instance_path)
    automation_store = AutomationStore(app.instance_path, app.config["SECRET_KEY"])
    datastore_store = LocalDatastore(app.instance_path)
    tftp_runtime_store = LocalDatastore(app.instance_path, "tftp_runtime")
    tftp_settings_store = TFTPSettingsStore(app.instance_path)
    tftp_history_store = TFTPHistoryStore(app.instance_path)
    ssh_transfer_runtime_store = LocalDatastore(app.instance_path, "ssh_transfer_runtime")
    ssh_transfer_settings_store = SSHTransferSettingsStore(app.instance_path)
    ssh_transfer_history_store = SSHTransferHistoryStore(app.instance_path)
    ftp_runtime_store = LocalDatastore(app.instance_path, "ftp_runtime")
    ftp_settings_store = FTPSettingsStore(app.instance_path)
    activity_store = ActivityStore(app.instance_path)
    dashboard_layout_store = DashboardLayoutStore(app.instance_path)
    server_settings_store = ServerSettingsStore(app.instance_path)
    store = ProfileStore(app.instance_path)
    fortiauthenticator_store = FortiAuthenticatorProfileStore(app.instance_path)
    backup_catalog = build_backup_catalog(app.instance_path)
    audit_store = AuditStore(app.instance_path)
    operational_store = OperationalSettingsStore(app.instance_path)

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
        idle_timeout_minutes = auth_store.idle_timeout_minutes()
        idle_seconds = idle_timeout_minutes * 60
        last_seen = session.get("last_seen")
        valid_session = (
            user
            and user.get("enabled", True)
            and session.get("session_version") == user.get("session_version", 1)
            and isinstance(last_seen, int)
            and (idle_timeout_minutes == 0 or now - last_seen <= idle_seconds)
        )
        if not valid_session:
            expired = bool(
                idle_timeout_minutes > 0
                and user_id
                and last_seen
                and now - int(last_seen) > idle_seconds
            )
            session.clear()
            if expired:
                flash("Your session expired due to inactivity.", "error")
            return redirect(url_for("login", next=_safe_next_url()))

        session["last_seen"] = now
        g.current_user = user
        g.allowed_tool_ids = auth_store.effective_tool_ids(user)
        denied_tool_id = tool_id_for_endpoint(endpoint, request.view_args)
        if denied_tool_id and not _tool_access_allowed(denied_tool_id):
            return Response("This user does not have access to that tool.", status=403)
        return None

    @app.after_request
    def audit_administrative_mutations(response: Response):
        user = getattr(g, "current_user", None)
        audited_reads = {"download_automation_run", "download_datastore_file", "bulk_download_datastore_files", "download_automation_artifact"}
        should_audit = request.method in {"POST", "PUT", "PATCH", "DELETE"} or (request.endpoint or "") in audited_reads
        if should_audit and user and user.get("is_admin"):
            try:
                audit_store.record(
                    user_id=user.get("id", ""), username=user.get("username", ""),
                    remote_ip=request.remote_addr or "", method=request.method,
                    endpoint=request.endpoint or "", path=request.path,
                    status_code=response.status_code,
                )
            except Exception:
                app.logger.exception("Administrative audit event could not be recorded")
        return response

    @app.context_processor
    def authentication_context():
        password_policy = auth_store.password_policy()
        current_user = getattr(g, "current_user", None)
        allowed_tool_ids = getattr(g, "allowed_tool_ids", None)
        nav_category_ids = set()
        sidebar_favorites = []
        sidebar_tool_groups = []
        sidebar_favorites_active = False
        current_tool_id = None
        if current_user:
            is_admin = bool(current_user.get("is_admin"))
            category_icons = {
                category["id"]: category.get("icon", "•")
                for category in TOOL_CATEGORIES
            }
            visible = visible_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)
            nav_category_ids = {
                tool.category
                for tool in visible
            }
            favorite_ids = auth_store.favorite_tool_ids(current_user["id"])
            sidebar_favorites = favorite_tools(
                favorite_ids, is_admin=is_admin, allowed_tool_ids=allowed_tool_ids
            )
            visible_by_id = {tool.id: tool for tool in visible}
            current_endpoint = request.endpoint or ""
            current_tool_id = tool_id_for_endpoint(current_endpoint, request.view_args)
            if current_tool_id is None:
                endpoint_matches = [
                    tool for tool in visible if tool.endpoint == current_endpoint
                ]
                if len(endpoint_matches) == 1:
                    current_tool_id = endpoint_matches[0].id
            sidebar_favorites_active = any(tool.id == current_tool_id for tool in sidebar_favorites)

            def is_active(tool: Any) -> bool:
                return tool.id == current_tool_id

            def active_in_tools(tools: list[Any]) -> bool:
                return any(is_active(tool) for tool in tools)

            fortinet_action_tools = [
                tool for tool in visible if tool.category_label == "FortiAP Tasks"
            ]
            fortinet_action_tools.extend(
                tool for tool in visible if tool.category_label == "FortiSwitch Tasks"
            )
            fortinet_action_tools.extend(
                tool
                for tool in visible
                if tool.category_label == "FortiAuthenticator Workflows"
            )
            fortigate_visible = any(tool.category == "fortigate" for tool in visible)
            fortiauthenticator_visible = any(
                tool.category == "fortiauthenticator" for tool in visible
            )
            fortigate_home = visible_by_id.get("fortigate.home") or (
                TOOL_BY_ID["fortigate.home"] if fortigate_visible else None
            )
            fortiauthenticator_home = visible_by_id.get("fortiauthenticator.home") or (
                TOOL_BY_ID["fortiauthenticator.home"] if fortiauthenticator_visible else None
            )
            fortinet_children = []
            if fortigate_home:
                fortinet_children.append(
                    {
                        "label": "FortiGate",
                        "tool": fortigate_home,
                        "favorite_enabled": fortigate_home.id in visible_by_id,
                        "active": is_active(fortigate_home)
                        or current_endpoint == fortigate_home.endpoint
                        or any(
                            tool.category_label in {"FortiAP Tasks", "FortiSwitch Tasks"}
                            and is_active(tool)
                            for tool in fortinet_action_tools
                        ),
                    }
                )
            if fortiauthenticator_home:
                fortinet_children.append(
                    {
                        "label": "FortiAuthenticator",
                        "tool": fortiauthenticator_home,
                        "favorite_enabled": fortiauthenticator_home.id in visible_by_id,
                        "active": is_active(fortiauthenticator_home)
                        or current_endpoint == fortiauthenticator_home.endpoint
                        or any(
                            tool.category_label == "FortiAuthenticator Workflows"
                            and is_active(tool)
                            for tool in fortinet_action_tools
                        ),
                    }
                )
            if fortinet_children:
                sidebar_tool_groups.append(
                    {
                        "label": "Fortinet Tools",
                        "icon": category_icons["fortigate"],
                        "children": fortinet_children,
                        "active": any(child["active"] for child in fortinet_children),
                    }
                )

            network_tools = [tool for tool in visible if tool.category == "network"]
            automation_tools = [tool for tool in visible if tool.category == "automation"]
            local_tools = [tool for tool in visible if tool.category == "local"]
            if automation_tools:
                sidebar_tool_groups.append(
                    {
                        "label": "Automation",
                        "icon": category_icons["automation"],
                        "tools": automation_tools,
                        "active": active_in_tools(automation_tools),
                    }
                )
            if network_tools:
                network_subgroups = []
                grouped_ids = set()
                for subgroup in NAVIGATION_SUBGROUPS.get("network", ()):
                    subgroup_tools = [
                        tool for tool in network_tools if tool.nav_group == subgroup["id"]
                    ]
                    if not subgroup_tools:
                        continue
                    grouped_ids.update(tool.id for tool in subgroup_tools)
                    network_subgroups.append({
                        **subgroup,
                        "tools": subgroup_tools,
                        "active": active_in_tools(subgroup_tools),
                    })
                ungrouped_network_tools = [
                    tool for tool in network_tools if tool.id not in grouped_ids
                ]
                sidebar_tool_groups.append(
                    {
                        "label": "Network Tools",
                        "icon": category_icons["network"],
                        "tools": ungrouped_network_tools,
                        "children": network_subgroups,
                        "count": len(network_tools),
                        "active": active_in_tools(network_tools),
                    }
                )
            if local_tools:
                sidebar_tool_groups.append(
                    {
                        "label": "Local Tools",
                        "icon": category_icons["local"],
                        "tools": local_tools,
                        "active": active_in_tools(local_tools),
                    }
                )

            admin_tools = [tool for tool in visible if tool.category == "administration"]
            if admin_tools:
                sidebar_tool_groups.append(
                    {
                        "label": "Administration",
                        "icon": category_icons["administration"],
                        "tools": admin_tools,
                        "active": active_in_tools(admin_tools),
                    }
                )
        identity = server_settings_store.get()
        page_title = ""
        if current_tool_id and current_tool_id in TOOL_BY_ID:
            page_title = TOOL_BY_ID[current_tool_id].label
        else:
            page_title = {
                "index": "Dashboard",
                "settings": "Settings",
                "help_page": "Help",
                "login": "Sign in",
                "setup": "First launch",
            }.get(request.endpoint or "", "")
        return {
            "current_user": current_user,
            "user_theme": current_user.get("theme", "light") if current_user else "system",
            "favorite_ids": auth_store.favorite_tool_ids(current_user["id"]) if current_user else [],
            "allowed_tool_ids": allowed_tool_ids,
            "nav_category_ids": nav_category_ids,
            "sidebar_favorites": sidebar_favorites,
            "sidebar_tool_groups": sidebar_tool_groups,
            "sidebar_favorites_active": sidebar_favorites_active,
            "current_tool_id": current_tool_id,
            "instance_name": identity["instance_name"],
            "preferred_fqdn": identity["preferred_fqdn"],
            "page_title": page_title,
            "app_version": APP_VERSION,
            "release_notes": RELEASE_NOTES,
            "min_password_length": password_policy["min_length"],
            "password_policy": password_policy,
        }

    def _tool_access_allowed(tool_id: str) -> bool:
        if g.current_user.get("is_admin"):
            return True
        return tool_id in (getattr(g, "allowed_tool_ids", None) or set())

    def _category_allowed(category: str) -> bool:
        if g.current_user.get("is_admin"):
            return True
        allowed_tool_ids = getattr(g, "allowed_tool_ids", None) or set()
        return any(tool.category == category and tool.id in allowed_tool_ids for tool in visible_tools(is_admin=True))

    register_fortigate_routes(
        app,
        profile_store=store,
        category_allowed=_category_allowed,
        tool_access_allowed=_tool_access_allowed,
    )
    register_fortiauthenticator_routes(
        app,
        profile_store=fortiauthenticator_store,
        category_allowed=_category_allowed,
        tool_access_allowed=_tool_access_allowed,
    )
    register_automation_routes(app, automation_store)
    register_datastore_routes(
        app,
        datastore_store,
        tftp_runtime_store,
        tftp_settings_store,
        tftp_history_store,
        ssh_transfer_runtime_store,
        ssh_transfer_settings_store,
        ssh_transfer_history_store,
        ftp_runtime_store,
        ftp_settings_store,
    )

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

    @app.get("/health")
    def health():
        return jsonify({"boot_id": app.config["BOOT_ID"]})

    @app.get("/help")
    def help_page():
        return render_template("help.html")

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

    register_admin_routes(
        app,
        auth_store=auth_store,
        automation_store=automation_store,
        server_settings_store=server_settings_store,
        backup_catalog=backup_catalog,
        start_session=_start_session,
        audit_store=audit_store,
        operational_store=operational_store,
    )

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
            "Delete all saved profiles, credentials, and automation definitions?"
        ):
            click.echo("Reset cancelled.")
            return
        for profile_store in build_reset_stores(app.instance_path):
            profile_store.clear()
        click.echo("The WiFi Ninja's Toolkit local profile data has been reset.")

    @app.get("/")
    def index():
        is_admin = bool(g.current_user.get("is_admin"))
        allowed_tool_ids = getattr(g, "allowed_tool_ids", None)
        favorite_ids = auth_store.favorite_tool_ids(g.current_user["id"])
        visible_category_ids = {
            tool.category
            for tool in visible_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)
        }
        dashboard = activity_store.summary(
            request.args.get("scoreboard_rank", "actions.total"),
            request.args.get("activity_window", "lifetime"),
            request.args.get("activity_start", ""),
            request.args.get("activity_end", ""),
        )
        dashboard["cards"] = dashboard_layout_store.arrange(dashboard["cards"])
        return render_template(
            "home.html",
            favorite_ids=favorite_ids,
            dashboard=dashboard,
            favorites=favorite_tools(
                favorite_ids, is_admin=is_admin, allowed_tool_ids=allowed_tool_ids
            ),
            tool_categories=[
                category for category in TOOL_CATEGORIES if category["id"] in visible_category_ids
            ],
            tool_groups=grouped_visible_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids),
        )

    @app.post("/dashboard/layout")
    def save_dashboard_layout():
        if not g.current_user.get("is_admin"):
            abort(403)
        cards = activity_store.summary()["cards"]
        available_ids = [str(card["metric"]) for card in cards]
        order = [item for item in request.form.get("order", "").split(",") if item]
        hidden = [item for item in request.form.get("hidden", "").split(",") if item]
        dashboard_layout_store.save(order, hidden, available_ids)
        flash("Dashboard layout saved.", "success")
        return redirect(url_for("index"))

    @app.post("/dashboard/layout/reset")
    def reset_dashboard_layout():
        if not g.current_user.get("is_admin"):
            abort(403)
        dashboard_layout_store.reset()
        flash("Dashboard layout restored to its defaults.", "success")
        return redirect(url_for("index"))

    @app.post("/activity/reset/<metric>")
    def reset_activity_metric(metric: str):
        if not g.current_user.get("is_admin"):
            abort(403)
        try:
            activity_store.reset_metric(metric)
        except ValueError:
            abort(404)
        flash("Dashboard counter reset.", "success")
        return redirect(_validated_next_url(request.form.get("next", "")))

    @app.post("/activity/scoreboard/reset")
    def reset_activity_scoreboard():
        if not g.current_user.get("is_admin"):
            abort(403)
        activity_store.reset_all_user_actions()
        flash("All user action scores reset.", "success")
        return redirect(_validated_next_url(request.form.get("next", "")))

    @app.post("/activity/scoreboard/users/<user_id>/reset")
    def reset_activity_user_score(user_id: str):
        if not g.current_user.get("is_admin"):
            abort(403)
        try:
            activity_store.reset_user_actions(user_id)
        except ValueError:
            abort(404)
        flash("User action score reset.", "success")
        return redirect(_validated_next_url(request.form.get("next", "")))

    @app.post("/favorites/tools/<tool_id>")
    def toggle_tool_favorite(tool_id: str):
        tool = TOOL_BY_ID.get(tool_id)
        if not tool:
            abort(404)
        if not tool.grantable:
            abort(404)
        if not _tool_access_allowed(tool_id):
            abort(403)
        auth_store.toggle_favorite_tool(g.current_user["id"], tool_id)
        return redirect(_validated_next_url(request.form.get("next", "")))


    @app.get("/favicon.ico")
    def favicon():
        return app.send_static_file("brand/favicon-32.png")

    return app
