from __future__ import annotations

import os
import base64
import secrets
import time
from hashlib import blake2s
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
from .acme_dns import AcmeDnsManager
from .certificate_automation import CertificateAutomationStore
from .datastore import LocalDatastore, MAX_UPLOAD_BYTES
from .datastore_routes import register_datastore_routes
from .tftp import TFTPHistoryStore, TFTPSettingsStore
from .ssh_transfer_server import SSHTransferHistoryStore, SSHTransferSettingsStore
from .ftp_server import FTPSettingsStore
from .auth import (
    APPEARANCE_PALETTES,
    DEFAULT_APPEARANCE,
    AuthStore,
    load_or_create_secret_key,
)
from .admin_routes import register_admin_routes
from .dashboard_layout import DashboardLayoutStore
from .fortiauthenticator_routes import register_fortiauthenticator_routes
from .fortigate_routes import register_fortigate_routes
from .iperf_server import IperfServerStore
from .investigation_routes import register_investigation_routes
from .investigations import InvestigationStore
from .live_tools import LiveToolStore
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
from .audit import AuditStore, annotate_audit_event
from .migrations import run_toolkit_migrations
from .operational import OperationalSettingsStore
from .remote_sessions import RemoteSessionManager, RemoteSessionStore
from .remote_connections import RemoteConnectionStore
from .distributed_agents import (
    GUI_TUNNEL_CAPABILITY,
    DistributedAgentStore,
    DistributedIdentityStore,
    DistributedSettingsStore,
    agent_supports_capability,
    selectable_gui_agents,
)
from .distributed_pki import DistributedPkiStore, PairingSessionStore
from .distributed_job_epochs import DistributedJobStore


def _asset_tree_revision(static_folder: str | os.PathLike[str]) -> str:
    """Return a cheap, deterministic revision for browser-served assets."""
    root = Path(static_folder)
    digest = blake2s(digest_size=8)
    try:
        paths = sorted(path for path in root.rglob("*") if path.is_file())
    except OSError:
        paths = []
    for path in paths:
        try:
            stat = path.stat()
            relative = path.relative_to(root).as_posix()
        except OSError:
            continue
        digest.update(relative.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
        digest.update(b":")
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _appearance_from_delegation(value: dict[str, Any]) -> dict[str, str]:
    appearance = dict(DEFAULT_APPEARANCE)
    for key in appearance:
        if key in value:
            appearance[key] = str(value[key])
    if appearance["palette"] not in APPEARANCE_PALETTES:
        return dict(DEFAULT_APPEARANCE)
    return appearance


def create_app(instance_path: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    app.config.from_mapping(
        BOOT_ID=secrets.token_hex(12),
        ASSET_REVISION_CHECK_INTERVAL_SECONDS=1.0,
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
    certificate_automation_store = CertificateAutomationStore(
        app.instance_path, app.config["SECRET_KEY"]
    )
    acme_dns_manager = AcmeDnsManager(app.instance_path)
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
    distributed_settings_store = DistributedSettingsStore(app.instance_path)
    distributed_identity_store = DistributedIdentityStore(app.instance_path)
    distributed_agent_store = DistributedAgentStore(app.instance_path)
    distributed_pki_store = DistributedPkiStore(app.instance_path)
    distributed_pairing_store = PairingSessionStore(app.instance_path)
    distributed_job_store = DistributedJobStore(app.instance_path)
    app.extensions["distributed_settings_store"] = distributed_settings_store
    app.extensions["distributed_identity_store"] = distributed_identity_store
    app.extensions["distributed_agent_store"] = distributed_agent_store
    app.extensions["distributed_pki_store"] = distributed_pki_store
    app.extensions["distributed_pairing_store"] = distributed_pairing_store
    app.extensions["distributed_job_store"] = distributed_job_store
    store = ProfileStore(app.instance_path)
    fortiauthenticator_store = FortiAuthenticatorProfileStore(app.instance_path)
    backup_catalog = build_backup_catalog(app.instance_path)
    audit_store = AuditStore(app.instance_path)
    operational_store = OperationalSettingsStore(app.instance_path)
    investigation_store = InvestigationStore(app.instance_path)
    app.extensions["investigation_store"] = investigation_store
    remote_connection_store = RemoteConnectionStore(
        app.instance_path, app.config["SECRET_KEY"]
    )
    app.extensions["remote_connection_store"] = remote_connection_store
    remote_session_store = RemoteSessionStore(app.instance_path)
    remote_session_manager = RemoteSessionManager(
        remote_session_store,
        investigation_store,
        logger=app.logger,
    )
    app.extensions["remote_session_manager"] = remote_session_manager
    asset_revision_state: dict[str, Any] = {
        "checked_at": 0.0,
        "revision": "",
    }

    def current_asset_version() -> str:
        now = time.monotonic()
        interval = float(
            app.config.get("ASSET_REVISION_CHECK_INTERVAL_SECONDS", 1.0)
        )
        if (
            not asset_revision_state["revision"]
            or now - float(asset_revision_state["checked_at"]) >= interval
        ):
            asset_revision_state["revision"] = _asset_tree_revision(app.static_folder)
            asset_revision_state["checked_at"] = now
        return (
            f"{APP_VERSION}-{app.config['BOOT_ID']}-"
            f"{asset_revision_state['revision']}"
        )

    @app.before_request
    def require_authentication():
        delegated_user = request.environ.get("twn.delegated_user")
        if app.config.get("DISTRIBUTED_AGENT_DISPATCH") and isinstance(
            delegated_user, dict
        ):
            g.current_user = delegated_user
            g.allowed_tool_ids = None
            return None
        if _is_cross_origin_mutation():
            return Response(
                "Cross-origin state-changing requests are not allowed.",
                status=403,
                mimetype="text/plain",
            )
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

    @app.before_request
    def enforce_agent_workspace_boundary():
        user = getattr(g, "current_user", None)
        if not user or distributed_settings_store.get()["role"] != "mainframe":
            return None
        agent_id = auth_store.execution_context(user["id"])
        if agent_id == "local":
            return None
        endpoint = request.endpoint or ""
        allowed = {
            "static",
            "favicon",
            "health",
            "logout",
            "update_appearance",
            "update_execution_context",
            "agent_workspace",
            "agent_dns_response",
            "refresh_agent_workspace_identity",
            "run_distributed_system_identity",
            "agent_ui",
        }
        if endpoint in allowed:
            return None
        agent = distributed_agent_store.get(agent_id)
        if not agent or agent["state"] != "approved":
            auth_store.set_execution_context(user["id"], "local")
            flash("The selected agent is no longer approved. Returned to this instance.", "error")
            return redirect(url_for("index"))
        if request.method == "GET" and request.accept_mimetypes.accept_html:
            return redirect(f"/agents/{agent_id}/ui{request.full_path.rstrip('?')}")
        return Response(
            "This operation is not remote-enabled for the selected agent.",
            status=409,
            mimetype="text/plain",
        )

    @app.route("/agents/<agent_id>/ui/", defaults={"remote_path": ""}, methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
    @app.route("/agents/<agent_id>/ui/<path:remote_path>", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
    def agent_ui(agent_id: str, remote_path: str):
        def return_to_local_instance(message: str):
            if request.method not in {"GET", "HEAD"} or not request.accept_mimetypes.accept_html:
                return None
            auth_store.set_execution_context(g.current_user["id"], "local")
            flash(f"{message} Returned to this instance.", "error")
            destination = "/" + remote_path
            if request.query_string:
                destination += "?" + request.query_string.decode("latin-1")
            return redirect(destination)

        if distributed_settings_store.get()["role"] != "mainframe":
            abort(404)
        if not g.current_user.get("is_admin"):
            return Response("Administrator access is required.", status=403)
        if auth_store.execution_context(g.current_user["id"]) != agent_id:
            return Response("Select this agent before accessing it.", status=409)
        agent = distributed_agent_store.get(agent_id)
        if not agent or agent["state"] != "approved":
            recovery = return_to_local_instance("The selected agent is no longer approved.")
            return recovery if recovery is not None else abort(404)
        if not agent["online"]:
            recovery = return_to_local_instance("The selected agent is offline.")
            return recovery if recovery is not None else Response("The selected agent is offline.", status=503)
        if not agent_supports_capability(agent, *GUI_TUNNEL_CAPABILITY):
            recovery = return_to_local_instance("The selected agent does not support GUI access.")
            return recovery if recovery is not None else Response("The selected agent does not support GUI access.", status=503)
        if remote_path.startswith("static/"):
            return app.send_static_file(remote_path[len("static/"):])
        body = request.get_data(cache=False)
        if len(body) > 192 * 1024:
            return Response("This request is too large for the agent tunnel.", status=413)
        path = "/" + remote_path
        if request.query_string:
            path += "?" + request.query_string.decode("latin-1")
        job = distributed_job_store.enqueue(
            agent_id=agent_id, requester_id=g.current_user["id"],
            capability_id="system.http.tunnel", capability_version="1",
            inputs={
                "method": request.method, "path": path,
                "prefix": f"/agents/{agent_id}/ui",
                "headers": {name: value for name, value in request.headers.items() if name.lower() in {"accept", "content-type", "range"}},
                "body": base64.b64encode(body).decode("ascii"),
                "user": {"id": g.current_user["id"], "username": g.current_user.get("username", ""), "is_admin": bool(g.current_user.get("is_admin"))},
                "fabric": {
                    "context_id": agent_id,
                    "context_url": url_for("update_execution_context"),
                    "logout_url": url_for("logout"),
                    "appearance_url": url_for("update_appearance"),
                    "appearance": auth_store.user_appearance(
                        g.current_user["id"], agent_id
                    ),
                    "local_name": server_settings_store.get()["instance_name"],
                    "agents": [
                        {"id": item["id"], "name": item["name"], "online": item["online"]}
                        for item in selectable_gui_agents(
                            distributed_agent_store.list("approved")
                        )
                    ],
                },
            },
        )
        # First use may initialize the agent application and its local stores;
        # subsequent requests reuse the warm per-user dispatcher.
        deadline = time.monotonic() + 30
        current = None
        while time.monotonic() < deadline:
            current = distributed_job_store.get(job["id"])
            if current and current["state"] in {"succeeded", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        else:
            recovery = return_to_local_instance("The selected agent did not respond in time.")
            return recovery if recovery is not None else Response("The selected agent did not respond in time.", status=504)
        distributed_job_store.delete(job["id"], requester_id=g.current_user["id"])
        if current["state"] != "succeeded" or not current.get("output"):
            message = current.get("error") or "The agent request failed."
            recovery = return_to_local_instance(message)
            return recovery if recovery is not None else Response(message, status=502)
        output = current["output"]
        try:
            content = base64.b64decode(str(output.get("body", "")), validate=True)
            status = int(output.get("status", 502))
        except (ValueError, TypeError):
            recovery = return_to_local_instance("The agent returned an invalid response.")
            return recovery if recovery is not None else Response("The agent returned an invalid response.", status=502)
        if (
            status == 404
            and request.method == "GET"
            and remote_path
            and request.accept_mimetypes.accept_html
        ):
            flash("That page is not available on the selected instance.", "warning")
            return redirect(url_for("agent_ui", agent_id=agent_id))
        response = Response(content, status=status)
        for pair in output.get("headers", []):
            if isinstance(pair, list) and len(pair) == 2:
                response.headers[str(pair[0])] = str(pair[1])
        response.headers["X-TWN-Instance"] = agent_id
        return response

    @app.after_request
    def audit_administrative_mutations(response: Response):
        user = getattr(g, "current_user", None)
        audited_reads = {
            "bulk_download_datastore_files",
            "download_investigation_evidence",
            "download_automation_artifact",
            "download_automation_run",
            "download_datastore_file",
            "tools.download_acme_dns_certificate",
            "tools.download_managed_certificate",
            "view_datastore_file_as_text",
            "view_datastore_pcap",
        }
        should_audit = request.method in {"POST", "PUT", "PATCH", "DELETE"} or (request.endpoint or "") in audited_reads
        context = getattr(g, "audit_event", {})
        if (
            should_audit
            and not getattr(g, "audit_suppressed", False)
            and user
            and context
        ):
            try:
                endpoint = request.endpoint or ""
                summary = str(context.get("summary", "")).strip() or endpoint.replace("_", " ").capitalize()
                profile_ids = {
                    str(item)
                    for item in user.get("access_profile_ids", [])
                    if isinstance(item, str)
                }
                profile_names = [
                    profile["name"]
                    for profile in auth_store.access_profiles()
                    if profile["id"] in profile_ids
                ]
                details = {
                    **context.get("details", {}),
                    "actor role": (
                        "System administrator"
                        if user.get("is_admin")
                        else "Operator"
                    ),
                    "actor access profiles": profile_names,
                }
                audit_store.record(
                    user_id=user.get("id", ""), username=user.get("username", ""),
                    remote_ip=request.remote_addr or "", method=request.method,
                    endpoint=endpoint, path=request.path,
                    status_code=response.status_code,
                    category=context.get("category", "Administration"),
                    action=context.get("action", endpoint), summary=summary,
                    resource_type=context.get("resource_type", ""),
                    resource_id=context.get("resource_id", ""),
                    resource_name=context.get("resource_name", ""),
                    details=details,
                )
            except Exception:
                app.logger.exception("Toolkit audit event could not be recorded")
        return response

    @app.after_request
    def apply_security_headers(response: Response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        if (request.endpoint or "") not in {"static", "favicon"}:
            response.headers.setdefault("Cache-Control", "no-store")
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
            investigation_tools = [
                tool for tool in visible if tool.category == "investigations"
            ]
            automation_tools = [tool for tool in visible if tool.category == "automation"]
            local_tools = [tool for tool in visible if tool.category == "local"]
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
            operations_children = []
            if investigation_tools:
                investigation_tool = investigation_tools[0]
                operations_children.append(
                    {
                        "label": "Investigations",
                        "tool": investigation_tool,
                        "direct": True,
                        "favorite_enabled": investigation_tool.grantable,
                        "active": active_in_tools(investigation_tools),
                    }
                )
            if local_tools:
                operations_children.append(
                    {
                        "label": "Local Tools",
                        "icon": category_icons["local"],
                        "tools": local_tools,
                        "active": active_in_tools(local_tools),
                    }
                )
            if automation_tools:
                operations_children.append(
                    {
                        "label": "Automation",
                        "icon": category_icons["automation"],
                        "tools": automation_tools,
                        "active": active_in_tools(automation_tools),
                    }
                )
            if operations_children:
                sidebar_tool_groups.append(
                    {
                        "label": "Operations",
                        "icon": "◇",
                        "children": operations_children,
                        "count": sum(
                            len(child.get("tools", ()))
                            + (1 if child.get("tool") else 0)
                            for child in operations_children
                        ),
                        "active": any(child["active"] for child in operations_children),
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
        distributed_settings = distributed_settings_store.get()
        delegated_fabric = request.environ.get("twn.delegated_fabric")
        execution_agents = (
            list(delegated_fabric.get("agents", []))
            if isinstance(delegated_fabric, dict)
            else
            selectable_gui_agents(distributed_agent_store.list("approved"))
            if distributed_settings["role"] == "mainframe" and current_user
            else []
        )
        execution_context_id = (
            str(delegated_fabric.get("context_id", "local"))
            if isinstance(delegated_fabric, dict)
            else
            auth_store.execution_context(current_user["id"])
            if current_user and distributed_settings["role"] == "mainframe"
            else "local"
        )
        selected_execution_agent = next(
            (agent for agent in execution_agents if agent["id"] == execution_context_id),
            None,
        )
        if isinstance(delegated_fabric, dict):
            # The remote app should render its complete native navigation. The
            # selected ID remains in the top-bar selector, but does not trigger
            # the Mainframe's transitional remote-only sidebar.
            selected_execution_agent = None
        page_title = ""
        if current_tool_id and current_tool_id in TOOL_BY_ID:
            page_title = TOOL_BY_ID[current_tool_id].label
        else:
            page_title = {
                "index": "Dashboard",
                "investigations": "Investigations",
                "settings": "Settings",
                "help_page": "Help",
                "login": "Sign in",
                "setup": "First launch",
            }.get(request.endpoint or "", "")
        investigation_access = bool(
            current_user
            and (
                current_user.get("is_admin")
                or allowed_tool_ids is None
                or "investigations.workspace" in allowed_tool_ids
            )
        )
        active_investigation = None
        if investigation_access:
            try:
                active_investigation = investigation_store.active_for_user(
                    str(current_user.get("id", ""))
                )
            except Exception:
                app.logger.exception(
                    "Active investigation context could not be loaded"
                )
        delegated_appearance = (
            delegated_fabric.get("appearance")
            if isinstance(delegated_fabric, dict)
            else None
        )
        appearance = (
            _appearance_from_delegation(delegated_appearance)
            if isinstance(delegated_appearance, dict)
            else auth_store.user_appearance(current_user["id"], execution_context_id)
            if current_user
            else dict(DEFAULT_APPEARANCE)
        )
        color_mode = APPEARANCE_PALETTES[appearance["palette"]]
        return {
            "current_user": current_user,
            "user_theme": color_mode,
            "user_appearance": appearance,
            "user_palette": appearance["palette"],
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
            "asset_version": current_asset_version(),
            "release_notes": RELEASE_NOTES,
            "min_password_length": password_policy["min_length"],
            "password_policy": password_policy,
            "investigation_access": investigation_access,
            "active_investigation": active_investigation,
            "execution_context_enabled": bool(
                current_user
                and current_user.get("is_admin")
                and (
                    distributed_settings["role"] == "mainframe"
                    or isinstance(delegated_fabric, dict)
                )
            ),
            "execution_context_url": (
                str(delegated_fabric.get("context_url", "/execution-context"))
                if isinstance(delegated_fabric, dict)
                else url_for("update_execution_context")
            ),
            "execution_local_name": (
                str(delegated_fabric.get("local_name", "Mainframe"))
                if isinstance(delegated_fabric, dict)
                else identity["instance_name"]
            ),
            "logout_url": (
                str(delegated_fabric.get("logout_url", "/logout"))
                if isinstance(delegated_fabric, dict)
                else url_for("logout")
            ),
            "appearance_url": (
                str(delegated_fabric.get("appearance_url", "/settings/appearance"))
                if isinstance(delegated_fabric, dict)
                else url_for("update_appearance")
            ),
            "execution_context_id": execution_context_id,
            "execution_agents": execution_agents,
            "selected_execution_agent": selected_execution_agent,
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
    register_investigation_routes(app, investigation_store)
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

    def _record_authentication_event(
        *,
        action: str,
        summary: str,
        outcome: str,
        username: str,
        user: dict[str, Any] | None = None,
        status_code: int,
    ) -> None:
        """Record public authentication routes that run without ``g.current_user``."""
        try:
            audit_store.record(
                user_id=(user or {}).get("id", ""),
                username=username,
                remote_ip=request.remote_addr or "",
                method=request.method,
                endpoint=request.endpoint or "",
                path=request.path,
                status_code=status_code,
                category="Authentication",
                action=action,
                summary=summary,
                resource_type="user",
                resource_id=(user or {}).get("id", ""),
                resource_name=username,
                details={
                    "outcome": outcome,
                    "actor role": (
                        "System administrator"
                        if (user or {}).get("is_admin")
                        else "Unauthenticated"
                    ),
                },
            )
        except Exception:
            app.logger.exception("Toolkit authentication audit event could not be recorded")

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if auth_store.is_configured():
            return redirect(url_for("login"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if password != request.form.get("confirm_password", ""):
                _record_authentication_event(
                    action="authentication.setup_failed",
                    summary="Initial administrator setup failed.",
                    outcome="failed",
                    username=username,
                    status_code=200,
                )
                flash("Passwords do not match.", "error")
            else:
                try:
                    user = auth_store.create_initial_admin(username, password)
                except ValueError as exc:
                    _record_authentication_event(
                        action="authentication.setup_failed",
                        summary="Initial administrator setup failed.",
                        outcome="failed",
                        username=username,
                        status_code=200,
                    )
                    flash(str(exc), "error")
                else:
                    _record_authentication_event(
                        action="authentication.setup_succeeded",
                        summary="Created the initial administrator account.",
                        outcome="succeeded",
                        username=user["username"],
                        user=user,
                        status_code=302,
                    )
                    _start_session(user)
                    flash("Administrator account created.", "success")
                    return redirect(url_for("index"))
        return render_template("auth/setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_store.is_configured():
            return redirect(url_for("setup"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            user = auth_store.authenticate(
                username,
                request.form.get("password", ""),
            )
            if user:
                _record_authentication_event(
                    action="authentication.login_succeeded",
                    summary="User signed in.",
                    outcome="succeeded",
                    username=user["username"],
                    user=user,
                    status_code=302,
                )
                _start_session(user)
                return redirect(_validated_next_url(request.form.get("next", "")))
            _record_authentication_event(
                action="authentication.login_failed",
                summary="Sign-in attempt failed.",
                outcome="failed",
                username=username,
                status_code=200,
            )
            flash("Invalid username or password.", "error")
        return render_template("auth/login.html", next_url=_safe_next_url())

    @app.post("/logout")
    def logout():
        user_id = session.get("user_id")
        user = next(
            (item for item in auth_store.users() if item["id"] == user_id),
            None,
        )
        _record_authentication_event(
            action="authentication.logout_succeeded",
            summary="User signed out.",
            outcome="succeeded",
            username=(user or {}).get("username", ""),
            user=user,
            status_code=302,
        )
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
        distributed_settings_store=distributed_settings_store,
        distributed_identity_store=distributed_identity_store,
        distributed_agent_store=distributed_agent_store,
        distributed_pki_store=distributed_pki_store,
        distributed_pairing_store=distributed_pairing_store,
        distributed_job_store=distributed_job_store,
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
        remote_connection_store.clear()
        certificate_automation_store.clear()
        acme_dns_manager.clear()
        click.echo("TWN Toolkit local profile data has been reset.")

    @app.get("/")
    def index():
        is_admin = bool(g.current_user.get("is_admin"))
        allowed_tool_ids = getattr(g, "allowed_tool_ids", None)
        favorite_ids = auth_store.favorite_tool_ids(g.current_user["id"])
        visible = visible_tools(
            is_admin=is_admin, allowed_tool_ids=allowed_tool_ids
        )
        visible_by_id = {tool.id: tool for tool in visible}
        visible_category_ids = {tool.category for tool in visible}
        favorites = favorite_tools(
            favorite_ids, is_admin=is_admin, allowed_tool_ids=allowed_tool_ids
        )
        suggested_tools = [
            visible_by_id[tool_id]
            for tool_id in (
                "tools.ping",
                "tools.dns_response",
                "tools.multi_ssh",
                "tools.packet_capture",
            )
            if tool_id in visible_by_id
        ]
        quick_tools = favorites[:4] or suggested_tools[:4]

        dashboard = activity_store.summary(
            request.args.get("scoreboard_rank", "actions.total"),
            request.args.get("activity_window", "lifetime"),
            request.args.get("activity_start", ""),
            request.args.get("activity_end", ""),
        )
        dashboard["cards"] = dashboard_layout_store.arrange(dashboard["cards"])
        visible_cards = [
            card for card in dashboard["cards"] if not card["dashboard_hidden"]
        ]
        dashboard["snapshot_cards"] = visible_cards[:4]

        live_sessions = LiveToolStore(app.instance_path).sessions_for_user(
            g.current_user["id"], renew_lease=False
        )
        if (
            is_admin
            or allowed_tool_ids is None
            or "tools.remote_terminal" in allowed_tool_ids
        ):
            live_sessions.extend(
                remote_session_manager.sessions_for_user(g.current_user["id"])
            )
        if is_admin or (
            allowed_tool_ids is not None
            and "tools.iperf3" in allowed_tool_ids
        ):
            active_iperf = IperfServerStore(
                app.instance_path
            ).active_for_user(g.current_user["id"])
            if active_iperf:
                live_sessions.append(
                    {
                        "state": (
                            "error"
                            if active_iperf["status"] == "error"
                            else "running"
                        )
                    }
                )
        live_errors = sum(
            1 for live_session in live_sessions if live_session["state"] == "error"
        )
        automation_stats = {
            "queued_jobs": 0,
            "waiting_jobs": 0,
            "running_jobs": 0,
            "failed_jobs": 0,
            "enabled": 0,
            "attention": 0,
        }
        if is_admin:
            automation_stats.update(automation_store.job_stats())
            automations = automation_store.all()
            automation_stats["enabled"] = sum(
                1 for automation in automations if automation["enabled"]
            )
            automation_stats["attention"] = sum(
                1
                for automation in automations
                if automation["state"]
                in {"error", "recovering", "suspect", "triggered"}
            )
        workspace_status = {
            "live_count": len(live_sessions),
            "live_errors": live_errors,
            "automation": automation_stats,
            "attention_count": (
                live_errors
                + automation_stats["failed_jobs"]
                + automation_stats["attention"]
            ),
        }
        enabled_user_count = sum(
            1 for user in auth_store.users() if user.get("enabled", True)
        )
        show_team_activity = (
            enabled_user_count > 1 or len(dashboard["scoreboard"]) > 1
        )

        return render_template(
            "home.html",
            favorite_ids=favorite_ids,
            dashboard=dashboard,
            favorites=favorites,
            quick_tools=quick_tools,
            quick_tools_are_suggestions=not favorites,
            workspace_status=workspace_status,
            show_team_activity=show_team_activity,
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
        before = dashboard_layout_store.get(available_ids)
        after = dashboard_layout_store.save(order, hidden, available_ids)
        annotate_audit_event(
            category="Administration", action="dashboard.layout_updated",
            summary="Updated the shared dashboard layout.",
            resource_type="dashboard", resource_id="layout",
            resource_name="Dashboard layout", before=before, after=after,
        )
        flash("Dashboard layout saved.", "success")
        return redirect(url_for("index"))

    @app.post("/dashboard/layout/reset")
    def reset_dashboard_layout():
        if not g.current_user.get("is_admin"):
            abort(403)
        dashboard_layout_store.reset()
        annotate_audit_event(
            category="Administration", action="dashboard.layout_reset",
            summary="Reset the shared dashboard layout.",
            resource_type="dashboard", resource_id="layout",
            resource_name="Dashboard layout",
        )
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
        annotate_audit_event(
            category="Administration", action="dashboard.metric_reset",
            summary="Reset a dashboard metric.", resource_type="dashboard_metric",
            resource_id=metric, resource_name=metric,
        )
        flash("Dashboard counter reset.", "success")
        return redirect(_validated_next_url(request.form.get("next", "")))

    @app.post("/activity/scoreboard/reset")
    def reset_activity_scoreboard():
        if not g.current_user.get("is_admin"):
            abort(403)
        activity_store.reset_all_user_actions()
        annotate_audit_event(
            category="Administration", action="scoreboard.all_scores_reset",
            summary="Reset every operator action score.",
            resource_type="scoreboard", resource_id="all-users",
            resource_name="All operator scores",
        )
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
        target = next(
            (user for user in auth_store.users() if user["id"] == user_id), None
        )
        annotate_audit_event(
            category="Administration", action="scoreboard.user_score_reset",
            summary="Reset an operator action score.", resource_type="user",
            resource_id=user_id,
            resource_name=(target or {}).get("username", user_id),
        )
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

    @app.post("/execution-context")
    def update_execution_context():
        settings = distributed_settings_store.get()
        if settings["role"] != "mainframe":
            return Response("Execution contexts require Mainframe mode.", status=409)
        context_id = str(request.form.get("context_id", "local"))
        selected_agent = None
        if context_id != "local":
            selected_agent = distributed_agent_store.get(context_id)
            if not selected_agent or selected_agent["state"] != "approved":
                flash("Select an approved agent.", "error")
                return redirect(_validated_next_url(request.form.get("next", "")))
            if not selected_agent["online"]:
                flash("That agent is offline and cannot be selected.", "error")
                return redirect(_validated_next_url(request.form.get("next", "")))
            if not agent_supports_capability(
                selected_agent, *GUI_TUNNEL_CAPABILITY
            ):
                flash("That agent does not support GUI access.", "error")
                return redirect(_validated_next_url(request.form.get("next", "")))
        before = auth_store.execution_context(g.current_user["id"])
        auth_store.set_execution_context(g.current_user["id"], context_id)
        annotate_audit_event(
            category="Mainframe",
            action="distributed.execution_context_changed",
            summary=(
                f"Changed execution context to {selected_agent['name']}."
                if selected_agent
                else "Changed execution context to this instance."
            ),
            resource_type="execution context",
            resource_id=context_id,
            resource_name=selected_agent["name"] if selected_agent else "This instance",
            before={"context": before},
            after={"context": context_id},
        )
        next_url = _validated_next_url(request.form.get("next", ""))
        if before != "local":
            prefix = f"/agents/{before}/ui"
            if next_url == prefix:
                next_url = "/"
            elif next_url.startswith(prefix + "/"):
                next_url = next_url[len(prefix):]
        if not next_url.startswith("/"):
            next_url = "/"
        if selected_agent:
            destination = f"/agents/{selected_agent['id']}/ui"
            return redirect(destination + (next_url if next_url != "/" else "/"))
        return redirect(next_url)

    @app.post("/favorites/order")
    def reorder_tool_favorites():
        current_ids = auth_store.favorite_tool_ids(g.current_user["id"])
        visible_ids = [
            tool.id
            for tool in favorite_tools(
                current_ids,
                is_admin=bool(g.current_user.get("is_admin")),
                allowed_tool_ids=getattr(g, "allowed_tool_ids", None),
            )
        ]
        ordered_ids = [
            tool_id.strip()
            for tool_id in request.form.get("order", "").split(",")
            if tool_id.strip()
        ]
        if len(ordered_ids) != len(set(ordered_ids)):
            abort(400)
        if set(ordered_ids) != set(visible_ids):
            abort(400)
        auth_store.reorder_favorite_tools(g.current_user["id"], ordered_ids)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return "", 204
        return redirect(_validated_next_url(request.form.get("next", "")))


    @app.get("/favicon.ico")
    def favicon():
        return Response(status=204)

    return app


def _is_cross_origin_mutation() -> bool:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    fetch_site = request.headers.get("Sec-Fetch-Site", "").lower()
    if fetch_site == "cross-site":
        return True
    if fetch_site == "same-origin":
        return False
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if not source:
        return False
    try:
        return _origin(source) != _origin(request.host_url)
    except ValueError:
        return True


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    if scheme not in {"http", "https"} or not hostname:
        raise ValueError("Invalid web origin")
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, hostname, port
