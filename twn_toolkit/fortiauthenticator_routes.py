from __future__ import annotations

import re
import secrets
import time
from typing import Any, Callable

from flask import (
    Flask,
    Response,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from .mso_ui import save_profile as save_mso_profile, delete_profile as delete_mso_profile
from .mso import MsoConflict
from .activity_context import record_current_activity
from .audit import (
    annotate_audit_event,
    annotate_profile_deleted,
    annotate_profile_duplicated,
    annotate_profile_saved,
    audit_reference,
    suppress_audit_event,
)
from .fortiauthenticator import (
    FortiAuthenticatorClient,
    FortiAuthenticatorError,
    normalize_host as normalize_fortiauthenticator_host,
)
from .profiles import FortiAuthenticatorProfileStore
from .preview_binding import issue_bound_preview, valid_bound_preview, PREVIEW_MAX_AGE_SECONDS
from .tool_catalog import grouped_visible_tools_for_category


def _record_fortinet_api_activity(
    title: str,
    detail: str = "",
    *,
    api_calls: int = 1,
    failures: int = 0,
    count_action: bool = True,
) -> None:
    record_current_activity(
        "Fortinet",
        title,
        detail,
        counters={"fortinet": {"api_calls": api_calls, "failures": failures}},
        count_action=count_action,
    )


def _annotate_mac_cleanup(
    profile: dict[str, Any],
    group_uri: str,
    operation: str,
    *,
    outcome: str,
    requested_count: int,
    target_count: int = 0,
    success_count: int = 0,
    failure_count: int = 0,
    group_name: str = "",
    status_code: int | None = None,
) -> None:
    operation_name = (
        "Remove group memberships"
        if operation == "remove_memberships"
        else "Delete MAC devices globally"
    )
    details: dict[str, Any] = {
        "profile": audit_reference(
            "FortiAuthenticator profile", profile["name"], profile["name"]
        ),
        "operation": operation_name,
        "outcome": outcome,
        "requested target count": requested_count,
        "validated target count": target_count,
        "successful target count": success_count,
        "failed target count": failure_count,
    }
    if status_code is not None:
        details["remote status code"] = status_code
    annotate_audit_event(
        category="FortiAuthenticator",
        action=f"fortiauthenticator.mac_cleanup_{outcome}",
        summary=(
            f"{operation_name}: {success_count} of {target_count} target(s) succeeded."
            if outcome in {"succeeded", "partial", "failed"} and target_count
            else f"{operation_name} {outcome.replace('_', ' ')}."
        ),
        resource_type="fortiauthenticator_mac_group",
        resource_id=group_uri,
        resource_name=group_name or group_uri or "MAC group",
        details=details,
    )


def register_fortiauthenticator_routes(
    app: Flask,
    *,
    profile_store: FortiAuthenticatorProfileStore,
    category_allowed: Callable[[str], bool],
    tool_access_allowed: Callable[[str], bool],
) -> None:
    from .appliance_read_routes import queue_read, register_read_routes, recent_read_links
    register_read_routes(app, 'fortiauthenticator')

    @app.get("/fortiauthenticator")
    def fortiauthenticator_home():
        if not category_allowed("fortiauthenticator"):
            return Response("This user does not have access to FortiAuthenticator tools.", status=403)
        profiles = profile_store.all()
        edit_profile = profile_store.get(request.args.get("edit", ""))
        return render_template(
            "fortiauthenticator/index.html",
            appliance_recent=recent_read_links('fortiauthenticator'),
            edit_profile=edit_profile,
            profiles=profiles,
            can_manage_profiles=tool_access_allowed("fortiauthenticator.home"),
            tool_groups=grouped_visible_tools_for_category(
                "fortiauthenticator",
                is_admin=bool(g.current_user.get("is_admin")),
                allowed_tool_ids=getattr(g, "allowed_tool_ids", None),
            ),
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
        existing_profile = profile_store.get(original_name) if original_name else None

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

        saved_profile = {
            "name": name,
            "host": host,
            "username": username,
            "password": password if password else existing_profile["password"],
            "verify_tls": verify_tls,
            "timeout": timeout,
            "is_default": is_default,
        }
        try:
            save_mso_profile(profile_store, saved_profile, original_name)
        except (MsoConflict, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("fortiauthenticator_home"))
        annotate_profile_saved(
            category="FortiAuthenticator",
            action_namespace="fortiauthenticator",
            profile_type="FortiAuthenticator profile",
            before=existing_profile,
            after=saved_profile,
            credential_updated=bool(password),
        )
        flash(f"Saved FortiAuthenticator profile '{name}'.", "success")
        return redirect(url_for("fortiauthenticator_home"))

    @app.post("/fortiauthenticator/profiles/<name>/delete")
    def delete_fortiauthenticator_profile(name: str):
        profile = profile_store.get(name)
        if profile:
            try:
                delete_mso_profile(profile_store, name)
            except (MsoConflict, ValueError) as exc:
                flash(str(exc), "error")
                return redirect(url_for("fortiauthenticator_home"))
            annotate_profile_deleted(
                category="FortiAuthenticator",
                action_namespace="fortiauthenticator",
                profile_type="FortiAuthenticator profile",
                profile=profile,
            )
        flash(f"Deleted FortiAuthenticator profile '{name}'.", "success")
        return redirect(url_for("fortiauthenticator_home"))

    @app.post("/fortiauthenticator/profiles/<name>/duplicate")
    def duplicate_fortiauthenticator_profile(name: str):
        source = profile_store.get(name)
        if not source:
            return jsonify({"error": "Profile not found."}), 404
        copied = profile_store.duplicate(name)
        annotate_profile_duplicated(
            category="FortiAuthenticator", action_namespace="fortiauthenticator",
            profile_type="FortiAuthenticator profile", source=source, copied=copied,
        )
        return jsonify({"profile": {"name": copied["name"]}})

    @app.post("/fortiauthenticator/profiles/<name>/test")
    def test_fortiauthenticator_profile(name: str):
        return queue_read(app, profile_store.get(name), provider='fortiauthenticator', mode='connection')

    from .fac_inventory_routes import register_fac_inventory_routes
    register_fac_inventory_routes(app, profile_store)

    from .fac_cleanup_routes import register_cleanup_jobs, queue_cleanup, recent_cleanup_links
    from .diagnostic_routes import diagnostic_store
    register_cleanup_jobs(app, profile_store)

    @app.route('/fortiauthenticator/mac-cleanup', methods=['GET', 'POST'])
    def fortiauthenticator_mac_cleanup():
        if request.method == 'POST':
            mode = 'preview' if request.form.get('intent') == 'preview' else 'groups'
            return queue_cleanup(app, profile_store.get(request.form.get('profile', '')), mode)
        return render_template('fortiauthenticator/mac_cleanup.html', profiles=profile_store.all(),
            groups=[], preview=None, selected_name='', selected_group_uri='', selected_action='remove_memberships',
            preview_minutes=PREVIEW_MAX_AGE_SECONDS//60, appliance_recent=recent_cleanup_links())

    @app.post('/fortiauthenticator/mac-cleanup/execute')
    def execute_fortiauthenticator_mac_cleanup():
        reviewed = diagnostic_store().get(request.form.get('preview_job', ''), g.current_user['id'])
        return queue_cleanup(app, profile_store.get(request.form.get('profile', '')), 'apply', reviewed=reviewed)


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


def _cleanup_preview_context(profile, group_uri, action, target_revision=""):
    return {"profile": profile, "group_uri": group_uri, "action": action,
            **({"target_revision": target_revision} if target_revision else {})}


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
                # Bind membership identities as well as display labels: two groups
                # may have the same name, and global deletion affects both.
                "membership_bindings": sorted(
                    [str(item.get(key) or "") for key in ("id", "resource_uri", "group", "group_name")]
                    for item in memberships_by_device.get(device_id, [])
                ),
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
