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

from .activity_context import record_current_activity
from .audit import (
    annotate_audit_event,
    annotate_profile_deleted,
    annotate_profile_duplicated,
    annotate_profile_saved,
    annotate_profile_tested,
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
    @app.get("/fortiauthenticator")
    def fortiauthenticator_home():
        if not category_allowed("fortiauthenticator"):
            return Response("This user does not have access to FortiAuthenticator tools.", status=403)
        profiles = profile_store.all()
        edit_profile = profile_store.get(request.args.get("edit", ""))
        return render_template(
            "fortiauthenticator/index.html",
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

        if existing_profile and original_name != name:
            profile_store.delete(original_name)

        saved_profile = {
            "name": name,
            "host": host,
            "username": username,
            "password": password if password else existing_profile["password"],
            "verify_tls": verify_tls,
            "timeout": timeout,
            "is_default": is_default,
        }
        profile_store.upsert(saved_profile)
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
            profile_store.delete(name)
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
        profile = profile_store.get(name)
        if not profile:
            flash("FortiAuthenticator profile not found.", "error")
            return redirect(url_for("fortiauthenticator_home"))

        try:
            result = FortiAuthenticatorClient.from_profile(profile).test_connection()
        except FortiAuthenticatorError as exc:
            _record_fortinet_api_activity(
                "Tested FortiAuthenticator profile",
                f"{name}: connection failed",
                failures=1,
            )
            annotate_profile_tested(
                category="FortiAuthenticator",
                action_namespace="fortiauthenticator",
                profile_type="FortiAuthenticator profile",
                profile=profile,
                outcome="failed",
                status_code=exc.status_code,
            )
            flash(f"Connection failed: {exc}", "error")
        else:
            total = result.get("meta", {}).get("total_count")
            suffix = f" ({total} MAC devices available)." if total is not None else "."
            detail = f"{name}: reachable"
            if total is not None:
                detail = f"{name}: {total} MAC devices available"
            _record_fortinet_api_activity("Tested FortiAuthenticator profile", detail)
            annotate_profile_tested(
                category="FortiAuthenticator",
                action_namespace="fortiauthenticator",
                profile_type="FortiAuthenticator profile",
                profile=profile,
                outcome="succeeded",
            )
            flash(f"Connection to '{name}' succeeded{suffix}", "success")
        return redirect(url_for("fortiauthenticator_home"))

    from .fac_inventory_routes import register_fac_inventory_routes
    register_fac_inventory_routes(app, profile_store)

    @app.route("/fortiauthenticator/mac-cleanup", methods=["GET", "POST"])
    def fortiauthenticator_mac_cleanup():
        profiles = profile_store.all()
        selected_name = request.form.get("profile", "") if request.method == "POST" else ""
        selected_group_uri = request.form.get("group_uri", "") if request.method == "POST" else ""
        selected_action = request.form.get("action", "remove_memberships")
        groups: list[dict[str, Any]] = []
        preview: dict[str, Any] | None = None

        if request.method == "POST":
            suppress_audit_event()
            profile = profile_store.get(selected_name)
            if not profile:
                flash("Select a valid FortiAuthenticator profile.", "error")
            else:
                client = FortiAuthenticatorClient.from_profile(profile)
                try:
                    memberships = client.get_all_mac_group_memberships()
                    groups = _mac_groups(memberships)
                    api_calls = 1
                    if request.form.get("intent") == "preview":
                        if selected_action not in {"remove_memberships", "delete_devices"}:
                            raise FortiAuthenticatorError("Select a valid cleanup action.")
                        if selected_group_uri not in {group["uri"] for group in groups}:
                            raise FortiAuthenticatorError("Select a valid MAC group.")
                        devices = client.get_all_mac_devices()
                        api_calls += 1
                        preview = _build_mac_cleanup_preview(
                            memberships,
                            devices,
                            selected_group_uri,
                            selected_action,
                        )
                        context = _cleanup_preview_context(profile, selected_group_uri, selected_action)
                        preview["context_token"] = issue_bound_preview("mac-cleanup-context-v1", context)
                        preview["candidate_token"] = issue_bound_preview(
                            "mac-cleanup-candidates-v1", {**context, "targets": preview["targets"],
                                                         "group_name": preview["group_name"]},
                        )
                except FortiAuthenticatorError as exc:
                    _record_fortinet_api_activity(
                        "Previewed FortiAuthenticator MAC cleanup",
                        f"{selected_name}: failed",
                        failures=1,
                        count_action=False,
                    )
                    flash(f"Cleanup preview failed: {exc}", "error")
                else:
                    _record_fortinet_api_activity(
                        "Previewed FortiAuthenticator MAC cleanup",
                        f"{selected_name}: {len(groups)} groups",
                        api_calls=api_calls,
                        count_action=False,
                    )

        return render_template(
            "fortiauthenticator/mac_cleanup.html",
            profiles=profiles,
            groups=groups,
            selected_name=selected_name,
            selected_group_uri=selected_group_uri,
            selected_action=selected_action,
            preview=preview,
            preview_limit=500,
            preview_minutes=PREVIEW_MAX_AGE_SECONDS // 60,
        )

    @app.post("/fortiauthenticator/mac-cleanup/execute")
    def execute_fortiauthenticator_mac_cleanup():
        profile = profile_store.get(request.form.get("profile", ""))
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

        context = _cleanup_preview_context(profile, group_uri, action)
        if not valid_bound_preview(request.form.get("context_token", ""), "mac-cleanup-context-v1", context):
            _annotate_mac_cleanup(profile, group_uri, action, outcome="aborted_stale_preview",
                                  requested_count=len(requested_ids))
            flash("Cleanup preview expired or its target changed. Nothing was changed; build a new preview.", "error")
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        client = FortiAuthenticatorClient.from_profile(profile)
        try:
            memberships = client.get_all_mac_group_memberships()
            if group_uri not in {group["uri"] for group in _mac_groups(memberships)}:
                raise FortiAuthenticatorError("The selected MAC group is no longer available.")
            devices = client.get_all_mac_devices()
            preview = _build_mac_cleanup_preview(memberships, devices, group_uri, action)
        except FortiAuthenticatorError as exc:
            _record_fortinet_api_activity(
                "Ran FortiAuthenticator MAC cleanup",
                f"{profile['name']}: validation failed",
                api_calls=2,
                failures=1,
            )
            _annotate_mac_cleanup(
                profile,
                group_uri,
                action,
                outcome="validation_failed",
                requested_count=len(requested_ids),
                status_code=exc.status_code,
            )
            flash(f"Cleanup validation failed: {exc}", "error")
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        if not valid_bound_preview(
            request.form.get("candidate_token", ""), "mac-cleanup-candidates-v1",
            {**context, "targets": preview["targets"], "group_name": preview["group_name"]},
        ):
            _annotate_mac_cleanup(profile, group_uri, action, outcome="aborted_stale_preview",
                                  requested_count=len(requested_ids), group_name=preview["group_name"])
            flash("Cleanup candidates changed or the preview expired. Nothing was changed; build a new preview.", "error")
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        if not preview["targets"]:
            _annotate_mac_cleanup(
                profile,
                group_uri,
                action,
                outcome="aborted_no_targets",
                requested_count=len(requested_ids),
                group_name=preview["group_name"],
            )
            flash("No matching records remain. Nothing was changed.", "error")
            return redirect(url_for("fortiauthenticator_mac_cleanup"))
        if not requested_ids:
            _annotate_mac_cleanup(
                profile,
                group_uri,
                action,
                outcome="aborted_no_selection",
                requested_count=0,
                group_name=preview["group_name"],
            )
            flash("Select at least one device. Nothing was changed.", "error")
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        id_key = "membership_id" if action == "remove_memberships" else "device_id"
        targets_by_id = {target[id_key]: target for target in preview["targets"]}
        stale_ids = [identifier for identifier in requested_ids if identifier not in targets_by_id]
        if stale_ids:
            _annotate_mac_cleanup(
                profile,
                group_uri,
                action,
                outcome="aborted_stale_preview",
                requested_count=len(requested_ids),
                target_count=len(targets_by_id),
                group_name=preview["group_name"],
            )
            flash(
                "The selected targets changed after the preview. Nothing was changed; build a new preview.",
                "error",
            )
            return redirect(url_for("fortiauthenticator_mac_cleanup"))

        targets = [targets_by_id[identifier] for identifier in requested_ids]
        expected_confirmation = _cleanup_confirmation(action, len(targets))
        if confirmation != expected_confirmation:
            _annotate_mac_cleanup(
                profile,
                group_uri,
                action,
                outcome="aborted_confirmation",
                requested_count=len(requested_ids),
                target_count=len(targets),
                group_name=preview["group_name"],
            )
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

        failures = sum(1 for result in results if result["status"] == "error")
        _record_fortinet_api_activity(
            "Ran FortiAuthenticator MAC cleanup",
            f"{profile['name']}: {len(targets) - failures} of {len(targets)} succeeded",
            api_calls=2 + len(targets),
            failures=failures,
        )
        success_count = len(targets) - failures
        outcome = (
            "succeeded"
            if not failures
            else "partial"
            if success_count
            else "failed"
        )
        _annotate_mac_cleanup(
            profile,
            group_uri,
            action,
            outcome=outcome,
            requested_count=len(requested_ids),
            target_count=len(targets),
            success_count=success_count,
            failure_count=failures,
            group_name=preview["group_name"],
        )
        return render_template(
            "fortiauthenticator/mac_cleanup_results.html",
            action=action,
            group_name=preview["group_name"],
            profile=profile,
            results=results,
        )


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


def _cleanup_preview_context(profile, group_uri, action):
    return {"profile": profile, "group_uri": group_uri, "action": action}


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
