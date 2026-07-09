from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from typing import Any, Callable

from flask import (
    Flask,
    Response,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from .fortiauthenticator import (
    FortiAuthenticatorClient,
    FortiAuthenticatorError,
    normalize_host as normalize_fortiauthenticator_host,
)
from .profiles import FortiAuthenticatorProfileStore
from .tool_catalog import grouped_visible_tools_for_category


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

        profile_store.upsert(
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
        profile_store.delete(name)
        flash(f"Deleted FortiAuthenticator profile '{name}'.", "success")
        return redirect(url_for("fortiauthenticator_home"))

    @app.post("/fortiauthenticator/profiles/<name>/test")
    def test_fortiauthenticator_profile(name: str):
        profile = profile_store.get(name)
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
        profiles = profile_store.all()
        selected_name = request.form.get("profile", "") if request.method == "POST" else ""
        rows: list[dict[str, Any]] | None = None
        total_count = 0
        preview_limit = 500

        if request.method == "POST":
            profile = profile_store.get(selected_name)
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
        profile = profile_store.get(request.form.get("profile", ""))
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
        safe_profile_name = _safe_filename_profile_name(profile["name"])
        filename = f"mac-devices-{safe_profile_name}-{stamp}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.route("/fortiauthenticator/mac-group-memberships", methods=["GET", "POST"])
    def fortiauthenticator_mac_group_memberships():
        profiles = profile_store.all()
        selected_name = request.form.get("profile", "") if request.method == "POST" else ""
        rows: list[dict[str, Any]] | None = None
        total_count = 0
        preview_limit = 500

        if request.method == "POST":
            profile = profile_store.get(selected_name)
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
        profile = profile_store.get(request.form.get("profile", ""))
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
        safe_profile_name = _safe_filename_profile_name(profile["name"])
        filename = f"mac-group-memberships-{safe_profile_name}-{stamp}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.route("/fortiauthenticator/mac-cleanup", methods=["GET", "POST"])
    def fortiauthenticator_mac_cleanup():
        profiles = profile_store.all()
        selected_name = request.form.get("profile", "") if request.method == "POST" else ""
        selected_group_uri = request.form.get("group_uri", "") if request.method == "POST" else ""
        selected_action = request.form.get("action", "remove_memberships")
        groups: list[dict[str, Any]] = []
        preview: dict[str, Any] | None = None

        if request.method == "POST":
            profile = profile_store.get(selected_name)
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


def _format_mac_device(item: dict[str, Any]) -> dict[str, Any]:
    resource_uri = str(item.get("resource_uri") or "")
    return {
        "ID": _resource_id(resource_uri) or item.get("id", ""),
        "MAC Address": item.get("address", ""),
        "Name": item.get("name", ""),
        "Description": item.get("description", ""),
        "Resource URI": resource_uri,
    }


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


def _safe_filename_profile_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "profile"
