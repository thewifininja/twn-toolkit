from __future__ import annotations

from datetime import datetime
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
from .fortigate import FortiGateClient, FortiGateError, normalize_api_key, normalize_host
from .fortiap_history import (
    LocalFortiGateWirelessHistorySource,
    normalize_client_mac,
    wireless_client_history,
)
from .profiles import ProfileStore
from .tasks import ExportTask, RenameTask, discover_export_fields, get_task
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


def register_fortigate_routes(
    app: Flask,
    *,
    profile_store: ProfileStore,
    category_allowed: Callable[[str], bool],
    tool_access_allowed: Callable[[str], bool],
) -> None:
    @app.get("/fortigate")
    def fortigate_home():
        if not category_allowed("fortigate"):
            return Response("This user does not have access to FortiGate tools.", status=403)
        profiles = profile_store.all()
        edit_profile = profile_store.get(request.args.get("edit", ""))
        return render_template(
            "index.html",
            edit_profile=edit_profile,
            profiles=profiles,
            can_manage_profiles=tool_access_allowed("fortigate.home"),
            tool_groups=grouped_visible_tools_for_category(
                "fortigate",
                is_admin=bool(g.current_user.get("is_admin")),
                allowed_tool_ids=getattr(g, "allowed_tool_ids", None),
            ),
        )

    @app.get("/fortigate/switch-order")
    def switch_order():
        return render_template("switch_order.html", profiles=profile_store.all())

    @app.route("/fortigate/fortiap/client-history", methods=["GET", "POST"])
    def fortiap_client_history():
        profiles = profile_store.all()
        selected_name = request.form.get("profile", "") if request.method == "POST" else ""
        mac = request.form.get("mac", "").strip() if request.method == "POST" else ""
        hours_value = request.form.get("hours", "24") if request.method == "POST" else "24"
        vdom = request.form.get("vdom", "").strip() if request.method == "POST" else ""
        result: dict[str, Any] | None = None

        if request.method == "POST":
            profile = profile_store.get(selected_name)
            if not profile:
                flash("Select a valid FortiGate profile.", "error")
            else:
                try:
                    normalized_mac = normalize_client_mac(mac)
                    hours = int(hours_value)
                    if not 1 <= hours <= 168:
                        raise ValueError("Choose a time window from 1 hour to 7 days.")
                    vdom = vdom or profile.get("default_vdom", "root")
                    result = wireless_client_history(
                        LocalFortiGateWirelessHistorySource(FortiGateClient.from_profile(profile)),
                        normalized_mac,
                        vdom,
                        hours,
                    )
                    _record_fortinet_api_activity(
                        "Loaded wireless client history",
                        f"{normalized_mac} via {selected_name} ({hours}h)",
                    )
                except ValueError as exc:
                    flash(str(exc), "error")

        return render_template(
            "fortiap_client_history.html",
            profiles=profiles,
            selected_name=selected_name,
            mac=mac,
            hours=hours_value,
            vdom=vdom,
            result=result,
        )

    @app.post("/fortigate/switch-order/objects")
    def switch_order_objects():
        profile = profile_store.get(request.form.get("profile", ""))
        if not profile:
            return jsonify({"error": "Select a valid FortiGate profile."}), 400
        vdom = request.form.get("vdom", "").strip() or profile.get("default_vdom", "root")
        try:
            switches = managed_switch_order(
                FortiGateClient.from_profile(profile).get_managed_switches(vdom)
            )
        except FortiGateError as exc:
            _record_fortinet_api_activity(
                "Loaded FortiSwitch order",
                f"{profile['name']}: failed",
                failures=1,
                count_action=False,
            )
            return jsonify({"error": str(exc)}), 502
        _record_fortinet_api_activity(
            "Loaded FortiSwitch order",
            f"{profile['name']}: {len(switches)} switches",
            count_action=False,
        )
        return jsonify({"switches": switches, "row_count": len(switches), "vdom": vdom})

    @app.post("/fortigate/switch-order/apply")
    def apply_switch_order():
        profile = profile_store.get(request.form.get("profile", ""))
        desired_ids = list(dict.fromkeys(request.form.getlist("switch_id")))
        if not profile:
            return jsonify({"error": "Select a valid FortiGate profile."}), 400
        if len(desired_ids) < 2:
            return jsonify({"error": "Load and order at least two switches."}), 400

        vdom = request.form.get("vdom", "").strip() or profile.get("default_vdom", "root")
        client = FortiGateClient.from_profile(profile)
        try:
            current = managed_switch_order(client.get_managed_switches(vdom))
        except FortiGateError as exc:
            _record_fortinet_api_activity(
                "Applied FortiSwitch order",
                f"{profile['name']}: initial load failed",
                failures=1,
            )
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

        moves = switch_order_moves(current_ids, desired_ids)
        completed: list[dict[str, str]] = []
        try:
            for move in moves:
                client.move_managed_switch_after(move["switch_id"], move["after"], vdom)
                completed.append(move)
            verified = managed_switch_order(client.get_managed_switches(vdom))
        except FortiGateError as exc:
            _record_fortinet_api_activity(
                "Applied FortiSwitch order",
                f"{profile['name']}: {len(completed)} of {len(moves)} moves completed",
                api_calls=2 + len(completed),
                failures=1,
            )
            progress = (
                "No switch moves were applied."
                if not completed
                else f"{len(completed)} switch move(s) completed before the error; reload to inspect the current order."
            )
            return jsonify(
                {
                    "error": str(exc),
                    "completed_moves": completed,
                    "detail": str(exc),
                    "message": (
                        f"FortiGate rejected the reorder after {len(completed)} "
                        "successful move(s). Reload to inspect its current order."
                    ),
                    "user_message": _switch_order_error_summary(exc, progress),
                }
            ), 502

        verified_ids = [item["id"] for item in verified]
        if verified_ids != desired_ids:
            _record_fortinet_api_activity(
                "Applied FortiSwitch order",
                f"{profile['name']}: verification mismatch after {len(completed)} moves",
                api_calls=2 + len(completed),
                failures=1,
            )
            return jsonify(
                {
                    "error": "FortiGate accepted the moves but the verified order does not match.",
                    "completed_moves": completed,
                    "switches": verified,
                }
            ), 409
        _record_fortinet_api_activity(
            "Applied FortiSwitch order",
            f"{profile['name']}: {len(completed)} moves verified",
            api_calls=2 + len(completed),
        )
        return jsonify(
            {
                "message": (
                    f"Verified the new order of {len(verified)} "
                    f"{'FortiSwitch' if len(verified) == 1 else 'FortiSwitches'}."
                ),
                "moves": completed,
                "switches": verified,
            }
        )

    @app.post("/profiles")
    def save_profile():
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        host = request.form.get("host", "").strip()
        api_key = request.form.get("api_key", "").strip()
        verify_tls = request.form.get("verify_tls") == "on"
        is_default = request.form.get("is_default") == "on"
        default_vdom = request.form.get("default_vdom", "root").strip() or "root"
        existing_profile = profile_store.get(original_name) if original_name else None

        if not name or not host or (not api_key and not existing_profile):
            flash("Profile name, FortiGate URL, and API key are required.", "error")
            return redirect(url_for("fortigate_home"))

        try:
            host = normalize_host(host)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("fortigate_home"))

        if existing_profile and original_name != name:
            profile_store.delete(original_name)

        profile_store.upsert(
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
        profile_store.delete(name)
        flash(f"Deleted profile '{name}'.", "success")
        return redirect(url_for("fortigate_home"))

    @app.post("/profiles/<name>/test")
    def test_profile(name: str):
        profile = profile_store.get(name)
        if not profile:
            flash("Profile not found.", "error")
            return redirect(url_for("fortigate_home"))

        client = FortiGateClient.from_profile(profile)
        try:
            result = client.test_connection()
        except FortiGateError as exc:
            _record_fortinet_api_activity(
                "Tested FortiGate profile",
                f"{name}: connection failed",
                failures=1,
            )
            flash(f"Connection failed: {connection_error_message(exc)}", "error")
        else:
            version = result.get("version") or result.get("build") or "reachable"
            _record_fortinet_api_activity(
                "Tested FortiGate profile",
                f"{name}: {version}",
            )
            flash(f"Connection OK: {version}", "success")

        return redirect(url_for("fortigate_home"))

    @app.get("/tasks/<task_id>")
    def task_form(task_id: str):
        task = get_task(task_id)
        if not task:
            flash("Task not found.", "error")
            return redirect(url_for("fortigate_home"))
        return render_template("task.html", profiles=profile_store.all(), task=task)

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
        profile = profile_store.get(request.form.get("profile", ""))
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
                _record_fortinet_api_activity(
                    "Ran FortiGate export",
                    f"{profile['name']}: {task.label} failed",
                    failures=1,
                )
                flash(f"Export failed: {exc}", "error")
                return redirect(url_for("task_form", task_id=task_id))

            _record_fortinet_api_activity(
                "Ran FortiGate export",
                f"{profile['name']}: {task.label}",
            )
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
        _record_fortinet_api_activity(
            "Ran FortiGate rename task",
            f"{profile['name']}: {task.label} ({len(entries)} row{'s' if len(entries) != 1 else ''})",
            api_calls=max(1, len(entries)),
            failures=sum(1 for result in results if result.status == "error"),
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
        profile = profile_store.get(request.form.get("profile", ""))
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
            _record_fortinet_api_activity(
                "Discovered FortiGate objects",
                f"{profile['name']}: {task.label} failed",
                failures=1,
                count_action=False,
            )
            return jsonify({"error": str(exc)}), 502

        _record_fortinet_api_activity(
            "Discovered FortiGate objects",
            f"{profile['name']}: {task.label} ({len(objects)} objects)",
            count_action=False,
        )
        return jsonify({"objects": objects, "row_count": len(objects)})

    @app.post("/tasks/<task_id>/rename")
    def rename_objects(task_id: str):
        task = get_task(task_id)
        profile = profile_store.get(request.form.get("profile", ""))
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
        _record_fortinet_api_activity(
            "Ran FortiGate rename task",
            f"{profile['name']}: {task.label} ({len(entries)} row{'s' if len(entries) != 1 else ''})",
            api_calls=max(1, len(entries)),
            failures=sum(1 for result in results if result.status == "error"),
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
        profile = profile_store.get(request.form.get("profile", ""))
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
            _record_fortinet_api_activity(
                "Loaded FortiGate export fields",
                f"{profile['name']}: {task.label} failed",
                failures=1,
                count_action=False,
            )
            return jsonify({"error": str(exc)}), 502

        _record_fortinet_api_activity(
            "Loaded FortiGate export fields",
            f"{profile['name']}: {task.label} ({len(rows)} rows)",
            count_action=False,
        )
        fields = discover_export_fields(task, rows)
        return jsonify({"endpoint_used": endpoint_used, "fields": fields, "row_count": len(rows)})

    @app.post("/tasks/<task_id>/preview")
    def task_preview(task_id: str):
        task = get_task(task_id)
        profile = profile_store.get(request.form.get("profile", ""))
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
            _record_fortinet_api_activity(
                "Previewed FortiGate export",
                f"{profile['name']}: {task.label} failed",
                failures=1,
                count_action=False,
            )
            return jsonify({"error": str(exc)}), 502

        _record_fortinet_api_activity(
            "Previewed FortiGate export",
            f"{profile['name']}: {task.label} ({len(rows)} rows)",
            count_action=False,
        )
        columns, formatted_rows = task.format_rows(rows, selected_fields)
        return jsonify(
            {
                "columns": columns,
                "endpoint_used": endpoint_used,
                "row_count": len(formatted_rows),
                "rows": formatted_rows,
            }
        )


def managed_switch_order(items: list[dict[str, Any]]) -> list[dict[str, str]]:
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


def switch_order_moves(
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


def _switch_order_error_summary(exc: FortiGateError, progress: str) -> str:
    if exc.status_code == 403:
        return (
            "FortiGate did not allow the reorder. Confirm the selected API profile has read-write access "
            f"to managed FortiSwitches. {progress}"
        )
    if exc.status_code == 401:
        return (
            "FortiGate rejected the API token while applying the reorder. Confirm the token, trusted hosts, "
            f"and API administrator status. {progress}"
        )
    return f"FortiGate rejected the reorder before it could be verified. {progress}"


def connection_error_message(exc: FortiGateError) -> str:
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
