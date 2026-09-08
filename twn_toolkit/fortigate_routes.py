from __future__ import annotations

import csv

from typing import Any, Callable
import secrets
import time

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
from .switch_order import managed_switch_order, switch_order_moves, _switch_order_error_summary, _valid_switch_order
from .preview_binding import issue_bound_preview, valid_bound_preview
from .rename_preview import (
    RENAME_PREVIEW_MAX_AGE_SECONDS, issue_rename_preview, valid_rename_preview, rename_target,
)
from .audit import (
    annotate_audit_event,
    annotate_profile_deleted,
    annotate_profile_duplicated,
    annotate_profile_saved,
    audit_reference,
    suppress_audit_event,
    suppress_case_bridge_event,
)
from .fortigate import FortiGateClient, FortiGateError, normalize_api_key, normalize_host
from .automation_heartbeat import read_automation_heartbeat
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .diagnostic_worker import record_unsuccessful_scan
from .investigations import InvestigationStore
from .wireless_history_diagnostic import TOOL as HISTORY_TOOL, prepare_history_config
from .investigation_context import (
    record_current_investigation_event,
)
from .profiles import ProfileStore
from .tasks import ExportTask, RenameTask, get_task
from .tool_catalog import grouped_visible_tools_for_category, tool_id_for_endpoint


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


def _switch_audit_references(
    switches: list[dict[str, str]],
) -> list[dict[str, str]]:
    return [
        audit_reference("FortiSwitch", switch["id"], switch["name"])
        for switch in switches[:100]
    ]


def _annotate_switch_order(
    profile: dict[str, Any],
    vdom: str,
    *,
    outcome: str,
    current: list[dict[str, str]] | None = None,
    desired_ids: list[str] | None = None,
    planned_moves: int = 0,
    completed_moves: int = 0,
    status_code: int | None = None,
) -> None:
    current = current or []
    desired_ids = desired_ids or []
    by_id = {switch["id"]: switch for switch in current}
    desired = [by_id[identifier] for identifier in desired_ids if identifier in by_id]
    details: dict[str, Any] = {
        "profile": audit_reference("FortiGate profile", profile["name"], profile["name"]),
        "VDOM": vdom,
        "outcome": outcome,
        "switch count": len(desired_ids),
        "planned move count": planned_moves,
        "completed move count": completed_moves,
    }
    if status_code is not None:
        details["remote status code"] = status_code
    before_snapshot = (
        {"switch order": _switch_audit_references(current)}
        if outcome == "succeeded" and current
        else None
    )
    after_snapshot = (
        {"switch order": _switch_audit_references(desired)}
        if outcome == "succeeded" and desired
        else None
    )
    annotate_audit_event(
        category="FortiGate",
        action=f"fortigate.switch_order_{outcome}",
        summary=(
            f"Applied and verified {completed_moves} FortiSwitch order move(s)."
            if outcome == "succeeded"
            else f"FortiSwitch order update {outcome.replace('_', ' ')} after {completed_moves} completed move(s)."
        ),
        resource_type="fortigate_switch_order",
        resource_id=f"{profile['name']}:{vdom}",
        resource_name=f"{profile['name']} · {vdom}",
        details=details,
        before=before_snapshot,
        after=after_snapshot,
    )


def register_fortigate_routes(
    app: Flask,
    *,
    profile_store: ProfileStore,
    category_allowed: Callable[[str], bool],
    tool_access_allowed: Callable[[str], bool],
) -> None:
    from .appliance_read_routes import queue_read, register_read_routes, recent_read_links
    from .switch_order_routes import register_switch_order_jobs, queue_switch_order
    register_switch_order_jobs(app)
    from .rename_routes import register_rename_jobs, queue_rename, bounded_rename_entries, read_rename_csv, recent_rename_links
    from .rename_jobs import target_key
    register_rename_jobs(app)

    def rename_preview_response(task, profile, entries, endpoint, *, start_row=1):
        try:
            bounded_rename_entries(entries, endpoint)
            results = task.run_entries(client=None, entries=entries, dry_run=True,
                                       endpoint_template=endpoint, default_vdom=profile.get('default_vdom', 'root'), start_row=start_row)
        except ValueError as exc:
            flash(str(exc), 'error')
            return redirect(url_for('task_form', task_id=task.id))
        valid_entries = [entry for entry in entries if entry['identifier'] and entry['new_name']]
        revision = diagnostic_store().mutation_revision(target_key(profile))
        suppress_audit_event()
        _record_fortinet_api_activity('Previewed FortiGate rename task',
            f"{profile['name']}: {task.label} ({len(entries)} rows)", api_calls=0, count_action=False)
        return render_template('results.html', entries=valid_entries, profile=profile, task=task,
            results=results, dry_run=True, endpoint_template=endpoint, target_origin=rename_target(profile),
            target_revision=revision, preview_expiry_minutes=RENAME_PREVIEW_MAX_AGE_SECONDS // 60,
            preview_token=issue_rename_preview(task, profile, endpoint, valid_entries, target_revision=revision) if valid_entries else '')
    register_read_routes(app, 'fortigate')
    register_read_routes(app, 'fortigate', task_routes=True)

    @app.get("/fortigate")
    def fortigate_home():
        if not category_allowed("fortigate"):
            return Response("This user does not have access to FortiGate tools.", status=403)
        profiles = profile_store.all()
        edit_profile = profile_store.get(request.args.get("edit", ""))
        return render_template(
            "index.html",
            appliance_recent=recent_read_links('fortigate'),
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
        return render_template("switch_order.html", profiles=profile_store.all(),
                               switch_order_recent=diagnostic_store().recent(g.current_user["id"], "switch_order"))

    @app.route("/fortigate/fortiap/client-history", methods=["GET", "POST"])
    def fortiap_client_history():
        store = diagnostic_store()
        user = g.current_user
        form = {"profile": "", "mac": "", "hours": "24", "vdom": ""}
        job = result = None
        page, total = 1, 0
        if request.method == "POST":
            form = {key: request.form.get(key, default).strip() for key, default in form.items()}
            suppress_audit_event()
            try:
                config = prepare_history_config(profile_store.get(form["profile"]), form)
                case = InvestigationStore(app.instance_path).active_for_user(user["id"])
                config.update(username=user["username"], investigation_id=case["id"] if case and case.get("is_recording") else "")
                job_id = store.enqueue(user_id=user["id"], tool=HISTORY_TOOL, config=config)
                return redirect(url_for("fortiap_client_history", job=job_id), code=303)
            except (ValueError, TypeError) as exc:
                error = str(exc) or "Enter valid wireless history settings."
                flash(error, "error")
                record_current_investigation_event(operation_id="fortigate-wireless-history-rejected:" + secrets.token_hex(12),
                    event_type="diagnostic.failed", tool_id="fortigate.wireless_client_history",
                    action="Wireless client history", outcome="failed", summary="Wireless client history rejected: " + error,
                    targets={"client_mac": form["mac"]}, parameters={"profile": form["profile"], "VDOM": form["vdom"], "hours": form["hours"]},
                    metrics={}, details={"error": error}, started_at=time.time(), completed_at=time.time())
        elif request.args.get("job"):
            job = owned_diagnostic(request.args["job"], HISTORY_TOOL)
            form = job["config"]["form"]
            try:
                page = max(1, min(50, int(request.args.get("page", 1))))
            except ValueError:
                pass
            if job["state"] == "succeeded":
                page = min(page, max(1, (job["summary"]["result"]["transition_count"] + 99) // 100))
                rows, total = store.page(job["id"], user["id"], page)
                result = {**job["summary"]["result"], "timeline": rows, "ap_path": [row["ap"] for row in rows]}
        return render_template("fortiap_client_history.html", profiles=profile_store.all(),
            selected_name=form["profile"], mac=form["mac"], hours=form["hours"], vdom=form["vdom"], result=result,
            journal_event=job["summary"].get("journal_event") if job else None,
            diagnostic_job=job, diagnostic_recent=store.recent(user["id"], HISTORY_TOOL),
            diagnostic_scheduler=read_automation_heartbeat(store.instance / "automation-heartbeat.json"),
            result_page=page, result_total=total)

    @app.get("/fortigate/fortiap/client-history/jobs/<job_id>/status")
    def wireless_history_job_status(job_id):
        job = owned_diagnostic(job_id, HISTORY_TOOL)
        response = jsonify(state=job["state"], error=job["error"])
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/fortigate/fortiap/client-history/jobs/<job_id>/cancel")
    def cancel_wireless_history_job(job_id):
        owned_diagnostic(job_id, HISTORY_TOOL)
        cancelled = diagnostic_store().cancel(job_id, g.current_user["id"])
        if cancelled:
            record_unsuccessful_scan(diagnostic_store(), cancelled, "cancelled", "Cancelled before execution started.")
        return redirect(url_for("fortiap_client_history", job=job_id), code=303)

    @app.post("/fortigate/switch-order/objects")
    def switch_order_objects():
        suppress_audit_event()
        profile = profile_store.get(request.form.get("profile", ""))
        if not profile:
            return jsonify({"error": "Select a valid FortiGate profile."}), 400
        vdom = request.form.get("vdom", "").strip() or profile.get("default_vdom", "root")
        return queue_switch_order(app, profile, vdom=vdom, mode="load")

    @app.post("/fortigate/switch-order/preview")
    def preview_switch_order():
        suppress_audit_event()
        profile = profile_store.get(request.form.get("profile", ""))
        vdom = request.form.get("vdom", "").strip() or (profile or {}).get("default_vdom", "root")
        original = request.form.getlist("original_switch_id")
        desired = request.form.getlist("switch_id")
        context = {"profile": profile, "vdom": vdom, "original_ids": original}
        if request.form.get("target_revision"):
            context["target_revision"] = request.form["target_revision"]
        if not profile or not _valid_switch_order(original, desired) or not valid_bound_preview(
            request.form.get("load_token", ""), "switch-order-load-v1", context,
        ):
            return jsonify({"error": "The loaded order is missing, expired, or belongs to a changed target. Reload the switches."}), 409
        return jsonify({"preview_token": issue_bound_preview(
            "switch-order-apply-v1", {**context, "desired_ids": desired}),
            "moves": switch_order_moves(original, desired)})

    @app.post("/fortigate/switch-order/apply")
    def apply_switch_order():
        profile = profile_store.get(request.form.get("profile", ""))
        desired_ids = request.form.getlist("switch_id")
        if not profile:
            return jsonify({"error": "Select a valid FortiGate profile."}), 400
        if len(desired_ids) < 2:
            return jsonify({"error": "Load and order at least two switches."}), 400

        vdom = request.form.get("vdom", "").strip() or profile.get("default_vdom", "root")
        if request.form.get("confirmed") != "on":
            _annotate_switch_order(
                profile,
                vdom,
                outcome="aborted_confirmation",
                desired_ids=desired_ids,
            )
            return jsonify(
                {
                    "error": (
                        "Review the move preview and confirm that the displayed order "
                        "should be applied."
                    )
                }
            ), 400

        original_ids = request.form.getlist("original_switch_id")
        context = {"profile": profile, "vdom": vdom, "original_ids": original_ids, "desired_ids": desired_ids}
        if request.form.get("target_revision"):
            context["target_revision"] = request.form["target_revision"]
        if not _valid_switch_order(original_ids, desired_ids) or not valid_bound_preview(
            request.form.get("preview_token", ""), "switch-order-apply-v1",
            context,
        ):
            _annotate_switch_order(profile, vdom, outcome="aborted_stale_preview", desired_ids=desired_ids)
            return jsonify({"error": "The confirmed preview is missing, expired, or no longer matches. Reload and review the switches."}), 409

        return queue_switch_order(app, profile, vdom=vdom, mode="apply",
                                  original_ids=original_ids, desired_ids=desired_ids,
                                  target_revision=request.form.get("target_revision", ""),
                                  preview_token=request.form.get("preview_token", ""))

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

        saved_profile = {
            "name": name,
            "host": host,
            "api_key": normalize_api_key(api_key) if api_key else existing_profile["api_key"],
            "verify_tls": verify_tls,
            "is_default": is_default,
            "default_vdom": default_vdom,
        }
        profile_store.upsert(saved_profile)
        annotate_profile_saved(
            category="FortiGate",
            action_namespace="fortigate",
            profile_type="FortiGate profile",
            before=existing_profile,
            after=saved_profile,
            credential_updated=bool(api_key),
        )
        flash(f"Saved profile '{name}'.", "success")
        return redirect(url_for("fortigate_home"))

    @app.post("/profiles/<name>/delete")
    def delete_profile(name: str):
        profile = profile_store.get(name)
        if profile:
            profile_store.delete(name)
            annotate_profile_deleted(
                category="FortiGate",
                action_namespace="fortigate",
                profile_type="FortiGate profile",
                profile=profile,
            )
        flash(f"Deleted profile '{name}'.", "success")
        return redirect(url_for("fortigate_home"))

    @app.post("/profiles/<name>/duplicate")
    def duplicate_profile(name: str):
        source = profile_store.get(name)
        if not source:
            return jsonify({"error": "Profile not found."}), 404
        copied = profile_store.duplicate(name)
        annotate_profile_duplicated(
            category="FortiGate", action_namespace="fortigate",
            profile_type="FortiGate profile", source=source, copied=copied,
        )
        return jsonify({"profile": {"name": copied["name"]}})

    @app.post("/profiles/<name>/test")
    def test_profile(name: str):
        return queue_read(app, profile_store.get(name), provider='fortigate', mode='connection')

    @app.get("/tasks/<task_id>")
    def task_form(task_id: str):
        task = get_task(task_id)
        if not task:
            flash("Task not found.", "error")
            return redirect(url_for("fortigate_home"))
        return render_template("task.html", profiles=profile_store.all(), task=task, appliance_recent=recent_read_links('fortigate', task_id) + recent_rename_links(task_id))

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

        if isinstance(task, RenameTask) and not dry_run:
            return _reject_rename_preview(task, profile)

        if isinstance(task, ExportTask):
            return queue_read(app, profile, provider='fortigate', mode='export', task=task)

        if not isinstance(task, RenameTask):
            flash("Task type is not supported yet.", "error")
            return redirect(url_for("fortigate_home"))

        if not upload or upload.filename == "":
            flash("Choose a CSV file to import.", "error")
            return redirect(url_for("task_form", task_id=task_id))

        try:
            entries = read_rename_csv(upload.stream, profile.get('default_vdom', 'root'))
        except (ValueError, csv.Error) as exc:
            flash(str(exc), 'error')
            return redirect(url_for('task_form', task_id=task_id))
        return rename_preview_response(task, profile, entries,
                                       endpoint_template or task.endpoint_template, start_row=2)

    @app.post("/tasks/<task_id>/objects")
    def task_objects(task_id: str):
        task = get_task(task_id)
        if not isinstance(task, RenameTask):
            return jsonify(error='Invalid task for this read operation.'), 400
        return queue_read(app, profile_store.get(request.form.get('profile', '')),
                          provider='fortigate', mode='objects', task=task, as_json=True)

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

        if not dry_run and request.form.get("confirmed_live") != "on":
            annotate_audit_event(
                category="FortiGate",
                action="fortigate.rename_aborted_confirmation",
                summary=f"Blocked an unconfirmed live {task.label} request.",
                resource_type="fortigate_task",
                resource_id=task.id,
                resource_name=task.label,
                details={
                    "profile": audit_reference(
                        "FortiGate profile", profile["name"], profile["name"]
                    ),
                    "outcome": "aborted confirmation",
                    "requested object count": len(identifiers),
                },
            )
            flash(
                "Run and review the dry-run preview before applying live changes.",
                "error",
            )
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
        if not dry_run and not valid_rename_preview(
            request.form.get("preview_token", ""), task, profile,
            endpoint_template or task.endpoint_template, entries,
            target_revision=request.form.get("target_revision", ""),
        ):
            return _reject_rename_preview(task, profile)

        endpoint = endpoint_template or task.endpoint_template
        try:
            bounded_rename_entries(entries, endpoint)
        except ValueError as exc:
            flash(str(exc), 'error')
            return redirect(url_for('task_form', task_id=task_id))
        if dry_run:
            return rename_preview_response(task, profile, entries, endpoint)
        return queue_rename(app, task, profile, entries, endpoint)

    @app.post("/tasks/<task_id>/fields")
    def task_fields(task_id: str):
        task = get_task(task_id)
        if not isinstance(task, ExportTask):
            return jsonify(error='Invalid task for this read operation.'), 400
        return queue_read(app, profile_store.get(request.form.get('profile', '')),
                          provider='fortigate', mode='fields', task=task, as_json=True)

    @app.post("/tasks/<task_id>/preview")
    def task_preview(task_id: str):
        task = get_task(task_id)
        if not isinstance(task, ExportTask):
            return jsonify(error='Invalid task for this read operation.'), 400
        return queue_read(app, profile_store.get(request.form.get('profile', '')),
                          provider='fortigate', mode='preview', task=task, as_json=True)





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


def _reject_rename_preview(task, profile):
    annotate_audit_event(
        category="FortiGate", action="fortigate.rename_aborted_preview",
        summary=f"Blocked a live {task.label} request without a matching preview.",
        resource_type="fortigate_task", resource_id=task.id, resource_name=task.label,
        details={"profile": audit_reference("FortiGate profile", profile["name"], profile["name"]),
                 "outcome": "aborted invalid or stale preview"},
    )
    flash("Build a new dry-run preview and review it before applying. The previous preview is missing, expired, or no longer matches the target or changes.", "error")
    return redirect(url_for("task_form", task_id=task.id))
