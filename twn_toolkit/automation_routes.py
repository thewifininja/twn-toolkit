from __future__ import annotations

import io
import json
import os
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from .automation import AutomationEngine, AutomationStore
from .automation_registry import AUTOMATION_REGISTRY
from .activity_context import record_current_activity
from .network_tools import ToolInputError


def register_automation_routes(app: Flask, store: AutomationStore) -> None:
    def require_admin() -> None:
        if not g.current_user.get("is_admin"):
            abort(403)

    def render_page(
        *,
        test_result: dict[str, Any] | None = None,
        form_error: str = "",
        form: dict[str, Any] | None = None,
        form_section: str = "",
    ) -> str:
        automations = store.all()
        for automation in automations:
            automation["recent_runs"] = [
                _format_run(run) for run in store.recent_runs(automation["id"], 10)
            ]
            automation["recent_checks"] = [
                _format_check(check) for check in store.recent_checks(automation["id"], 10)
            ]
            automation["last_check_display"] = _format_time(automation["last_check_at"])
            automation["last_triggered_display"] = _format_time(
                automation["last_triggered_at"]
            )
        return render_template(
            "automations/index.html",
            automations=automations,
            condition_definitions=store.condition_definitions(),
            action_definitions=store.action_definitions(),
            condition_types=AUTOMATION_REGISTRY.conditions.values(),
            action_types=AUTOMATION_REGISTRY.actions.values(),
            test_result=test_result,
            form_error=form_error,
            form=form or _empty_form(),
            form_section=form_section,
            scheduler=_scheduler_status(store.instance_path),
        )

    @app.get("/automations")
    def automations():
        require_admin()
        return render_page()

    @app.post("/automations/save")
    def save_automation():
        require_admin()
        form = {key: value for key, value in request.form.items()}
        form["action_definition_ids"] = request.form.getlist("action_definition_id")
        automation_id = request.form.get("automation_id", "").strip()
        try:
            saved_id = store.save(
                automation_id=automation_id,
                name=request.form.get("name", ""),
                interval_seconds=int(request.form.get("interval_seconds", "30")),
                trigger_after=int(request.form.get("trigger_after", "3")),
                recover_after=int(request.form.get("recover_after", "3")),
                cooldown_seconds=int(request.form.get("cooldown_seconds", "300")),
                condition_definition_id=request.form.get("condition_definition_id", ""),
                action_definition_ids=request.form.getlist("action_definition_id"),
                created_by=str(g.current_user["id"]),
            )
        except (ToolInputError, ValueError) as exc:
            return render_page(
                form_error=str(exc), form=form, form_section="automation"
            ), 400
        flash("Automation saved. It remains paused until you arm it.", "success")
        return redirect(url_for("automations", focus=saved_id))

    @app.post("/automations/conditions/save")
    def save_automation_condition():
        require_admin()
        form = {key: value for key, value in request.form.items()}
        try:
            type_id = request.form.get("condition_type", "ping.multi")
            config = AUTOMATION_REGISTRY.validate_condition(
                type_id,
                {
                    "targets": request.form.get("condition_targets", ""),
                    "timeout": request.form.get("condition_timeout", "1"),
                    "failure_mode": request.form.get("condition_failure_mode", "all"),
                    "failure_count": request.form.get("condition_failure_count", "1"),
                },
            )
            definition_id = store.save_condition_definition(
                definition_id=request.form.get("condition_definition_id", ""),
                name=request.form.get("condition_name", ""),
                type_id=type_id,
                config=config,
            )
        except (ToolInputError, ValueError) as exc:
            return render_page(
                form_error=str(exc), form=form, form_section="condition"
            ), 400
        flash(
            "Condition saved. Any automation using an edited condition was paused.",
            "success",
        )
        return redirect(url_for("automations", focus_condition=definition_id))

    @app.post("/automations/actions/save")
    def save_automation_action():
        require_admin()
        form = {key: value for key, value in request.form.items()}
        definition_id = request.form.get("action_definition_id", "")
        password = request.form.get("action_password", "")
        if definition_id and not password:
            existing = store.get_action_definition(definition_id, include_secrets=True)
            if existing:
                password = str(existing["config"].get("password", ""))
        try:
            type_id = request.form.get("action_type", "ssh.collect")
            config = AUTOMATION_REGISTRY.validate_action(
                type_id,
                {
                    "hosts": request.form.get("action_hosts", ""),
                    "username": request.form.get("action_username", ""),
                    "password": password,
                    "commands": request.form.get("action_commands", ""),
                    "port": request.form.get("action_port", "22"),
                    "allow_unknown_hosts": "action_allow_unknown_hosts" in request.form,
                    "send_ctrl_y": "action_send_ctrl_y" in request.form,
                },
            )
            definition_id = store.save_action_definition(
                definition_id=definition_id,
                name=request.form.get("action_name", ""),
                type_id=type_id,
                config=config,
            )
        except (ToolInputError, ValueError) as exc:
            return render_page(
                form_error=str(exc), form=form, form_section="action"
            ), 400
        flash(
            "Action saved. Any automation using an edited action was paused.",
            "success",
        )
        return redirect(url_for("automations", focus_action=definition_id))

    @app.post("/automations/conditions/<definition_id>/test")
    def test_condition_definition(definition_id: str):
        require_admin()
        definition = store.get_condition_definition(definition_id)
        if not definition:
            abort(404)
        try:
            condition = AUTOMATION_REGISTRY.conditions[definition["type"]]
            result = condition.evaluate(definition["config"])
            test_result = {
                "condition_id": definition_id,
                "status": result.status,
                "summary": result.summary,
                "evidence": result.evidence,
            }
        except Exception as exc:
            test_result = {
                "condition_id": definition_id,
                "status": "error",
                "summary": f"{type(exc).__name__}: {exc}",
                "evidence": {},
            }
        return render_page(test_result=test_result)

    @app.post("/automations/conditions/<definition_id>/delete")
    def delete_automation_condition(definition_id: str):
        require_admin()
        try:
            store.delete_condition_definition(definition_id)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("Condition deleted.", "success")
        return redirect(url_for("automations"))

    @app.post("/automations/actions/<definition_id>/delete")
    def delete_automation_action(definition_id: str):
        require_admin()
        try:
            store.delete_action_definition(definition_id)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("Action deleted.", "success")
        return redirect(url_for("automations"))

    @app.post("/automations/<automation_id>/toggle")
    def toggle_automation(automation_id: str):
        require_admin()
        automation = store.get(automation_id)
        if not automation:
            abort(404)
        if automation["condition"]["type"] == "manual.trigger":
            flash("Manual-trigger automations run only with Run now.", "error")
            return redirect(url_for("automations", focus=automation_id))
        store.set_enabled(automation_id, not automation["enabled"])
        flash(
            "Automation armed; its first check is due now."
            if not automation["enabled"]
            else "Automation paused.",
            "success",
        )
        return redirect(url_for("automations", focus=automation_id))

    @app.post("/automations/<automation_id>/run-now")
    def run_automation_now(automation_id: str):
        require_admin()
        automation = store.get(automation_id, include_secrets=True)
        if not automation:
            abort(404)
        if automation["condition"]["type"] != "manual.trigger":
            flash("Run now is available only for Manual trigger automations.", "error")
            return redirect(url_for("automations", focus=automation_id))
        condition = AUTOMATION_REGISTRY.conditions["manual.trigger"]
        trigger = condition.evaluate(automation["condition"]["config"])
        trigger.evidence["started_by"] = str(g.current_user["username"])
        run_id = AutomationEngine(store).execute_actions(automation, trigger)
        record_current_activity(
            "Automation",
            "Ran automation manually",
            automation["name"],
        )
        flash("Manual automation completed. Review or download the collected run.", "success")
        return redirect(url_for("automations", focus=automation_id, focus_run=run_id))

    @app.post("/automations/<automation_id>/test-condition")
    def test_automation_condition(automation_id: str):
        require_admin()
        automation = store.get(automation_id, include_secrets=True)
        if not automation:
            abort(404)
        try:
            result = AutomationEngine(store).test_condition(automation)
            test_result = {
                "automation_id": automation_id,
                "status": result.status,
                "summary": result.summary,
                "evidence": result.evidence,
            }
        except Exception as exc:
            test_result = {
                "automation_id": automation_id,
                "status": "error",
                "summary": f"{type(exc).__name__}: {exc}",
                "evidence": {},
            }
        return render_page(test_result=test_result)

    @app.post("/automations/<automation_id>/delete")
    def delete_automation(automation_id: str):
        require_admin()
        try:
            store.delete(automation_id)
        except ValueError:
            abort(404)
        flash("Automation and its retained history deleted.", "success")
        return redirect(url_for("automations"))

    @app.post("/automations/<automation_id>/runs/clear")
    def clear_automation_runs(automation_id: str):
        require_admin()
        try:
            deleted = store.clear_runs(automation_id)
        except ValueError:
            abort(404)
        flash(
            f"Deleted {deleted} collected action run{'s' if deleted != 1 else ''}.",
            "success",
        )
        return redirect(url_for("automations", focus=automation_id))

    @app.post("/automations/runs/<run_id>/delete")
    def delete_automation_run(run_id: str):
        require_admin()
        run = store.get_run(run_id)
        if not run:
            abort(404)
        store.delete_run(run_id)
        flash("Collected action run deleted.", "success")
        return redirect(url_for("automations", focus=run["automation_id"]))

    @app.get("/automations/runs/<run_id>/download")
    def download_automation_run(run_id: str):
        require_admin()
        run = store.get_run(run_id)
        if not run:
            abort(404)
        output = io.BytesIO()
        file_timestamp = _filename_timestamp(run["started_at"])
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            metadata = {
                "automation": run["automation_name"],
                "started_at": _format_time(run["started_at"]),
                "finished_at": _format_time(run["finished_at"]),
                "status": run["status"],
                "trigger": run["trigger_summary"],
            }
            archive.writestr("summary.json", json.dumps(metadata, indent=2))
            for action_index, result in enumerate(run["results"], 1):
                archive.writestr(
                    f"action-{action_index}-summary.json",
                    json.dumps(
                        {key: value for key, value in result.items() if key != "output"},
                        indent=2,
                    ),
                )
                for host_index, host in enumerate(result.get("output", {}).get("hosts", []), 1):
                    host_name = _safe_filename(str(host.get("host", f"host-{host_index}")))
                    body = str(host.get("output", ""))
                    if host.get("error"):
                        body = f"ERROR: {host['error']}\n\n{body}"
                    archive.writestr(
                        f"action-{action_index}/{file_timestamp}-{host_name}.txt",
                        body or "No output captured.\n",
                    )
        filename = _safe_filename(str(run["automation_name"])) or "automation-run"
        return Response(
            output.getvalue(),
            mimetype="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}-{run_id}.zip"'
            },
        )


def _empty_form() -> dict[str, str]:
    return {
        "interval_seconds": "30",
        "trigger_after": "3",
        "recover_after": "3",
        "cooldown_seconds": "300",
        "condition_timeout": "1",
        "condition_failure_mode": "all",
        "condition_failure_count": "1",
        "action_port": "22",
    }


def _format_time(value: Any) -> str:
    if not value:
        return "Never"
    return datetime.fromtimestamp(float(value)).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def _filename_timestamp(value: Any) -> str:
    """Return a portable, chronologically sortable local timestamp."""
    return datetime.fromtimestamp(float(value)).astimezone().strftime("%Y%m%d%H%M%S")


def _format_run(run: dict[str, Any]) -> dict[str, Any]:
    return {**run, "started_display": _format_time(run["started_at"])}


def _format_check(check: dict[str, Any]) -> dict[str, Any]:
    return {**check, "checked_display": _format_time(check["checked_at"])}


def _scheduler_status(instance_path: Path) -> dict[str, Any]:
    pid_path = instance_path / "twn-automation.pid"
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
    except (OSError, ValueError):
        return {"running": False, "pid": None}
    return {"running": True, "pid": pid}


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")[:100]
