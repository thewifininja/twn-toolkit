from __future__ import annotations

import io
import json
import os
import re
import time
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

from .automation import (
    STAGE_CONTINUATION_LABELS,
    AutomationEngine,
    AutomationStore,
)
from .automation_registry import AUTOMATION_REGISTRY
from .audit import annotate_audit_event
from .activity_context import record_current_activity
from .datastore import LocalDatastore
from .duplication import duplicate_name
from .investigation_context import add_current_investigation_generated_evidence_event
from .network_tools import (
    SSH_EXECUTION_BATCH_SIZE,
    SSH_EXECUTION_WORKERS,
    SSH_TARGET_LIMIT,
    ToolInputError,
    ping_engine_capability,
)
from .packet_capture import capture_interfaces
from .schedule_tools import describe_schedule_rule, schedule_preview
from .profiles import SNMPHostProfileStore, SNMPOidProfileStore
from .snmp_tools import parse_oid_profile
from .ssh_commandlets import SSHCommandletStore, ssh_hosts_to_matrix
from .system_identity import collect_system_identity
from .time_settings import TimeSettingsStore


def _automation_audit_snapshot(automation: dict[str, Any] | None) -> dict[str, Any]:
    if not automation:
        return {}
    return {
        "name": automation.get("name", ""),
        "enabled": bool(automation.get("enabled")),
        "check interval seconds": automation.get("interval_seconds"),
        "trigger after": automation.get("trigger_after"),
        "recover after": automation.get("recover_after"),
        "cooldown seconds": automation.get("cooldown_seconds"),
        "condition operator": automation.get("condition_operator", "all"),
        "conditions": [
            condition.get("name", "")
            for condition in automation.get("conditions", [])
        ] or [(automation.get("condition") or {}).get("name", "")],
        "action stages": [
            {
                "name": stage.get("name", ""),
                "continue policy": stage.get("continue_policy", ""),
                "delay seconds": stage.get("delay_seconds", 0),
                "actions": [action.get("name", "") for action in stage.get("actions", [])],
            }
            for stage in automation.get("action_stages", [])
        ],
    }


def _definition_audit_snapshot(definition: dict[str, Any] | None) -> dict[str, Any]:
    if not definition:
        return {}
    return {
        "name": definition.get("name", ""),
        "type": definition.get("type", ""),
        "configuration": definition.get("config", {}),
    }


def register_automation_routes(app: Flask, store: AutomationStore) -> None:
    def require_admin() -> None:
        if not g.current_user.get("is_admin"):
            abort(403)

    def _annotate_duplicate(
        resource_type: str,
        source: dict[str, Any],
        copied: dict[str, Any] | None,
    ) -> None:
        if not copied:
            return
        annotate_audit_event(
            category="Automation",
            action=f"{resource_type}.duplicated",
            summary=(
                f"Duplicated {resource_type} {source['name']} as {copied['name']}."
            ),
            resource_type=resource_type,
            resource_id=str(copied["id"]),
            resource_name=str(copied["name"]),
            details={f"source {resource_type} id": str(source["id"])},
            after=_definition_audit_snapshot(copied),
        )

    def render_page(
        *,
        page_section: str = "automations",
        test_result: dict[str, Any] | None = None,
        form_error: str = "",
        form: dict[str, Any] | None = None,
        form_section: str = "",
    ) -> Response:
        page_started = time.perf_counter()
        workspace_started = time.perf_counter()
        workspace = store.workspace_snapshot(recent_limit=10)
        workspace_duration = (time.perf_counter() - workspace_started) * 1000
        context_started = time.perf_counter()
        automations = workspace["automations"]
        for automation in automations:
            for stage in automation["action_stages"]:
                stage["delay_display"] = _format_duration(
                    int(stage.get("delay_seconds", 0))
                )
                stage["continue_label"] = STAGE_CONTINUATION_LABELS.get(
                    str(stage.get("continue_policy", "")), "Unknown route"
                )
            automation["run_mode"] = (
                "manual"
                if automation["condition"]["type"] == "manual.trigger"
                else "startup"
                if automation["condition"]["type"] == "system.startup"
                else "schedule"
                if automation["condition"]["type"] == "schedule.calendar"
                else "condition"
            )
            automation["stage_form"] = [
                {
                    "id": stage["id"],
                    "name": stage["name"],
                    "continue_policy": stage["continue_policy"],
                    "delay_seconds": stage["delay_seconds"],
                    "action_definition_ids": stage["action_definition_ids"],
                }
                for stage in automation["action_stages"]
            ]
            automation["recent_runs"] = [
                _format_run(run)
                for run in workspace["recent_runs"].get(automation["id"], [])
            ]
            automation["recent_checks"] = [
                _format_check(check)
                for check in workspace["recent_checks"].get(automation["id"], [])
            ]
            automation["last_check_display"] = _format_time(automation["last_check_at"])
            automation["last_triggered_display"] = _format_time(
                automation["last_triggered_at"]
            )
            automation["next_check_display"] = _format_time(
                automation.get("pending_schedule_at") or automation["next_check_at"]
            )
        condition_definitions = [
            definition
            for definition in workspace["source_definitions"]
            if definition["type"] not in AUTOMATION_REGISTRY.triggers
        ]
        schedule_definitions = [
            definition
            for definition in workspace["source_definitions"]
            if definition["type"] == "schedule.calendar"
        ]
        for definition in schedule_definitions:
            if definition["type"] == "schedule.calendar":
                definition["rule_descriptions"] = [
                    describe_schedule_rule(rule) for rule in definition["config"]["rules"]
                ]
                definition["schedule_preview"] = schedule_preview(
                    definition["config"], time.time(), 5
                )
        for definition in condition_definitions:
            if definition["type"] in {
                "tcp.reachability", "snmp.value", "certificate.health"
            }:
                # Normalize legacy global host/port definitions for display.
                definition["config"] = AUTOMATION_REGISTRY.validate_condition(
                    definition["type"], definition["config"]
                )
        action_definitions = workspace["action_definitions"]
        for definition in action_definitions:
            config = definition.get("config", {})
            if definition.get("type") != "ssh.collect" or config.get("matrix"):
                continue
            try:
                config["matrix"] = ssh_hosts_to_matrix(config.get("hosts", ""))
                config["target_count"] = max(
                    0, len(config["matrix"].splitlines()) - 1
                )
            except ToolInputError:
                config["matrix"] = ""
                config["target_count"] = 0
        render_started = time.perf_counter()
        context_duration = (render_started - context_started) * 1000
        body = render_template(
            "automations/index.html",
            automations=automations,
            condition_definitions=condition_definitions,
            schedule_definitions=schedule_definitions,
            action_definitions=action_definitions,
            action_choices=[
                {"id": item["id"], "name": item["name"], "type": item["type"]}
                for item in action_definitions
            ],
            condition_types=AUTOMATION_REGISTRY.conditions.values(),
            action_types=AUTOMATION_REGISTRY.actions.values(),
            snmp_hosts=SNMPHostProfileStore(store.instance_path).all(),
            snmp_oid_profiles=SNMPOidProfileStore(store.instance_path).all(),
            snmp_oid_choices=_snmp_oid_choices(store.instance_path),
            test_result=test_result,
            form_error=form_error,
            form=form or _empty_form(),
            form_section=form_section,
            scheduler={
                **_scheduler_status(store.instance_path),
                **workspace["job_stats"],
            },
            schedule_default_timezone=TimeSettingsStore(
                store.instance_path
            ).resolved_timezone(),
            datastore_folders=LocalDatastore(store.instance_path).folders(),
            capture_interfaces=capture_interfaces(),
            ssh_commandlets=SSHCommandletStore(store.instance_path).all(),
            ssh_target_limit=SSH_TARGET_LIMIT,
            ssh_target_limit_label=f"{SSH_TARGET_LIMIT:,}",
            ssh_batch_size=SSH_EXECUTION_BATCH_SIZE,
            ssh_execution_workers=SSH_EXECUTION_WORKERS,
            automation_ping_capability=ping_engine_capability(),
            page_section=page_section,
        )
        render_duration = (time.perf_counter() - render_started) * 1000
        total_duration = (time.perf_counter() - page_started) * 1000
        response = app.make_response(body)
        response.headers["Server-Timing"] = ", ".join(
            (
                f"workspace;dur={workspace_duration:.1f}",
                f"context;dur={context_duration:.1f}",
                f"render;dur={render_duration:.1f}",
                f"total;dur={total_duration:.1f}",
            )
        )
        return response

    @app.get("/automations")
    def automations():
        require_admin()
        return render_page()

    @app.get("/automations/conditions")
    def automation_conditions():
        require_admin()
        return render_page(page_section="conditions")

    @app.get("/automations/schedules")
    def automation_schedules():
        require_admin()
        return render_page(page_section="schedules")

    @app.get("/automations/actions")
    def automation_actions():
        require_admin()
        return render_page(page_section="actions")

    @app.post("/automations/save")
    def save_automation():
        require_admin()
        form = {key: value for key, value in request.form.items()}
        form["snmp_host_names"] = request.form.getlist("snmp_host_name")
        form["action_definition_ids"] = request.form.getlist("action_definition_id")
        form["condition_definition_ids"] = request.form.getlist(
            "condition_definition_id"
        )
        try:
            form["action_stages"] = json.loads(
                request.form.get("action_stages_json", "[]")
            )
        except json.JSONDecodeError:
            form["action_stages"] = []
        automation_id = request.form.get("automation_id", "").strip()
        before = store.get(automation_id) if automation_id else None
        try:
            run_mode = request.form.get("run_mode", "").strip()
            if run_mode:
                if run_mode == "manual":
                    source_definition_id = store.ensure_manual_trigger_definition()
                    source_definition_ids = [source_definition_id]
                elif run_mode == "startup":
                    startup_config = AUTOMATION_REGISTRY.trigger_config_from_form(
                        "system.startup", request.form
                    )
                    source_definition_id = store.ensure_startup_trigger_definition(
                        startup_config
                    )
                    source_definition_ids = [source_definition_id]
                elif run_mode == "schedule":
                    source_definition_id = request.form.get(
                        "schedule_definition_id", ""
                    )
                    source = store.get_condition_definition(source_definition_id)
                    if not source or source["type"] != "schedule.calendar":
                        raise ValueError("Select a reusable schedule.")
                    source_definition_ids = [source_definition_id]
                elif run_mode == "condition":
                    source_definition_ids = request.form.getlist(
                        "condition_definition_id"
                    )
                    if not source_definition_ids:
                        raise ValueError("Select at least one reusable condition.")
                    sources = [
                        store.get_condition_definition(definition_id)
                        for definition_id in source_definition_ids
                    ]
                    if any(
                        not source
                        or source["type"] in AUTOMATION_REGISTRY.triggers
                        for source in sources
                    ):
                        raise ValueError("Select only reusable conditions.")
                    source_definition_id = source_definition_ids[0]
                else:
                    raise ValueError("Select when this automation should run.")
            else:
                # Compatibility for pre-run-mode forms and imported requests.
                source_definition_id = request.form.get(
                    "condition_definition_id", ""
                )
                source_definition_ids = [source_definition_id]
            saved_id = store.save(
                automation_id=automation_id,
                name=request.form.get("name", ""),
                interval_seconds=int(request.form.get("interval_seconds", "30")),
                trigger_after=int(request.form.get("trigger_after", "3")),
                recover_after=int(request.form.get("recover_after", "3")),
                cooldown_seconds=int(request.form.get("cooldown_seconds", "300")),
                condition_definition_id=source_definition_id,
                condition_definition_ids=source_definition_ids,
                condition_operator=request.form.get("condition_operator", "all"),
                action_definition_ids=request.form.getlist("action_definition_id"),
                action_stages=form["action_stages"],
                created_by=str(g.current_user["id"]),
            )
        except (ToolInputError, ValueError) as exc:
            return render_page(
                form_error=str(exc), form=form, form_section="automation"
            ), 400
        after = store.get(saved_id)
        annotate_audit_event(
            category="Automation",
            action="automation.updated" if before else "automation.created",
            summary=f"{'Updated' if before else 'Created'} automation {after['name'] if after else saved_id}.",
            resource_type="automation",
            resource_id=saved_id,
            resource_name=str((after or {}).get("name", "")),
            before=_automation_audit_snapshot(before),
            after=_automation_audit_snapshot(after),
        )
        flash("Automation saved. It remains paused until you arm it.", "success")
        return redirect(url_for("automations", focus=saved_id))

    @app.post("/automations/conditions/save")
    def save_automation_condition():
        require_admin()
        form = {key: value for key, value in request.form.items()}
        form["snmp_host_names"] = request.form.getlist("snmp_host_name")
        try:
            form["rules"] = json.loads(request.form.get("schedule_rules_json", "[]"))
        except json.JSONDecodeError:
            form["rules"] = []
        requested_definition_id = request.form.get("condition_definition_id", "")
        before = store.get_condition_definition(requested_definition_id) if requested_definition_id else None
        try:
            type_id = request.form.get("condition_type", "ping.multi")
            config = AUTOMATION_REGISTRY.condition_config_from_form(type_id, request.form)
            definition_id = store.save_condition_definition(
                definition_id=request.form.get("condition_definition_id", ""),
                name=request.form.get("condition_name", ""),
                type_id=type_id,
                config=config,
            )
        except (ToolInputError, ValueError) as exc:
            return render_page(
                page_section="conditions",
                form_error=str(exc), form=form, form_section="condition"
            ), 400
        after = store.get_condition_definition(definition_id)
        annotate_audit_event(
            category="Automation",
            action="condition.updated" if before else "condition.created",
            summary=f"{'Updated' if before else 'Created'} condition {after['name'] if after else definition_id}.",
            resource_type="condition",
            resource_id=definition_id,
            resource_name=str((after or {}).get("name", "")),
            before=_definition_audit_snapshot(before),
            after=_definition_audit_snapshot(after),
        )
        flash(
            "Condition saved. Any automation using an edited condition was paused.",
            "success",
        )
        return redirect(url_for("automation_conditions", focus_condition=definition_id))

    @app.post("/automations/schedules/save")
    def save_automation_schedule():
        require_admin()
        form = {key: value for key, value in request.form.items()}
        try:
            form["rules"] = json.loads(request.form.get("schedule_rules_json", "[]"))
        except json.JSONDecodeError:
            form["rules"] = []
        requested_definition_id = request.form.get("schedule_definition_id", "")
        before = (
            store.get_condition_definition(requested_definition_id)
            if requested_definition_id
            else None
        )
        try:
            type_id = "schedule.calendar"
            config = AUTOMATION_REGISTRY.trigger_config_from_form(
                "schedule.calendar", request.form
            )
            definition_id = store.save_condition_definition(
                definition_id=requested_definition_id,
                name=request.form.get("schedule_name", ""),
                type_id=type_id,
                config=config,
            )
        except (ToolInputError, ValueError) as exc:
            return render_page(
                page_section="schedules",
                form_error=str(exc),
                form=form,
                form_section="schedule",
            ), 400
        after = store.get_condition_definition(definition_id)
        annotate_audit_event(
            category="Automation",
            action="schedule.updated" if before else "schedule.created",
            summary=(
                f"{'Updated' if before else 'Created'} schedule "
                f"{after['name'] if after else definition_id}."
            ),
            resource_type="schedule",
            resource_id=definition_id,
            resource_name=str((after or {}).get("name", "")),
            before=_definition_audit_snapshot(before),
            after=_definition_audit_snapshot(after),
        )
        flash(
            "Schedule saved. Any automation using an edited schedule was paused.",
            "success",
        )
        return redirect(url_for("automation_schedules", focus_schedule=definition_id))

    @app.post("/automations/actions/save")
    def save_automation_action():
        require_admin()
        form = {key: value for key, value in request.form.items()}
        definition_id = request.form.get("action_definition_id", "")
        existing_config: dict[str, Any] = {}
        if definition_id:
            existing = store.get_action_definition(definition_id, include_secrets=True)
            if existing:
                existing_config = dict(existing["config"])
        before = store.get_action_definition(definition_id) if definition_id else None
        try:
            type_id = request.form.get("action_type", "ssh.collect")
            config = AUTOMATION_REGISTRY.action_config_from_form(
                type_id, request.form, existing_config
            )
            definition_id = store.save_action_definition(
                definition_id=definition_id,
                name=request.form.get("action_name", ""),
                type_id=type_id,
                config=config,
            )
        except (ToolInputError, ValueError) as exc:
            return render_page(
                page_section="actions",
                form_error=str(exc), form=form, form_section="action"
            ), 400
        after = store.get_action_definition(definition_id)
        annotate_audit_event(
            category="Automation",
            action="action.updated" if before else "action.created",
            summary=f"{'Updated' if before else 'Created'} action {after['name'] if after else definition_id}.",
            resource_type="action",
            resource_id=definition_id,
            resource_name=str((after or {}).get("name", "")),
            before=_definition_audit_snapshot(before),
            after=_definition_audit_snapshot(after),
        )
        flash(
            "Action saved. Any automation using an edited action was paused.",
            "success",
        )
        return redirect(url_for("automation_actions", focus_action=definition_id))

    @app.post("/automations/conditions/<definition_id>/test")
    def test_condition_definition(definition_id: str):
        require_admin()
        definition = store.get_condition_definition(definition_id)
        if not definition:
            abort(404)
        annotate_audit_event(
            category="Automation", action="condition.tested",
            summary=f"Tested condition {definition['name']}.",
            resource_type="condition", resource_id=definition_id,
            resource_name=definition["name"],
        )
        try:
            result = AUTOMATION_REGISTRY.evaluate_condition(
                definition["type"], definition["config"]
            )
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
        return render_page(page_section="conditions", test_result=test_result)

    @app.post("/automations/schedules/<definition_id>/test")
    def test_schedule_definition(definition_id: str):
        require_admin()
        definition = store.get_condition_definition(definition_id)
        if not definition or definition["type"] != "schedule.calendar":
            abort(404)
        annotate_audit_event(
            category="Automation",
            action="schedule.tested",
            summary=f"Tested schedule {definition['name']}.",
            resource_type="schedule",
            resource_id=definition_id,
            resource_name=definition["name"],
        )
        try:
            result = AUTOMATION_REGISTRY.evaluate_trigger(
                definition["type"], definition["config"]
            )
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
        return render_page(page_section="schedules", test_result=test_result)

    @app.post("/automations/conditions/<definition_id>/delete")
    def delete_automation_condition(definition_id: str):
        require_admin()
        definition = store.get_condition_definition(definition_id)
        try:
            store.delete_condition_definition(definition_id)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Automation", action="condition.deleted",
                summary=f"Deleted condition {(definition or {}).get('name', definition_id)}.",
                resource_type="condition", resource_id=definition_id,
                resource_name=str((definition or {}).get("name", "")),
                details={"deleted definition": _definition_audit_snapshot(definition)},
            )
            flash("Condition deleted.", "success")
        return redirect(url_for("automation_conditions"))

    @app.post("/automations/schedules/<definition_id>/delete")
    def delete_automation_schedule(definition_id: str):
        require_admin()
        definition = store.get_condition_definition(definition_id)
        if not definition or definition["type"] != "schedule.calendar":
            abort(404)
        try:
            store.delete_condition_definition(definition_id)
        except ValueError as exc:
            flash(str(exc).replace("condition", "schedule"), "error")
        else:
            annotate_audit_event(
                category="Automation",
                action="schedule.deleted",
                summary=f"Deleted schedule {definition['name']}.",
                resource_type="schedule",
                resource_id=definition_id,
                resource_name=definition["name"],
                details={"deleted definition": _definition_audit_snapshot(definition)},
            )
            flash("Schedule deleted.", "success")
        return redirect(url_for("automation_schedules"))

    @app.post("/automations/actions/<definition_id>/delete")
    def delete_automation_action(definition_id: str):
        require_admin()
        definition = store.get_action_definition(definition_id)
        try:
            store.delete_action_definition(definition_id)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            annotate_audit_event(
                category="Automation", action="action.deleted",
                summary=f"Deleted action {(definition or {}).get('name', definition_id)}.",
                resource_type="action", resource_id=definition_id,
                resource_name=str((definition or {}).get("name", "")),
                details={"deleted definition": _definition_audit_snapshot(definition)},
            )
            flash("Action deleted.", "success")
        return redirect(url_for("automation_actions"))

    @app.post("/automations/conditions/<definition_id>/duplicate")
    def duplicate_automation_condition(definition_id: str):
        require_admin()
        source = store.get_condition_definition(definition_id)
        if not source or source["type"] in AUTOMATION_REGISTRY.triggers:
            abort(404)
        copied_id = store.save_condition_definition(
            name=duplicate_name(
                source["name"],
                (item["name"] for item in store.condition_definitions()),
            ),
            type_id=source["type"],
            config=dict(source["config"]),
        )
        copied = store.get_condition_definition(copied_id)
        _annotate_duplicate("condition", source, copied)
        flash(f"Duplicated condition as {copied['name']}.", "success")
        return redirect(url_for("automation_conditions", focus_condition=copied_id))

    @app.post("/automations/schedules/<definition_id>/duplicate")
    def duplicate_automation_schedule(definition_id: str):
        require_admin()
        source = store.get_condition_definition(definition_id)
        if not source or source["type"] != "schedule.calendar":
            abort(404)
        copied_id = store.save_condition_definition(
            name=duplicate_name(
                source["name"],
                (item["name"] for item in store.schedule_definitions()),
            ),
            type_id=source["type"],
            config=dict(source["config"]),
        )
        copied = store.get_condition_definition(copied_id)
        _annotate_duplicate("schedule", source, copied)
        flash(f"Duplicated schedule as {copied['name']}.", "success")
        return redirect(url_for("automation_schedules", focus_schedule=copied_id))

    @app.post("/automations/actions/<definition_id>/duplicate")
    def duplicate_automation_action(definition_id: str):
        require_admin()
        source = store.get_action_definition(definition_id, include_secrets=True)
        if not source:
            abort(404)
        copied_id = store.save_action_definition(
            name=duplicate_name(
                source["name"],
                (item["name"] for item in store.action_definitions()),
            ),
            type_id=source["type"],
            config=dict(source["config"]),
        )
        copied = store.get_action_definition(copied_id)
        _annotate_duplicate("action", source, copied)
        flash(f"Duplicated action as {copied['name']}.", "success")
        return redirect(url_for("automation_actions", focus_action=copied_id))

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
        updated = store.get(automation_id)
        annotate_audit_event(
            category="Automation", action="automation.paused" if automation["enabled"] else "automation.armed",
            summary=f"{'Paused' if automation['enabled'] else 'Armed'} automation {automation['name']}.",
            resource_type="automation", resource_id=automation_id,
            resource_name=automation["name"],
            before={"enabled": bool(automation["enabled"])},
            after={"enabled": bool((updated or {}).get("enabled"))},
        )
        if automation["enabled"]:
            message = "Automation paused."
        elif updated and updated["condition"]["type"] == "schedule.calendar":
            message = (
                "Schedule armed for its next occurrence."
                if updated["enabled"]
                else "Schedule has no future occurrences to arm."
            )
        elif updated and updated["condition"]["type"] == "system.startup":
            message = (
                "Startup automation armed for the next host boot."
                if updated["condition"]["config"]["mode"] == "host_boot"
                else "Startup automation armed for the next complete toolkit start."
            )
        else:
            message = "Automation armed; its first check is due now."
        flash(message, "success")
        return redirect(url_for("automations", focus=automation_id))

    @app.post("/automations/<automation_id>/duplicate")
    def duplicate_automation(automation_id: str):
        require_admin()
        source = store.get(automation_id)
        if not source:
            abort(404)
        copied_id = store.save(
            name=duplicate_name(
                source["name"],
                (item["name"] for item in store.all()),
            ),
            interval_seconds=int(source["interval_seconds"]),
            trigger_after=int(source["trigger_after"]),
            recover_after=int(source["recover_after"]),
            cooldown_seconds=int(source["cooldown_seconds"]),
            condition_definition_ids=list(source["condition_definition_ids"]),
            condition_operator=str(source["condition_operator"]),
            action_stages=[
                {
                    "id": stage["id"],
                    "name": stage["name"],
                    "continue_policy": stage["continue_policy"],
                    "delay_seconds": stage["delay_seconds"],
                    "action_definition_ids": list(stage["action_definition_ids"]),
                }
                for stage in source["action_stages"]
            ],
            created_by=str(g.current_user["id"]),
        )
        copied = store.get(copied_id)
        annotate_audit_event(
            category="Automation",
            action="automation.duplicated",
            summary=f"Duplicated automation {source['name']} as {copied['name']}.",
            resource_type="automation",
            resource_id=copied_id,
            resource_name=str(copied["name"]),
            details={"source automation id": automation_id},
            after=_automation_audit_snapshot(copied),
        )
        flash(f"Duplicated automation as {copied['name']}. The copy is paused.", "success")
        return redirect(url_for("automations", focus=copied_id))

    @app.post("/automations/<automation_id>/run-now")
    def run_automation_now(automation_id: str):
        require_admin()
        automation = store.get(automation_id, include_secrets=True)
        if not automation:
            abort(404)
        source_type = automation["condition"]["type"]
        if source_type not in {"manual.trigger", "system.startup"}:
            flash(
                "Run now is available only for Manual and Startup automations.",
                "error",
            )
            return redirect(url_for("automations", focus=automation_id))
        is_startup_test = source_type == "system.startup"
        if is_startup_test:
            job_id = store.enqueue_startup_test_job(
                automation_id,
                collect_system_identity(store.instance_path),
                started_by=str(g.current_user["username"]),
            )
        else:
            trigger = AUTOMATION_REGISTRY.evaluate_trigger(
                "manual.trigger", automation["condition"]["config"]
            )
            trigger.evidence["started_by"] = str(g.current_user["username"])
            job_id = store.enqueue_manual_job(automation_id, trigger)
        job = store.claim_job(job_id)
        if not job:
            raise RuntimeError("Automation job could not be claimed.")
        run_id = AutomationEngine(store).process_job(job)
        run = store.get_run(run_id) if run_id else None
        run_status = (run or {}).get("status", "waiting")
        annotate_audit_event(
            category="Automation",
            action=(
                "automation.startup_tested"
                if is_startup_test
                else "automation.ran_manually"
            ),
            summary=(
                f"{'Tested startup automation' if is_startup_test else 'Ran automation'} {automation['name']}."
                if run_id
                else f"Started {'startup test for' if is_startup_test else 'automation'} {automation['name']}; it is waiting between stages."
            ),
            resource_type="automation", resource_id=automation_id,
            resource_name=automation["name"],
            details={
                "job id": job_id,
                "run id": run_id or "",
                "run status": run_status,
                "action stages": len(automation.get("action_stages", [])),
                "actions": len(automation.get("actions", [])),
            },
        )
        record_current_activity(
            "Automation",
            (
                "Tested startup automation"
                if is_startup_test and run_id
                else "Started startup automation test"
                if is_startup_test
                else "Ran automation manually"
                if run_id
                else "Started automation manually"
            ),
            automation["name"],
        )
        if not run_id:
            flash(
                f"{'Startup test' if is_startup_test else 'Manual automation'} started. It is waiting between stages and will continue in the background.",
                "success",
            )
            return redirect(url_for("automations", focus=automation_id))
        flash(
            f"{'Startup notification test' if is_startup_test else 'Manual automation'} completed. Review or download the collected run.",
            "success",
        )
        return redirect(url_for("automations", focus=automation_id, focus_run=run_id))

    @app.post("/automations/<automation_id>/test-condition")
    def test_automation_condition(automation_id: str):
        require_admin()
        automation = store.get(automation_id, include_secrets=True)
        if not automation:
            abort(404)
        annotate_audit_event(
            category="Automation", action="automation.condition_tested",
            summary=f"Tested the condition for automation {automation['name']}.",
            resource_type="automation", resource_id=automation_id,
            resource_name=automation["name"],
        )
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
        automation = store.get(automation_id)
        if not automation:
            abort(404)
        try:
            store.delete(automation_id)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("automations", focus=automation_id))
        annotate_audit_event(
            category="Automation", action="automation.deleted",
            summary=f"Deleted automation {(automation or {}).get('name', automation_id)}.",
            resource_type="automation", resource_id=automation_id,
            resource_name=str((automation or {}).get("name", "")),
            details={"deleted automation": _automation_audit_snapshot(automation)},
        )
        flash("Automation and its retained history deleted.", "success")
        return redirect(url_for("automations"))

    @app.post("/automations/jobs/retry-failed")
    def retry_failed_automation_jobs():
        require_admin()
        retried = store.retry_failed_jobs()
        annotate_audit_event(
            category="Automation",
            action="automation.failed_jobs_retried",
            summary=(
                f"Requeued {retried} failed automation "
                f"job{'s' if retried != 1 else ''}."
            ),
            resource_type="automation jobs",
            details={"requeued jobs": retried},
        )
        flash(
            (
                f"Requeued {retried} failed automation "
                f"job{'s' if retried != 1 else ''}."
            ),
            "success",
        )
        return redirect(url_for("automations"))

    @app.post("/automations/<automation_id>/runs/clear")
    def clear_automation_runs(automation_id: str):
        require_admin()
        automation = store.get(automation_id)
        try:
            deleted = store.clear_runs(automation_id)
        except ValueError:
            abort(404)
        annotate_audit_event(
            category="Automation", action="automation.runs_cleared",
            summary=f"Cleared {deleted} collected run{'s' if deleted != 1 else ''} from {(automation or {}).get('name', automation_id)}.",
            resource_type="automation", resource_id=automation_id,
            resource_name=str((automation or {}).get("name", "")),
            details={"deleted runs": deleted},
        )
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
        annotate_audit_event(
            category="Automation", action="automation.run_deleted",
            summary=f"Deleted a collected run from {run['automation_name']}.",
            resource_type="automation run", resource_id=run_id,
            resource_name=run["automation_name"],
            details={"automation id": run["automation_id"], "started at": run["started_at"]},
        )
        flash("Collected action run deleted.", "success")
        return redirect(url_for("automations", focus=run["automation_id"]))

    @app.get("/automations/runs/<run_id>/download")
    def download_automation_run(run_id: str):
        require_admin()
        run = store.get_run(run_id)
        if not run:
            abort(404)
        annotate_audit_event(
            category="Automation", action="automation.run_downloaded",
            summary=f"Downloaded a collected run from {run['automation_name']}.",
            resource_type="automation run", resource_id=run_id,
            resource_name=run["automation_name"],
            details={"automation id": run["automation_id"], "started at": run["started_at"]},
        )
        output, filename = _automation_run_archive(store, run)
        return Response(
            output,
            mimetype="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/automations/runs/<run_id>/case")
    def add_automation_run_to_case(run_id: str):
        require_admin()
        run = store.get_run(run_id)
        if not run:
            abort(404)
        output, filename = _automation_run_archive(store, run)
        results = [
            {
                "status": result.get("status", ""),
                "summary": str(result.get("summary", ""))[:2_000],
                "stage": result.get("output", {}).get("_pipeline", {}).get("stage_name", ""),
                "action": result.get("output", {}).get("_pipeline", {}).get("action_name", ""),
            }
            for result in run.get("results", [])[:100]
            if isinstance(result, dict)
        ]
        succeeded = sum(result["status"] == "success" for result in results)
        failed = sum(result["status"] == "error" for result in results)
        added = add_current_investigation_generated_evidence_event(
            operation_id=f"automation-run:{run_id}",
            event_type="automation.run.attached",
            tool_id="automation.home",
            action="Automation run",
            outcome=(
                "succeeded"
                if run["status"] == "success"
                else "failed"
                if run["status"] == "error"
                else "incomplete"
            ),
            summary=f"Attached collected run from automation {run['automation_name']}.",
            targets={"automation_id": run["automation_id"], "automation": run["automation_name"]},
            parameters={"run_id": run_id, "trigger": run["trigger_summary"]},
            metrics={
                "result_count": len(results),
                "successful_results": succeeded,
                "failed_results": failed,
                "archive_bytes": len(output),
            },
            details={"results": results},
            started_at=float(run["started_at"]),
            completed_at=float(run["finished_at"]),
            filename=filename,
            content_type="application/zip",
            content=output,
        )
        annotate_audit_event(
            category="Automation",
            action="automation.run_added_to_case" if added else "automation.run_case_add_skipped",
            summary=(
                f"Added a collected run from {run['automation_name']} to the active case."
                if added
                else f"Could not add a collected run from {run['automation_name']} because no case was recording."
            ),
            resource_type="automation run",
            resource_id=run_id,
            resource_name=run["automation_name"],
            details={"automation id": run["automation_id"], "run status": run["status"]},
        )
        flash(
            "Added the collected run ZIP to the active case."
            if added
            else "Open or resume a recording case before adding a collected run.",
            "success" if added else "error",
        )
        return redirect(url_for("automations", focus=run["automation_id"], focus_run=run_id))


def _automation_run_archive(
    store: AutomationStore, run: dict[str, Any]
) -> tuple[bytes, str]:
    run_id = str(run["id"])
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
            destinations = result.get("output", {}).get("destinations", [])
            if destinations:
                archive.writestr(
                    f"action-{action_index}-destinations.json",
                    json.dumps(destinations, indent=2),
                )
            endpoints = result.get("output", {}).get("endpoints", [])
            if endpoints:
                archive.writestr(
                    f"action-{action_index}-endpoints.json",
                    json.dumps(endpoints, indent=2),
                )
            for host_index, host in enumerate(
                result.get("output", {}).get("hosts", []), 1
            ):
                host_name = _safe_filename(
                    str(
                        host.get("host_label")
                        or host.get("host", f"host-{host_index}")
                    )
                )
                body = str(host.get("output", ""))
                if host.get("host_label"):
                    body = (
                        f"Friendly name: {host['host_label']}\n"
                        f"Target: {host.get('host', '')}\n\n{body}"
                    )
                if host.get("error"):
                    body = f"ERROR: {host['error']}\n\n{body}"
                archive.writestr(
                    f"action-{action_index}/{file_timestamp}-{host_name}.txt",
                    body or "No output captured.\n",
                )
            for artifact in result.get("output", {}).get("artifacts", []):
                try:
                    source = store.run_artifact(run_id, str(artifact["artifact_path"]))
                except (KeyError, ValueError):
                    continue
                archive.write(
                    source,
                    (
                        f"action-{action_index}/files/"
                        f"{_safe_filename(str(artifact.get('filename', source.name)))}"
                    ),
                )
    filename = _safe_filename(str(run["automation_name"])) or "automation-run"
    return output.getvalue(), f"{filename}-{run_id}.zip"


def _empty_form() -> dict[str, str]:
    return {
        "interval_seconds": "30",
        "trigger_after": "3",
        "recover_after": "3",
        "cooldown_seconds": "300",
        "startup_mode": "host_boot",
        "startup_network_wait_seconds": "120",
        "condition_timeout": "1",
        "condition_failure_mode": "all",
        "condition_failure_count": "1",
        "action_port": "22",
    }


def _snmp_oid_choices(instance_path: Path) -> list[dict[str, str]]:
    choices: list[dict[str, str]] = []
    for profile in SNMPOidProfileStore(instance_path).all():
        try:
            entries = parse_oid_profile(profile["source"])
        except ToolInputError:
            continue
        for entry in entries:
            choices.append({
                "value": f"{profile['name']}|{entry['oid']}",
                "profile_name": profile["name"],
                "oid": entry["oid"],
                "label": entry["label"],
                "operation": entry["operation"],
                "display": f"{profile['name']} · {entry['label']} ({entry['oid']})",
            })
    return choices


def _format_time(value: Any) -> str:
    if not value:
        return "Never"
    return datetime.fromtimestamp(float(value)).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def _format_duration(seconds: int) -> str:
    if seconds <= 0:
        return ""
    if seconds % 3600 == 0:
        value, unit = seconds // 3600, "hour"
    elif seconds % 60 == 0:
        value, unit = seconds // 60, "minute"
    else:
        value, unit = seconds, "second"
    return f"{value} {unit}{'' if value == 1 else 's'}"


def _filename_timestamp(value: Any) -> str:
    """Return a portable, chronologically sortable local timestamp."""
    return datetime.fromtimestamp(float(value)).astimezone().strftime("%Y%m%d%H%M%S")


def _format_run(run: dict[str, Any]) -> dict[str, Any]:
    formatted_results = []
    for result in run.get("results", []):
        output = dict(result.get("output", {}))
        hosts = []
        for host in output.get("hosts", []):
            formatted_host = dict(host)
            captured = str(formatted_host.get("output", ""))
            if len(captured) > 40_000:
                formatted_host["output"] = (
                    f"{captured[:40_000]}\n\n"
                    "[Browser preview shortened. Download the ZIP for the complete captured output.]"
                )
            hosts.append(formatted_host)
        if "hosts" in output:
            output["hosts"] = hosts
        formatted_results.append({**result, "output": output})
    return {
        **run,
        "results": formatted_results,
        "started_display": _format_time(run["started_at"]),
    }


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
