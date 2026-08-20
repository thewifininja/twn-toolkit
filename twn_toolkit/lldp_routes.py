from __future__ import annotations

import json
import secrets
import time
from typing import Any

from flask import Blueprint, current_app, g, jsonify, redirect, render_template, request, url_for

from .activity_context import record_current_activity
from .audit import annotate_tool_run, suppress_audit_event
from .dhcp_tools import available_interfaces
from .investigation_context import (
    add_current_investigation_generated_evidence_event,
    record_current_investigation_event,
)
from .investigations import InvestigationStore
from .lldp_sessions import LLDPSessionStore
from .lldp_tools import (
    CAPABILITY_BITS,
    PRESETS,
    default_persona,
    format_custom_tlvs,
    lldpcli_capability,
    persona_from_form,
    preferred_interface,
    preview_persona,
    read_neighbors,
    validate_persona,
)
from .network_tools import ToolInputError
from .profiles import LLDPPersonaStore
from .route_utils import disable_client_caching


def register_lldp_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/lldp-lab", methods=["GET", "POST"])
    def lldp_lab():
        user = getattr(g, "current_user", {}) or {}
        user_id = str(user.get("id", ""))
        persona_store = LLDPPersonaStore(current_app.instance_path)
        session_store = LLDPSessionStore(current_app.instance_path)
        interfaces = available_interfaces()
        # A POST to the current page retains its query string. Prefer the
        # submitted form so a stale ``?interface=en0`` cannot override the
        # operator's newly selected transmit interface.
        request_fields = request.form if request.method == "POST" else request.args
        selected_interface = request_fields.get("interface", "").strip()
        if not selected_interface and interfaces:
            selected_interface = preferred_interface(interfaces)
        view = request_fields.get("view", "observe").strip()
        if view not in {"observe", "emulate"}:
            view = "observe"
        preset = request_fields.get("preset", "generic").strip()
        selected_name = request_fields.get("persona", "").strip()
        selected = persona_store.get(selected_name) if selected_name else None
        if selected:
            persona = default_persona(
                preset=str(selected.get("preset", "generic")),
                interface=selected_interface,
            )
            persona.update(selected)
        else:
            persona = default_persona(preset=preset, interface=selected_interface)
        persona.setdefault("custom_tlvs", [])
        persona["custom_tlvs_text"] = format_custom_tlvs(persona["custom_tlvs"])
        preview = None
        journal_event = None
        error = ""
        message = ""
        neighbors: list[dict[str, Any]] = []
        capability = lldpcli_capability()

        if request.method == "POST":
            action = request.form.get("action", "preview")
            if action == "neighbor_persona":
                view = "emulate"
                try:
                    observed = read_neighbors()
                    neighbor_index = int(request.form.get("neighbor_index", "-1"))
                    if not 0 <= neighbor_index < len(observed):
                        raise ToolInputError("That LLDP neighbor is no longer available.")
                    neighbor = observed[neighbor_index]
                    persona = default_persona(
                        preset="switch", interface=selected_interface
                    )
                    persona.update(
                        {
                            "name": f"{neighbor['system_name'] or 'Observed neighbor'} copy",
                            "system_name": neighbor["system_name"] or "Observed neighbor",
                            "system_description": neighbor["system_description"],
                            "source_mac": (
                                neighbor["chassis_id"]
                                if neighbor.get("chassis_id_type") == "mac"
                                else persona["source_mac"]
                            ),
                            "chassis_id": neighbor["chassis_id"] or persona["chassis_id"],
                            "port_id": neighbor["port_id"] or persona["port_id"],
                            "port_description": neighbor["port_description"],
                            "capabilities": [
                                item.lower()
                                for item in neighbor["capabilities"]
                                if item.lower() in CAPABILITY_BITS
                            ],
                            "management_address": (
                                neighbor["management_addresses"][0]
                                if neighbor["management_addresses"]
                                else ""
                            ),
                        }
                    )
                    persona["custom_tlvs_text"] = ""
                    message = "Copied the visible standards-based fields into a new unsaved persona."
                except (ToolInputError, TypeError, ValueError) as exc:
                    error = str(exc)
                suppress_audit_event()
            elif action in {"preview", "save", "start"}:
                view = "emulate"
                try:
                    persona = persona_from_form(request.form, interface=selected_interface)
                    persona["custom_tlvs_text"] = format_custom_tlvs(persona["custom_tlvs"])
                    preview = preview_persona(persona, interface=selected_interface)
                    if action == "save":
                        original_name = request.form.get("original_name", "").strip()
                        stored = dict(persona)
                        stored.pop("custom_tlvs_text", None)
                        persona_store.upsert(stored, original_name=original_name)
                        selected_name = stored["name"]
                        message = f"Saved LLDP persona {stored['name']}."
                        annotate_tool_run(
                            category="Network tools",
                            action_namespace="lldp.persona.save",
                            tool_name="LLDP Lab persona",
                            outcome="succeeded",
                            details={"preset": stored["preset"]},
                        )
                    elif action == "start":
                        if request.form.get("confirm_send") != "on":
                            raise ToolInputError(
                                "Confirm that you are authorized to transmit this LLDP identity."
                            )
                        investigation_id = _recording_investigation_id(user_id)
                        session_id = session_store.create(
                            interface=selected_interface,
                            persona=persona,
                            frame_hex=preview["frame_hex"],
                            shutdown_frame_hex=preview["shutdown_frame_hex"],
                            created_by=user_id,
                            created_by_username=str(user.get("username", "")),
                            investigation_id=investigation_id,
                        )
                        session_store.launch(session_id)
                        record_current_activity(
                            "Traffic",
                            "Started LLDP Lab transmission",
                            f"{persona['name']} on {selected_interface}",
                            counters={"lldp": {"sessions": 1}},
                        )
                        annotate_tool_run(
                            category="Network tools",
                            action_namespace="lldp.transmit.start",
                            tool_name="LLDP Lab",
                            outcome="succeeded",
                            details={
                                "interface": selected_interface,
                                "persona": persona["name"],
                                "duration minutes": persona["duration_minutes"],
                            },
                        )
                        journal_event = record_current_investigation_event(
                            operation_id=f"lldp-emission:{session_id}",
                            event_type="action.started",
                            tool_id="tools.lldp_lab",
                            action="LLDP identity emission",
                            outcome="running",
                            summary=(
                                f"Started LLDP persona {persona['name']} on "
                                f"{selected_interface} for up to {persona['duration_minutes']} minutes."
                            ),
                            targets={"interface": selected_interface},
                            parameters={
                                "persona": persona["name"],
                                "preset": persona["preset"],
                                "interval_seconds": persona["interval_seconds"],
                                "duration_minutes": persona["duration_minutes"],
                            },
                            metrics={},
                            details={"tlvs": preview["tlvs"]},
                            started_at=time.time(),
                            completed_at=time.time(),
                        )
                        message = (
                            f"Started {persona['name']} on {selected_interface}. "
                            "A shutdown PDU will be sent when it stops."
                        )
                    else:
                        suppress_audit_event()
                except (OSError, ToolInputError, TypeError, ValueError) as exc:
                    error = str(exc) or "Enter a valid LLDP persona."
                    if action == "start":
                        annotate_tool_run(
                            category="Network tools",
                            action_namespace="lldp.transmit.start",
                            tool_name="LLDP Lab",
                            outcome="failed",
                            details={"interface": selected_interface, "error": error},
                        )
                    elif action == "preview":
                        suppress_audit_event()
                    elif action == "save":
                        annotate_tool_run(
                            category="Network tools",
                            action_namespace="lldp.persona.save",
                            tool_name="LLDP Lab persona",
                            outcome="failed",
                            details={"error": error},
                        )
            elif action == "snapshot":
                view = "observe"
                try:
                    neighbors = read_neighbors()
                    content = json.dumps(
                        {
                            "captured_at": time.time(),
                            "neighbors": neighbors,
                        },
                        indent=2,
                    ).encode("utf-8")
                    generated = add_current_investigation_generated_evidence_event(
                        filename=f"lldp-neighbors-{time.strftime('%Y%m%d-%H%M%S')}.json",
                        content_type="application/json",
                        content=content,
                        operation_id=f"lldp-neighbors:{secrets.token_hex(12)}",
                        event_type="diagnostic.completed",
                        tool_id="tools.lldp_lab",
                        action="LLDP neighbor snapshot",
                        outcome="succeeded",
                        summary=f"Captured {len(neighbors)} LLDP neighbor(s).",
                        targets={
                            "interfaces": sorted(
                                {neighbor["interface"] for neighbor in neighbors}
                            )
                        },
                        parameters={},
                        metrics={"neighbor_count": len(neighbors)},
                        details={"neighbors": neighbors},
                        started_at=time.time(),
                        completed_at=time.time(),
                    )
                    if generated:
                        journal_event = generated["event"]
                        message = "Saved the LLDP neighbor snapshot to the active case."
                    else:
                        error = "Open or resume a recording case before saving a snapshot."
                    annotate_tool_run(
                        category="Network tools",
                        action_namespace="lldp.snapshot",
                        tool_name="LLDP Lab neighbor snapshot",
                        outcome="succeeded" if generated else "not_recorded",
                        details={"neighbor count": len(neighbors)},
                    )
                except ToolInputError as exc:
                    error = str(exc)
                    annotate_tool_run(
                        category="Network tools",
                        action_namespace="lldp.snapshot",
                        tool_name="LLDP Lab neighbor snapshot",
                        outcome="failed",
                        details={"error": error},
                    )
            else:
                suppress_audit_event()
        else:
            suppress_audit_event()

        if view == "observe" and not neighbors and capability["connected"]:
            try:
                neighbors = read_neighbors()
            except ToolInputError as exc:
                error = str(exc)

        return render_template(
            "tools/lldp_lab.html",
            view=view,
            capability=capability,
            neighbors=neighbors,
            interfaces=interfaces,
            interface=selected_interface,
            presets=PRESETS,
            capabilities=CAPABILITY_BITS,
            personas=persona_store.all(),
            selected_name=selected_name,
            persona=persona,
            preview=preview,
            sessions=session_store.recent(user_id=user_id),
            error=error,
            message=message,
            journal_event=journal_event,
        )

    @tools_bp.post("/lldp-lab/personas/<path:name>/duplicate")
    def duplicate_lldp_persona(name: str):
        store = LLDPPersonaStore(current_app.instance_path)
        try:
            copied = store.duplicate(name)
        except ValueError:
            annotate_tool_run(
                category="Network tools",
                action_namespace="lldp.persona.duplicate",
                tool_name="LLDP Lab persona",
                outcome="not_found",
                details={"source": name},
            )
            return redirect(url_for("tools.lldp_lab", view="emulate"))
        annotate_tool_run(
            category="Network tools",
            action_namespace="lldp.persona.duplicate",
            tool_name="LLDP Lab persona",
            outcome="succeeded",
            details={"source": name, "copy": copied["name"]},
        )
        return redirect(
            url_for("tools.lldp_lab", view="emulate", persona=copied["name"])
        )

    @tools_bp.post("/lldp-lab/personas/<path:name>/delete")
    def delete_lldp_persona(name: str):
        deleted = LLDPPersonaStore(current_app.instance_path).delete(name)
        annotate_tool_run(
            category="Network tools",
            action_namespace="lldp.persona.delete",
            tool_name="LLDP Lab persona",
            outcome="succeeded" if deleted else "not_found",
            details={"persona": name},
        )
        return redirect(url_for("tools.lldp_lab", view="emulate"))

    @tools_bp.post("/lldp-lab/sessions/<session_id>/stop")
    def stop_lldp_session(session_id: str):
        user = getattr(g, "current_user", {}) or {}
        store = LLDPSessionStore(current_app.instance_path)
        try:
            item = store.request_stop(session_id, user_id=str(user.get("id", "")))
        except ToolInputError as exc:
            annotate_tool_run(
                category="Network tools",
                action_namespace="lldp.transmit.stop",
                tool_name="LLDP Lab",
                outcome="failed",
                details={"session": session_id, "error": str(exc)},
            )
            return redirect(
                url_for("tools.lldp_lab", view="emulate", session_error=str(exc))
            )
        annotate_tool_run(
            category="Network tools",
            action_namespace="lldp.transmit.stop",
            tool_name="LLDP Lab",
            outcome="succeeded",
            details={
                "interface": item.get("interface", ""),
                "persona": item.get("persona_name", ""),
                "frames sent": int(item.get("frames_sent", 0)),
            },
        )
        return redirect(url_for("tools.lldp_lab", view="emulate"))

    @tools_bp.get("/lldp-lab/sessions")
    def lldp_session_status():
        user = getattr(g, "current_user", {}) or {}
        sessions = LLDPSessionStore(current_app.instance_path).recent(
            user_id=str(user.get("id", ""))
        )
        response = jsonify(
            {
                "sessions": [
                    {
                        key: session.get(key)
                        for key in (
                            "id",
                            "status",
                            "interface",
                            "persona_name",
                            "frames_sent",
                            "elapsed_seconds",
                            "error",
                            "active",
                        )
                    }
                    for session in sessions
                ]
            }
        )
        disable_client_caching(response)
        return response


def _recording_investigation_id(user_id: str) -> str:
    store = current_app.extensions.get("investigation_store")
    if not isinstance(store, InvestigationStore):
        store = InvestigationStore(current_app.instance_path)
    investigation = store.active_for_user(user_id)
    if not investigation or not investigation.get("is_recording"):
        return ""
    return str(investigation["id"])
