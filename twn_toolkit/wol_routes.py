from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_profile_deleted, annotate_profile_saved, annotate_tool_run
from .network_tools import ToolInputError
from .profiles import WOLTargetProfileStore
from .wol_tools import (
    MAX_WOL_TARGETS,
    available_wol_interfaces,
    parse_wol_targets,
    run_wake_on_lan,
)


def register_wol_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/wake-on-lan", methods=["GET", "POST"])
    def wake_on_lan():
        interfaces = available_wol_interfaces()
        default_interface = interfaces[0]["name"] if interfaces else ""
        form = {
            "targets": "",
            "interface": default_interface,
            "destination_mode": "local",
            "custom_destination": "",
            "port": "9",
            "repeats": "3",
            "verify": False,
            "verify_timeout": "20",
        }
        outcome = None
        error = ""
        if request.method == "POST":
            form = {
                "targets": request.form.get("targets", "").strip(),
                "interface": request.form.get("interface", "").strip(),
                "destination_mode": request.form.get("destination_mode", "local").strip(),
                "custom_destination": request.form.get("custom_destination", "").strip(),
                "port": request.form.get("port", "9").strip(),
                "repeats": request.form.get("repeats", "3").strip(),
                "verify": request.form.get("verify") == "1",
                "verify_timeout": request.form.get("verify_timeout", "20").strip(),
            }
            try:
                targets = parse_wol_targets(form["targets"])
                outcome = run_wake_on_lan(
                    targets,
                    interface_name=form["interface"],
                    destination_mode=form["destination_mode"],
                    custom_destination=form["custom_destination"],
                    port=int(form["port"]),
                    repeats=int(form["repeats"]),
                    verify=bool(form["verify"]),
                    verify_timeout=int(form["verify_timeout"]),
                    interfaces=interfaces,
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid Wake-on-LAN settings."
                record_current_activity("Devices", "Sent Wake-on-LAN", "Request failed")
            else:
                record_current_activity(
                    "Devices",
                    "Sent Wake-on-LAN",
                    (
                        f"{outcome['device_count']} device(s) · "
                        f"{outcome['packets_sent']} packet(s) · "
                        f"{outcome['confirmed_awake']} confirmed awake"
                    ),
                    counters={
                        "wol": {
                            "devices": outcome["device_count"],
                            "packets": outcome["packets_sent"],
                            "confirmed": outcome["confirmed_awake"],
                        }
                    },
                )
            audit_outcome = (
                "failed"
                if error
                else "partial"
                if outcome and outcome["send_failures"]
                else "succeeded"
            )
            annotate_tool_run(
                category="Network tools",
                action_namespace="wol.send",
                tool_name="Wake-on-LAN",
                outcome=audit_outcome,
                details={
                    "device count": outcome["device_count"] if outcome else 0,
                    "packet count": outcome["packets_sent"] if outcome else 0,
                    "send failure count": outcome["send_failures"] if outcome else 0,
                    "destination mode": form["destination_mode"],
                    "source interface": form["interface"],
                    "UDP port": int(form["port"]) if form["port"].isdigit() else 0,
                    "repeat count": int(form["repeats"]) if form["repeats"].isdigit() else 0,
                    "verification requested": bool(form["verify"]),
                    "confirmed awake count": outcome["confirmed_awake"] if outcome else 0,
                },
            )
        return render_template(
            "tools/wake_on_lan.html",
            error=error,
            form=form,
            interfaces=interfaces,
            profiles=WOLTargetProfileStore(current_app.instance_path).all(),
            outcome=outcome,
            target_limit=MAX_WOL_TARGETS,
        )

    @tools_bp.post("/wake-on-lan/profiles")
    def save_wol_profile():
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        values = request.form.get("values", "").strip()
        if not name or len(name) > 100:
            return jsonify({"error": "Enter a group name of 100 characters or fewer."}), 400
        try:
            targets = parse_wol_targets(values)
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 400
        profile = {
            "name": name,
            "values": values,
            "targets": targets,
            "count": len(targets),
        }
        store = WOLTargetProfileStore(current_app.instance_path)
        before = store.get(original_name or name)
        store.upsert(profile, original_name=original_name)
        annotate_profile_saved(
            category="Network tools",
            action_namespace="wol",
            profile_type="Wake-on-LAN device group",
            before=_profile_audit_snapshot(before) if before else None,
            after=_profile_audit_snapshot(profile),
        )
        return jsonify({"profile": profile})

    @tools_bp.post("/wake-on-lan/profiles/delete")
    def delete_wol_profile():
        name = request.form.get("name", "").strip()
        store = WOLTargetProfileStore(current_app.instance_path)
        profile = store.get(name)
        if not profile or not store.delete(name):
            return jsonify({"error": "Device group not found."}), 404
        annotate_profile_deleted(
            category="Network tools",
            action_namespace="wol",
            profile_type="Wake-on-LAN device group",
            profile=_profile_audit_snapshot(profile),
        )
        return jsonify({"deleted": name})


def _profile_audit_snapshot(profile: dict[str, object] | None) -> dict[str, object]:
    if not profile:
        return {}
    targets = profile.get("targets")
    target_list = targets if isinstance(targets, list) else []
    return {
        "name": str(profile.get("name", "")),
        "device count": int(profile.get("count", len(target_list))),
        "verification host count": sum(
            bool(target.get("host")) for target in target_list if isinstance(target, dict)
        ),
    }
