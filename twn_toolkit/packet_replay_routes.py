from __future__ import annotations

from flask import Blueprint, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run, suppress_audit_event
from .dhcp_tools import available_interfaces
from .network_tools import ToolInputError
from .packet_replay_tools import (
    encode_prepared_packets,
    parse_hex_packet,
    parse_packet_capture,
    parse_prepared_packets,
    prepare_replay_plan,
    send_replay_frames,
)


def register_packet_replay_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/packet-replay", methods=["GET", "POST"])
    def packet_replay():
        interfaces = available_interfaces()
        default_interface = interfaces[0]["name"] if interfaces else ""
        form = {
            "interface": default_interface,
            "packet_hex": "",
            "source_mac": "",
            "destination_mac": "",
            "vlan_action": "keep",
            "vlan_ids": "",
            "repeat_count": "1",
            "interval_seconds": "1.0",
            "prepared_packet_hex": "",
        }
        plan = None
        send_result = None
        error = ""
        action = "preview"
        send_attempted = False
        if request.method == "POST":
            form = {key: request.form.get(key, default).strip() for key, default in form.items()}
            action = request.form.get("action", "preview")
            send_attempted = action == "send"
            try:
                upload = request.files.get("packet_file")
                if upload and upload.filename:
                    packets = parse_packet_capture(upload.read())
                else:
                    packet_hex = form["packet_hex"] or (
                        form["prepared_packet_hex"] if action == "send" else ""
                    )
                    packets = (
                        parse_prepared_packets(packet_hex)
                        if action == "send" and not form["packet_hex"]
                        else [parse_hex_packet(packet_hex)]
                    )
                plan = prepare_replay_plan(
                    packets,
                    source_mac=form["source_mac"],
                    destination_mac=form["destination_mac"],
                    vlan_action=form["vlan_action"],
                    vlan_ids=form["vlan_ids"],
                    repeat_count=int(form["repeat_count"]),
                    interval_seconds=float(form["interval_seconds"]),
                )
                form["prepared_packet_hex"] = encode_prepared_packets(plan.originals)
                if action == "send":
                    send_result = send_replay_frames(
                        plan.frames,
                        interface=form["interface"],
                        interval_seconds=plan.summary["interval_seconds"],
                    )
                    record_current_activity(
                        "Packets",
                        "Sent packet replay",
                        f"{send_result['sent']} frame(s) on {form['interface']}",
                        counters={"packet_replay": {"frames": int(send_result["sent"])}},
                    )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter a valid packet replay request."
                if send_attempted:
                    record_current_activity("Packets", "Sent packet replay", "Request failed")
            if send_attempted:
                annotate_tool_run(
                    category="Network tools",
                    action_namespace="packet_replay",
                    tool_name="packet replay",
                    outcome="failed" if error else "succeeded",
                    details={
                        "frame count": int(send_result.get("sent", 0)) if send_result else 0,
                        "VLAN action": form["vlan_action"],
                    },
                )
            else:
                suppress_audit_event()
        return render_template(
            "tools/packet_replay.html",
            error=error,
            form=form,
            interfaces=interfaces,
            plan=plan,
            send_result=send_result,
            action=action,
            send_attempted=send_attempted,
        )
