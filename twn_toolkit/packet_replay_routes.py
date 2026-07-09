from __future__ import annotations

from flask import Blueprint, render_template, request

from .dhcp_tools import available_interfaces
from .network_tools import ToolInputError
from .packet_replay_tools import (
    MAX_REPEATS,
    MAX_TOTAL_FRAMES,
    parse_hex_packet,
    parse_single_packet_capture,
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
            "confirm_send": "",
        }
        plan = None
        send_result = None
        error = ""
        action = "preview"
        if request.method == "POST":
            form = {key: request.form.get(key, default).strip() for key, default in form.items()}
            action = request.form.get("action", "preview")
            try:
                upload = request.files.get("packet_file")
                if upload and upload.filename:
                    packet = parse_single_packet_capture(upload.read())
                else:
                    packet = parse_hex_packet(form["packet_hex"])
                plan = prepare_replay_plan(
                    packet,
                    source_mac=form["source_mac"],
                    destination_mac=form["destination_mac"],
                    vlan_action=form["vlan_action"],
                    vlan_ids=form["vlan_ids"],
                    repeat_count=int(form["repeat_count"]),
                    interval_seconds=float(form["interval_seconds"]),
                )
                if action == "send":
                    if form["confirm_send"] != "SEND":
                        raise ToolInputError('Type "SEND" to confirm packet transmission.')
                    send_result = send_replay_frames(
                        plan.frames,
                        interface=form["interface"],
                        interval_seconds=plan.summary["interval_seconds"],
                    )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter a valid packet replay request."
        return render_template(
            "tools/packet_replay.html",
            error=error,
            form=form,
            interfaces=interfaces,
            max_repeats=MAX_REPEATS,
            max_total_frames=MAX_TOTAL_FRAMES,
            plan=plan,
            send_result=send_result,
            action=action,
        )
