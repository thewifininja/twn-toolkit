from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from flask import Blueprint, current_app, g, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run, suppress_audit_event
from .datastore import DatastoreError, LocalDatastore, format_bytes
from .dhcp_tools import available_interfaces
from .network_tools import ToolInputError
from .packet_replay_tools import (
    MAX_UPLOAD_BYTES as MAX_REPLAY_CAPTURE_BYTES,
    encode_prepared_packets,
    parse_hex_packet,
    parse_packet_capture,
    parse_prepared_packets,
    prepare_replay_plan,
    send_replay_frames,
)


REPLAY_CAPTURE_SUFFIXES = {".cap", ".pcap"}


def _datastore_packet_captures(store: LocalDatastore) -> list[dict[str, object]]:
    captures: list[dict[str, object]] = []
    for folder in store.folders():
        for entry in store.list(str(folder["path"]))["entries"]:
            if entry["is_dir"]:
                continue
            if Path(str(entry["name"])).suffix.casefold() not in REPLAY_CAPTURE_SUFFIXES:
                continue
            captures.append(
                {
                    **entry,
                    "size_display": format_bytes(int(entry["size"])),
                    "replayable": int(entry["size"]) <= MAX_REPLAY_CAPTURE_BYTES,
                }
            )
    return sorted(captures, key=lambda item: str(item["path"]).casefold())


def _read_capture_stream(stream: BinaryIO) -> list[bytes]:
    return parse_packet_capture(stream.read(MAX_REPLAY_CAPTURE_BYTES + 1))


def register_packet_replay_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/packet-replay", methods=["GET", "POST"])
    def packet_replay():
        datastore = LocalDatastore(current_app.instance_path)
        can_use_datastore = bool(
            g.current_user.get("is_admin")
            or "local.datastore" in getattr(g, "allowed_tool_ids", set())
        )
        datastore_captures = (
            _datastore_packet_captures(datastore) if can_use_datastore else []
        )
        datastore_capture_count = sum(
            bool(capture["replayable"]) for capture in datastore_captures
        )
        interfaces = available_interfaces()
        default_interface = interfaces[0]["name"] if interfaces else ""
        form = {
            "interface": default_interface,
            "packet_hex": "",
            "datastore_capture": "",
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
                if action == "send":
                    packets = (
                        [parse_hex_packet(form["packet_hex"])]
                        if form["packet_hex"]
                        else parse_prepared_packets(form["prepared_packet_hex"])
                    )
                else:
                    upload = request.files.get("packet_file")
                    has_upload = bool(upload and upload.filename)
                    has_datastore_capture = bool(form["datastore_capture"])
                    has_packet_hex = bool(form["packet_hex"])
                    if sum((has_upload, has_datastore_capture, has_packet_hex)) != 1:
                        raise ToolInputError(
                            "Choose exactly one packet source: a datastore PCAP, "
                            "a local PCAP upload, or raw Ethernet frame hex."
                        )
                    if has_upload and upload:
                        packets = _read_capture_stream(upload.stream)
                    elif has_datastore_capture:
                        if not can_use_datastore:
                            raise ToolInputError(
                                "Datastore access is required to select a stored PCAP."
                            )
                        capture_path = datastore.file(form["datastore_capture"])
                        if capture_path.suffix.casefold() not in REPLAY_CAPTURE_SUFFIXES:
                            raise ToolInputError(
                                "Choose a classic .pcap or .cap file from the datastore."
                            )
                        with capture_path.open("rb") as capture_source:
                            packets = _read_capture_stream(capture_source)
                    else:
                        packets = [parse_hex_packet(form["packet_hex"])]
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
                    if request.form.get("confirm_send") != "on":
                        raise ToolInputError(
                            "Review the replay preview and confirm that you are authorized "
                            "to send these frames."
                        )
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
            except (DatastoreError, OSError, ToolInputError, TypeError, ValueError) as exc:
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
            datastore_captures=datastore_captures,
            datastore_capture_count=datastore_capture_count,
            can_use_datastore=can_use_datastore,
            plan=plan,
            send_result=send_result,
            action=action,
            send_attempted=send_attempted,
        )
