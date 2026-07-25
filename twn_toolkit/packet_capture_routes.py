from __future__ import annotations

from datetime import datetime

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .datastore import DatastoreError, LocalDatastore
from .network_tools import ToolInputError
from .packet_capture import (
    DEFAULT_DURATION_SECONDS,
    DEFAULT_PACKET_COUNT,
    DEFAULT_SIZE_MIB,
    DEFAULT_SNAP_LENGTH,
    PacketCaptureStore,
    capture_capability,
    capture_interfaces,
)
from .pcap_viewer import inspect_packet_capture


def register_packet_capture_routes(tools_bp: Blueprint) -> None:
    def store() -> PacketCaptureStore:
        return PacketCaptureStore(current_app.instance_path)

    def datastore() -> LocalDatastore:
        return LocalDatastore(current_app.instance_path)

    def can_use_datastore() -> bool:
        return bool(
            g.current_user.get("is_admin")
            or "local.datastore" in getattr(g, "allowed_tool_ids", set())
        )

    @tools_bp.get("/packet-capture")
    def packet_capture():
        form = {
            "interface": request.args.get("interface", ""),
            "capture_filter": "",
            "duration_seconds": str(DEFAULT_DURATION_SECONDS),
            "packet_count": str(DEFAULT_PACKET_COUNT),
            "max_size_mib": str(DEFAULT_SIZE_MIB),
            "snap_length": str(DEFAULT_SNAP_LENGTH),
            "promiscuous": True,
        }
        interfaces = capture_interfaces()
        if not form["interface"] and interfaces:
            non_loopback = next(
                (item for item in interfaces if not item["loopback"]), interfaces[0]
            )
            form["interface"] = non_loopback["name"]
        datastore_folders = []
        if can_use_datastore():
            datastore_folders = datastore().folders()
        return render_template(
            "tools/packet_capture.html",
            capability=capture_capability(),
            interfaces=interfaces,
            captures=store().recent(),
            can_use_datastore=can_use_datastore(),
            datastore_folders=datastore_folders,
            form=form,
        )

    @tools_bp.post("/packet-capture/start")
    def start_packet_capture():
        config = {
            "interface": request.form.get("interface", ""),
            "capture_filter": request.form.get("capture_filter", ""),
            "duration_seconds": request.form.get("duration_seconds", ""),
            "packet_count": request.form.get("packet_count", ""),
            "max_size_mib": request.form.get("max_size_mib", ""),
            "snap_length": request.form.get("snap_length", ""),
            "promiscuous": "promiscuous" in request.form,
        }
        try:
            capture_store = store()
            capture_id = capture_store.create(
                config, created_by=str(g.current_user["id"])
            )
            capture_store.launch(capture_id)
        except ToolInputError as exc:
            annotate_tool_run(
                category="Network tools",
                action_namespace="packet_capture",
                tool_name="packet capture",
                outcome="failed",
                details={
                    "interface": str(config["interface"])[:100],
                    "duration seconds": str(config["duration_seconds"])[:20],
                },
            )
            flash(str(exc), "error")
            return redirect(
                url_for("tools.packet_capture", interface=config["interface"])
            )
        annotate_tool_run(
            category="Network tools",
            action_namespace="packet_capture",
            tool_name="packet capture",
            outcome="started",
            details={
                "capture id": capture_id,
                "interface": config["interface"],
                "duration seconds": int(config["duration_seconds"]),
                "packet limit": int(config["packet_count"]),
                "size limit MiB": int(config["max_size_mib"]),
            },
        )
        record_current_activity(
            "Packets",
            "Started packet capture",
            f"Capture started on {config['interface']}",
        )
        flash("Packet capture started.", "success")
        return redirect(url_for("tools.packet_capture", focus=capture_id))

    @tools_bp.get("/packet-capture/<capture_id>/status")
    def packet_capture_status(capture_id: str):
        capture = store().get(capture_id)
        if not capture:
            abort(404)
        return jsonify(
            {
                key: capture[key]
                for key in (
                    "id",
                    "status",
                    "active",
                    "downloadable",
                    "viewable",
                    "elapsed_seconds",
                    "size_bytes",
                    "size_display",
                    "packet_count",
                    "termination_reason",
                    "error",
                )
            }
        )

    @tools_bp.get("/packet-capture/<capture_id>/packets")
    def inspect_captured_packets(capture_id: str):
        capture_store = store()
        capture = capture_store.get(capture_id)
        if not capture:
            abort(404)
        path = capture_store.output_file(capture)
        try:
            result = inspect_packet_capture(
                path,
                start=request.args.get("start", 0),
                allow_incomplete=capture["active"],
                cursor=request.args.get("cursor"),
            )
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 422
        return jsonify(result)

    @tools_bp.post("/packet-capture/<capture_id>/stop")
    def stop_packet_capture(capture_id: str):
        try:
            capture_store = store()
            capture = capture_store.get(capture_id)
            if not capture:
                abort(404)
            capture_store.request_stop(capture_id)
        except ToolInputError as exc:
            flash(str(exc), "error")
        else:
            annotate_tool_run(
                category="Network tools",
                action_namespace="packet_capture",
                tool_name="packet capture",
                outcome="stop requested",
                details={"capture id": capture_id, "interface": capture["interface"]},
            )
            flash("Packet capture is stopping.", "success")
        return redirect(url_for("tools.packet_capture", focus=capture_id))

    @tools_bp.get("/packet-capture/<capture_id>/download")
    def download_packet_capture(capture_id: str):
        capture_store = store()
        capture = capture_store.get(capture_id)
        if not capture or not capture["downloadable"]:
            abort(404)
        path = capture_store.output_file(capture)
        if not path.is_file():
            abort(404)
        filename = _capture_filename(capture)
        annotate_tool_run(
            category="Network tools",
            action_namespace="packet_capture",
            tool_name="packet capture",
            outcome="downloaded",
            details={
                "capture id": capture_id,
                "interface": capture["interface"],
                "size bytes": capture["size_bytes"],
            },
        )
        return send_file(
            path,
            mimetype="application/vnd.tcpdump.pcap",
            as_attachment=True,
            download_name=filename,
        )

    @tools_bp.post("/packet-capture/<capture_id>/save")
    def save_packet_capture(capture_id: str):
        if not can_use_datastore():
            abort(403)
        capture_store = store()
        capture = capture_store.get(capture_id)
        if not capture or not capture["downloadable"]:
            abort(404)
        source = capture_store.output_file(capture)
        if not source.is_file():
            abort(404)
        destination_folder = request.form.get("destination", "")
        filename = _capture_filename(capture)
        try:
            with source.open("rb") as stream:
                saved, size = datastore().save_upload(
                    destination_folder,
                    filename,
                    stream,
                    max_bytes=max(1, int(capture["max_size_mib"])) * 1024 * 1024,
                )
        except (DatastoreError, OSError) as exc:
            flash(f"PCAP was not saved: {exc}", "error")
        else:
            relative_path = datastore().relative(saved)
            annotate_tool_run(
                category="Network tools",
                action_namespace="packet_capture",
                tool_name="packet capture",
                outcome="saved to datastore",
                details={
                    "capture id": capture_id,
                    "interface": capture["interface"],
                    "datastore path": relative_path,
                    "size bytes": size,
                },
            )
            record_current_activity(
                "Packets", "Saved packet capture", relative_path
            )
            flash(f"Saved PCAP to datastore as {relative_path}.", "success")
        return redirect(
            url_for("tools.packet_capture", focus=capture_id, _anchor=f"capture-{capture_id}")
        )

    @tools_bp.post("/packet-capture/<capture_id>/delete")
    def delete_packet_capture(capture_id: str):
        try:
            capture = store().delete(capture_id)
        except ToolInputError as exc:
            flash(str(exc), "error")
        else:
            annotate_tool_run(
                category="Network tools",
                action_namespace="packet_capture",
                tool_name="packet capture",
                outcome="deleted",
                details={
                    "capture id": capture_id,
                    "interface": capture["interface"],
                    "size bytes": capture["size_bytes"],
                },
            )
            flash("Packet capture deleted.", "success")
        return redirect(url_for("tools.packet_capture"))


def _safe_filename(value: str) -> str:
    cleaned = "".join(
        character if character.isalnum() or character in "._-" else "-"
        for character in value
    ).strip(".-_")
    return (cleaned or "interface")[:100]


def _capture_filename(capture: dict[str, object]) -> str:
    stamp = datetime.fromtimestamp(float(capture["created_at"])).astimezone()
    return (
        f"{stamp:%Y%m%d%H%M%S}-"
        f"{_safe_filename(str(capture['interface']))}-capture.pcap"
    )
