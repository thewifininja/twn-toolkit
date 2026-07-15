from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_profile_deleted, annotate_profile_saved, annotate_tool_run
from .network_tools import (
    ToolInputError,
    parse_ping_targets,
    parse_tcp_ports,
    scan_tcp_ports,
)
from .profiles import PortScanProfileStore


def register_port_scanner_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/port-scanner", methods=["GET", "POST"])
    def port_scanner():
        form = {
            "hosts": "",
            "ports": "22, 53, 80, 443",
            "timeout": "1",
            "concurrency": "100",
            "open_only": True,
        }
        results = None
        stats = None
        error = ""
        if request.method == "POST":
            form = {
                "hosts": request.form.get("hosts", "").strip(),
                "ports": request.form.get("ports", "").strip(),
                "timeout": request.form.get("timeout", "1").strip(),
                "concurrency": request.form.get("concurrency", "100").strip(),
                "open_only": request.form.get("open_only") == "on",
            }
            try:
                targets = parse_ping_targets(form["hosts"], limit=50)
                ports = parse_tcp_ports(form["ports"], limit=200)
                all_results = scan_tcp_ports(
                    targets,
                    ports,
                    timeout=float(form["timeout"]),
                    max_workers=int(form["concurrency"]),
                )
                stats = {
                    "combinations": len(all_results),
                    "open": sum(result["status"] == "open" for result in all_results),
                    "closed": sum(result["status"] == "closed" for result in all_results),
                    "timeout": sum(result["status"] == "timeout" for result in all_results),
                    "error": sum(result["status"] == "error" for result in all_results),
                }
                results = (
                    [result for result in all_results if result["status"] == "open"]
                    if form["open_only"]
                    else all_results
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid scanner settings."
                record_current_activity("Ports", "Ran TCP port scan", "Request failed")
            else:
                record_current_activity(
                    "Ports",
                    "Ran TCP port scan",
                    f"{len(targets)} host(s), {len(ports)} port(s), {stats['open']} open",
                    counters={"tcp": {"ports_scanned": len(all_results)}},
                )
            annotate_tool_run(
                category="Network tools",
                action_namespace="tcp_scanner",
                tool_name="TCP port scan",
                outcome="failed" if error else "succeeded",
                details={
                    "host count": len(targets) if not error else 0,
                    "port count": len(ports) if not error else 0,
                    "combination count": len(all_results) if not error else 0,
                    "open port count": int(stats["open"]) if stats else 0,
                },
            )
        return render_template(
            "tools/port_scanner.html",
            error=error,
            form=form,
            host_profiles=_port_scan_profile_store("hosts").all(),
            port_profiles=_port_scan_profile_store("ports").all(),
            results=results,
            stats=stats,
        )

    @tools_bp.post("/port-scanner/profiles/<kind>")
    def save_port_scan_profile(kind: str):
        if kind not in {"hosts", "ports"}:
            return jsonify({"error": "Unknown port scanner profile type."}), 404
        name = request.form.get("name", "").strip()
        original_name = request.form.get("original_name", "").strip()
        values = request.form.get("values", "").strip()
        if not name or len(name) > 100:
            return jsonify({"error": "Enter a profile name of 100 characters or fewer."}), 400
        try:
            if kind == "hosts":
                parsed = parse_ping_targets(values, limit=50)
                profile = {"name": name, "values": values, "count": len(parsed)}
            else:
                parsed = parse_tcp_ports(values, limit=200)
                profile = {"name": name, "values": values, "count": len(parsed)}
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 400
        store = _port_scan_profile_store(kind)
        before = store.get(original_name or name)
        store.upsert(profile, original_name=original_name)
        annotate_profile_saved(
            category="Network tools",
            action_namespace=f"tcp_scanner.{kind}",
            profile_type=f"TCP scanner {kind[:-1]} profile",
            before=before,
            after=profile,
        )
        return jsonify({"profile": profile})

    @tools_bp.post("/port-scanner/profiles/<kind>/delete")
    def delete_port_scan_profile(kind: str):
        if kind not in {"hosts", "ports"}:
            return jsonify({"error": "Unknown port scanner profile type."}), 404
        name = request.form.get("name", "").strip()
        store = _port_scan_profile_store(kind)
        profile = store.get(name)
        if not profile or not store.delete(name):
            return jsonify({"error": "Profile not found."}), 404
        annotate_profile_deleted(
            category="Network tools",
            action_namespace=f"tcp_scanner.{kind}",
            profile_type=f"TCP scanner {kind[:-1]} profile",
            profile=profile,
        )
        return jsonify({"deleted": name})


def _port_scan_profile_store(kind: str) -> PortScanProfileStore:
    return PortScanProfileStore(current_app.instance_path, kind)
