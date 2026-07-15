from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_profile_deleted, annotate_profile_saved
from .network_tools import (
    ToolInputError,
    dns_lookup_matrix,
    parse_dns_hosts,
    parse_dns_servers,
)
from .profiles import DNSProfileStore


def register_dns_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/dns-response", methods=["GET", "POST"])
    def dns_response():
        form = {
            "hosts": "",
            "servers": "",
            "host_profile": "",
            "server_profile": "",
            "record_type": "A",
            "timeout": "3",
        }
        results = None
        error = ""
        if request.method == "POST":
            form = {key: request.form.get(key, "").strip() for key in form}
            try:
                hosts = parse_dns_hosts(form["hosts"], limit=100)
                servers = parse_dns_servers(form["servers"], limit=20)
                results = dns_lookup_matrix(
                    hosts, servers, form["record_type"], float(form["timeout"])
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter a valid DNS timeout."
                record_current_activity("Resolution", "Ran DNS lookup", "Request failed")
            else:
                record_current_activity(
                    "Resolution",
                    "Ran DNS lookup",
                    f"{len(hosts)} host(s) across {len(servers)} resolver(s)",
                    counters={"dns": {"queries": len(results)}},
                )
        return render_template(
            "tools/dns_response.html",
            error=error,
            form=form,
            host_profiles=_dns_profile_store("hosts").all(),
            server_profiles=_dns_profile_store("servers").all(),
            results=results,
        )

    @tools_bp.post("/dns-response/profiles/<kind>")
    def save_dns_profile(kind: str):
        if kind not in {"hosts", "servers"}:
            return jsonify({"error": "Unknown DNS profile type."}), 404
        name = request.form.get("profile_name", "").strip()
        values = request.form.get("values", "").strip()
        if not name:
            return jsonify({"error": "Enter a profile name."}), 400
        if len(name) > 100:
            return jsonify({"error": "Profile names must be 100 characters or fewer."}), 400
        try:
            parsed = parse_dns_hosts(values) if kind == "hosts" else parse_dns_servers(values)
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 400
        profile = {"name": name, "values": parsed}
        store = _dns_profile_store(kind)
        before = store.get(name)
        store.upsert(profile)
        annotate_profile_saved(
            category="Network tools",
            action_namespace=f"dns.{kind}",
            profile_type=f"DNS {'host' if kind == 'hosts' else 'server'} profile",
            before=before,
            after=profile,
        )
        return jsonify({"profile": profile})

    @tools_bp.post("/dns-response/profiles/<kind>/delete")
    def delete_dns_profile(kind: str):
        if kind not in {"hosts", "servers"}:
            return jsonify({"error": "Unknown DNS profile type."}), 404
        name = request.form.get("name", "").strip()
        store = _dns_profile_store(kind)
        profile = store.get(name)
        if not profile or not store.delete(name):
            return jsonify({"error": "Profile not found."}), 404
        annotate_profile_deleted(
            category="Network tools",
            action_namespace=f"dns.{kind}",
            profile_type=f"DNS {'host' if kind == 'hosts' else 'server'} profile",
            profile=profile,
        )
        return jsonify({"deleted": name})


def _dns_profile_store(kind: str) -> DNSProfileStore:
    return DNSProfileStore(current_app.instance_path, kind)
