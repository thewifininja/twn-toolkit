from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_profile_deleted, annotate_profile_saved, annotate_tool_run
from .network_tools import (
    DNS_LOAD_MAX_CONCURRENCY,
    DNS_LOAD_MAX_DURATION_SECONDS,
    DNS_LOAD_MAX_QPS_PER_SERVER,
    DNS_LOAD_MAX_QUERIES,
    DNS_LOAD_MAX_SERVERS,
    ToolInputError,
    dns_load_test,
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
            "mode": "compare",
            "duration": "10",
            "qps": "50",
            "concurrency": "40",
            "authorized": "",
        }
        results = None
        load_result = None
        lookup_summary = None
        error = ""
        if request.method == "POST":
            form = {
                key: request.form.get(key, default).strip()
                for key, default in form.items()
            }
            try:
                if form["mode"] not in {"compare", "load"}:
                    raise ToolInputError("Select a valid DNS test mode.")
                hosts = parse_dns_hosts(form["hosts"], limit=100)
                server_limit = (
                    DNS_LOAD_MAX_SERVERS if form["mode"] == "load" else 20
                )
                servers = parse_dns_servers(
                    form["servers"],
                    limit=server_limit,
                )
                timeout = float(form["timeout"])
                if form["mode"] == "load":
                    if form["authorized"] != "on":
                        raise ToolInputError(
                            "Confirm that you are authorized to load test these "
                            "DNS servers."
                        )
                    load_result = dns_load_test(
                        hosts,
                        servers,
                        form["record_type"],
                        timeout,
                        duration_seconds=int(form["duration"]),
                        qps_per_server=int(form["qps"]),
                        concurrency=int(form["concurrency"]),
                    )
                else:
                    results = dns_lookup_matrix(
                        hosts,
                        servers,
                        form["record_type"],
                        timeout,
                    )
                    successful = [
                        result
                        for result in results
                        if result.get("status") == "success"
                    ]
                    lookup_summary = {
                        "queries": len(results),
                        "successful": len(successful),
                        "failed": len(results) - len(successful),
                        "average_ms": (
                            round(
                                sum(
                                    float(result["response_ms"])
                                    for result in successful
                                )
                                / len(successful),
                                1,
                            )
                            if successful
                            else None
                        ),
                        "slowest_ms": (
                            max(
                                float(result["response_ms"])
                                for result in successful
                            )
                            if successful
                            else None
                        ),
                    }
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid DNS test settings."
                activity_title = (
                    "Ran DNS load test"
                    if form["mode"] == "load"
                    else "Ran DNS lookup"
                )
                record_current_activity(
                    "Resolution",
                    activity_title,
                    "Request failed",
                )
            else:
                query_count = (
                    load_result["completed_queries"]
                    if load_result is not None
                    else len(results or [])
                )
                activity_title = (
                    "Ran DNS load test"
                    if form["mode"] == "load"
                    else "Ran DNS lookup"
                )
                activity_summary = (
                    f"{query_count} queries across {len(servers)} resolver(s)"
                    if form["mode"] == "load"
                    else f"{len(hosts)} host(s) across {len(servers)} resolver(s)"
                )
                record_current_activity(
                    "Resolution",
                    activity_title,
                    activity_summary,
                    counters={"dns": {"queries": query_count}},
                )
            annotate_tool_run(
                category="Network tools",
                action_namespace=(
                    "dns.load_test"
                    if form["mode"] == "load"
                    else "dns.lookup"
                ),
                tool_name=(
                    "DNS load test"
                    if form["mode"] == "load"
                    else "DNS lookup"
                ),
                outcome="failed" if error else "succeeded",
                details={
                    "host count": len(hosts) if not error else 0,
                    "resolver count": len(servers) if not error else 0,
                    "query count": (
                        load_result["completed_queries"]
                        if load_result is not None
                        else len(results or [])
                    ),
                    "record type": form["record_type"],
                    "mode": form["mode"],
                    "duration seconds": (
                        form["duration"] if form["mode"] == "load" else None
                    ),
                    "queries per second per resolver": (
                        form["qps"] if form["mode"] == "load" else None
                    ),
                    "concurrency": (
                        form["concurrency"]
                        if form["mode"] == "load"
                        else None
                    ),
                },
            )
        return render_template(
            "tools/dns_response.html",
            error=error,
            form=form,
            host_profiles=_dns_profile_store("hosts").all(),
            server_profiles=_dns_profile_store("servers").all(),
            load_limits={
                "concurrency": DNS_LOAD_MAX_CONCURRENCY,
                "duration": DNS_LOAD_MAX_DURATION_SECONDS,
                "qps": DNS_LOAD_MAX_QPS_PER_SERVER,
                "queries": DNS_LOAD_MAX_QUERIES,
                "servers": DNS_LOAD_MAX_SERVERS,
            },
            load_result=load_result,
            lookup_summary=lookup_summary,
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
