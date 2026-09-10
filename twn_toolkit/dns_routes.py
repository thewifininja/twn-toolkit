from __future__ import annotations

import secrets
import time

from flask import Blueprint, current_app, g, jsonify, redirect, render_template, request, url_for

from .mso_ui import save_profile, delete_profile, mutation
from .activity_context import record_current_activity
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .diagnostic_worker import record_unsuccessful_scan
from .dns_diagnostic import prepare_dns_config
from .investigations import InvestigationStore
from .automation_heartbeat import read_automation_heartbeat
from .audit import annotate_profile_deleted, annotate_profile_duplicated, annotate_profile_saved, annotate_tool_run
from .investigation_context import record_current_investigation_event
from .network_tools import (
    DNS_LOAD_MAX_CONCURRENCY,
    DNS_LOAD_MAX_DURATION_SECONDS,
    DNS_LOAD_MAX_QPS_PER_SERVER,
    DNS_LOAD_MAX_QUERIES,
    DNS_LOAD_MAX_SERVERS,
    ToolInputError,
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
        journal_event = None
        error = ""
        store = diagnostic_store()
        user = g.current_user
        job = None
        page, total = 1, 0
        if request.method == "POST":
            form = {key: request.form.get(key, default).strip() for key, default in form.items()}
            try:
                config = prepare_dns_config(form)
                investigation = InvestigationStore(current_app.instance_path).active_for_user(user['id'])
                config.update(username=user['username'], investigation_id=(
                    investigation['id'] if investigation and investigation.get('is_recording') else ''))
                job_id = store.enqueue(user_id=user['id'], tool='dns', config=config)
                annotate_tool_run(category='Network tools', action_namespace='dns.' + form['mode'],
                                  tool_name='DNS test', outcome='queued', details={'operation id': job_id})
                return redirect(url_for('tools.dns_response', job=job_id), code=303)
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or 'Enter valid DNS test settings.'
                record_current_activity('Resolution', 'Ran DNS load test' if form['mode'] == 'load' else 'Ran DNS lookup', 'Request failed')
                record_current_investigation_event(
                    operation_id='dns-rejected:' + secrets.token_hex(12), event_type='diagnostic.failed',
                    tool_id='tools.dns_response', action='DNS test', outcome='failed',
                    summary='DNS test rejected: ' + error, targets={'hosts': form['hosts'], 'resolvers': form['servers']},
                    parameters=form, metrics={}, details={'error': error}, started_at=time.time(), completed_at=time.time())
                annotate_tool_run(category='Network tools', action_namespace='dns.' + ('load_test' if form['mode'] == 'load' else 'lookup'),
                                  tool_name='DNS test', outcome='failed')
        elif request.args.get('job'):
            job = owned_diagnostic(request.args['job'], 'dns')
            form = job['config']['form']
            try:
                page = max(1, min(50, int(request.args.get('page', 1))))
            except ValueError:
                page = 1
            if job['state'] == 'succeeded':
                load_result = job['summary'].get('load_result')
                lookup_summary = job['summary'].get('lookup_summary')
                journal_event = job['summary'].get('journal_event')
                if form['mode'] == 'compare':
                    results, total = store.page(job['id'], user['id'], page)
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
            journal_event=journal_event,
            diagnostic_job=job, diagnostic_recent=store.recent(user['id'], 'dns'),
            diagnostic_scheduler=read_automation_heartbeat(store.instance / 'automation-heartbeat.json'),
            result_page=page, result_total=total,
        )

    @tools_bp.get('/dns-response/jobs/<job_id>/status')
    def dns_job_status(job_id):
        job = owned_diagnostic(job_id, 'dns')
        response = jsonify({'state': job['state'], 'error': job['error']})
        response.headers['Cache-Control'] = 'no-store'
        return response

    @tools_bp.post('/dns-response/jobs/<job_id>/cancel')
    def cancel_dns_job(job_id):
        owned_diagnostic(job_id, 'dns')
        store = diagnostic_store()
        cancelled = store.cancel(job_id, g.current_user['id'])
        if cancelled:
            record_unsuccessful_scan(store, cancelled, 'cancelled', 'Cancelled before execution started.')
        annotate_tool_run(category='Network tools', action_namespace='dns.cancel', tool_name='DNS test',
                          outcome='requested', details={'operation id': job_id})
        return redirect(url_for('tools.dns_response', job=job_id), code=303)

    @tools_bp.post("/dns-response/profiles/<kind>")
    @mutation
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
        original_name = request.form.get("original_name", "").strip()
        before = store.get(original_name or name)
        save_profile(store, profile, original_name=original_name)
        annotate_profile_saved(
            category="Network tools",
            action_namespace=f"dns.{kind}",
            profile_type=f"DNS {'host' if kind == 'hosts' else 'server'} profile",
            before=before,
            after=profile,
        )
        return jsonify({"profile": profile})

    @tools_bp.post("/dns-response/profiles/<kind>/delete")
    @mutation
    def delete_dns_profile(kind: str):
        if kind not in {"hosts", "servers"}:
            return jsonify({"error": "Unknown DNS profile type."}), 404
        name = request.form.get("name", "").strip()
        store = _dns_profile_store(kind)
        profile = store.get(name)
        if not profile or not delete_profile(store, name):
            return jsonify({"error": "Profile not found."}), 404
        annotate_profile_deleted(
            category="Network tools",
            action_namespace=f"dns.{kind}",
            profile_type=f"DNS {'host' if kind == 'hosts' else 'server'} profile",
            profile=profile,
        )
        return jsonify({"deleted": name})

    @tools_bp.post("/dns-response/profiles/<kind>/duplicate")
    def duplicate_dns_profile(kind: str):
        if kind not in {"hosts", "servers"}:
            return jsonify({"error": "Unknown DNS profile type."}), 404
        name = request.form.get("name", "").strip()
        store = _dns_profile_store(kind)
        source = store.get(name)
        if not source:
            return jsonify({"error": "Profile not found."}), 404
        copied = store.duplicate(name)
        annotate_profile_duplicated(
            category="Network tools", action_namespace=f"dns.{kind}",
            profile_type=f"DNS {'host' if kind == 'hosts' else 'server'} profile",
            source=source, copied=copied,
        )
        return jsonify({"profile": next(p for p in store.mso_store().profiles(metadata=True) if p["name"] == copied["name"])})


def _dns_profile_store(kind: str) -> DNSProfileStore:
    return DNSProfileStore(current_app.instance_path, kind)
