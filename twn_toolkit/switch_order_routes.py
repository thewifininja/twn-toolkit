"""Owner/tool-scoped switch-order admission and retained operation pages."""
from __future__ import annotations

import hashlib
from flask import abort, g, jsonify, make_response, redirect, render_template, request, url_for
from .audit import suppress_audit_event, suppress_case_bridge_event
from .automation_heartbeat import read_automation_heartbeat
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .investigations import InvestigationStore
from .switch_order_jobs import TOOL, MAX_SWITCHES, record_switch_outcome
from .rename_preview import rename_target


def queue_switch_order(app, profile, *, mode, vdom, **review):
    user = g.current_user
    if mode == 'apply' and (len(review['original_ids']) > MAX_SWITCHES or any(len(value) > 128 for value in review['original_ids'])):
        return jsonify(error='Switch ordering supports up to 500 switches with identifiers up to 128 characters.'), 400
    case = InvestigationStore(app.instance_path).active_for_user(user['id'])
    config = dict(profile=profile, mode=mode, vdom=vdom, username=user['username'],
                  investigation_id=case['id'] if case and case.get('is_recording') else '', **review)
    key = hashlib.sha256(('switch-order:' + review['preview_token']).encode()).hexdigest() if mode == 'apply' else None
    suppress_audit_event()
    suppress_case_bridge_event()
    try:
        job_id = diagnostic_store().enqueue(user_id=user['id'], tool=TOOL, config=config, request_key=key)
    except ValueError as exc:
        return jsonify(error=str(exc)), 409
    return jsonify(job_url=url_for('switch_order_job', job_id=job_id),
                   status_url=url_for('switch_order_status', job_id=job_id),
                   cancel_url=url_for('switch_order_cancel', job_id=job_id)), 202


def register_switch_order_jobs(app):
    @app.get('/fortigate/switch-order/jobs/<job_id>')
    def switch_order_job(job_id):
        job = owned_diagnostic(job_id, TOOL)
        try:
            page = max(1, min(10, int(request.args.get('page', '1'))))
        except ValueError:
            abort(400, 'Invalid result page.')
        summary = job['summary']
        rows = summary.get('switches', [])
        moves = summary.get('completed_moves', [])
        original = job['config'].get('original_ids', [])
        desired = job['config'].get('desired_ids', [])
        pages = max(1, (max(len(rows), len(moves), len(original)) + 49)//50)
        page = min(page, pages)
        start, end = (page-1)*50, page*50
        response = make_response(render_template('switch_order_job.html', diagnostic_job=job,
            diagnostic_label='FortiSwitch ' + ('reorder' if job['config']['mode'] == 'apply' else 'inventory'),
            diagnostic_scheduler=read_automation_heartbeat(diagnostic_store().instance/'automation-heartbeat.json'),
            diagnostic_status_url=url_for('switch_order_status', job_id=job_id),
            diagnostic_cancel_url=url_for('switch_order_cancel', job_id=job_id),
            diagnostic_result_url=url_for('switch_order_job', job_id=job_id),
            target_origin=rename_target(job['config']['profile']),
            switches=rows[start:end], completed_moves=moves[start:end],
            reviewed_orders=list(zip(original[start:end], desired[start:end])), page=page, pages=pages))
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    @app.get('/fortigate/switch-order/jobs/<job_id>/status')
    def switch_order_status(job_id):
        job = owned_diagnostic(job_id, TOOL)
        response = jsonify(state=job['state'], error=job['error'], data=job['summary'],
                           stage=job['summary'].get('phase', 'queued').replace('_', ' '))
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.post('/fortigate/switch-order/jobs/<job_id>/cancel')
    def switch_order_cancel(job_id):
        owned_diagnostic(job_id, TOOL)
        previous = diagnostic_store().cancel(job_id, g.current_user['id'])
        if previous:
            record_switch_outcome(diagnostic_store(), previous, 'cancelled')
        return redirect(url_for('switch_order_job', job_id=job_id), code=303)
