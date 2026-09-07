"""Owner/tool-scoped appliance job pages and finite polling responses."""
from __future__ import annotations

import time
import json
from flask import abort, flash, g, jsonify, redirect, render_template, request, send_file, url_for
from .audit import suppress_audit_event
from .automation_heartbeat import read_automation_heartbeat
from .appliance_read import TOOL, record_read_outcome
from .csv_exports import csv_download_filename, normalize_csv_download_format
from .diagnostic_artifacts import artifact_directory
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .investigations import InvestigationStore
from .tool_catalog import tool_id_for_endpoint


def queue_read(app, profile, *, provider, mode, task=None, as_json=False):
    if not profile:
        if as_json:
            return jsonify(error='Select a valid appliance profile.'), 400
        flash('Profile not found.', 'error')
        return redirect(url_for(provider + '_home'))
    user = g.current_user
    case = InvestigationStore(app.instance_path).active_for_user(user['id'])
    config = dict(profile=profile, provider=provider, mode=mode, username=user['username'],
        investigation_id=case['id'] if case and case.get('is_recording') else '',
        tool_id=tool_id_for_endpoint(request.endpoint, request.view_args),
        label=(task.label if task else ('FortiGate' if provider == 'fortigate' else 'FortiAuthenticator') + ' connection test'),
        task_id=task.id if task else '', fields=request.form.get('fields', '').strip(),
        endpoint_template=request.form.get('endpoint_template', '').strip(),
        csv_format=normalize_csv_download_format(request.form.get('csv_format')))
    suppress_audit_event()
    try:
        identifier = diagnostic_store().enqueue(user_id=user['id'], tool=TOOL, config=config)
    except ValueError as exc:
        if as_json:
            return jsonify(error=str(exc)), 409
        abort(409, str(exc))
    prefix = 'appliance_task' if task else provider + '_connection'
    args = {'task_id': task.id} if task else {}
    location = url_for(prefix + '_job', job_id=identifier, **args)
    if as_json:
        return jsonify(job_url=location, status_url=url_for(prefix + '_status', job_id=identifier, **args),
                       cancel_url=url_for(prefix + '_cancel', job_id=identifier, **args)), 202
    return redirect(location, code=303)


def register_read_routes(app, provider, *, task_routes=False):
    prefix = 'appliance_task' if task_routes else provider + '_connection'
    base = '/tasks/<task_id>/jobs' if task_routes else '/' + provider + '/connection-jobs'

    def owned(job_id, task_id=None):
        job = owned_diagnostic(job_id, TOOL)
        config = job['config']
        if config['provider'] != provider or config['task_id'] != (task_id or ''):
            abort(404)
        return job

    def page(job_id, task_id=None):
        job = owned(job_id, task_id)
        args = {'task_id': task_id} if task_id else {}
        store = diagnostic_store()
        return render_template('appliance_read_job.html', diagnostic_job=job, diagnostic_label=job['config']['label'],
            diagnostic_status_url=url_for(prefix + '_status', job_id=job_id, **args),
            diagnostic_cancel_url=url_for(prefix + '_cancel', job_id=job_id, **args),
            diagnostic_status_endpoint=prefix + '_status', diagnostic_cancel_endpoint=prefix + '_cancel',
            diagnostic_result_endpoint=prefix + '_job', diagnostic_result_url=url_for(prefix + '_job', job_id=job_id, **args), diagnostic_recent=[],
            diagnostic_scheduler=read_automation_heartbeat(store.instance/'automation-heartbeat.json'),
            download_url=url_for(prefix + '_download', job_id=job_id, **args),
            back_url=url_for('task_form', task_id=task_id) if task_id else url_for(provider + '_home'))

    def status(job_id, task_id=None):
        job = owned(job_id, task_id)
        response = jsonify(state=job['state'], error=job['error'], data=job['summary'] if job['state'] == 'succeeded' else None)
        response.headers['Cache-Control'] = 'no-store'
        return response

    def cancel(job_id, task_id=None):
        owned(job_id, task_id)
        job = diagnostic_store().cancel(job_id, g.current_user['id'])
        if job:
            record_read_outcome(diagnostic_store(), job, 'cancelled')
        args = {'task_id': task_id} if task_id else {}
        return redirect(url_for(prefix + '_job', job_id=job_id, **args), code=303)

    def download(job_id, task_id=None):
        job = owned(job_id, task_id)
        if job['state'] != 'succeeded' or not job['summary'].get('archive'):
            abort(404)
        store = diagnostic_store()
        if time.time() - job['completed'] > store.policy.get()['diagnostic_retention_hours'] * 3600:
            abort(410, 'This export has expired.')
        path = artifact_directory(store, job_id, TOOL) / 'download.csv'
        if not path.is_file() or path.is_symlink():
            abort(410, 'This export is no longer available.')
        response = send_file(path, as_attachment=True, conditional=True, mimetype='text/csv',
            download_name=csv_download_filename(job['config']['task_id'] + '-' + job_id[:12] + '.csv', job['config']['csv_format']))
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    for suffix, handler, method in [('job', page, 'GET'), ('status', status, 'GET'), ('cancel', cancel, 'POST'), ('download', download, 'GET')]:
        app.add_url_rule(base + '/<job_id>/' + suffix, prefix + '_' + suffix, handler, methods=[method])


def recent_read_links(provider, task_id=''):
    store = diagnostic_store()
    links = []
    with store.connect() as db:
        recent = db.execute("SELECT id,state,config FROM diagnostic_jobs WHERE user_id=? AND tool=? ORDER BY created DESC LIMIT 10",
                            (g.current_user['id'], TOOL)).fetchall()
    for row in recent:
        job = dict(row)
        config = json.loads(store.cipher.open(job['config'], job['id'] + ':diagnostic-config'))
        if config['provider'] != provider or config['task_id'] != task_id:
            continue
        prefix = 'appliance_task' if task_id else provider + '_connection'
        args = {'task_id': task_id} if task_id else {}
        links.append({'url': url_for(prefix + '_job', job_id=job['id'], **args),
                      'id': job['id'], 'state': job['state'], 'mode': config['mode']})
    return links
