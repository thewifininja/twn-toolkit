"""Finite local preview input and owner/task-scoped supervised rename routes."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import string

from flask import abort, flash, g, make_response, redirect, render_template, request, url_for

from .audit import suppress_audit_event, suppress_case_bridge_event
from .automation_heartbeat import read_automation_heartbeat
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .investigations import InvestigationStore
from .rename_jobs import TOOL, MAX_ENTRIES, record_rename_outcome
from .rename_preview import rename_target
from .tasks import get_task

MAX_PREVIEW_BYTES = 64 * 1024


def bounded_rename_entries(entries, endpoint):
    if len(entries) > MAX_ENTRIES:
        raise ValueError('A rename preview supports up to 500 rows. Split the input and review each batch.')
    if len(endpoint) > 2048:
        raise ValueError('The rename endpoint is too long.')
    try:
        for _, field, specification, conversion in string.Formatter().parse(endpoint):
            if field is not None and (field != 'current_name' or specification or conversion):
                raise ValueError('Unsupported endpoint placeholder.')
    except (KeyError, IndexError, ValueError) as exc:
        raise ValueError('The rename endpoint must use only the {current_name} placeholder.') from exc
    if len(json.dumps(entries, ensure_ascii=False).encode()) > MAX_PREVIEW_BYTES:
        raise ValueError('Rename preview input exceeds the 64 KiB envelope. Split the input and review each batch.')
    return entries


def read_rename_csv(stream, default_vdom):
    raw = stream.read(MAX_PREVIEW_BYTES + 1)
    if len(raw) > MAX_PREVIEW_BYTES:
        raise ValueError('Rename CSV input exceeds 64 KiB. Split the file and review each batch.')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeError as exc:
        raise ValueError('Rename CSV must use UTF-8 text.') from exc
    rows = csv.DictReader(io.StringIO(text, newline=''))
    if not rows.fieldnames:
        raise ValueError('CSV file is empty.')
    if 'new_name' not in rows.fieldnames or not {'identifier', 'current_name'}.intersection(rows.fieldnames):
        raise ValueError('CSV requires new_name and either identifier or current_name.')
    entries = []
    for row in rows:
        if len(entries) >= MAX_ENTRIES:
            raise ValueError('A rename preview supports up to 500 rows. Split the file and review each batch.')
        entries.append({'identifier': (row.get('identifier') or row.get('current_name') or '').strip(),
                        'current_name': (row.get('current_name') or '').strip(),
                        'new_name': (row.get('new_name') or '').strip(),
                        'vdom': (row.get('vdom') or default_vdom).strip() or 'root'})
    return entries


def queue_rename(app, task, profile, entries, endpoint):
    case = InvestigationStore(app.instance_path).active_for_user(g.current_user['id'])
    config = dict(profile=profile, task_id=task.id, endpoint=endpoint, entries=entries,
                  target_revision=request.form.get('target_revision', ''), preview_token=request.form.get('preview_token', ''),
                  username=g.current_user['username'], investigation_id=case['id'] if case and case.get('is_recording') else '')
    suppress_audit_event()
    suppress_case_bridge_event()
    try:
        identifier = diagnostic_store().enqueue(user_id=g.current_user['id'], tool=TOOL, config=config,
            request_key=hashlib.sha256(('rename:' + config['preview_token']).encode()).hexdigest())
    except ValueError as exc:
        flash(str(exc), 'error')
        return redirect(url_for('task_form', task_id=task.id))
    return redirect(url_for('rename_job', task_id=task.id, job_id=identifier), code=303)


def register_rename_jobs(app):
    def owned(task_id, job_id):
        job = owned_diagnostic(job_id, TOOL)
        if job['config']['task_id'] != task_id:
            abort(404)
        return job

    @app.get('/tasks/<task_id>/rename-jobs/<job_id>')
    def rename_job(task_id, job_id):
        job = owned(task_id, job_id)
        try:
            page = max(1, min(10, int(request.args.get('page', '1'))))
        except ValueError:
            abort(400)
        pages = max(1, (len(job['config']['entries']) + 49)//50)
        page = min(page, pages)
        rows = job['summary'].get('results', [])
        response = make_response(render_template('rename_job.html', diagnostic_job=job,
            task=get_task(task_id), diagnostic_label=get_task(task_id).label,
            diagnostic_scheduler=read_automation_heartbeat(diagnostic_store().instance/'automation-heartbeat.json'),
            diagnostic_result_url=url_for('rename_job', task_id=task_id, job_id=job_id),
            diagnostic_status_url=url_for('rename_job_status', task_id=task_id, job_id=job_id),
            diagnostic_cancel_url=url_for('rename_job_cancel', task_id=task_id, job_id=job_id),
            target_origin=rename_target(job['config']['profile']), page=page, pages=pages,
            entries=job['config']['entries'][(page-1)*50:page*50], results=rows[(page-1)*50:page*50]))
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    @app.get('/tasks/<task_id>/rename-jobs/<job_id>/status')
    def rename_job_status(task_id, job_id):
        job = owned(task_id, job_id)
        from flask import jsonify
        response = jsonify(state=job['state'], error=job['error'], stage=job['summary'].get('phase', 'queued').replace('_', ' '))
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.post('/tasks/<task_id>/rename-jobs/<job_id>/cancel')
    def rename_job_cancel(task_id, job_id):
        owned(task_id, job_id)
        previous = diagnostic_store().cancel(job_id, g.current_user['id'])
        if previous:
            record_rename_outcome(diagnostic_store(), previous, 'cancelled')
        return redirect(url_for('rename_job', task_id=task_id, job_id=job_id), code=303)


def recent_rename_links(task_id):
    store = diagnostic_store()
    links = []
    for row in store.recent(g.current_user['id'], TOOL):
        job = store.get(row['id'], g.current_user['id'])
        if job and job['config']['task_id'] == task_id:
            links.append({**row, 'mode': 'apply', 'url': url_for('rename_job', task_id=task_id, job_id=row['id'])})
    return links
