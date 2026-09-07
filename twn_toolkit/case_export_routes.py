"""Owner-scoped preparation, progress, and downloads for case export jobs."""
from __future__ import annotations

import time
from flask import abort, current_app, g, jsonify, redirect, render_template, send_file, url_for, request

from .audit import annotate_audit_event, suppress_audit_event
from .automation_heartbeat import read_automation_heartbeat
from .datastore import format_bytes
from .diagnostic_artifacts import artifact_directory
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .case_export import KINDS, TOOL, record_case_export_outcome
from .investigations import InvestigationStore, InvestigationError


def queue_case_export(case_id, kind):
    user = g.current_user
    try:
        InvestigationStore(current_app.instance_path).get_for_user(case_id, user['id'])
    except InvestigationError:
        abort(404)
    suppress_audit_event()
    try:
        identifier = diagnostic_store().enqueue(user_id=user['id'], tool=TOOL, config={
            'kind':kind, 'investigation_id':case_id, 'username':user['username']})
    except ValueError as exc:
        abort(409, str(exc))
    return redirect(url_for('case_export_job', job=identifier), code=303)


def register_case_export_routes(app):
    def owned(identifier, *, require_case=True):
        job = owned_diagnostic(identifier, TOOL)
        if require_case:
            try:
                InvestigationStore(app.instance_path).get_for_user(job['config']['investigation_id'], g.current_user['id'])
            except InvestigationError:
                abort(404)
        return job

    @app.get('/investigations/exports')
    def case_export_job():
        job = owned(request.args.get('job', ''))
        store = diagnostic_store()
        return render_template('investigations/export_job.html', diagnostic_job=job, format_bytes=format_bytes,
            diagnostic_label=KINDS[job['config']['kind']], diagnostic_result_endpoint='case_export_job',
            diagnostic_status_endpoint='case_export_status', diagnostic_cancel_endpoint='case_export_cancel',
            diagnostic_recent=store.recent(g.current_user['id'], TOOL),
            diagnostic_scheduler=read_automation_heartbeat(store.instance/'automation-heartbeat.json'))

    @app.get('/investigations/exports/<job_id>/status')
    def case_export_status(job_id):
        job = owned(job_id)
        response = jsonify(state=job['state'], error=job['error'])
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.post('/investigations/exports/<job_id>/cancel')
    def case_export_cancel(job_id):
        owned(job_id, require_case=False)
        store = diagnostic_store()
        job = store.cancel(job_id, g.current_user['id'])
        if job:
            record_case_export_outcome(store, job, 'cancelled')
        return redirect(url_for('case_export_job', job=job_id), code=303)

    @app.get('/investigations/exports/<job_id>/download')
    def case_export_download(job_id):
        job = owned(job_id)
        if job['state'] != 'succeeded':
            abort(404)
        store = diagnostic_store()
        if time.time()-job['completed'] > store.policy.get()['diagnostic_retention_hours']*3600:
            abort(410, 'This case export has expired.')
        path = artifact_directory(store, job_id, TOOL)/'export.bin'
        if not path.is_file() or path.is_symlink():
            abort(410, 'This case export is no longer available.')
        kind = job['config']['kind']
        action = {'pdf':'report_pdf_downloaded', 'package':'package_downloaded', 'portable':'portable_case_downloaded'}[kind]
        annotate_audit_event(category='Investigations', action='investigation.'+action,
            summary='Downloaded '+KINDS[kind]+'.', resource_type='investigation',
            resource_id=job['config']['investigation_id'],
            details={'operation id':job_id, 'event count':job['summary']['event_count'],
                     'evidence count':job['summary']['artifact_count'], 'byte count':job['summary']['byte_count']})
        response = send_file(path, as_attachment=True, conditional=True,
            download_name=job['summary']['filename'], mimetype=job['summary']['mimetype'])
        response.headers['Cache-Control'] = 'private, no-store'
        return response
