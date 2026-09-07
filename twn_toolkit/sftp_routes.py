from __future__ import annotations

import time
import secrets
from flask import abort, current_app, g, jsonify, redirect, render_template, request, send_file, url_for

from .activity_context import record_current_activity
from .investigation_context import record_current_investigation_event
from .audit import annotate_tool_run, suppress_audit_event
from .automation_heartbeat import read_automation_heartbeat
from .datastore import DatastoreError, LocalDatastore, format_bytes
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .diagnostic_worker import record_unsuccessful_scan
from .investigations import InvestigationStore
from .network_tools import ToolInputError
from .transfer_diagnostic import artifact_directory, prepare_transfer_config
from .transfer_tools import DEFAULT_TRANSFER_FILENAME_PATTERN


def register_sftp_routes(tools_bp):
    @tools_bp.route('/multi-transfer', methods=['GET', 'POST'])
    def multi_transfer():
        datastore = LocalDatastore(current_app.instance_path)
        store = diagnostic_store()
        user = g.current_user
        protocol = request.args.get('protocol', 'sftp').lower()
        form = {'hosts': '', 'username': '', 'port': '21' if protocol == 'ftp' else '22',
                'remote_paths': '', 'allow_unknown_hosts': False, 'allow_legacy_algorithms': False,
                'destination': '', 'output_mode': 'download',
                'filename_pattern': DEFAULT_TRANSFER_FILENAME_PATTERN, 'protocol': protocol}
        job = None
        results = None
        error = ''
        page, total = 1, 0
        if request.method == 'POST':
            form = {key: request.form.get(key) == 'on' if isinstance(default, bool)
                    else request.form.get(key, default).strip() for key, default in form.items()}
            try:
                config = prepare_transfer_config(form, request.form.get('password', ''))
                if form['output_mode'] == 'datastore':
                    datastore.list(form['destination'])
                case = InvestigationStore(current_app.instance_path).active_for_user(user['id'])
                config.update(username=user['username'], investigation_id=(case['id'] if case and case.get('is_recording') else ''))
                job_id = store.enqueue(user_id=user['id'], tool='transfer', config=config)
                annotate_tool_run(category='Network tools', action_namespace='transfer.multi_host_fetch',
                    tool_name='Bulk Transfer', outcome='queued', details={'operation id': job_id, 'protocol': form['protocol']})
                return redirect(url_for('tools.multi_transfer', job=job_id), code=303)
            except (ToolInputError, DatastoreError, OSError, TypeError, ValueError) as exc:
                error = str(exc) or 'Enter valid transfer settings.'
                record_current_activity('Network tools', 'Ran Bulk Transfer', 'Request failed')
                record_current_investigation_event(operation_id='multi-transfer-rejected:' + secrets.token_hex(12),
                    event_type='action.failed', tool_id='tools.multi_sftp', action='Bulk Transfer', outcome='failed',
                    summary='Bulk Transfer rejected: ' + error, targets={'hosts': form['hosts']},
                    parameters=form, metrics={}, details={'error': error}, started_at=time.time(), completed_at=time.time())
                annotate_tool_run(category='Network tools', action_namespace='transfer.multi_host_fetch',
                    tool_name='Bulk Transfer', outcome='failed')
        elif request.args.get('job'):
            job = owned_diagnostic(request.args['job'], 'transfer')
            form = job['config']['form']
            try:
                page = max(1, min(50, int(request.args.get('page', 1))))
            except ValueError:
                pass
            if job['state'] == 'succeeded':
                results, total = store.page(job['id'], user['id'], page)
                error = job['summary'].get('error', '')
        for row in results or []:
            row['size_display'] = format_bytes(int(row.get('size', 0)))
        return render_template('tools/multi_sftp.html', error=error, form=form, results=results,
            datastore_folders=datastore.folders(), journal_event=job['summary'].get('journal_event') if job else None,
            diagnostic_job=job, diagnostic_recent=store.recent(user['id'], 'transfer'),
            diagnostic_scheduler=read_automation_heartbeat(store.instance / 'automation-heartbeat.json'),
            result_page=page, result_total=total, transfer_limits=store.policy.get())

    @tools_bp.get('/multi-transfer/jobs/<job_id>/status')
    def transfer_job_status(job_id):
        job = owned_diagnostic(job_id, 'transfer')
        response = jsonify(state=job['state'], error=job['error'], stage=job['summary'].get('stage', ''))
        response.headers['Cache-Control'] = 'no-store'
        return response

    @tools_bp.post('/multi-transfer/jobs/<job_id>/cancel')
    def cancel_transfer_job(job_id):
        owned_diagnostic(job_id, 'transfer')
        store = diagnostic_store()
        cancelled = store.cancel(job_id, g.current_user['id'])
        if cancelled:
            record_unsuccessful_scan(store, cancelled, 'cancelled', 'Cancelled before execution started.')
        annotate_tool_run(category='Network tools', action_namespace='transfer.cancel',
            tool_name='Bulk Transfer', outcome='requested', details={'operation id': job_id})
        return redirect(url_for('tools.multi_transfer', job=job_id), code=303)

    @tools_bp.get('/multi-transfer/jobs/<job_id>/download')
    def download_transfer_job(job_id):
        job = owned_diagnostic(job_id, 'transfer')
        store = diagnostic_store()
        if job['state'] != 'succeeded' or not job['summary'].get('archive'):
            abort(404)
        if time.time() - job['completed'] > store.policy.get()['diagnostic_retention_hours'] * 3600:
            abort(410, 'This transfer archive has expired.')
        archive = artifact_directory(store, job_id) / 'download.zip'
        if not archive.is_file() or archive.is_symlink():
            abort(410, 'This transfer archive is no longer available.')
        response = send_file(archive, mimetype='application/zip', as_attachment=True,
            download_name=f"multi-transfer-{job['config']['form']['protocol']}-{job_id[:12]}.zip", conditional=True)
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    @tools_bp.route('/multi-sftp', methods=['GET', 'POST'])
    def multi_sftp():
        suppress_audit_event()
        return redirect(url_for('tools.multi_transfer', protocol='sftp'), code=307 if request.method == 'POST' else 302)
