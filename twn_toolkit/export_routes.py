"""Owner-only admission, progress and downloads for finite export jobs."""
import time
from flask import abort, current_app, g, jsonify, redirect, render_template, request, send_file, url_for

from .auth import load_or_create_secret_key
from .automation import AutomationStore
from .audit import annotate_audit_event
from .automation_heartbeat import read_automation_heartbeat
from .datastore import format_bytes
from .diagnostic_artifacts import artifact_directory
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .investigations import InvestigationStore, InvestigationError



def require_admin():
    if not g.current_user.get('is_admin'):
        abort(403)


def automation_store():
    return AutomationStore(current_app.instance_path,load_or_create_secret_key(current_app.instance_path))


def queue_automation_export(runs, run_id, *, attach=False):
    require_admin()
    run=runs.get_run(run_id,metadata_only=True)
    if run is None:
        abort(404)
    config={'run_id':run_id,'username':g.current_user['username']}
    if attach:
        case=InvestigationStore(current_app.instance_path).active_for_user(g.current_user['id'])
        if not case or not case.get('is_recording'):
            raise ValueError('Open or resume a recording case before adding a collected run.')
        config['investigation_id']=case['id']
    identifier=diagnostic_store().enqueue(user_id=g.current_user['id'],tool='automation_export',config=config)
    annotate_audit_event(category='Automation',action='automation.export_queued',
        summary='Queued a collected run ZIP'+(' for the original case.' if attach else '.'),
        resource_type='automation run',resource_id=run_id,
        details={'operation id':identifier,'case id':config.get('investigation_id','')})
    return redirect(url_for('automation_export_job',job=identifier),code=303)


def queue_configuration_export(selected_items, encrypted, password):
    require_admin()
    if len(password)>4096:
        raise ValueError('The backup encryption password must not exceed 4096 characters.')
    config={'selected_ids':[item['id'] for item in selected_items],
            'encrypted':bool(encrypted),'username':g.current_user['username']}
    if encrypted:
        config['password']=password
    identifier=diagnostic_store().enqueue(user_id=g.current_user['id'],tool='configuration_export',config=config)
    annotate_audit_event(category='Backup and restore',action='backup.export_queued',
        summary='Queued a configuration backup.',resource_type='configuration_backup',resource_id=identifier,
        details={'group count':len(selected_items),'encrypted':bool(encrypted)})
    return redirect(url_for('configuration_export_job',job=identifier),code=303)


def register_export_family(app, family):
    assert family in ('automation_export','configuration_export')
    prefix='/automations/exports' if family=='automation_export' else '/settings/backup/exports'
    label='Automation run ZIP' if family=='automation_export' else 'Configuration backup'

    def owned(job_id, *, require_resource=True):
        require_admin()
        job=owned_diagnostic(job_id,family)
        if family=='automation_export' and require_resource:
            if not job['config'].get('investigation_id'):
                if automation_store().get_run(job['config']['run_id'],metadata_only=True) is None:
                    abort(404)
            else:
                try:
                    from .case_export_source import require_case_export_access
                    require_case_export_access(app.instance_path,job['config']['investigation_id'],g.current_user['id'])
                except InvestigationError:
                    abort(404)
        # Never pass retained encryption passwords into HTML/JSON contexts.
        job['config'].pop('password',None)
        return job

    def result():
        job=owned(request.args.get('job',''))
        store=diagnostic_store()
        return render_template('exports/job.html',diagnostic_job=job,format_bytes=format_bytes,
            diagnostic_label=label,diagnostic_result_endpoint=family+'_job',
            diagnostic_status_endpoint=family+'_status',diagnostic_cancel_endpoint=family+'_cancel',
            export_download_endpoint=family+'_download',export_family=family,
            diagnostic_recent=store.recent(g.current_user['id'],family),
            diagnostic_scheduler=read_automation_heartbeat(store.instance/'automation-heartbeat.json'))

    def status(job_id):
        job=owned(job_id)
        response=jsonify(state=job['state'],error=job['error'])
        response.headers['Cache-Control']='no-store'
        return response

    def cancel(job_id):
        owned(job_id,require_resource=False)
        store=diagnostic_store();job=store.cancel(job_id,g.current_user['id'])
        if job:
            from .export_jobs import record_outcome
            record_outcome(store,job,'cancelled')
        return redirect(url_for(family+'_job',job=job_id),code=303)

    def download(job_id):
        job=owned(job_id)
        if job['state']!='succeeded' or job['config'].get('investigation_id'):
            abort(404)
        store=diagnostic_store()
        if time.time()-job['completed']>store.policy.get()['diagnostic_retention_hours']*3600:
            abort(410,'This export has expired.')
        path=artifact_directory(store,job_id,family)/'export.bin'
        if not path.is_file() or path.is_symlink():
            abort(410,'This export is no longer available.')
        if family == 'configuration_export':
            annotate_audit_event(category='Backup and restore',action='backup.exported',
                summary='Downloaded a configuration backup.',resource_type='configuration_backup',resource_id=job_id,
                details={'selected groups':job['summary']['selected_groups'],'group count':job['summary']['group_count'],
                         'encrypted':job['summary']['encrypted'],'contains sensitive groups':job['summary']['contains_sensitive_groups'],
                         'export size bytes':job['summary']['byte_count']})
        else:
            annotate_audit_event(category='Automation',action='automation.run_downloaded',summary='Downloaded a collected run ZIP.',
                resource_type='automation run',resource_id=job['config']['run_id'],
                details={'operation id':job_id,'byte count':job['summary']['byte_count']})
        response=send_file(path,as_attachment=True,conditional=True,
                           download_name=job['summary']['filename'],mimetype=job['summary']['mimetype'])
        response.headers['Cache-Control']='private, no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        return response

    app.add_url_rule(prefix,endpoint=family+'_job',view_func=result,methods=['GET'])
    app.add_url_rule(prefix+'/<job_id>/status',endpoint=family+'_status',view_func=status,methods=['GET'])
    app.add_url_rule(prefix+'/<job_id>/cancel',endpoint=family+'_cancel',view_func=cancel,methods=['POST'])
    app.add_url_rule(prefix+'/<job_id>/download',endpoint=family+'_download',view_func=download,methods=['GET'])
