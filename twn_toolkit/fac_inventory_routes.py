"""Shared request handlers for the two read-only appliance inventory jobs."""
from __future__ import annotations

import time
from flask import abort, flash, g, jsonify, redirect, render_template, request, send_file, url_for

from .audit import suppress_audit_event
from .automation_heartbeat import read_automation_heartbeat
from .csv_exports import csv_download_filename
from .diagnostic_artifacts import artifact_directory
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .diagnostic_worker import record_unsuccessful_scan
from .fac_inventory import KINDS, PREVIEW_LIMIT, prepare_inventory_config
from .investigations import InvestigationStore


def register_fac_inventory_routes(app, profile_store):
    for kind in KINDS:
        _register_kind(app, profile_store, kind)


def _register_kind(app, profile_store, kind):
    spec = KINDS[kind]
    tool = 'fac_inventory_'+kind
    endpoint = spec['endpoint']
    base = '/fortiauthenticator/'+spec['path']

    def owned(job_id):
        job = owned_diagnostic(job_id, tool)
        if job['config']['kind'] != kind:
            abort(404)
        return job

    def page(exporting=False):
        store = diagnostic_store(); user = g.current_user
        selected = ''; csv_format = 'spreadsheet'
        job = rows = None; total = 0; number = 1
        if request.method=='POST':
            suppress_audit_event()
            selected = request.form.get('profile','')
            csv_format = request.form.get('csv_format','spreadsheet')
            try:
                config = prepare_inventory_config(profile_store.get(selected),kind,'export' if exporting else 'preview',csv_format)
                case = InvestigationStore(app.instance_path).active_for_user(user['id'])
                config.update(username=user['username'],investigation_id=case['id'] if case and case.get('is_recording') else '')
                job_id = store.enqueue(user_id=user['id'],tool=tool,config=config)
                return redirect(url_for(endpoint,job=job_id),code=303)
            except (ValueError,TypeError) as exc:
                flash(str(exc),'error')
        elif request.args.get('job'):
            job = owned(request.args['job']); selected=job['config']['profile']['name']; csv_format=job['config']['csv_format']
            if job['state']=='succeeded':
                try:
                    number=max(1,int(request.args.get('page','1')))
                except ValueError:
                    pass
                number=min(number,max(1,(job['summary']['preview_count']+99)//100))
                rows,_=store.page(job['id'],user['id'],number);total=job['summary']['total_count']
        return render_template(spec['template'],profiles=profile_store.all(),selected_name=selected,csv_format=csv_format,
            rows=rows,total_count=total,preview_limit=PREVIEW_LIMIT,result_page=number,
            diagnostic_label=spec['label'],diagnostic_result_endpoint=endpoint,
            diagnostic_status_endpoint=endpoint+'_status',diagnostic_cancel_endpoint=endpoint+'_cancel',
            inventory_download_endpoint=endpoint+'_download',diagnostic_job=job,
            diagnostic_recent=store.recent(user['id'],tool),
            diagnostic_scheduler=read_automation_heartbeat(store.instance/'automation-heartbeat.json'),
            journal_event=job['summary'].get('journal_event') if job else None)

    def status(job_id):
        job=owned(job_id)
        response=jsonify(state=job['state'],error=job['error'])
        response.headers['Cache-Control']='no-store'
        return response

    def cancel(job_id):
        owned(job_id);store=diagnostic_store()
        job=store.cancel(job_id,g.current_user['id'])
        if job:
            record_unsuccessful_scan(store,job,'cancelled','Cancelled before execution started.')
        return redirect(url_for(endpoint,job=job_id),code=303)

    def download(job_id):
        job=owned(job_id);store=diagnostic_store()
        if job['state']!='succeeded' or not job['summary'].get('archive'):
            abort(404)
        if time.time()-job['completed']>store.policy.get()['diagnostic_retention_hours']*3600:
            abort(410,'This inventory export has expired.')
        path=artifact_directory(store,job_id,tool)/'download.csv'
        if not path.is_file() or path.is_symlink():
            abort(410,'This inventory export is no longer available.')
        response=send_file(path,mimetype='text/csv',as_attachment=True,conditional=True,
            download_name=csv_download_filename(spec['path']+'-'+job_id[:12]+'.csv',job['config']['csv_format']))
        response.headers['Cache-Control']='private, no-store'
        return response

    app.add_url_rule(base,endpoint,page,methods=['GET','POST'])
    app.add_url_rule(base+'.csv','export_'+endpoint,lambda:page(exporting=True),methods=['POST'])
    for suffix,handler,method in [('status',status,'GET'),('cancel',cancel,'POST'),('download',download,'GET')]:
        app.add_url_rule(base+'/jobs/<job_id>/'+suffix,endpoint+'_'+suffix,handler,methods=[method])

