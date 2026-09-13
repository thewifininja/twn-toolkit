"""Queued Fabric discovery for tools without the export-task route family."""
from flask import abort, g, jsonify, redirect, render_template, request, url_for
from .appliance_read import TOOL, record_read_outcome
from .audit import suppress_audit_event
from .automation_heartbeat import read_automation_heartbeat
from .diagnostic_routes import diagnostic_store, owned_diagnostic

KINDS = {'switch-order': ('fortigate.switch_order','switch_order'),
         'wireless-history': ('fortigate.wireless_client_history','fortiap_client_history')}


def register_fabric_routes(app, profiles):
    def owned(kind, job_id):
        if kind not in KINDS:
            abort(404)
        job=owned_diagnostic(job_id, TOOL)
        if job['config'].get('tool_id') != KINDS[kind][0] or job['config'].get('mode')!='fabric_discovery':
            abort(404)
        return job

    @app.post('/fortigate/fabric/<kind>')
    def fabric_discovery(kind):
        if kind not in KINDS:
            abort(404)
        profile=profiles.get(request.form.get('profile',''))
        if not profile:
            return jsonify(error='Select a valid FortiGate profile.'),400
        config=dict(profile=profile,provider='fortigate',mode='fabric_discovery',task_id='',
                    tool_id=KINDS[kind][0],label='Fabric discovery',username=g.current_user['username'],investigation_id='')
        suppress_audit_event()
        try:
            identifier=diagnostic_store().enqueue(user_id=g.current_user['id'],tool=TOOL,config=config)
        except ValueError as exc:
            return jsonify(error=str(exc)),409
        return jsonify(job_url=url_for('fabric_discovery_job',kind=kind,job_id=identifier),
                       status_url=url_for('fabric_discovery_status',kind=kind,job_id=identifier),
                       cancel_url=url_for('fabric_discovery_cancel',kind=kind,job_id=identifier)),202

    @app.get('/fortigate/fabric/<kind>/jobs/<job_id>')
    def fabric_discovery_job(kind,job_id):
        job=owned(kind,job_id)
        response=app.make_response(render_template('appliance_read_job.html',diagnostic_job=job,
            diagnostic_label='Fabric discovery',diagnostic_recent=[],
            diagnostic_scheduler=read_automation_heartbeat(diagnostic_store().instance/'automation-heartbeat.json'),
            diagnostic_status_url=url_for('fabric_discovery_status',kind=kind,job_id=job_id),
            diagnostic_cancel_url=url_for('fabric_discovery_cancel',kind=kind,job_id=job_id),
            diagnostic_result_url=url_for('fabric_discovery_job',kind=kind,job_id=job_id),
            download_url='',back_url=url_for(KINDS[kind][1])))
        response.headers['Cache-Control']='private, no-store'
        return response

    @app.get('/fortigate/fabric/<kind>/jobs/<job_id>/status')
    def fabric_discovery_status(kind,job_id):
        job=owned(kind,job_id)
        response=jsonify(state=job['state'],error=job['error'],data=job['summary'] if job['state']=='succeeded' else None)
        response.headers['Cache-Control']='no-store'
        return response

    @app.post('/fortigate/fabric/<kind>/jobs/<job_id>/cancel')
    def fabric_discovery_cancel(kind,job_id):
        owned(kind,job_id)
        job=diagnostic_store().cancel(job_id,g.current_user['id'])
        if job:record_read_outcome(diagnostic_store(),job,'cancelled')
        return redirect(url_for('fabric_discovery_job',kind=kind,job_id=job_id),code=303)
