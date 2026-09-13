"""Experimental switch inspector on the existing bounded read queue."""
import json
import time
from urllib.parse import urlparse
from .fortigate import normalize_host
from flask import abort, flash, g, jsonify, make_response, redirect, render_template, request, url_for
from .appliance_read import TOOL, record_read_outcome
from .audit import suppress_audit_event
from .automation_heartbeat import read_automation_heartbeat
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .investigations import InvestigationStore


def register_loop_routes(app, profiles):
    def owned(identifier):
        job = owned_diagnostic(identifier, TOOL)
        if job['config'].get('tool_id') != 'fortigate.loop_inspector' or job['config'].get('mode') != 'loop_inspector':
            abort(404)
        return job

    @app.route('/fortigate/loop-inspector', methods=['GET', 'POST'])
    def fortigate_loop():
        store = diagnostic_store()
        connections = app.extensions['remote_connection_store']
        user = g.current_user
        hosts = connections.library_for_user(user['id'], is_admin=bool(user.get('is_admin')), host_page=1)['hosts']
        if request.method == 'POST':
            suppress_audit_event()
            profile = profiles.get(request.form.get('profile', ''))
            vd = request.form.get('vdom', '').strip() or (profile or {}).get('default_vdom', 'root')
            scope = request.form.get('scope', 'single')
            if not profile or scope not in ('single', 'fabric') or not vd or vd=='*' or len(vd)>80 or any(ord(c)<32 for c in vd):
                flash('Select a valid profile, scope and one VDOM.', 'error')
            else:
                case = InvestigationStore(app.instance_path).active_for_user(g.current_user['id'])
                config = dict(profile=profile, provider='fortigate', mode='loop_inspector', task_id='loop-inspector',
                    tool_id='fortigate.loop_inspector', label='Switch loop inspector', username=g.current_user['username'],
                    investigation_id=case['id'] if case and case.get('is_recording') else '', fabric=scope=='fabric', vdom=vd)
                ssh_id = request.form.get('ssh_host', '')
                if ssh_id:
                    host = connections.get_host(ssh_id, user_id=user['id'], is_admin=bool(user.get('is_admin')))
                    if (not host or host['protocol']!='ssh' or vd!='root' or
                            host['host'].casefold()!=urlparse(normalize_host(profile['host'])).hostname.casefold()):
                        abort(400, 'Choose a saved SSH host matching this FortiGate; SSH inspection currently requires root VDOM.')
                    from .remote_connections import RemoteConnectionError
                    try:
                        credential = connections.resolve_credential(host['effective_credential_id'], user_id=user['id'],
                            is_admin=bool(user.get('is_admin')), host_id=ssh_id)
                    except RemoteConnectionError:
                        abort(400, 'The saved host needs an accessible assigned credential.')
                    config['ssh'] = dict(hostname=host['host'], port=host['port'], username=credential['username'],
                        password=credential['password'], allow_unknown_hosts=host['allow_unknown_hosts'],
                        allow_legacy_algorithms=host['allow_legacy_algorithms'])
                try:
                    identifier = store.enqueue(user_id=g.current_user['id'], tool=TOOL, config=config)
                except ValueError as exc:
                    flash(str(exc), 'error')
                else:
                    return redirect(url_for('fortigate_loop', job=identifier), code=303)
        job = owned(request.args['job']) if request.args.get('job') else None
        config = job['config'] if job else {}
        data = job['summary'] if job and job['state']=='succeeded' else None
        recent = []
        for entry in store.recent(g.current_user['id'], TOOL):
            saved = store.get(entry['id'], g.current_user['id'])
            if saved['config'].get('mode') == 'loop_inspector':
                recent.append({**entry, 'state':'partial' if entry['state']=='succeeded' and saved['summary'].get('partial') else entry['state']})
        gate = next((g for g in (data or {}).get('gates', []) if g['serial']==request.args.get('gate')), None)
        switch = next((s for s in (gate or {}).get('switches', []) if s['serial']==request.args.get('switch')), None)
        try:
            page = max(1, min(int(request.args.get('page', 1)), max(1, (len((switch or {}).get('ports', []))+49)//50)))
        except ValueError:
            page = 1
        response = make_response(render_template('fortigate_loop.html', profiles=profiles.all(), ssh_hosts=[h for h in hosts if h['protocol']=='ssh'], data=data, gate=gate, switch=switch,
            ports=(switch or {}).get('ports', [])[(page-1)*50:page*50], page=page,
            selected_name=config.get('profile', {}).get('name',''), vdom=config.get('vdom',''), scope='fabric' if config.get('fabric') else 'single',
            diagnostic_job=job, diagnostic_recent=recent, diagnostic_label='Switch loop inspector',
            diagnostic_result_endpoint='fortigate_loop', diagnostic_status_endpoint='fortigate_loop_status',
            diagnostic_cancel_endpoint='fortigate_loop_cancel',
            diagnostic_scheduler=read_automation_heartbeat(store.instance/'automation-heartbeat.json')))
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    @app.get('/fortigate/loop-inspector/jobs/<job_id>/status')
    def fortigate_loop_status(job_id):
        response = jsonify(state=owned(job_id)['state']); response.headers['Cache-Control']='no-store'
        return response

    @app.post('/fortigate/loop-inspector/jobs/<job_id>/cancel')
    def fortigate_loop_cancel(job_id):
        owned(job_id)
        job = diagnostic_store().cancel(job_id, g.current_user['id'])
        if job: record_read_outcome(diagnostic_store(), job, 'cancelled')
        return redirect(url_for('fortigate_loop', job=job_id), code=303)

    @app.get('/fortigate/loop-inspector/jobs/<job_id>/download')
    def fortigate_loop_download(job_id):
        job=owned(job_id);store=diagnostic_store()
        if job['state']!='succeeded':abort(404)
        if time.time()-job['completed']>store.policy.get()['diagnostic_retention_hours']*3600:abort(410)
        return make_response(json.dumps(job['summary'],indent=2),200,{'Content-Type':'application/json',
            'Content-Disposition':f'attachment; filename="switch-inspector-{job_id[:12]}.json"','Cache-Control':'private, no-store'})
