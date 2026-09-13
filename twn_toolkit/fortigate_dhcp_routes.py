"""Owner-scoped DHCP snapshots on the shared appliance read queue."""
import csv
import io
import json
import time

from flask import abort, flash, g, jsonify, make_response, redirect, render_template, request, url_for
from .appliance_read import TOOL, record_read_outcome
from .audit import suppress_audit_event
from .automation_heartbeat import read_automation_heartbeat
from .csv_exports import spreadsheet_safe_csv
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .fortigate_dhcp import lease_duration
from .investigations import InvestigationStore


def register_dhcp_routes(app, profiles):
    def owned(identifier):
        job = owned_diagnostic(identifier, TOOL)
        if job['config'].get('tool_id') != 'fortigate.dhcp' or job['config'].get('mode') != 'dhcp':
            abort(404)
        return job

    @app.route('/fortigate/dhcp', methods=['GET', 'POST'])
    def fortigate_dhcp():
        store = diagnostic_store()
        if request.method == 'POST':
            profile = profiles.get(request.form.get('profile', ''))
            vd = request.form.get('vdom', '').strip() or (profile or {}).get('default_vdom', 'root')
            scope = request.form.get('scope', 'single')
            if not profile or scope not in ('single', 'fabric') or len(vd) > 80 or any(ord(c)<32 for c in vd):
                flash('Select a valid profile, scope and VDOM.', 'error')
            elif vd == '*' and scope != 'fabric':
                flash('Choose Fabric to discover all advertised VDOMs, or enter a specific VDOM.', 'error')
            else:
                case = InvestigationStore(app.instance_path).active_for_user(g.current_user['id'])
                config = dict(profile=profile, provider='fortigate', mode='dhcp', task_id='dhcp-inventory',
                    tool_id='fortigate.dhcp', label='DHCP inventory', username=g.current_user['username'],
                    investigation_id=case['id'] if case and case.get('is_recording') else '',
                    fabric=scope == 'fabric', vdom=vd)
                suppress_audit_event()
                try:
                    identifier = store.enqueue(user_id=g.current_user['id'], tool=TOOL, config=config)
                except ValueError as exc:
                    flash(str(exc), 'error')
                else:
                    return redirect(url_for('fortigate_dhcp', job=identifier), code=303)
        job = owned(request.args['job']) if request.args.get('job') else None
        config = job['config'] if job else {}
        data = job['summary'] if job and job['state']=='succeeded' else None
        selected = request.values.get('profile', config.get('profile', {}).get('name', ''))
        recent = []
        for entry in store.recent(g.current_user['id'], TOOL):
            saved = store.get(entry['id'], g.current_user['id'])
            if saved['config'].get('mode') == 'dhcp':
                recent.append({**entry, 'state': 'partial' if saved['summary'].get('partial') and entry['state']=='succeeded' else entry['state']})
        view = request.args.get('view', 'pools')
        if view not in ('pools', 'reservations', 'leases'):
            view = 'pools'
        q = request.args.get('q', '').strip()[:200]
        device = request.args.get('device', '')
        entries = []
        gates = {}
        if data:
            entries = data['leases'] if view == 'leases' else data['scopes']
            if view == 'reservations':
                entries = [{**r, 'device': s['device'], 'serial': s['serial'], 'vdom': s['vdom'],
                            'interface': s.get('interface', ''), 'server_id': s.get('id')}
                           for s in data['scopes'] for r in s['reserved-address']]
            for context in data['devices']:
                gate = gates.setdefault(context['serial'], dict(serial=context['serial'],
                    hostname=context['hostname'], model=context['model'], contexts=[], count=0))
                gate['contexts'].append(context)
            entries = [s for s in entries if (not device or s['serial']==device) and
                       (not q or q.casefold() in json.dumps(s, ensure_ascii=False).casefold())]
            for entry in entries:
                if entry['serial'] in gates:
                    gates[entry['serial']]['count'] += 1
            gates = {serial: gate for serial, gate in gates.items()
                     if (not device or serial == device) and (not q or gate['count'])}
        total = len(entries)
        try:
            page = max(1, min(int(request.args.get('page', 1)), max(1, (total+49)//50)))
        except ValueError:
            page = 1
        response = make_response(render_template('fortigate_dhcp.html', page_title='DHCP inventory',
            profiles=profiles.all(), selected_name=selected, data=data, gates=list(gates.values()),
            entries=entries[(page-1)*50:page*50] if device else [],
            view=view, q=q, device=device, page=page, total=total, lease_duration=lease_duration,
            scope=request.values.get('scope', 'fabric' if config.get('fabric') else 'single'),
            vdom=request.values.get('vdom', config.get('vdom', '')),
            diagnostic_job=job, diagnostic_recent=recent, diagnostic_label='DHCP inventory',
            diagnostic_result_endpoint='fortigate_dhcp', diagnostic_status_endpoint='fortigate_dhcp_status',
            diagnostic_cancel_endpoint='fortigate_dhcp_cancel',
            diagnostic_completion_label='Partial' if data and data['partial'] else None,
            diagnostic_scheduler=read_automation_heartbeat(store.instance/'automation-heartbeat.json')))
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    @app.get('/fortigate/dhcp/jobs/<job_id>/status')
    def fortigate_dhcp_status(job_id):
        job = owned(job_id)
        response = jsonify(state=job['state'])
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.post('/fortigate/dhcp/jobs/<job_id>/cancel')
    def fortigate_dhcp_cancel(job_id):
        owned(job_id)
        job = diagnostic_store().cancel(job_id, g.current_user['id'])
        if job:
            record_read_outcome(diagnostic_store(), job, 'cancelled')
        return redirect(url_for('fortigate_dhcp', job=job_id), code=303)

    @app.get('/fortigate/dhcp/jobs/<job_id>/download')
    def fortigate_dhcp_download(job_id):
        job = owned(job_id)
        if job['state'] != 'succeeded':
            abort(404)
        store = diagnostic_store()
        if time.time()-job['completed'] > store.policy.get()['diagnostic_retention_hours']*3600:
            abort(410, 'This snapshot has expired.')
        data = job['summary']
        fmt = request.args.get('format', 'json')
        if fmt == 'json':
            response = make_response(json.dumps(data, indent=2), 200, {'Content-Type': 'application/json'})
        elif fmt == 'csv':
            output = io.StringIO()
            fields = ['device', 'serial', 'vdom', 'id', 'status', 'interface', 'interface_details',
                      'ip-range', 'subnets', 'netmask', 'default-gateway', 'dns-service', 'dns-server1',
                      'dns-server2', 'dns-server3', 'dns-server4', 'lease-time', 'domain',
                      'exclude-range', 'reserved-address', 'options']
            writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore'); writer.writeheader()
            for s in data['scopes']:
                writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict,list)) else v for k,v in s.items()})
            response = make_response(spreadsheet_safe_csv(output.getvalue()), 200, {'Content-Type':'text/csv; charset=utf-8'})
        else:
            abort(400)
        response.headers['Content-Disposition'] = f'attachment; filename="dhcp-inventory-{job_id[:12]}.{fmt}"'
        response.headers['Cache-Control'] = 'private, no-store'
        return response
