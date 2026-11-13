"""Temporary standalone authoring fixture. No schedulers, exports or device execution."""
import argparse
import json
import socket
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
parser = argparse.ArgumentParser()
parser.add_argument('--port',type=int,default=5124)
parser.add_argument('--with-closed-case',action='store_true')
parser.add_argument('--collaborator',action='store_true')
parser.add_argument('--source-root',default=str(Path(__file__).resolve().parents[2]))
args = parser.parse_args()
sys.path.insert(0,args.source_root)
from flask import Response, abort, g, jsonify, request
from twn_toolkit import create_app
from twn_toolkit.investigations import InvestigationError
from twn_toolkit.distributed_agents import DistributedSettingsStore

root = Path(tempfile.mkdtemp(prefix='twn-investigation-authoring-'))
control_path = root/'control.json'; control_path.write_text('{}')
counts = {'note_posts':0,'case_posts':0,'export_gets':0}
def control(): return json.loads(control_path.read_text())
def fake_export(case_id,kind):
    app.extensions['investigation_store'].get_for_user(case_id,g.current_user['id'])
    counts['export_gets'] += 1; (root/'counts.json').write_text(json.dumps(counts))
    return Response('<h1>Synthetic saved-choice export boundary</h1><p>No job or export worker was started.</p>',mimetype='text/html')
with patch('twn_toolkit.case_export_routes.queue_case_export',fake_export):
    app = create_app(str(root))
app.testing = True; app.jinja_env.auto_reload = True
app.config['SESSION_COOKIE_NAME'] = 'twn_case_fixture_'+str(args.port)
assert DistributedSettingsStore(str(root)).get()['role'] == 'standalone'
store = app.extensions['investigation_store']; original_add = store.add_note
seeded = {}
if args.with_closed_case:
    closed = store.create(owner_user_id='test-user',owner_username='test-user',title='Closed viewed fixture case')
    store.set_state(closed['id'],'test-user','test-user','completed')
    seeded['closed_case'] = '/investigations/'+closed['id']
if args.collaborator:
    shared = store.create(owner_user_id='fixture-owner',owner_username='Fixture owner',title='Shared fixture case')
    store.add_participant(shared['id'],'fixture-owner','Fixture owner','test-user','test-user')
    seeded['shared_case'] = '/investigations/'+shared['id']

def add_note(*values,**kwargs):
    current = control()
    time.sleep(max(0,min(20,float(current.get('delay',0)))))
    if current.get('close_before_note'):
        case = store.get_for_user(values[0],values[1])
        store.set_state(case['id'],case['owner_user_id'],case['owner_username'],'completed')
    if current.get('response') == 'validation': raise InvestigationError('Synthetic validation: preserve this note and try after correction.')
    event = original_add(*values,**kwargs)
    request.environ['fixture.note_committed'] = True
    for number in range(max(0,min(101,int(current.get('later_notes',0))))):
        original_add(values[0],values[1],values[2],f'Synthetic later note {number+1}')
    return event
store.add_note = add_note

@app.before_request
def fixture_guard():
    allowed_get = request.path.startswith('/static/') or request.path in {'/fixture','/investigations','/session/activity','/tools/live-sessions','/tools/dns-response','/tools/snmp-test','/tools/api-request'} or request.path.startswith('/investigations/') and (request.path.count('/') == 2 or request.path.endswith('/report') or request.path.endswith('/report.pdf') or request.path.endswith('/package.zip') or request.path.endswith('/portable.twncase'))
    if request.method == 'GET' and allowed_get: return
    if request.method == 'POST' and request.path == '/investigations':
        counts['case_posts'] += 1; (root/'counts.json').write_text(json.dumps(counts)); return
    if request.method == 'POST' and request.path.startswith('/investigations/') and request.path.endswith('/notes'):
        counts['note_posts'] += 1; (root/'counts.json').write_text(json.dumps(counts))
        current = control()
        if current.get('revoke_before_note'):
            case_id = request.path.split('/')[2]
            case = store.get_for_user(case_id,'test-user')
            store.remove_participant(case_id,case['owner_user_id'],case['owner_username'],'test-user')
        if current.get('response') == 'forbidden': abort(403)
        if current.get('response') in {'html_after','json500_after','wrong_summary'}: request.environ['fixture.response_after'] = current['response']
        return
    if request.method == 'POST' and request.path.startswith('/investigations/') and request.path.endswith('/report/contents'): return
    abort(403)

@app.after_request
def uncertain_ack(response):
    mode = request.environ.get('fixture.response_after')
    if response.status_code in {201,302}:
        if mode == 'html_after':
            response = Response('<h1>Synthetic lost acknowledgement after note save</h1>',mimetype='text/html')
        elif mode == 'json500_after':
            response = jsonify(error='Synthetic internal failure after committed note')
            response.status_code = 500
        elif mode == 'wrong_summary' and response.is_json:
            payload = response.get_json(); payload['event']['summary'] = 'Synthetic different note acknowledgment'
            response = jsonify(payload)
            response.status_code = 201
    if request.method == 'POST' and request.path.endswith('/notes'):
        counts.setdefault('note_responses',[]).append({
            'status':response.status_code, 'mimetype':response.mimetype,
            'mode':mode or 'normal',
            'committed':bool(request.environ.get('fixture.note_committed')),
        })
        (root/'counts.json').write_text(json.dumps(counts))
    return response

@app.get('/fixture')
def fixture_index():
    return '<h1>Synthetic case authoring</h1><a href="/investigations">Create a case</a><p>Notes/report choices only. No actual exports, closing, invitations or device actions.</p>'

print(json.dumps({'instance':str(root),'control':str(control_path),'url':f'http://127.0.0.1:{args.port}/investigations','source':args.source_root,'seeded':seeded}),flush=True)
with patch.object(socket,'create_connection',side_effect=AssertionError('No fixture outbound connections')):
    app.run(host='127.0.0.1',port=args.port,threaded=True,use_reloader=False)
