"""Synthetic dependency CRUD and invalid-run fixture; never dispatches network work."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import socket
import sys
import tempfile
import time
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from flask import Response,abort,jsonify,request
from twn_toolkit import create_app
from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.profiles import RadiusProfileStore
parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=5132);args=parser.parse_args()
root=Path(tempfile.mkdtemp(prefix='twn-network-dependency-'));control_path=root/'control.json';control_path.write_text('{}')
counts={'profile_posts':0,'invalid_runs':0,'responses':[],'blocked_calls':{}}
def persist(): (root/'counts.json').write_text(json.dumps(counts))
def control():return json.loads(control_path.read_text())
def blocked(name):
    counts['blocked_calls'][name]=0
    def fail(*args,**kwargs):
        counts['blocked_calls'][name]+=1;persist();raise AssertionError('No fixture execution: '+name)
    return fail
fixture_getaddrinfo=socket.getaddrinfo;stack=ExitStack()
for target in ('twn_toolkit.snmp_routes.run_snmp_tests','twn_toolkit.snmp_routes.discover_snmp_interfaces','twn_toolkit.snmp_routes.poll_snmp_interface','twn_toolkit.snmp_routes.poll_snmp_interfaces','twn_toolkit.radius_routes.radius_authenticate','socket.create_connection','socket.getaddrinfo'):
    stack.enter_context(patch(target,side_effect=blocked(target)))
app=create_app(str(root));app.testing=True;app.jinja_env.auto_reload=True
app.config['SESSION_COOKIE_NAME']='twn_network_dependency_fixture'
assert DistributedSettingsStore(str(root)).get()['role']=='standalone'
RadiusProfileStore(str(root),'servers').upsert({'name':'Fixture initial server','host':'192.0.2.44','port':1812,'secret':'SyntheticServerSecret'})
RadiusProfileStore(str(root),'credentials').upsert({'name':'Fixture initial credential','username':'fixture-user','password':'SyntheticCredentialSecret'})
profile_paths={f'/tools/{tool}/profiles/{kind}{action}' for tool,kinds in [('snmp-test',('credentials','hosts','oids')),('radius-test',('servers','credentials','attributes'))] for kind in kinds for action in ('','/duplicate','/delete')}
persist()
@app.before_request
def isolate():
    if request.method=='GET' and (request.path.startswith('/static/') or request.path in {'/fixture','/fixture/status','/tools/snmp-test','/tools/radius-test','/tools/snmp-test/profile-choices','/tools/radius-test/profile-choices','/tools/live-sessions','/session/activity'}):return
    if request.method=='POST' and request.path in profile_paths:
        if request.form.get('mso_enabled') not in (None,'false'):abort(403)
        counts['profile_posts']+=1;persist();current=control()
        request.environ['fixture.profile_mode']=current.get('response','normal')
        time.sleep(max(0,min(20,float(current.get('delay',0)))))
        if current.get('response')=='validation':return jsonify(error='Synthetic validation: preserve this draft.'),400
        if current.get('response')=='forbidden':abort(403)
        return
    if request.method=='POST' and request.path=='/tools/snmp-test' and not request.form.getlist('oid_profile_names'):
        counts['invalid_runs']+=1;persist();return
    if request.method=='POST' and request.path=='/tools/radius-test' and (not request.form.getlist('server_names') or not request.form.get('credential_name') or request.form.get('timeout','3')==''):
        counts['invalid_runs']+=1;persist();return
    abort(403)
@app.after_request
def simulate_response(response):
    mode=request.environ.get('fixture.profile_mode')
    if mode is None:return response
    committed=response.status_code==200 and response.is_json and isinstance(response.get_json(),dict) and 'profile' in response.get_json()
    if committed:
        if mode=='html_after':response=Response('<h1>Synthetic lost JSON acknowledgment after save</h1>',mimetype='text/html')
        elif mode=='json500_after':response=jsonify(error='Synthetic internal failure after committed save');response.status_code=500
        elif mode=='wrong_metadata':
            payload=response.get_json();profile=payload['profile']
            field=current_field=control().get('wrong_field')
            if field not in {'host','port','username','version','count','credential_name','timeout','retries'}:
                field=next((key for key in ('version','host','username','count') if key in profile),'name')
            profile[field]=control().get('wrong_value',999 if field in {'port','count','timeout','retries'} else 'synthetic-wrong-metadata')
            response=jsonify(payload)
        elif mode=='wrong_profile':
            payload=response.get_json();payload['profile']['name']='Unrelated synthetic acknowledgment';response=jsonify(payload)
    counts['responses'].append({'status':response.status_code,'mimetype':response.mimetype,'mode':mode,'committed':committed})
    persist();return response
@app.get('/fixture')
def fixture_index():return '<h1>Isolated network dependency drafts</h1><a href="/tools/snmp-test">SNMP</a> · <a href="/tools/radius-test">RADIUS</a><p>Only synthetic profile CRUD and deliberately invalid Run requests. No schedulers, agents or network execution.</p>'
@app.get('/fixture/status')
def fixture_status():return jsonify(counts)
print(json.dumps({'instance':str(root),'control':str(control_path),'counts':str(root/'counts.json'),'url':f'http://127.0.0.1:{args.port}/fixture'}),flush=True)
from werkzeug.serving import make_server
with patch('socket.getaddrinfo',fixture_getaddrinfo):server=make_server('127.0.0.1',args.port,app,threaded=True)
try:server.serve_forever()
finally:server.server_close();stack.close()
