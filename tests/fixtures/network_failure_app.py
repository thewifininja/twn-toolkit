"""Loopback-only invalid-request/seeded-result fixture. Never runs network tools."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import socket
import tempfile
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from flask import abort,jsonify,request
from twn_toolkit import create_app
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.dns_diagnostic import prepare_dns_config
from twn_toolkit.profiles import NTPHostProfileStore,RadiusProfileStore

parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=5131);args=parser.parse_args()
root=Path(tempfile.mkdtemp(prefix='twn-network-failure-'))
counts={'invalid_ntp_posts':0,'invalid_radius_posts':0,'blocked_calls':{}}
counts_path=root/'counts.json'
def save_counts():counts_path.write_text(json.dumps(counts))
def blocked(name):
    counts['blocked_calls'][name]=0
    def fail(*args,**kwargs):
        counts['blocked_calls'][name]+=1;save_counts();raise AssertionError('No fixture execution: '+name)
    return fail
fixture_getaddrinfo = socket.getaddrinfo
stack=ExitStack()
for target in ('twn_toolkit.dns_diagnostic.dns_lookup_matrix','twn_toolkit.dns_diagnostic.dns_load_test','twn_toolkit.ntp_routes.test_ntp_servers','twn_toolkit.radius_routes.radius_authenticate','socket.create_connection','socket.getaddrinfo'):
    stack.enter_context(patch(target,side_effect=blocked(target)))
app=create_app(str(root));app.testing=True;app.jinja_env.auto_reload=True
app.config['SESSION_COOKIE_NAME']='twn_network_failure_fixture'
assert DistributedSettingsStore(str(root)).get()['role']=='standalone'
NTPHostProfileStore(str(root)).upsert({'name':'Remembered','values':'remembered.test','targets':[{'host':'remembered.test','label':''}],'count':1})
RadiusProfileStore(str(root),'credentials').upsert({'name':'Fixture credentials','username':'fixture-user','password':'SyntheticFixtureOnly'})
store=DiagnosticJobStore(str(root));app.extensions['diagnostic_job_store']=store
config={**prepare_dns_config({'hosts':'fixture.test','servers':'192.0.2.53','mode':'compare','record_type':'A','timeout':'1'}),'username':'fixture','investigation_id':''}
job=store.enqueue(user_id='test-user',tool='dns',config=config);claim=store.claim()
base={'host':'fixture.test','server':'192.0.2.53','host_label':'','server_label':'','record_type':'A','answers':[],'status':'timeout','error':'<script>alert("fixture")</script> '+'unbroken'*100}
rows=[{**base,'response_ms':None},{**base,'status':'success','answers':['192.0.2.1'],'error':'','response_ms':0},{**base,'status':'success','answers':['192.0.2.2'],'error':'','response_ms':12.5},{**base,'error':'Historic missing response time'}]
assert store.finish(job,claim['token'],rows,{'load_result':None,'lookup_summary':{'queries':4,'successful':2,'failed':2,'average_ms':6.25,'slowest_ms':12.5}})
store.release(job,claim['token'])
invalid_hosts='\n'.join(f'edited{number:02d}.test' for number in range(1,22))
save_counts()
@app.before_request
def isolate():
    if request.method=='GET' and (request.path.startswith('/static/') or request.path in {'/fixture','/fixture/status','/tools/ntp-test','/tools/radius-test','/tools/dns-response','/tools/live-sessions','/session/activity'} or request.path.startswith(f'/tools/dns-response/jobs/{job}/')):return
    posted_hosts=request.form.get('hosts','').replace('\r\n','\n').strip()
    if request.method=='POST' and request.path=='/tools/ntp-test' and (posted_hosts==invalid_hosts or not posted_hosts):
        counts['invalid_ntp_posts']+=1;save_counts();return
    if request.method=='POST' and request.path=='/tools/radius-test' and not request.form.getlist('server_names') and request.form.get('credential_name')=='Fixture credentials' and request.form.get('protocol')=='pap':
        counts['invalid_radius_posts']+=1;save_counts();return
    abort(403)
@app.get('/fixture')
def fixture_index():
    return '<h1>Synthetic network failure continuity</h1><p>No schedulers, agents or tool execution. All POSTs invalid and allowlisted.</p>'+f'<a href="/tools/dns-response?job={job}">Seeded DNS failures</a><p><a href="/tools/ntp-test">NTP</a> · <a href="/tools/radius-test">RADIUS</a></p>'
@app.get('/fixture/status')
def fixture_status():return jsonify(counts)
print(json.dumps({'instance':str(root),'counts':str(counts_path),'url':f'http://127.0.0.1:{args.port}/fixture','dns':f'/tools/dns-response?job={job}','ntp_invalid_hosts':invalid_hosts,'radius_payload':{'server_names':[],'credential_name':'Fixture credentials','protocol':'pap'}}),flush=True)
from werkzeug.serving import make_server
# Only binding this numeric loopback HTTP listener may use the original resolver;
# all request handling remains inside the fail-closed tool/socket boundaries.
with patch('socket.getaddrinfo',fixture_getaddrinfo):
    server=make_server('127.0.0.1',args.port,app,threaded=True)
try:server.serve_forever()
finally:server.server_close();stack.close()
