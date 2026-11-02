"""Synthetic API sender only. External HTTP/process/socket boundaries fail closed."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import socket
import sys
import tempfile
import time
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from flask import Response, abort, jsonify, request
from twn_toolkit import create_app
from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.network_tools import ToolInputError

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=5135)
args = parser.parse_args()
root = Path(tempfile.mkdtemp(prefix='twn-api-continuity-'))
control_path = root / 'control.json'; control_path.write_text('{}')
counts = {'posts': 0, 'synthetic_sender_calls': 0, 'responses': [], 'blocked_calls': {}}
def persist(): (root / 'counts.json').write_text(json.dumps(counts))
def control(): return json.loads(control_path.read_text())
def blocked(name):
    counts['blocked_calls'][name] = 0
    def fail(*args, **kwargs):
        counts['blocked_calls'][name] += 1; persist()
        raise AssertionError('No fixture outbound boundary: ' + name)
    return fail

def synthetic_sender(*args, **kwargs):
    counts['synthetic_sender_calls'] += 1; persist()
    mode = control().get('response', 'normal')
    time.sleep(max(0, min(20, float(control().get('delay', 0)))))
    if mode == 'sender_timeout': raise ToolInputError('Synthetic sender deadline; remote operation unconfirmed.')
    if mode == 'unexpected': raise RuntimeError('Synthetic private exception marker')
    return {'status': 200, 'reason': 'Synthetic <response>', 'elapsed_ms': 2, 'bytes': 23,
            'resolved_addresses': ['192.0.2.2'], 'request_headers': {},
            'response_headers': {'Content-Type': 'text/plain'}, 'body': '<script>synthetic text</script>',
            'truncated': False, 'redirect': ''}

fixture_getaddrinfo = socket.getaddrinfo
stack = ExitStack()
for target in ('subprocess.Popen', 'requests.request', 'requests.sessions.Session.request', 'socket.create_connection', 'socket.getaddrinfo'):
    stack.enter_context(patch(target, side_effect=blocked(target)))
stack.enter_context(patch('twn_toolkit.api_request_routes.send_api_request', side_effect=synthetic_sender))
app = create_app(str(root)); app.testing = True; app.jinja_env.auto_reload = True
app.config['SESSION_COOKIE_NAME'] = 'twn_api_continuity_fixture'
assert DistributedSettingsStore(str(root)).get()['role'] == 'standalone'
persist()

@app.before_request
def isolate():
    if request.method == 'GET' and (request.path.startswith('/static/') or request.path in {
        '/fixture', '/fixture/status', '/tools/api-request', '/tools/api-request/admission',
        '/session/activity', '/tools/live-sessions'}): return
    if request.method == 'POST' and request.path == '/tools/api-request':
        # Exact synthetic destinations only; FormData line endings do not affect admission.
        if request.form.get('url') not in {'https://fixture.test/read', 'https://fixture.test/write'}: abort(403)
        counts['posts'] += 1; persist()
        request.environ['fixture.mode'] = control().get('response', 'normal')
        if request.environ['fixture.mode'] == 'forbidden': abort(403)
        return
    abort(403)

@app.after_request
def protocol(response):
    mode = request.environ.get('fixture.mode')
    if mode is None: return response
    payload = response.get_json(silent=True) if response.is_json else None
    dispatched = bool(payload and payload.get('dispatched')) or (response.status_code == 303 and 'receipt=' in response.headers.get('Location', ''))
    if dispatched:
        if mode == 'html_after': response = Response('<h1>Synthetic lost acknowledgment</h1>', mimetype='text/html')
        elif mode == 'json500_after': response = jsonify(error='Synthetic acknowledgment unavailable'); response.status_code = 500
        elif mode == 'wrong_token': payload['admission_token'] = 'f' * 64; response = jsonify(payload)
    counts['responses'].append({'status': response.status_code, 'mimetype': response.mimetype,
                                'mode': mode, 'dispatched': dispatched})
    persist(); return response

@app.get('/fixture')
def api_fixture_index():
    return '<h1>Isolated API request continuity</h1><a href="/tools/api-request">API Tester</a><p>Only fixture.test/read or /write synthetic sender admissions. No external HTTP, agents, schedulers or subprocess execution.</p>'
@app.get('/fixture/status')
def status(): return jsonify(counts)
print(json.dumps({'instance': str(root), 'control': str(control_path), 'counts': str(root/'counts.json'),
                  'url': f'http://127.0.0.1:{args.port}/fixture'}), flush=True)
from werkzeug.serving import make_server
with patch('socket.getaddrinfo', fixture_getaddrinfo):
    server = make_server('127.0.0.1', args.port, app, threaded=True)
try: server.serve_forever()
finally: server.server_close(); stack.close()
