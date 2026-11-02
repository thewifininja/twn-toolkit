"""Loopback, temporary standalone automation composition fixture; never starts an engine."""
import argparse
import json
import socket
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from flask import Response, abort, jsonify, request
from twn_toolkit import create_app
from twn_toolkit.automation import AutomationStore
from twn_toolkit.distributed_agents import DistributedSettingsStore


def build_fixture(directory):
    app = create_app(directory)
    app.testing = True
    app.config['SESSION_COOKIE_NAME'] = 'twn_automation_prerequisite_fixture'
    app.jinja_env.auto_reload = True
    assert DistributedSettingsStore(directory).get()['role'] == 'standalone'
    store = AutomationStore(directory, app.secret_key)
    assert store.all() == []
    control_path = Path(directory) / 'control.json'
    control_path.write_text('{}')
    counts = {'save_posts': 0}
    allowed_get = {'/automations', '/automations/conditions', '/automations/schedules', '/automations/actions', '/automations/builder/choices', '/fixture', '/session/activity', '/tools/live-sessions'}
    allowed_post = {'/automations/save', '/automations/conditions/save', '/automations/schedules/save', '/automations/actions/save'}

    @app.before_request
    def fixture_guard():
        if request.method == 'GET' and (request.path in allowed_get or request.path.startswith('/static/') or request.path.startswith('/automations/') and request.path.endswith('/history')):
            return
        if request.method == 'POST' and request.path in allowed_post:
            counts['save_posts'] += 1
            (Path(directory) / 'counts.json').write_text(json.dumps(counts))
            control = json.loads(control_path.read_text())
            time.sleep(max(0, min(20, float(control.get('delay', 0)))))
            if control.get('response') == 'html_after':
                request.environ['fixture.html_after'] = True
            if control.get('response') == 'validation':
                return jsonify(error='Synthetic validation: choose another name.'), 400
            if control.get('response') == 'html':
                return Response('<h1>Synthetic unconfirmed response</h1>', mimetype='text/html')
            if control.get('response') == 'forbidden':
                abort(403)
            return
        abort(403)

    @app.after_request
    def unconfirmed_ack(response):
        if request.environ.get('fixture.html_after') and response.status_code == 201:
            return Response('<h1>Synthetic lost JSON acknowledgment after save</h1>', mimetype='text/html')
        return response

    @app.get('/fixture')
    def fixture_index():
        return '<h1>Synthetic automation composition fixture</h1><p>No scheduler, workers, agents, or outbound connections. Save only; never arm/test/run.</p><a href="/automations">Build an automation</a>'

    return app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--port', type=int, default=5120)
    args = parser.parse_args()
    directory = tempfile.mkdtemp(prefix='twn-automation-prerequisites-')
    app = build_fixture(directory)
    print(json.dumps({'instance': directory, 'url': f'http://127.0.0.1:{args.port}/fixture'}), flush=True)
    with patch.object(socket, 'create_connection', side_effect=AssertionError('No fixture outbound connections')):
        app.run(host='127.0.0.1', port=args.port, threaded=True, use_reloader=False)
