"""Loopback-only browser fixture. No scheduler, agent enrollment or device work.

Run: /tmp/twn-qol-venv/bin/python tests/fixtures/diagnostic_continuity_app.py
The printed control.json can set states/poll_status/cancel_status by fixture key.
"""
import argparse
import json
import socket
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from flask import abort, request
from twn_toolkit import create_app
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.distributed_agents import DistributedSettingsStore


def build_fixture(directory):
    root = Path(directory).resolve()
    app = create_app(str(root)); app.testing = True
    app.config['SESSION_COOKIE_NAME'] = 'twn_continuity_fixture'
    app.jinja_env.auto_reload = True
    assert DistributedSettingsStore(str(root)).get()['role'] == 'standalone'
    client = app.test_client()
    cases = {
        'tcp': ('/tools/port-scanner', dict(hosts='old.test', ports='443', timeout='.1', concurrency='1')),
        'dns': ('/tools/dns-response', dict(hosts='old.test', servers='192.0.2.53', mode='compare', record_type='A', timeout='.2', duration='1', qps='2', concurrency='1')),
        'transfer': ('/tools/multi-transfer', dict(hosts='old.test', username='fixture', password='fixture-only', port='22', remote_paths='/old-config', destination='', output_mode='download', filename_pattern='{filename}', protocol='sftp')),
    }
    jobs = {}
    store = DiagnosticJobStore(str(root))
    control_path = root / 'control.json'
    control_path.write_text('{}')
    applied = {}
    counts = {'get': 0, 'status': 0, 'cancel': 0, 'submit': 0}

    def control():
        try:
            return json.loads(control_path.read_text())
        except (OSError, ValueError):
            return {}

    def set_state(key, state):
        job = jobs[key]
        summary = {'stats': {'combinations': 0, 'open': 0, 'closed': 0, 'timeout': 0, 'error': 0},
                   'lookup_summary': {'queries': 0, 'successful': 0, 'failed': 0, 'average_ms': None, 'slowest_ms': None},
                   'successful': 0, 'total': 0, 'archive': False, 'published_paths': [], 'stage': 'Synthetic ' + state}
        with store.connect(write=True) as db:
            db.execute("UPDATE diagnostic_jobs SET state=?,token=?,completed=?,error=?,summary=? WHERE id=?", (state,
                'fixture-token' if state in ('running', 'cancel_requested') else '',
                None if state in ('queued', 'running', 'cancel_requested') else time.time(),
                'Synthetic failure' if state == 'failed' else '', store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary'), job['id']))

    @app.before_request
    def fixture_guard():
        if app.config.get('FIXTURE_SEEDING'):
            return
        current = control()
        for key, state in current.get('states', {}).items():
            if key in jobs and state in {'queued', 'running', 'cancel_requested', 'succeeded', 'failed', 'cancelled', 'unknown'} and applied.get(key) != state:
                set_state(key, state); applied[key] = state
        if request.path.startswith('/static/') or request.path in {'/fixture', '/session/activity', '/tools/live-sessions'}:
            return
        matching = next((key for key, job in jobs.items() if request.path.startswith(job['path'])), None)
        if matching is None:
            abort(403)
        if request.path.endswith('/status'):
            counts['status'] += 1
            (root / 'counts.json').write_text(json.dumps(counts))
            code = int(current.get('poll_status', {}).get(matching, 200))
            if code != 200:
                abort(code)
        elif request.path.endswith('/cancel'):
            counts['cancel'] += 1
            (root / 'counts.json').write_text(json.dumps(counts))
            code = int(current.get('cancel_status', {}).get(matching, 200))
            if code != 200:
                abort(code)
        elif request.method == 'POST':
            counts['submit'] += 1
            (root / 'counts.json').write_text(json.dumps(counts))
            # The browser checks never need to run a new diagnostic. Preserve
            # the explicit boundary and make any accidental submission visible.
            abort(403)
        else:
            counts['get'] += 1
        (root / 'counts.json').write_text(json.dumps(counts))

    @app.get('/fixture')
    def fixture_index():
        links = ''.join(f'<p><a href="{job["url"]}">{key}: retained running fixture</a></p>' for key, job in jobs.items())
        return '<h1>Synthetic diagnostic continuity fixture</h1>' + links + f'<a href="/tools/port-scanner?job={foreign}">Foreign-owned result (404)</a>'

    app.config['FIXTURE_SEEDING'] = True
    for key, (path, form) in cases.items():
        response = client.post(path, data=form)
        assert response.status_code == 303, response.data
        jobs[key] = {'path': path, 'id': response.location.split('job=')[1], 'url': response.location}
    with store.connect(write=True) as db:
        db.execute("UPDATE diagnostic_jobs SET state='running',token='fixture-token',started=?", (time.time(),))
    foreign = store.enqueue(user_id='foreign-owner', config={})
    app.config['FIXTURE_SEEDING'] = False
    return app, {'instance': str(root), 'control': str(control_path), 'counts': str(root / 'counts.json'), 'jobs': jobs}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--port', type=int, default=5104)
    args = parser.parse_args()
    app, info = build_fixture(tempfile.mkdtemp(prefix='twn-continuity-ui-'))
    print(json.dumps(info), flush=True)
    # This entrypoint does not launch twn, workers, schedulers or enrolled agents.
    with patch.object(socket, 'create_connection', side_effect=AssertionError('No fixture outbound connections')):
        app.run(host='127.0.0.1', port=args.port, threaded=True, use_reloader=False)
