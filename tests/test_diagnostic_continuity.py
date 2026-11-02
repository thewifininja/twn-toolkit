"""Returning to a retained diagnostic must not resubmit or lose job identity."""
import re

import pytest

from twn_toolkit import create_app
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore

CASES = [
    ('tcp_scan', '/tools/port-scanner', 'port-scan-form', dict(hosts='old.test', ports='443', timeout='.1', concurrency='1')),
    ('dns', '/tools/dns-response', 'dns-form', dict(hosts='old.test', servers='192.0.2.53', mode='compare', record_type='A', timeout='.2', duration='1', qps='2', concurrency='1')),
    ('transfer', '/tools/multi-transfer', 'bulk-transfer-form', dict(hosts='old.test', username='fixture', password='not-a-real-secret', port='22', remote_paths='/old-config', destination='', output_mode='download', filename_pattern='{filename}', protocol='sftp')),
]


@pytest.fixture
def continuity(tmp_path, monkeypatch):
    app = create_app(str(tmp_path)); app.testing = True
    # Admission and GET/status/cancel are request-side only; a regression must not
    # turn this fixture into device execution.
    def no_device(*args, **kwargs):
        pytest.fail('Web continuity flow attempted device execution')
    monkeypatch.setattr('twn_toolkit.diagnostic_worker.scan_tcp_ports', no_device)
    monkeypatch.setattr('twn_toolkit.dns_diagnostic.dns_lookup_matrix', no_device)
    monkeypatch.setattr('twn_toolkit.transfer_diagnostic.fetch_transfer_files', no_device)
    return app, app.test_client(), DiagnosticJobStore(app.instance_path)


@pytest.mark.parametrize('tool,path,form_id,form', CASES)
def test_retained_page_exposes_protected_form_and_bound_new_tab_result(continuity, tool, path, form_id, form):
    app, client, store = continuity
    submitted = client.post(path, data=form)
    assert submitted.status_code == 303
    job_id = submitted.location.split('job=')[1]
    with store.connect() as db:
        count = db.execute('SELECT COUNT(*) FROM diagnostic_jobs').fetchone()[0]
    page = client.get(submitted.location, environ_overrides={'SCRIPT_NAME': '/agents/fixture/ui'}).data.decode()
    assert re.search(r'<form\b[^>]*\bid="' + form_id + r'"[^>]*\bdata-unsaved-form', page) or re.search(r'<form\b[^>]*\bdata-unsaved-form[^>]*\bid="' + form_id + r'"', page)
    assert f'data-diagnostic-draft-form="{form_id}"' in page
    assert f'data-diagnostic-result-url="/agents/fixture/ui{path}?job={job_id}"' in page
    assert re.search(r'<a\b[^>]*data-diagnostic-result-link[^>]*target="_blank"[^>]*rel="noopener"', page)
    assert 'data-diagnostic-cancel' in page
    assert 'unsaved-forms.js' in page
    assert 'not-a-real-secret' not in page
    status = client.get(f'{path}/jobs/{job_id}/status')
    assert status.status_code == 200 and status.json['state'] == 'queued'
    assert client.get(f'{path}?job={job_id}').status_code == 200
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM diagnostic_jobs').fetchone()[0] == count
    assert store.get(job_id, 'test-user')['config']['form']['hosts'] == 'old.test'


@pytest.mark.parametrize('tool,path,form_id,form', CASES)
def test_cancel_and_result_navigation_preserve_owned_job_boundary(continuity, tool, path, form_id, form):
    app, client, store = continuity
    submitted = client.post(path, data=form)
    job_id = submitted.location.split('job=')[1]
    foreign_id = store.enqueue(user_id='another-owner', tool=tool, config={})
    assert client.get(f'{path}?job={foreign_id}').status_code == 404
    assert client.get(f'{path}/jobs/{foreign_id}/status').status_code == 404
    assert client.post(f'{path}/jobs/{foreign_id}/cancel').status_code == 404
    page = client.get(submitted.location, environ_overrides={'SCRIPT_NAME': '/agents/fixture/ui'}).data.decode()
    result_url = re.search(r'data-diagnostic-result-url="([^"]+)"', page).group(1)
    response = client.post(f'{path}/jobs/{job_id}/cancel', headers={'Accept': 'application/json'}, environ_overrides={'SCRIPT_NAME': '/agents/fixture/ui'})
    assert response.status_code == 303 and response.location == result_url
    assert store.get(job_id, 'test-user')['state'] == 'cancelled'
    assert client.get(submitted.location).status_code == 200
    # Reading/revisiting/cancelling an already terminal job never queues work.
    assert client.post(f'{path}/jobs/{job_id}/cancel').status_code == 303
    assert len(store.recent('test-user', tool)) == 1
    assert store.get(foreign_id, 'another-owner')['state'] == 'queued'


def test_recent_keeps_old_active_jobs_and_bounds_terminal_history(continuity):
    app, client, store = continuity
    # Direct synthetic rows avoid queue/storage limits while checking a history
    # projection against old active work buried under many newer completions.
    with store.connect(write=True) as db:
        for state, count, owner, tool in [('running', 3, 'owner', 'dns'), ('succeeded', 30, 'owner', 'dns'), ('queued', 2, 'other', 'dns'), ('running', 2, 'owner', 'tcp_scan')]:
            for i in range(count):
                identity = f'{state}-{owner}-{tool}-{i}'
                created = i if state != 'succeeded' else 100+i
                db.execute("INSERT INTO diagnostic_jobs(id,user_id,tool,state,config,summary,created,timeout) VALUES(?,?,?,?,?,?,?,30)", (identity, owner, tool, state, '{}', '{}', created))
    rows = store.recent('owner', 'dns')
    assert len(rows) == 13
    assert sum(row['state'] == 'running' for row in rows) == 3
    assert sum(row['state'] == 'succeeded' for row in rows) == 10
    assert all('other' not in row['id'] and 'tcp_scan' not in row['id'] for row in rows)
    assert [row['created'] for row in rows] == sorted((row['created'] for row in rows), reverse=True)
    assert all(set(row) == {'id', 'state', 'created'} for row in rows)


def test_recent_preview_is_bounded_even_for_legacy_excess_active_rows(continuity):
    app, client, store = continuity
    with store.connect(write=True) as db:
        db.executemany("INSERT INTO diagnostic_jobs(id,user_id,tool,state,config,summary,created,timeout) VALUES(?,'owner','dns','running','{}','{}',?,30)", [(f'legacy-{i}', i) for i in range(250)])
    assert len(store.recent('owner', 'dns')) == 200


@pytest.mark.parametrize('tool,path,form_id,form', CASES)
def test_continuity_routes_still_require_tool_permission(tmp_path, tool, path, form_id, form):
    from twn_toolkit.auth import AuthStore
    app = create_app(str(tmp_path)); auth = AuthStore(str(tmp_path))
    auth.create_user('admin', 'TemporaryPassword123!', is_admin=True)
    user = auth.create_user('restricted', 'TemporaryPassword123!')
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id=user['id'], tool=tool, config={})
    client = app.test_client()
    client.post('/login', data={'username': 'restricted', 'password': 'TemporaryPassword123!'})
    assert client.get(f'{path}?job={job_id}').status_code == 403
    assert client.get(f'{path}/jobs/{job_id}/status').status_code == 403
    assert client.post(f'{path}/jobs/{job_id}/cancel').status_code == 403
    assert store.get(job_id, user['id'])['state'] == 'queued'


def test_browser_fixture_has_real_retained_results_and_controlled_failures(tmp_path):
    import importlib.util
    import json
    from pathlib import Path
    path = Path(__file__).parent / 'fixtures' / 'diagnostic_continuity_app.py'
    spec = importlib.util.spec_from_file_location('continuity_fixture', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    app, info = module.build_fixture(tmp_path)
    client = app.test_client()
    for key, job in info['jobs'].items():
        assert client.get(job['url']).status_code == 200
        Path(info['control']).write_text(json.dumps({'states': {key: 'succeeded'}}))
        assert client.get(f"{job['path']}/jobs/{job['id']}/status").json['state'] == 'succeeded'
        assert client.get(job['url']).status_code == 200
    tcp = info['jobs']['tcp']
    Path(info['control']).write_text(json.dumps({'poll_status': {'tcp': 403}, 'cancel_status': {'tcp': 403}}))
    assert client.get(f"{tcp['path']}/jobs/{tcp['id']}/status").status_code == 403
    assert client.post(f"{tcp['path']}/jobs/{tcp['id']}/cancel").status_code == 403
    assert client.post(tcp['path'], data={'hosts': 'never-execute.test'}).status_code == 403
    counts = json.loads(Path(info['counts']).read_text())
    assert counts['submit'] == 1 and counts['cancel'] == 1


@pytest.mark.parametrize("include_summary", [False, True])
def test_recent_is_one_snapshot_during_worker_completion(continuity, monkeypatch, include_summary):
    from contextlib import contextmanager
    app, client, store = continuity
    job_id = store.enqueue(user_id='owner', tool='dns', config={})
    with store.connect(write=True) as db:
        db.execute("UPDATE diagnostic_jobs SET state='running' WHERE id=?", (job_id,))
    original_connect = store.connect
    triggered = False
    statements = []

    class Connection:
        def __init__(self, db): self.db = db
        def execute(self, sql, parameters=()):
            nonlocal triggered
            cursor = self.db.execute(sql, parameters)
            if sql.lstrip().startswith('WITH active AS') or sql.lstrip().startswith('SELECT id,state,created'):
                statements.append(sql)
                if not triggered:
                    triggered = True
                    with original_connect(write=True) as worker:
                        worker.execute("UPDATE diagnostic_jobs SET state='succeeded',completed=123 WHERE id=?", (job_id,))
            return cursor

    @contextmanager
    def concurrent_connect(*, write=False):
        with original_connect(write=write) as db:
            yield Connection(db)

    monkeypatch.setattr(store, 'connect', concurrent_connect)
    rows = store.recent('owner', 'dns', include_summary=include_summary)
    assert triggered
    assert len(statements) == 1
    assert len(rows) == 1 and rows[0]['id'] == job_id
    assert rows[0]['state'] in ('running', 'succeeded')
    with original_connect() as db:
        assert db.execute('SELECT state FROM diagnostic_jobs WHERE id=?', (job_id,)).fetchone()[0] == 'succeeded'


def test_slow_native_post_fixture_enqueues_only_explicit_synthetic_work(tmp_path):
    import importlib.util
    import json
    from pathlib import Path
    spec = importlib.util.spec_from_file_location('native_fixture', Path(__file__).parent / 'fixtures' / 'diagnostic_continuity_app.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    app, info = module.build_fixture(tmp_path, baseline_client='// immutable test baseline')
    client = app.test_client(); old = info['jobs']['dns']
    control = {'baseline_client': True, 'native_post': {'dns': True}, 'post_delay': {'dns': 0}, 'complete_during_post': {'dns': True}}
    Path(info['control']).write_text(json.dumps(control))
    baseline = client.get('/static/diagnostic-job.js')
    assert baseline.status_code == 200 and baseline.data == b'// immutable test baseline'
    response = client.post(old['path'], data=CASES[1][3])
    assert response.status_code == 303 and response.location != old['url']
    store = DiagnosticJobStore(tmp_path)
    assert store.get(old['id'], 'test-user')['state'] == 'succeeded'
    new_id = response.location.split('job=')[1]
    assert store.get(new_id, 'test-user')['state'] == 'queued'
    counts = json.loads(Path(info['counts']).read_text())
    assert counts['submit'] == 1 and counts['native_responses'] == [{'status': 303, 'location': response.location}]
