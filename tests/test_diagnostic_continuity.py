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
    response = client.post(f'{path}/jobs/{job_id}/cancel', headers={'Accept': 'application/json'})
    assert response.status_code == 303
    assert store.get(job_id, 'test-user')['state'] == 'cancelled'
    assert client.get(response.location).status_code == 200
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
