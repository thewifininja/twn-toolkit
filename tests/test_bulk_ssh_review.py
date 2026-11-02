"""Automatic command review never connects; explicit run choices stay host scoped."""
import re
from unittest.mock import patch

import pytest

from twn_toolkit import create_app
from twn_toolkit import bulk_ssh_jobs as jobs
from twn_toolkit import network_tools as network
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.ssh_commandlets import SSHHostMatrixStore


@pytest.fixture
def review(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    client = app.test_client()
    client.post('/tools/multi-ssh', data=dict(action='save_host_matrix',
        host_matrix_name='Lab', matrix='Host | Site\nfirst.test | A\nsecond.test | B'))
    client.post('/tools/multi-ssh', data=dict(action='save_matrix_action',
        host_matrix_original_name='Lab', matrix_action_name='Status', commands='show {{ site }}'))
    form = dict(action='preview', matrix_action_run='on', host_matrix_original_name='Lab',
                selected_actions=['Status'], port='22')
    return app, client, form


def prepare(client, form):
    response = client.post('/tools/multi-ssh', data=form, headers={'Accept': 'application/json'})
    assert response.status_code == 200, response.data
    return response.json


def run(client, form, token, **changes):
    return client.post('/tools/multi-ssh', data={**form, 'action': 'run',
        'preview_token': token, 'confirm_execution': 'on', 'username': 'fixture',
        'password': 'fixture-only', 'per_host_options': 'on', **changes},
        headers={'Accept': 'application/json'})


def test_automatic_review_never_connects_admits_or_retains_credentials(review):
    app, client, form = review
    with patch('twn_toolkit.ssh_routes._enqueue_ssh') as enqueue, patch.object(network, '_ssh_host_connection') as connect:
        payload = prepare(client, {**form, 'password': 'must-not-render'})
    enqueue.assert_not_called()
    connect.assert_not_called()
    assert 'must-not-render' not in payload['html']
    assert 'first.test' in payload['connection_html'] and 'second.test' in payload['connection_html']
    assert re.search(r'<input\b[^>]*\schecked(?:\s|=|>)', payload['connection_html']) is None
    assert DiagnosticJobStore(app.instance_path).recent('test-user', 'bulk_ssh') == []


def test_run_button_is_confirmation_but_unsigned_and_unconfirmed_runs_fail(review):
    app, client, form = review
    payload = prepare(client, form)
    assert run(client, form, '').status_code == 400
    assert run(client, form, payload['token'], confirm_execution='').status_code == 400
    result = run(client, form, payload['token'])
    assert result.status_code == 202
    # Repeated clicks recover the same admission, not a second execution.
    again = run(client, form, payload['token'])
    assert again.json['job_id'] == result.json['job_id']


def test_mixed_host_choices_override_global_flags_and_reach_only_selected_host(review):
    app, client, form = review
    payload = prepare(client, form)
    response = run(client, form, payload['token'], unknown_key_hosts=['first.test'],
                   legacy_algorithm_hosts=['second.test'], allow_unknown_hosts='on', allow_legacy_algorithms='on')
    assert response.status_code == 202
    store = DiagnosticJobStore(app.instance_path)
    config = store.get(response.json['job_id'], 'test-user')['config']
    plans = jobs.plans_for(config)
    calls = []
    def connected(*args):
        calls.append((args[0], args[5], args[9]))
        return {'host': args[0], 'status': 'success', 'output': ''}
    with patch.object(network, '_ssh_host_connection', connected):
        network.run_ssh_host_plans(plans, username='fixture', password='fixture',
                                  allow_unknown_hosts=True, allow_legacy_algorithms=True)
    assert sorted(calls) == [('first.test', True, False), ('second.test', False, True)]


@pytest.mark.parametrize('change', [dict(unknown_key_hosts=['unreviewed.test']),
                                   dict(legacy_algorithm_hosts=['unreviewed.test']), dict(port='2222')])
def test_stale_port_or_unreviewed_host_choices_rejected(review, change):
    app, client, form = review
    payload = prepare(client, form)
    assert run(client, form, payload['token'], **change).status_code == 400
    assert DiagnosticJobStore(app.instance_path).recent('test-user', 'bulk_ssh') == []


def test_saved_command_change_invalidates_review_and_refresh_preserves_order(review):
    app, client, form = review
    payload = prepare(client, form)
    store = SSHHostMatrixStore(app.instance_path)
    matrix = store.get('Lab')
    matrix['actions'][0]['commands'] = 'show changed'
    store.upsert(matrix)
    assert run(client, form, payload['token']).status_code == 400
    refreshed = prepare(client, form)
    assert 'show changed' in refreshed['html']
    assert run(client, form, refreshed['token']).status_code == 202


def test_corrupt_retained_host_options_fail_closed(review):
    app, client, form = review
    response = run(client, form, prepare(client, form)['token'])
    config = DiagnosticJobStore(app.instance_path).get(response.json['job_id'], 'test-user')['config']
    config['host_options'].pop('first.test')
    with pytest.raises(ValueError, match='connection choices'):
        jobs.plans_for(config)


def test_per_host_legacy_choice_survives_changed_key_retry_token(review):
    from itsdangerous import URLSafeTimedSerializer
    from twn_toolkit.auth import load_or_create_secret_key
    from twn_toolkit.diagnostic_worker import execute_scan
    app, client, form = review
    response = run(client, form, prepare(client, form)['token'], legacy_algorithm_hosts=['second.test'])
    store = DiagnosticJobStore(app.instance_path)
    def mismatch(*args):
        return dict(host=args[0], host_label=args[8], status='error', output='',
                    host_key_mismatch=dict(expected_fingerprint='SHA256:' + 'A'*43,
                                           presented_fingerprint='SHA256:' + 'B'*43))
    job = store.claim()
    with patch.object(network, '_ssh_host_connection', mismatch):
        execute_scan(store, job['id'], job['token'])
    store.release(job['id'], job['token'])
    retained = store.get(response.json['job_id'], 'test-user')
    serializer = URLSafeTimedSerializer(load_or_create_secret_key(app.instance_path), salt=jobs.RETRY_SALT)
    choices = [serializer.loads(row['host_key_retry_token'])['allow_legacy_algorithms']
               for row in jobs.host_rows(store, retained)]
    assert choices == [False, True]


def test_allow_unknown_never_overwrites_a_changed_key(review):
    from unittest.mock import MagicMock
    import paramiko
    app, client, form = review
    response = run(client, form, prepare(client, form)['token'], unknown_key_hosts=['first.test'])
    config = DiagnosticJobStore(app.instance_path).get(response.json['job_id'], 'test-user')['config']
    first, second = MagicMock(), MagicMock()
    key = paramiko.RSAKey.generate(1024)
    expected = paramiko.RSAKey.generate(1024)
    first.connect.side_effect = paramiko.BadHostKeyException('first.test', key, expected)
    second.connect.side_effect = paramiko.SSHException('Server second.test not found in known_hosts')
    with patch('paramiko.SSHClient', side_effect=[first, second]), patch('twn_toolkit.ssh_security.forget_ssh_known_host') as forget:
        # Serialize this fixture's connection order, without changing the live worker.
        with patch.object(network, 'SSH_EXECUTION_WORKERS', 1):
            rows = network.run_ssh_host_plans(jobs.plans_for(config), username='fixture', password='fixture')
    assert rows[0]['host_key_mismatch']['hostname'] == 'first.test'
    assert rows[1]['status'] == 'error'
    assert isinstance(first.set_missing_host_key_policy.call_args.args[0], paramiko.AutoAddPolicy)
    assert isinstance(second.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)
    forget.assert_not_called()
    first.save_host_keys.assert_not_called()
    second.save_host_keys.assert_not_called()


def test_direct_legacy_port_refresh_requires_explicit_admission(review):
    import re
    app, client, _ = review
    form = dict(action='preview', matrix='Name | Host\nLegacy | legacy.test',
                commands='show status', port='22')
    def token(page):
        assert page.status_code == 200
        return re.search(rb'name="preview_token" type="hidden" value="([^"]+)"', page.data)[1].decode()
    original = token(client.post('/tools/multi-ssh', data=form))
    run_form = {**form, 'action': 'run', 'port': '2222', 'preview_token': original,
                'username': 'fixture', 'password': 'fixture-only', 'confirm_execution': 'on'}
    assert client.post('/tools/multi-ssh', data=run_form, headers={'Accept':'application/json'}).status_code == 400
    refreshed = token(client.post('/tools/multi-ssh', data={**form, 'port':'2222'}))
    store = DiagnosticJobStore(app.instance_path)
    assert store.recent('test-user', 'bulk_ssh') == []
    response = client.post('/tools/multi-ssh', data={**run_form, 'preview_token':refreshed}, headers={'Accept':'application/json'})
    assert response.status_code == 202
    config = store.get(response.json['job_id'], 'test-user')['config']
    assert config['port'] == 2222 and config['host_options'] is None


def test_mixed_run_composition_admission_and_stale_edit(review):
    import json
    app, client, form = review
    steps = [{'source': 'inline', 'id': 'first', 'name': 'Typed first', 'commands': 'show clock', 'command_timeout': 10},
             {'source': 'saved', 'name': 'Status'},
             {'source': 'inline', 'id': 'last', 'name': 'Typed last', 'commands': 'show {{ site }} detail', 'command_timeout': 20}]
    form = {**form, 'run_steps': json.dumps(steps)}
    payload = prepare(client, form)
    assert payload['html'].index('Typed first') < payload['html'].index('Status') < payload['html'].index('Typed last')
    changed = [dict(step) for step in steps]
    changed[0]['commands'] = 'show changed'
    assert run(client, form, payload['token'], run_steps=json.dumps(changed)).status_code == 400
    response = run(client, form, payload['token'])
    assert response.status_code == 202
    config = DiagnosticJobStore(app.instance_path).get(response.json['job_id'], 'test-user')['config']
    plans = jobs.plans_for(config)
    assert len(plans) == 2
    rendered = repr(plans[0])
    assert rendered.index('show clock') < rendered.index('show A') < rendered.index('show A detail')
    assert len(SSHHostMatrixStore(app.instance_path).get('Lab')['actions']) == 1


def test_same_matrix_save_preserves_unadded_typed_draft(review):
    app, client, form = review
    response = client.post('/tools/multi-ssh', data={**form, 'action': 'save_matrix_action',
        'matrix_action_name': 'New saved', 'commands': 'show version',
        'inline_draft_commands': 'show unadded', 'inline_draft_timeout': '15'})
    assert response.status_code == 200
    assert b'show unadded</textarea>' in response.data
    assert b'value="15" form="multi-ssh-run-form" data-ssh-inline-draft-timeout' in response.data
