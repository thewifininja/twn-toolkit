from contextlib import contextmanager
import io
import re
from unittest.mock import patch

import pytest

from twn_toolkit import rename_jobs as operations
from twn_toolkit.auth import load_or_create_secret_key
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.fortigate import FortiGateError
from twn_toolkit.preview_binding import PreviewSigner, PREVIEW_MAX_AGE_SECONDS
from twn_toolkit.profiles import ProfileStore
from twn_toolkit.rename_preview import _context, _SCOPE
from twn_toolkit.tasks import get_task
from tests.test_fortigate_preview_binding import browser, entries_form, preview

REAL_RECORD = operations.record_rename_outcome


@pytest.fixture
def operation(tmp_path, monkeypatch):
    store = DiagnosticJobStore(tmp_path)
    profile = {'name': 'Lab', 'host': 'https://fixture.invalid', 'api_key': 'fixture-secret', 'default_vdom': 'root'}
    ProfileStore(str(tmp_path)).upsert(profile)
    task = get_task('rename-aps')
    config = dict(profile=profile, task_id=task.id, endpoint=task.endpoint_template, username='owner', investigation_id='',
                  target_revision='', entries=[{'identifier': 'AP1', 'current_name': 'Old 1', 'new_name': 'New 1', 'vdom': 'root'},
                                               {'identifier': 'AP2', 'current_name': 'Old 2', 'new_name': 'New 2', 'vdom': 'root'}])
    signer = PreviewSigner(load_or_create_secret_key(str(tmp_path)), store.instance, 'owner')
    config['preview_token'] = signer.issue(_SCOPE, _context(task, profile, config['endpoint'], config['entries']))
    identifier = store.enqueue(user_id='owner', tool=operations.TOOL, config=config)
    job = store.claim()
    events = []

    class Appliance:
        names = {'AP1': 'Old 1', 'AP2': 'Old 2'}
        calls = []

        @contextmanager
        def pooled(self):
            yield self

        def get_object(self, endpoint, identifier, vdom):
            self.calls.append(('get', identifier))
            return {'results': [{'name': self.names[identifier]}]}

        def rename_object(self, endpoint, target, name, vdom, **kwargs):
            saved = store.get(identifier, 'owner')['summary']
            assert saved['in_flight'] == {'identifier': target, 'new_name': name, 'vdom': vdom}
            assert store.mutation_revision(operations.target_key(profile)) == identifier
            self.calls.append(('put', target))
            self.names[target] = name
            return {'status': 'success'}

    appliance = Appliance()
    monkeypatch.setattr(operations.FortiGateClient, 'from_profile', lambda _: appliance)
    monkeypatch.setattr(operations, 'record_rename_outcome', lambda *args, **kwargs: events.append(args[2]))
    return store, job, config, appliance, events


def run(operation):
    store, job, config, _, _ = operation
    operations.execute_rename(store, job, config)
    return store.get(job['id'], 'owner')


def test_each_rename_is_acknowledged_and_verified_before_next(operation):
    store, job, _, appliance, events = operation
    result = run(operation)
    assert result['state'] == 'succeeded'
    assert appliance.calls == [('get', 'AP1'), ('put', 'AP1'), ('get', 'AP1'), ('get', 'AP2'), ('put', 'AP2'), ('get', 'AP2')]
    assert result['summary']['api_calls'] == 6
    assert [row['row_number'] for row in result['summary']['results']] == [1, 2]
    assert len(result['summary']['completed_moves']) == 2
    assert result['summary']['in_flight'] is None
    assert events == ['succeeded']
    assert b'fixture-secret' not in store.path.read_bytes()


@pytest.mark.parametrize('boundary', ['before_intent', 'after_send', 'after_ack', 'after_verified'])
def test_cancellation_never_sends_remaining_renames(operation, monkeypatch, boundary):
    store, job, _, appliance, _ = operation
    progress = store.progress
    move = appliance.rename_object

    def checkpoint(job_id, token, summary):
        if boundary == 'before_intent' and summary['in_flight']:
            store.cancel(job_id, 'owner')
        saved = progress(job_id, token, summary)
        if boundary == 'after_ack' and summary['completed_moves'] or boundary == 'after_verified' and summary['results']:
            store.cancel(job_id, 'owner')
        return saved

    def rename(*args, **kwargs):
        result = move(*args, **kwargs)
        if boundary == 'after_send':
            store.cancel(job['id'], 'owner')
        return result

    monkeypatch.setattr(store, 'progress', checkpoint)
    monkeypatch.setattr(appliance, 'rename_object', rename)
    result = run(operation)
    assert result['state'] == ('cancelled' if boundary == 'before_intent' else 'unknown')
    assert ('put', 'AP2') not in appliance.calls
    if boundary == 'before_intent':
        assert ('put', 'AP1') not in appliance.calls
    if boundary == 'after_send':
        assert result['summary']['in_flight'] and result['summary']['completed_moves'] == []


@pytest.mark.parametrize('failure', ['read', 'send', 'ack_storage', 'verification', 'mismatch'])
def test_failure_boundary_retains_honest_progress_and_stops(operation, monkeypatch, failure):
    store, _, _, appliance, _ = operation
    get = appliance.get_object
    put = appliance.rename_object
    progress = store.progress

    def read(*args):
        if failure == 'read' or failure == 'verification' and appliance.names['AP1'] == 'New 1':
            raise FortiGateError('fixture-secret read failure')
        if failure == 'mismatch' and appliance.names['AP1'] == 'New 1':
            return {'results': [{'name': 'Unexpected'}]}
        return get(*args)

    def rename(*args, **kwargs):
        result = put(*args, **kwargs)
        if failure == 'send':
            raise FortiGateError('fixture-secret acknowledgement lost')
        return result

    def checkpoint(job_id, token, summary):
        if failure == 'ack_storage' and summary['completed_moves']:
            raise OSError('Injected storage failure')
        return progress(job_id, token, summary)

    monkeypatch.setattr(appliance, 'get_object', read)
    monkeypatch.setattr(appliance, 'rename_object', rename)
    monkeypatch.setattr(store, 'progress', checkpoint)
    result = run(operation)
    assert result['state'] == ('failed' if failure == 'read' else 'unknown')
    assert ('put', 'AP2') not in appliance.calls
    assert 'fixture-secret' not in result['error']
    assert all('fixture-secret' not in row['message'] for row in result['summary']['results'])
    if failure in {'send', 'ack_storage'}:
        assert result['summary']['in_flight'] and result['summary']['completed_moves'] == []


@pytest.mark.parametrize('change', ['profile', 'actor', 'expiry', 'name', 'revision'])
def test_review_drift_is_rejected_before_mutation(operation, monkeypatch, change):
    store, job, config, appliance, _ = operation
    if change == 'profile':
        ProfileStore(str(store.instance)).upsert({**config['profile'], 'api_key': 'replacement'})
    elif change == 'actor':
        job['user_id'] = 'different'
    elif change == 'expiry':
        import time
        now = time.time()
        monkeypatch.setattr('time.time', lambda: now + PREVIEW_MAX_AGE_SECONDS + 2)
    elif change == 'name':
        appliance.names['AP1'] = 'Changed since review'
    else:
        config['target_revision'] = 'tampered'
    result = run(operation)
    assert result['state'] == 'failed'
    assert not any(call[0] == 'put' for call in appliance.calls)


def test_secondary_recording_failure_is_visible_in_retained_result(operation, monkeypatch):
    from twn_toolkit.audit import AuditStore
    store, job, config, _, _ = operation
    assert run(operation)['state'] == 'succeeded'
    def fail(*args, **kwargs):
        raise OSError('Fixture audit write failure')
    monkeypatch.setattr(AuditStore, 'record', fail)
    REAL_RECORD(store, job, 'succeeded', config=config)
    result = store.get(job['id'], 'owner')
    assert result['state'] == 'succeeded'
    assert 'could not be fully confirmed' in result['summary']['recording_warning']


def test_live_request_is_nonblocking_duplicate_admission_and_scoped(browser):
    app, client = browser
    token = preview(client)
    with patch('twn_toolkit.fortigate.FortiGateClient.from_profile') as connect:
        first = client.post('/tasks/rename-aps/rename', data={**entries_form(), 'preview_token': token})
        second = client.post('/tasks/rename-aps/rename', data={**entries_form(), 'preview_token': token})
        assert first.status_code == second.status_code == 303
        assert first.location == second.location
        assert client.get('/health').status_code == 200
        assert client.get(first.location).status_code == 200
        connect.assert_not_called()
    store = DiagnosticJobStore(app.instance_path)
    job = store.claim()
    wrong_owner = store.enqueue(user_id='other', tool=operations.TOOL, config={})
    for location in [first.location.replace('/rename-aps/', '/rename-switches/'), first.location.rsplit('/', 1)[0] + '/' + wrong_owner]:
        assert client.get(location).status_code == 404
        assert client.get(location + '/status').status_code == 404
        assert client.post(location + '/cancel').status_code == 404


@pytest.mark.parametrize('data', [
    {'csv_file': (b'identifier,new_name\n' + b'a,b\n' * 501, 'too-many.csv')},
    {'csv_file': (b'x' * (64 * 1024 + 1), 'too-large.csv')},
    {'csv_file': (b'identifier,new_name\n\xff,b\n', 'invalid.csv')},
])
def test_csv_preview_bounds_fail_without_appliance_access(browser, data):
    _, client = browser
    content, name = data['csv_file']
    with patch('twn_toolkit.fortigate.FortiGateClient.from_profile') as connect:
        response = client.post('/tasks/rename-aps/run', data={'profile': 'Lab', 'dry_run': 'on', 'csv_file': (io.BytesIO(content), name)})
        assert response.status_code == 302
        connect.assert_not_called()


def test_local_preview_never_constructs_appliance_client(browser):
    _, client = browser
    with patch('twn_toolkit.fortigate.FortiGateClient.from_profile') as connect:
        token = preview(client)
        assert token
        connect.assert_not_called()


def test_success_preserves_original_case_and_bounded_audit_changes(operation):
    from twn_toolkit.audit import AuditStore
    from twn_toolkit.investigations import InvestigationStore

    store, job, config, _, _ = operation
    cases = InvestigationStore(str(store.instance))
    case = cases.create(owner_user_id='owner', owner_username='owner', title='Original')
    config['investigation_id'] = case['id']
    cases.set_state(case['id'], 'owner', 'owner', 'paused')
    assert run(operation)['state'] == 'succeeded'
    REAL_RECORD(store, job, 'succeeded', config=config)
    events = [event for event in cases.events_for_user(case['id'], 'owner') if event['operation_id'] == 'rename:' + job['id']]
    assert len(events) == 1
    assert events[0]['event_type'] == 'external.action.completed'
    assert events[0]['tool_id'] == 'fortigate.rename_aps'
    audit = AuditStore(str(store.instance)).recent(1)[0]
    assert audit['details']['changes']
    assert audit['details']['successful object count'] == 2


def test_verification_after_first_row_does_not_allow_changed_profile(operation, monkeypatch):
    store, _, config, appliance, _ = operation
    original = appliance.get_object

    def read(*args):
        value = original(*args)
        if appliance.names['AP1'] == 'New 1':
            ProfileStore(str(store.instance)).upsert({**config['profile'], 'api_key': 'changed'})
        return value
    monkeypatch.setattr(appliance, 'get_object', read)
    result = run(operation)
    assert result['state'] == 'unknown'
    assert result['summary']['results'][0]['status'] == 'success'
    assert ('put', 'AP2') not in appliance.calls


@pytest.mark.parametrize('endpoint', ['/api/{current_name:>1000000000}', '/api/{current_name!r}', '/api/{current_name.__class__}', '/api/{unknown}', '/api/{'])
def test_preview_endpoint_rejects_format_expansion_before_rendering(endpoint):
    from twn_toolkit.rename_routes import bounded_rename_entries
    with pytest.raises(ValueError, match='placeholder'):
        bounded_rename_entries([], endpoint)
