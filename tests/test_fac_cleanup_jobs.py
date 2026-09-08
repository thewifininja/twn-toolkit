import copy
import time
from unittest.mock import patch

import pytest

from twn_toolkit import fac_cleanup_jobs as operations
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.fortiauthenticator import FortiAuthenticatorError
from twn_toolkit.profiles import FortiAuthenticatorProfileStore
from tests.test_fortiauthenticator import _cleanup_memberships, _cleanup_devices
from tests.test_mac_cleanup_preview import browser, prepare, FORM

REAL_RECORD = operations.record_cleanup_outcome


@pytest.fixture
def cleanup(tmp_path, monkeypatch):
    store = DiagnosticJobStore(tmp_path)
    profile = {'name': 'Lab', 'host': 'https://fixture.invalid', 'username': 'api', 'password': 'fixture-secret', 'verify_tls': True, 'timeout': 10}
    FortiAuthenticatorProfileStore(str(tmp_path)).upsert(profile)
    profile = FortiAuthenticatorProfileStore(str(tmp_path)).get('Lab')
    config = dict(profile=profile, mode='preview', action='delete_devices', group_uri='/api/v1/macgroups/8/', username='owner', investigation_id='')
    events = []
    class Appliance:
        memberships = _cleanup_memberships()
        devices = _cleanup_devices()
        deletes = []
        def get_all_mac_group_memberships(self): return copy.deepcopy(self.memberships)
        def get_all_mac_devices(self): return copy.deepcopy(self.devices)
        def delete_mac_group_membership(self, identifier):
            self.deletes.append(identifier)
            self.memberships = [row for row in self.memberships if str(row['id']) != identifier]
        def delete_mac_device(self, identifier):
            self.deletes.append(identifier)
            self.devices = [row for row in self.devices if not row['resource_uri'].endswith('/'+identifier+'/')]
            self.memberships = [row for row in self.memberships if not row['device'].endswith('/'+identifier+'/')]
    appliance = Appliance()
    monkeypatch.setattr(operations.FortiAuthenticatorClient, 'from_profile', lambda _: appliance)
    monkeypatch.setattr(operations, 'record_cleanup_outcome', lambda *args, **kwargs: events.append(args[2]))
    return store, config, appliance, events


def execute(cleanup, config=None):
    store, default, _, _ = cleanup
    config = config or default
    identifier = store.enqueue(user_id='owner', tool=operations.TOOL, config=config)
    job = store.claim()
    assert job['id'] == identifier
    operations.execute_cleanup(store, job, config)
    store.release(identifier, job['token'])
    return store.get(identifier, 'owner')


def apply_config(cleanup, action='delete_devices'):
    config = {**cleanup[1], 'action': action}
    review = execute(cleanup, config)
    assert review['state'] == 'succeeded', review
    preview = review['summary']['preview']
    key = 'device_id' if action == 'delete_devices' else 'membership_id'
    return {**config, 'mode': 'apply', 'preview_job': review['id'], 'context_token': preview['context_token'],
            'candidate_token': preview['candidate_token'], 'selected_ids': [row[key] for row in preview['targets']],
            'confirmation': preview['confirmation']}


@pytest.mark.parametrize('action', ['delete_devices', 'remove_memberships'])
def test_reviewed_cleanup_verifies_absence_before_next_target(cleanup, action):
    config = apply_config(cleanup, action)
    result = execute(cleanup, config)
    assert result['state'] == 'succeeded', result
    assert cleanup[2].deletes == config['selected_ids']
    assert len(result['summary']['completed_moves']) == len(result['summary']['results']) == 2
    assert result['summary']['in_flight'] is None
    assert cleanup[0].mutation_revision(operations.target_key(config['profile'])) == result['id']
    if action == 'remove_memberships':
        assert len(cleanup[2].devices) == 2
        assert [row['id'] for row in cleanup[2].memberships] == [93]
    assert b'fixture-secret' not in cleanup[0].path.read_bytes()


@pytest.mark.parametrize('drift', ['profile', 'candidate', 'group', 'selection', 'confirmation', 'token', 'origin', 'missing_preview'])
def test_changed_review_never_deletes(cleanup, drift):
    store, _, appliance, _ = cleanup
    config = apply_config(cleanup)
    if drift == 'profile':
        FortiAuthenticatorProfileStore(str(store.instance)).upsert({**config['profile'], 'password': 'different'})
    elif drift == 'candidate': appliance.memberships[-1]['group'] = '/api/v1/macgroups/99/'
    elif drift == 'group': config['group_uri'] = '/api/v1/macgroups/9/'
    elif drift == 'selection': config['selected_ids'] = ['999']
    elif drift == 'confirmation': config['confirmation'] = 'DELETE 1 DEVICE'
    elif drift == 'token': config['candidate_token'] += 'changed'
    elif drift == 'origin':
        with store.connect(write=True) as db: db.execute('INSERT INTO diagnostic_mutation_targets VALUES (?,?)', (operations.target_key(config['profile']), 'other'))
    elif drift == 'missing_preview':
        with store.connect(write=True) as db: db.execute('DELETE FROM diagnostic_jobs WHERE id=?', (config['preview_job'],))
    result = execute(cleanup, config)
    assert result['state'] == 'failed', result
    assert appliance.deletes == []


@pytest.mark.parametrize('boundary', ['before_intent', 'after_send', 'after_ack', 'after_verified'])
def test_cleanup_cancellation_stops_remaining_targets(cleanup, monkeypatch, boundary):
    store, _, appliance, _ = cleanup
    config = apply_config(cleanup)
    progress = store.progress
    delete = appliance.delete_mac_device
    def checkpoint(identifier, token, summary):
        if boundary == 'before_intent' and summary['in_flight']: store.cancel(identifier, 'owner')
        saved = progress(identifier, token, summary)
        if (boundary == 'after_ack' and summary['completed_moves']) or (boundary == 'after_verified' and summary['results']): store.cancel(identifier, 'owner')
        return saved
    def send(identifier):
        delete(identifier)
        if boundary == 'after_send':
            with store.connect() as db: current = db.execute("SELECT id FROM diagnostic_jobs WHERE state='running'").fetchone()[0]
            store.cancel(current, 'owner')
    monkeypatch.setattr(store, 'progress', checkpoint)
    monkeypatch.setattr(appliance, 'delete_mac_device', send)
    result = execute(cleanup, config)
    assert result['state'] == ('cancelled' if boundary == 'before_intent' else 'unknown'), result
    assert len(appliance.deletes) == (0 if boundary == 'before_intent' else 1)


@pytest.mark.parametrize('failure', ['lost_ack', 'still_present', 'verification_read', 'progress_before', 'progress_after'])
def test_uncertainty_retains_evidence_without_continuing(cleanup, monkeypatch, failure):
    store, _, appliance, _ = cleanup
    config = apply_config(cleanup)
    delete = appliance.delete_mac_device
    read = appliance.get_all_mac_devices
    progress = store.progress
    def send(identifier):
        if failure == 'still_present': appliance.deletes.append(identifier)
        else: delete(identifier)
        if failure == 'lost_ack': raise FortiAuthenticatorError('Lost fixture-secret acknowledgement')
    def inventory():
        if failure == 'verification_read' and appliance.deletes: raise FortiAuthenticatorError('Read failed fixture-secret')
        return read()
    def checkpoint(identifier, token, summary):
        if (failure == 'progress_before' and summary['in_flight']) or (failure == 'progress_after' and summary['completed_moves']): raise OSError('disk')
        return progress(identifier, token, summary)
    monkeypatch.setattr(appliance, 'delete_mac_device', send)
    monkeypatch.setattr(appliance, 'get_all_mac_devices', inventory)
    monkeypatch.setattr(store, 'progress', checkpoint)
    result = execute(cleanup, config)
    assert result['state'] == ('failed' if failure == 'progress_before' else 'unknown'), result
    assert len(appliance.deletes) == (0 if failure == 'progress_before' else 1)
    assert 'fixture-secret' not in result['error']


def test_cleanup_preview_bounds_never_truncate_review(cleanup):
    cleanup[2].devices[0]['name'] = 'x' * (operations.MAX_PREVIEW_BYTES + 1)
    result = execute(cleanup)
    assert result['state'] == 'failed'
    assert 'envelope' in result['error']
    assert cleanup[2].deletes == []


def test_remaining_target_drift_after_verified_deletion_stops_batch(cleanup, monkeypatch):
    config = apply_config(cleanup)
    delete = cleanup[2].delete_mac_device
    def send(identifier):
        delete(identifier)
        cleanup[2].memberships[0]['group_name'] = 'Changed'
    monkeypatch.setattr(cleanup[2], 'delete_mac_device', send)
    result = execute(cleanup, config)
    assert result['state'] == 'unknown'
    assert len(result['summary']['results']) == len(cleanup[2].deletes) == 1


def test_cleanup_admission_is_nonblocking_and_deduplicated(browser):
    app, client = browser
    data = {**FORM, **prepare(client)}
    with patch('twn_toolkit.fac_cleanup_jobs.FortiAuthenticatorClient.from_profile') as connect:
        first = client.post('/fortiauthenticator/mac-cleanup/execute', data=data)
        second = client.post('/fortiauthenticator/mac-cleanup/execute', data=data)
    assert first.status_code == second.status_code == 303
    assert first.headers['Location'] == second.headers['Location']
    connect.assert_not_called()
    location = first.headers['Location']
    assert client.get(location).status_code == 200
    assert client.get(location+'/status').json['state'] == 'queued'
    from twn_toolkit.auth import AuthStore
    AuthStore(app.instance_path).create_user('other', 'TemporaryPassword123!', is_admin=True)
    other = app.test_client()
    other.post('/login', data={'username': 'other', 'password': 'TemporaryPassword123!'})
    assert other.get(location).status_code == 404
    assert other.get(location+'/status').status_code == 404
    assert other.post(location+'/cancel').status_code == 404


def test_cleanup_result_access_follows_current_tool_permission(browser):
    app, _ = browser
    from twn_toolkit.auth import AuthStore
    auth = AuthStore(app.instance_path)
    grant = auth.save_access_profile(name='Cleanup', tool_ids=['fortiauthenticator.mac_cleanup'])
    auth.create_user('operator', 'TemporaryPassword123!', access_profile_ids=[grant['id']])
    client = app.test_client()
    client.post('/login', data={'username': 'operator', 'password': 'TemporaryPassword123!'})
    response = client.post('/fortiauthenticator/mac-cleanup', data={**FORM, 'intent': 'load_groups'})
    assert response.status_code == 303
    location = response.headers['Location']
    assert client.get(location).status_code == 200
    auth.save_access_profile(name='Cleanup', tool_ids=[], profile_id=grant['id'])
    assert client.get(location).status_code == 403
    assert client.get(location+'/status').status_code == 403
    assert client.post(location+'/cancel').status_code == 403


def test_expired_cleanup_in_queue_never_deletes(cleanup):
    from twn_toolkit.preview_binding import PREVIEW_MAX_AGE_SECONDS
    config = apply_config(cleanup)
    with patch('itsdangerous.timed.time.time', return_value=time.time()+PREVIEW_MAX_AGE_SECONDS+1):
        result = execute(cleanup, config)
    assert result['state'] == 'failed'
    assert cleanup[2].deletes == []


def test_cleanup_intent_and_origin_revision_are_durable_before_delete(cleanup, monkeypatch):
    store, _, appliance, _ = cleanup
    config = apply_config(cleanup)
    original = appliance.delete_mac_device
    def delete(identifier):
        with store.connect() as db:
            job_id = db.execute("SELECT id FROM diagnostic_jobs WHERE state='running'").fetchone()[0]
        progress = store.get(job_id, 'owner')['summary']
        assert progress['in_flight']['device_id'] == identifier
        assert progress['attempted_moves'] == len(appliance.deletes)+1
        assert store.mutation_revision(operations.target_key(config['profile'])) == job_id
        original(identifier)
    monkeypatch.setattr(appliance, 'delete_mac_device', delete)
    assert execute(cleanup, config)['state'] == 'succeeded'


def test_original_paused_case_receives_verified_cleanup(cleanup):
    from twn_toolkit.audit import AuditStore
    from twn_toolkit.investigations import InvestigationStore
    store = cleanup[0]
    config = apply_config(cleanup)
    cases = InvestigationStore(str(store.instance))
    case = cases.create(owner_user_id='owner', owner_username='owner', title='Original')
    cases.set_state(case['id'], 'owner', 'owner', 'paused')
    config['investigation_id'] = case['id']
    result = execute(cleanup, config)
    assert result['state'] == 'succeeded'
    REAL_RECORD(store, result, 'succeeded', config=config)
    events = [event for event in cases.events_for_user(case['id'], 'owner') if event['operation_id'] == 'fac-cleanup:'+result['id']]
    assert len(events) == 1
    assert events[0]['event_type'] == 'external.action.completed'
    assert events[0]['tool_id'] == 'fortiauthenticator.mac_cleanup'
    audit = AuditStore(str(store.instance)).recent(1)[0]
    assert audit['details']['successful target count'] == 2


def test_cleanup_recording_failure_preserves_result_and_warning(cleanup, monkeypatch):
    from twn_toolkit.audit import AuditStore
    store = cleanup[0]
    config = apply_config(cleanup)
    result = execute(cleanup, config)
    def fail(*args, **kwargs): raise OSError('fixture')
    monkeypatch.setattr(AuditStore, 'record', fail)
    REAL_RECORD(store, result, 'succeeded', config=config)
    saved = store.get(result['id'], 'owner')
    assert saved['state'] == 'succeeded'
    assert 'could not be fully confirmed' in saved['summary']['recording_warning']


@pytest.mark.parametrize('mode', ['preview', 'groups'])
def test_cleanup_row_limit_refuses_without_partial_review(cleanup, mode):
    appliance = cleanup[2]
    appliance.memberships = [{'id': index, 'resource_uri': f'/api/v1/macgroup-memberships/{index}/',
        'device': f'/api/v1/macdevices/{index}/', 'device_name': f'Device {index}',
        'group': f'/api/v1/macgroups/{index}/' if mode == 'groups' else '/api/v1/macgroups/8/',
        'group_name': f'Group {index}' if mode == 'groups' else 'Cleanup Group'} for index in range(1, 502)]
    appliance.devices = [{'resource_uri': f'/api/v1/macdevices/{index}/', 'name': f'Device {index}'} for index in range(1, 502)]
    result = execute(cleanup, {**cleanup[1], 'mode': mode})
    assert result['state'] == 'failed'
    assert '500' in result['error']
    assert 'preview' not in result['summary']
    assert 'groups' not in result['summary']
    assert appliance.deletes == []
