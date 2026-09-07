from __future__ import annotations

import json
import socket
import time
from datetime import datetime
from unittest.mock import Mock

import pytest

from twn_toolkit import create_app
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import DiagnosticScheduler, execute_scan
from twn_toolkit.investigations import InvestigationStore
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.wireless_history_diagnostic import prepare_history_config

URL = '/fortigate/fortiap/client-history'
PROFILE = {'name': 'Lab', 'host': 'https://fortigate.example', 'api_key': 'private-key', 'default_vdom': 'root'}
FORM = {'profile': 'Lab', 'mac': 'aabb.ccdd.eeff', 'hours': '24', 'vdom': ''}


def config(profile=None):
    return {**prepare_history_config(profile or PROFILE, FORM), 'username': 'operator', 'investigation_id': ''}


def history(count=1, **changes):
    return {'mac': 'aa:bb:cc:dd:ee:ff', 'vdom': 'root', 'hours': 24, 'source': 'Local FortiGate',
            'timeline': [{'ap': f'AP-{i:04}', 'event_count': 1, 'details': 'associated',
                          'events': [{'raw_secret': 'never-save', 'sort_time': datetime.now()}]} for i in range(count)],
            'raw_event_count': count, 'log_row_count': count, 'omitted_unknown_ap_count': 0,
            'live_clients': [], 'log_error': '', 'live_error': '', **changes}


def app_client(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    (tmp_path / 'profiles.json').write_text(json.dumps([PROFILE]))
    return app, app.test_client()


def test_submission_snapshot_pagination_case_and_no_replay(tmp_path, monkeypatch):
    app, client = app_client(tmp_path)
    client.post('/investigations', data={'title': 'Original'})
    cases = InvestigationStore(str(tmp_path)); original = cases.active_for_user('test-user')['id']
    lookup = Mock(return_value=history(101))
    monkeypatch.setattr('twn_toolkit.wireless_history_diagnostic.wireless_client_history', lookup)
    response = client.post(URL, data=FORM)
    assert response.status_code == 303
    lookup.assert_not_called()
    client.post('/investigations', data={'title': 'Different'})
    (tmp_path / 'profiles.json').write_text(json.dumps([{**PROFILE, 'host': 'https://changed.example', 'api_key': 'changed-key'}]))
    store = DiagnosticJobStore(tmp_path); job = store.claim()
    execute_scan(store, job['id'], job['token'])
    source = lookup.call_args.args[0]
    assert source.client.host == PROFILE['host'] and source.client.api_key == PROFILE['api_key']
    for _ in range(2):
        first = client.get(response.location)
        assert b'AP-0099' in first.data and b'AP-0100' not in first.data
        assert b'Recorded in the active case' in first.data
        assert b'private-key' not in first.data
    second = client.get(response.location + '&page=2')
    assert b'AP-0100' in second.data and b'AP-0099' not in second.data
    assert b'AP-0100' in client.get(response.location + '&page=50').data
    lookup.assert_called_once()
    rows, total = store.page(job['id'], 'test-user')
    assert total == 101 and len(rows) == 100
    assert 'events' not in rows[0]
    assert b'private-key' not in store.path.read_bytes()
    events = [event for event in cases.events_for_user(original, 'test-user') if event['tool_id'] == 'fortigate.wireless_client_history']
    assert len(events) == 1 and events[0]['metrics']['AP_transitions'] == 101
    assert 'never-save' not in json.dumps(events)
    status = client.get(f'{URL}/jobs/{job["id"]}/status')
    assert status.get_json()['state'] == 'succeeded' and status.headers['Cache-Control'] == 'no-store'
    foreign = store.enqueue(user_id='other', tool='wireless_history', config=config())
    wrong_tool = store.enqueue(user_id='test-user', tool='dns', config={})
    for identifier in (foreign, wrong_tool):
        assert client.get(URL + '?job=' + identifier).status_code == 404
        assert client.get(f'{URL}/jobs/{identifier}/status').status_code == 404
        assert client.post(f'{URL}/jobs/{identifier}/cancel').status_code == 404


@pytest.mark.parametrize('log_error,live_error,outcome', [('', '', 'succeeded'), ('private-key failure', '', 'incomplete'), ('bad logs', 'bad live', 'failed')])
def test_source_failure_classification_and_redaction(tmp_path, monkeypatch, log_error, live_error, outcome):
    app, client = app_client(tmp_path)
    client.post('/investigations', data={'title': 'Errors'})
    monkeypatch.setattr('twn_toolkit.wireless_history_diagnostic.wireless_client_history', Mock(return_value=history(0, log_error=log_error, live_error=live_error)))
    submitted = client.post(URL, data=FORM)
    store = DiagnosticJobStore(tmp_path); job = store.claim(); execute_scan(store, job['id'], job['token'])
    saved = store.get(job['id'], 'test-user')
    assert saved['summary']['outcome'] == outcome
    html = client.get(submitted.location).data
    assert b'private-key' not in html
    if log_error:
        assert b'This does not confirm that no matching events exist' in html
        assert b'No matching wireless-client history logs were found' not in html
    cases = InvestigationStore(str(tmp_path)); case = cases.active_for_user('test-user')
    events = [event for event in cases.events_for_user(case['id'], 'test-user') if event['tool_id'] == 'fortigate.wireless_client_history']
    assert len(events) == 1 and events[0]['outcome'] == outcome


def test_result_limits_and_field_projection_are_explicit(tmp_path, monkeypatch):
    store = DiagnosticJobStore(tmp_path)
    output = history(1, live_clients=[{'ap': 'x' * 600}] * 101)
    output['timeline'][0]['details'] = 'x' * 2100
    monkeypatch.setattr('twn_toolkit.wireless_history_diagnostic.wireless_client_history', Mock(return_value=output))
    identifier = store.enqueue(user_id='owner', tool='wireless_history', config=config()); job = store.claim()
    execute_scan(store, identifier, job['token'])
    saved = store.get(identifier, 'owner')['summary']['result']
    assert saved['fields_clipped'] and saved['live_clients_omitted'] == 1
    assert len(store.page(identifier, 'owner')[0][0]['details']) == 2000
    for limit in ('rows', 'bytes'):
        with monkeypatch.context() as patch:
            if limit == 'rows':
                patch.setattr('twn_toolkit.wireless_history_diagnostic.MAX_RESULT_ROWS', 0)
            else:
                patch.setattr('twn_toolkit.diagnostic_jobs.MAX_RESULT_BYTES', 1)
            identifier = store.enqueue(user_id='owner', tool='wireless_history', config=config()); job = store.claim()
            execute_scan(store, identifier, job['token'])
            assert store.get(identifier, 'owner')['state'] == 'failed'
            assert 'shorter time window' in store.get(identifier, 'owner')['error']
            assert store.page(identifier, 'owner') == ([], 0)


@pytest.mark.parametrize('cancel', [False, True])
def test_stalled_appliance_is_reaped_on_deadline_or_cancel(tmp_path, cancel):
    OperationalSettingsStore(str(tmp_path)).save({'diagnostic_timeout_seconds': 5})
    scheduler = DiagnosticScheduler(tmp_path)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(10)
        identifier = scheduler.store.enqueue(user_id='owner', tool='wireless_history', config=config({**PROFILE, 'host': f'http://127.0.0.1:{listener.getsockname()[1]}'}))
        try:
            scheduler.tick(); process = scheduler.active[identifier]['process']
            connection, _ = listener.accept()
            with connection:
                if cancel:
                    scheduler.store.cancel(identifier, 'owner')
                end = time.monotonic() + 12
                while time.monotonic() < end and scheduler.active:
                    scheduler.tick(); time.sleep(.03)
                assert process.poll() is not None and not scheduler.active
                assert scheduler.store.get(identifier, 'owner')['state'] == ('cancelled' if cancel else 'failed')
                assert scheduler.store.page(identifier, 'owner') == ([], 0)
        finally:
            scheduler.close()


def test_queued_cancel_and_invalid_input_never_contact_appliance(tmp_path, monkeypatch):
    app, client = app_client(tmp_path)
    lookup = Mock(); monkeypatch.setattr('twn_toolkit.wireless_history_diagnostic.wireless_client_history', lookup)
    for fields in ({'mac': 'bad'}, {'hours': '169'}, {'profile': 'missing'}, {'vdom': 'x' * 257}):
        assert client.post(URL, data={**FORM, **fields}).status_code == 200
    store = DiagnosticJobStore(tmp_path); assert store.claim() is None
    response = client.post(URL, data=FORM); identifier = response.location.split('job=')[1]
    assert client.post(f'{URL}/jobs/{identifier}/cancel').status_code == 303
    assert store.claim() is None and store.get(identifier, 'test-user')['state'] == 'cancelled'
    lookup.assert_not_called()


def test_status_cancel_and_results_require_wireless_tool_permission(tmp_path):
    from twn_toolkit.auth import AuthStore
    app = create_app(str(tmp_path)); auth = AuthStore(str(tmp_path))
    auth.create_user('admin', 'TemporaryPassword123!', is_admin=True)
    user = auth.create_user('restricted', 'TemporaryPassword123!')
    store = DiagnosticJobStore(tmp_path); identifier = store.enqueue(user_id=user['id'], tool='wireless_history', config=config())
    client = app.test_client(); client.post('/login', data={'username': 'restricted', 'password': 'TemporaryPassword123!'})
    assert client.get(URL + '?job=' + identifier).status_code == 403
    assert client.get(f'{URL}/jobs/{identifier}/status').status_code == 403
    assert client.post(f'{URL}/jobs/{identifier}/cancel').status_code == 403
