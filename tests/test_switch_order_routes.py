from unittest.mock import patch

import pytest

from twn_toolkit.auth import AuthStore
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from tests.switch_order_helpers import complete_switch_order
from tests.test_switch_order_preview import browser, confirm, order_form, SWITCHES


def test_queued_load_never_contacts_appliance_in_request_and_retains_scoped_pages(browser):
    app, client = browser
    with patch('twn_toolkit.fortigate.FortiGateClient.from_profile') as connect:
        response = client.post('/fortigate/switch-order/objects', data={'profile': 'Lab'})
        assert response.status_code == 202
        connect.assert_not_called()
    links = response.get_json()
    assert client.get('/health').status_code == 200
    assert b'Run in progress' not in client.get(links['job_url']).data
    store = DiagnosticJobStore(app.instance_path)
    job = store.claim()
    assert client.get(links['status_url']).get_json()['state'] == 'running'
    rows = [{'id': f'id-{i:03}', 'name': f'row-{i:03}', 'description': '<script>fixture</script>', 'serial': ''} for i in range(500)]
    store.finish(job['id'], job['token'], [], {'switches': rows, 'phase': 'loaded'})
    first = client.get(links['job_url'])
    assert b'row-049' in first.data and b'row-050' not in first.data
    assert b'&lt;script&gt;' in first.data
    assert first.headers['Cache-Control'] == 'private, no-store'
    last = client.get(links['job_url'] + '?page=999')
    assert b'row-499' in last.data and b'row-449' not in last.data
    assert b'256 characters' in last.data
    assert b'fixture-secret' not in first.data
    assert client.get(links['job_url'] + '?page=invalid').status_code == 400
    other = store.enqueue(user_id='other', tool='switch_order', config={'mode': 'load'})
    wrong_tool = store.enqueue(user_id=job['user_id'], tool='tcp_scan', config={})
    for identifier in [other, wrong_tool]:
        base = '/fortigate/switch-order/jobs/' + identifier
        assert client.get(base).status_code == 404
        assert client.get(base + '/status').status_code == 404
        assert client.post(base + '/cancel').status_code == 404


def test_duplicate_submission_and_cancel_retry_return_original_operation(browser):
    app, client = browser
    token = confirm(client)
    form = {**order_form(), 'preview_token': token}
    with patch('twn_toolkit.fortigate.FortiGateClient.from_profile') as connect:
        first = client.post('/fortigate/switch-order/apply', data=form)
        second = client.post('/fortigate/switch-order/apply', data=form)
        assert first.status_code == second.status_code == 202
        assert first.get_json() == second.get_json()
        links = first.get_json()
        assert client.post(links['cancel_url']).status_code == 303
        third = client.post('/fortigate/switch-order/apply', data=form)
        assert third.get_json() == links
        assert client.get(links['status_url']).get_json()['state'] == 'cancelled'
        connect.assert_not_called()
    assert DiagnosticJobStore(app.instance_path).claim() is None


@pytest.mark.parametrize('phase', ['preview', 'apply'])
@pytest.mark.parametrize('revision', ['', 'tampered'])
def test_reconciled_revision_cannot_be_stripped_or_changed(browser, phase, revision):
    _, client = browser
    token = confirm(client)
    with patch('twn_toolkit.fortigate.FortiGateClient.get_managed_switches', side_effect=[SWITCHES, list(reversed(SWITCHES))]), patch('twn_toolkit.fortigate.FortiGateClient.move_managed_switch_after'):
        result = complete_switch_order(client, client.post('/fortigate/switch-order/apply', data={**order_form(), 'preview_token': token})).get_json()
    assert result['state'] == 'succeeded'
    loaded = result['data']
    form = {**order_form(), 'original_switch_id': ['b', 'a'], 'switch_id': ['a', 'b'],
            'load_token': loaded['load_token'], 'target_revision': loaded['target_revision']}
    if phase == 'apply':
        confirmed = client.post('/fortigate/switch-order/preview', data=form)
        assert confirmed.status_code == 200
        form['preview_token'] = confirmed.get_json()['preview_token']
    form['target_revision'] = revision
    with patch('twn_toolkit.fortigate.FortiGateClient.from_profile') as connect:
        assert client.post('/fortigate/switch-order/' + phase, data=form).status_code == 409
        connect.assert_not_called()


def test_result_and_cancel_require_current_tool_permission(browser):
    app, _ = browser
    auth = AuthStore(app.instance_path)
    grant = auth.save_access_profile(name='Switch ordering', tool_ids=['fortigate.switch_order'])
    user = auth.create_user('operator', 'TemporaryReviewPassword123!', is_admin=False, access_profile_ids=[grant['id']])
    client = app.test_client()
    client.post('/login', data={'username': 'operator', 'password': 'TemporaryReviewPassword123!'})
    response = client.post('/fortigate/switch-order/objects', data={'profile': 'Lab'})
    assert response.status_code == 202
    links = response.get_json()
    auth.update_user_access(user['id'], is_admin=False, access_profile_ids=[])
    assert client.get(links['job_url']).status_code == 302  # Revokes the existing session.
    client.post('/login', data={'username': 'operator', 'password': 'TemporaryReviewPassword123!'})
    assert client.get(links['job_url']).status_code == 403
    assert client.get(links['status_url']).status_code == 403
    assert client.post(links['cancel_url']).status_code == 403


def test_worker_and_request_bind_same_instance_through_symlink(tmp_path):
    from twn_toolkit import create_app
    from twn_toolkit.profiles import ProfileStore

    actual = tmp_path / 'actual'
    actual.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(actual, target_is_directory=True)
    app = create_app(str(alias))
    app.testing = True
    ProfileStore(str(alias)).upsert({'name': 'Lab', 'host': 'https://fixture.invalid',
                                   'api_key': 'fixture-secret', 'default_vdom': 'root'})
    client = app.test_client()
    try:
        with patch('twn_toolkit.fortigate.FortiGateClient.get_managed_switches', return_value=SWITCHES):
            result = complete_switch_order(client, client.post('/fortigate/switch-order/objects', data={'profile': 'Lab'})).get_json()
        assert result['state'] == 'succeeded'
        response = client.post('/fortigate/switch-order/preview', data={**order_form(), 'load_token': result['data']['load_token']})
        assert response.status_code == 200
        assert response.get_json()['preview_token']
    finally:
        app.extensions['remote_session_manager'].close()
