from __future__ import annotations

import time
from unittest.mock import patch

from twn_toolkit.profiles import ProfileStore
from twn_toolkit.preview_binding import PREVIEW_MAX_AGE_SECONDS

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore

SWITCHES = [{'switch-id': 'a', 'name': 'Switch A'}, {'switch-id': 'b', 'name': 'Switch B'}]


@pytest.fixture
def browser(tmp_path):
    app = create_app(str(tmp_path))
    AuthStore(str(tmp_path)).create_user('reviewer', 'TemporaryReviewPassword123!', is_admin=True)
    client = app.test_client()
    client.post('/login', data={'username': 'reviewer', 'password': 'TemporaryReviewPassword123!'})
    client.post('/profiles', data={'name': 'Lab', 'host': 'https://fortigate.example', 'api_key': 'fixture-secret', 'default_vdom': 'root'})
    yield app, client
    app.extensions['remote_session_manager'].close()


def order_form():
    return {'profile': 'Lab', 'vdom': 'root', 'original_switch_id': ['a', 'b'],
            'switch_id': ['b', 'a'], 'confirmed': 'on'}


def test_unbound_confirmation_does_not_create_client(browser):
    _, client = browser
    with patch('twn_toolkit.fortigate_routes.FortiGateClient.from_profile') as connect:
        connect.return_value.get_managed_switches.return_value = SWITCHES
        response = client.post('/fortigate/switch-order/apply', data=order_form())
    assert response.status_code == 409
    connect.assert_not_called()


def load(client):
    with patch('twn_toolkit.fortigate_routes.FortiGateClient.get_managed_switches', return_value=SWITCHES):
        response = client.post('/fortigate/switch-order/objects', data={'profile': 'Lab', 'vdom': 'root'})
    assert response.status_code == 200
    assert b'fixture-secret' not in response.data
    return response.get_json()['load_token']


def confirm(client):
    token = load(client)
    with patch('twn_toolkit.fortigate_routes.FortiGateClient.from_profile') as connect:
        response = client.post('/fortigate/switch-order/preview', data={**order_form(), 'load_token': token})
    assert response.status_code == 200
    connect.assert_not_called()
    assert response.get_json()['moves'] == [{'switch_id': 'a', 'after': 'b'}]
    return response.get_json()['preview_token']


def test_reviewed_order_applies_and_returns_fresh_load_binding(browser):
    _, client = browser
    token = confirm(client)
    with patch('twn_toolkit.fortigate_routes.FortiGateClient.get_managed_switches', side_effect=[SWITCHES, list(reversed(SWITCHES))]), patch('twn_toolkit.fortigate_routes.FortiGateClient.move_managed_switch_after') as move:
        response = client.post('/fortigate/switch-order/apply', data={**order_form(), 'preview_token': token})
    assert response.status_code == 200
    move.assert_called_once_with('a', 'b', 'root')
    refreshed = client.post('/fortigate/switch-order/preview', data={
        **order_form(), 'original_switch_id': ['b', 'a'], 'switch_id': ['a', 'b'],
        'load_token': response.get_json()['load_token'],
    })
    assert refreshed.status_code == 200


@pytest.mark.parametrize('field,value', [('vdom', 'other'), ('switch_id', ['a', 'b']),
    ('switch_id', ['b', 'b']), ('original_switch_id', ['b', 'a']), ('preview_token', 'invalid')])
def test_apply_context_changes_are_rejected_before_client_creation(browser, field, value):
    _, client = browser
    token = confirm(client)
    with patch('twn_toolkit.fortigate_routes.FortiGateClient.from_profile') as connect:
        response = client.post('/fortigate/switch-order/apply', data={**order_form(), 'preview_token': token, field: value})
    assert response.status_code == 409
    connect.assert_not_called()


@pytest.mark.parametrize('phase', ['preview', 'apply'])
@pytest.mark.parametrize('change', ['profile', 'actor', 'expired'])
def test_binding_context_and_expiry(browser, phase, change):
    app, client = browser
    key = 'load_token' if phase == 'preview' else 'preview_token'
    token = load(client) if phase == 'preview' else confirm(client)
    if change == 'profile':
        store = ProfileStore(app.instance_path)
        item = store.get('Lab');item['host'] = 'https://other.example';store.upsert(item)
    elif change == 'actor':
        AuthStore(app.instance_path).create_user('other', 'TemporaryReviewPassword123!', is_admin=True)
        client = app.test_client();client.post('/login', data={'username': 'other', 'password': 'TemporaryReviewPassword123!'})
    future = int(time.time()) + (PREVIEW_MAX_AGE_SECONDS + 5 if change == 'expired' else 0)
    with patch('itsdangerous.timed.TimestampSigner.get_timestamp', return_value=future), patch('twn_toolkit.fortigate_routes.FortiGateClient.from_profile') as connect:
        response = client.post('/fortigate/switch-order/' + phase, data={**order_form(), key: token})
    assert response.status_code == 409
    connect.assert_not_called()


@pytest.mark.parametrize('changed', [list(reversed(SWITCHES)), SWITCHES[:1]])
def test_device_order_or_inventory_drift_aborts_before_moves(browser, changed):
    _, client = browser
    token = confirm(client)
    with patch('twn_toolkit.fortigate_routes.FortiGateClient.get_managed_switches', return_value=changed), patch('twn_toolkit.fortigate_routes.FortiGateClient.move_managed_switch_after') as move:
        response = client.post('/fortigate/switch-order/apply', data={**order_form(), 'preview_token': token})
    assert response.status_code == 409
    move.assert_not_called()


def test_preview_uses_existing_tool_access_policy(browser):
    app, _ = browser
    auth = AuthStore(app.instance_path)
    auth.create_user('blocked', 'TemporaryReviewPassword123!', is_admin=False)
    grant = auth.save_access_profile(name='Switch ordering', tool_ids=['fortigate.switch_order'])
    auth.create_user('allowed', 'TemporaryReviewPassword123!', is_admin=False, access_profile_ids=[grant['id']])
    for username, expected in [('blocked', 403), ('allowed', 409)]:
        client = app.test_client()
        client.post('/login', data={'username': username, 'password': 'TemporaryReviewPassword123!'})
        with patch('twn_toolkit.fortigate_routes.FortiGateClient.from_profile') as connect:
            response = client.post('/fortigate/switch-order/preview', data=order_form())
        assert response.status_code == expected
        connect.assert_not_called()
