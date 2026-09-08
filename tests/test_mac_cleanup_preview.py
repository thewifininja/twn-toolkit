"""Real HTTP previews; all appliance operations mocked."""
import re
from tests.fac_cleanup_helpers import complete_cleanup
import time
from copy import deepcopy
from unittest.mock import patch

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.preview_binding import PREVIEW_MAX_AGE_SECONDS
from test_fortiauthenticator import _cleanup_devices, _cleanup_memberships

CLIENT = 'twn_toolkit.fortiauthenticator_routes.FortiAuthenticatorClient.from_profile'
FORM = {'profile': 'Lab', 'group_uri': '/api/v1/macgroups/8/',
        'action': 'delete_devices', 'selected_id': ['42'], 'confirmation': 'DELETE 1 DEVICE'}


@pytest.fixture
def browser(tmp_path):
    app = create_app(str(tmp_path))
    AuthStore(str(tmp_path)).create_user('reviewer', 'TemporaryReviewPassword123!', is_admin=True)
    client = app.test_client()
    client.post('/login', data={'username': 'reviewer', 'password': 'TemporaryReviewPassword123!'})
    client.post('/fortiauthenticator/profiles', data={
        'name': 'Lab', 'host': 'https://fac.example.com', 'username': 'api-user',
        'password': 'fixture-secret', 'timeout': '20',
    })
    yield app, client
    app.extensions['remote_session_manager'].close()


def prepare(client):
    with patch(CLIENT) as connect:
        connect.return_value.get_all_mac_group_memberships.return_value = _cleanup_memberships()
        connect.return_value.get_all_mac_devices.return_value = _cleanup_devices()
        response = client.post('/fortiauthenticator/mac-cleanup', data={**FORM, 'intent': 'preview'})
        response = complete_cleanup(client, response)
    assert response.status_code == 200
    assert b'fixture-secret' not in response.data
    return {name: re.search(fr'name="{name}" type="hidden" value="([^"]+)"', response.text).group(1)
            for name in ('context_token', 'candidate_token', 'preview_job')}


def test_missing_preview_never_connects(browser):
    _, client = browser
    with patch(CLIENT) as connect:
        response = client.post('/fortiauthenticator/mac-cleanup/execute', data=FORM, follow_redirects=True)
    assert b'preview' in response.data.lower()
    connect.assert_not_called()


@pytest.mark.parametrize('change', ['group', 'action', 'profile', 'actor', 'expired', 'token'])
def test_changed_context_never_connects(browser, change):
    app, client = browser
    data = {**FORM, **prepare(client)}
    if change == 'group':
        data['group_uri'] = '/api/v1/macgroups/9/'
    elif change == 'action':
        data['action'] = 'remove_memberships'
    elif change == 'profile':
        client.post('/fortiauthenticator/profiles', data={
            'original_name': 'Lab', 'name': 'Lab', 'host': 'https://different.example.com',
            'username': 'api-user', 'password': '', 'timeout': '20',
        })
    elif change == 'actor':
        AuthStore(app.instance_path).create_user('other', 'TemporaryReviewPassword123!', is_admin=True)
        client.post('/logout')
        client.post('/login', data={'username': 'other', 'password': 'TemporaryReviewPassword123!'})
    elif change == 'token':
        data['context_token'] = 'invalid'
    now = time.time() + (PREVIEW_MAX_AGE_SECONDS + 1 if change == 'expired' else 0)
    with patch('itsdangerous.timed.time.time', return_value=now), patch(CLIENT) as connect:
        response = client.post('/fortiauthenticator/mac-cleanup/execute', data=data, follow_redirects=True)
    assert b'preview' in response.data.lower()
    connect.assert_not_called()


@pytest.mark.parametrize('change', ['mac', 'name', 'membership', 'other_group_same_label', 'unselected', 'missing_token'])
def test_candidate_drift_prevents_all_deletions(browser, change):
    _, client = browser
    data = {**FORM, **prepare(client)}
    memberships, devices = deepcopy(_cleanup_memberships()), deepcopy(_cleanup_devices())
    if change == 'mac':
        devices[0]['address'] = '00:00:00:00:00:01'
    elif change == 'name':
        devices[0]['name'] = 'Replacement'
    elif change == 'membership':
        memberships[0]['id'] = 101
    elif change == 'other_group_same_label':
        memberships[2]['group'] = '/api/v1/macgroups/10/'
    elif change == 'unselected':
        devices[1]['name'] = 'Changed unselected device'
    else:
        data.pop('candidate_token')
    with patch(CLIENT) as connect:
        appliance = connect.return_value
        appliance.get_all_mac_group_memberships.return_value = memberships
        appliance.get_all_mac_devices.return_value = devices
        response = client.post('/fortiauthenticator/mac-cleanup/execute', data=data)
        if change != 'missing_token':
            response = complete_cleanup(client, response, expected='failed')
        else:
            assert response.status_code == 302
            response = client.get(response.headers['Location'])
        appliance.delete_mac_device.assert_not_called()
        appliance.delete_mac_group_membership.assert_not_called()
    assert b'preview' in response.data.lower()


def test_selected_subset_survives_collection_reordering(browser):
    _, client = browser
    data = {**FORM, **prepare(client)}
    with patch(CLIENT) as connect:
        appliance = connect.return_value
        appliance.get_all_mac_group_memberships.return_value = list(reversed(_cleanup_memberships()))
        appliance.get_all_mac_devices.return_value = list(reversed(_cleanup_devices()))
        def deleted(identifier):
            appliance.get_all_mac_devices.return_value = [row for row in appliance.get_all_mac_devices.return_value if not row['resource_uri'].endswith('/'+identifier+'/')]
            appliance.get_all_mac_group_memberships.return_value = [row for row in appliance.get_all_mac_group_memberships.return_value if not row['device'].endswith('/'+identifier+'/')]
        appliance.delete_mac_device.side_effect = deleted
        response = client.post('/fortiauthenticator/mac-cleanup/execute', data=data)
        response = complete_cleanup(client, response)
        appliance.delete_mac_device.assert_called_once_with('42')
        appliance.delete_mac_group_membership.assert_not_called()
    assert response.status_code == 200
    assert b'MAC device deleted globally' in response.data
