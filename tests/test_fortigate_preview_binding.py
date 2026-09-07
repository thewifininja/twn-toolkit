from __future__ import annotations

import io
import re
import time

from twn_toolkit.profiles import ProfileStore
from twn_toolkit.rename_preview import RENAME_PREVIEW_MAX_AGE_SECONDS
from unittest.mock import patch

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore


@pytest.fixture
def browser(tmp_path):
    app = create_app(str(tmp_path))
    AuthStore(str(tmp_path)).create_user('reviewer', 'TemporaryReviewPassword123!', is_admin=True)
    client = app.test_client()
    client.post('/login', data={'username': 'reviewer', 'password': 'TemporaryReviewPassword123!'})
    client.post('/profiles', data={'name': 'Lab', 'host': 'https://fortigate.example', 'api_key': 'profile-secret', 'default_vdom': 'root'})
    yield app, client
    app.extensions['remote_session_manager'].close()


def entries_form():
    return {'profile': 'Lab', 'identifier': ['AP-1'], 'current_name': ['Lobby AP'],
            'new_name': ['Lobby AP New'], 'vdom': ['root'], 'confirmed_live': 'on'}


def test_confirmation_without_preview_never_executes(browser):
    _, client = browser
    with patch('twn_toolkit.fortigate_routes.RenameTask.run_entries', return_value=[]) as run:
        response = client.post('/tasks/rename-aps/rename', data=entries_form())
    assert response.status_code == 302
    run.assert_not_called()


def test_csv_cannot_bypass_preview(browser):
    _, client = browser
    with patch('twn_toolkit.fortigate_routes.RenameTask.run_with_entries', return_value=([], [])) as run:
        response = client.post('/tasks/rename-aps/run', data={
            'profile': 'Lab', 'confirmed_live': 'on',
            'csv_file': (io.BytesIO(b'identifier,new_name\nAP-1,Changed\n'), 'rename.csv'),
        })
    assert response.status_code == 302
    run.assert_not_called()


def preview(client, form=None):
    data = {**(form or entries_form()), "dry_run": "on"}
    response = client.post('/tasks/rename-aps/rename', data=data)
    assert response.status_code == 200
    assert b'https://fortigate.example' in response.data
    assert b'profile-secret' not in response.data
    return re.search(rb'name="preview_token"[^>]*value="([^"]+)"', response.data)[1].decode()


def test_matching_preview_executes_exact_reviewed_rows(browser):
    _, client = browser
    token = preview(client)
    with patch('twn_toolkit.fortigate_routes.RenameTask.run_entries', return_value=[]) as run:
        response = client.post('/tasks/rename-aps/rename', data={**entries_form(), 'preview_token': token})
    assert response.status_code == 200
    assert run.call_count == 1
    assert run.call_args.kwargs['dry_run'] is False
    assert run.call_args.kwargs['entries'] == [dict(identifier='AP-1', current_name='Lobby AP', new_name='Lobby AP New', vdom='root')]


@pytest.mark.parametrize('field,value', [
    ('identifier', ['AP-2']), ('current_name', ['Different']),
    ('new_name', ['Different']), ('vdom', ['other']),
    ('endpoint_template', '/api/v2/cmdb/other/{current_name}'),
])
def test_modified_request_is_rejected_before_client_creation(browser, field, value):
    _, client = browser
    token = preview(client)
    with patch('twn_toolkit.fortigate_routes.FortiGateClient.from_profile') as connect:
        response = client.post('/tasks/rename-aps/rename', data={**entries_form(), 'preview_token': token, field: value})
    assert response.status_code == 302
    connect.assert_not_called()


@pytest.mark.parametrize('field,value', [
    ('host', 'https://different.example'), ('api_key', 'replacement-secret'),
    ('default_vdom', 'other'), ('verify_tls', False),
])
def test_profile_edit_invalidates_preview(browser, field, value):
    app, client = browser
    token = preview(client)
    store = ProfileStore(app.instance_path)
    profile = store.get('Lab')
    profile[field] = not profile.get(field, True) if field == 'verify_tls' else value
    store.upsert(profile)
    with patch('twn_toolkit.fortigate_routes.FortiGateClient.from_profile') as connect:
        response = client.post('/tasks/rename-aps/rename', data={**entries_form(), 'preview_token': token})
    assert response.status_code == 302
    connect.assert_not_called()


@pytest.mark.parametrize('change', ['actor', 'task', 'tamper', 'expired'])
def test_preview_identity_integrity_and_expiry(browser, change):
    app, client = browser
    token = preview(client)
    path = '/tasks/rename-aps/rename'
    if change == 'actor':
        AuthStore(app.instance_path).create_user('other', 'TemporaryReviewPassword123!', is_admin=True)
        client = app.test_client()
        client.post('/login', data={'username': 'other', 'password': 'TemporaryReviewPassword123!'})
    elif change == 'task':
        path = '/tasks/rename-switches/rename'
    elif change == 'tamper':
        token += 'x'
    future = int(time.time()) + (RENAME_PREVIEW_MAX_AGE_SECONDS + 5 if change == 'expired' else 0)
    with patch('itsdangerous.timed.TimestampSigner.get_timestamp', return_value=future), patch('twn_toolkit.fortigate_routes.FortiGateClient.from_profile') as connect:
        response = client.post(path, data={**entries_form(), 'preview_token': token})
    assert response.status_code == 302
    connect.assert_not_called()


def test_csv_preview_produces_usable_bound_confirmation(browser):
    _, client = browser
    response = client.post('/tasks/rename-aps/run', data={
        'profile': 'Lab', 'dry_run': 'on',
        'csv_file': (io.BytesIO(b'identifier,current_name,new_name,vdom\nAP-1,Lobby AP,Lobby AP New,root\n'), 'rename.csv'),
    })
    assert response.status_code == 200
    token = re.search(rb'name="preview_token"[^>]*value="([^"]+)"', response.data)[1].decode()
    with patch('twn_toolkit.fortigate_routes.RenameTask.run_entries', return_value=[]) as run:
        response = client.post('/tasks/rename-aps/rename', data={**entries_form(), 'preview_token': token})
    assert response.status_code == 200
    assert run.call_count == 1
