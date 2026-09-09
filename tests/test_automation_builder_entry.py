import json

import pytest

from twn_toolkit import create_app
from twn_toolkit.automation import AutomationStore
from twn_toolkit.auth import AuthStore


@pytest.fixture
def setup(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    return app, AutomationStore(str(tmp_path), app.secret_key)


def test_retired_wizard_redirects_to_full_builder_and_cannot_create(setup):
    app, store = setup
    client = app.test_client()
    response = client.get('/automations/guided', environ_overrides={'SCRIPT_NAME': '/agents/example/ui'})
    assert response.status_code == 302
    assert response.location == '/agents/example/ui/automations'
    page = client.get('/automations')
    assert page.status_code == 200
    assert b'New automation' in page.data
    assert b'action="/automations/save"' in page.data
    assert b'Guided automation' not in page.data
    assert b'automation-guide.js' not in page.data
    for path in ('preview', 'create'):
        assert client.post(f'/automations/guided/{path}', data={'name': 'Old wizard submission'}).status_code == 404
    assert store.all() == []


def test_existing_inline_workflow_remains_editable_in_full_builder(setup):
    app, store = setup
    # The removed wizard stored ordinary inline definitions; preserve that shape.
    automation_id = store.save(
        name='Existing inline workflow', interval_seconds=30, trigger_after=3,
        recover_after=3, cooldown_seconds=300, created_by='owner',
        condition={'type': 'manual.trigger', 'config': {}},
        actions=[{'type': 'ssh.collect', 'config': {
            'hosts': '192.0.2.1', 'username': 'fixture', 'password': 'FixtureSecret',
            'port': 22, 'commands': 'show clock', 'command_timeout': 30,
        }}],
    )
    before = store.get(automation_id, include_secrets=True)
    client = app.test_client()
    page = client.get('/automations/guided', follow_redirects=True)
    assert page.status_code == 200
    assert b'Existing inline workflow' in page.data
    assert f'edit-automation-{automation_id}'.encode() in page.data
    assert store.get(automation_id, include_secrets=True) == before
    response = client.post('/automations/save', data={
        'automation_id': automation_id, 'name': 'Edited inline workflow',
        'interval_seconds': '30', 'trigger_after': '3', 'recover_after': '3',
        'cooldown_seconds': '300', 'run_mode': 'manual',
        'action_stages_json': json.dumps(before['action_stages']),
    })
    assert response.status_code == 302, response.data.decode()
    after = store.get(automation_id, include_secrets=True)
    assert after['name'] == 'Edited inline workflow'
    assert after['actions'] == before['actions']
    assert len(store.all()) == 1
    assert store.recent_runs(automation_id) == []


def test_legacy_bookmark_still_requires_admin(setup):
    app, _ = setup
    auth = AuthStore(app.instance_path)
    auth.create_user('owner', 'TemporaryPassword123!', is_admin=True)
    auth.create_user('viewer', 'TemporaryPassword123!', is_admin=False)
    app.testing = False
    client = app.test_client()
    assert '/login' in client.get('/automations/guided').location
    client.post('/login', data={'username': 'viewer', 'password': 'TemporaryPassword123!'})
    assert client.get('/automations/guided').status_code == 403
