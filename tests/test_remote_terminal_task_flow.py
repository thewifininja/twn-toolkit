"""Refreshing terminal recovery state never starts a connection or leaks another owner."""
from unittest.mock import Mock, patch

import pytest
from flask import g

from twn_toolkit import create_app
from twn_toolkit.remote_sessions import RemoteSessionManager, RemoteSessionStore


@pytest.fixture
def terminal(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    store = RemoteSessionStore(str(tmp_path))
    opener = Mock(side_effect=AssertionError('No fixture network connections'))
    manager = RemoteSessionManager(store, app.extensions['investigation_store'], ssh_opener=opener)
    app.extensions['remote_session_manager'] = manager
    yield app, app.test_client(), manager, opener
    manager.close()


def retained(manager, owner='test-user', state='stopped'):
    row = manager.store.create_session(user_id=owner, username=owner,
        title='Previous fixture', host='fixture.test', port=2222, remote_username='operator',
        record_transcript=False, source_host_id='previous-host',
        owner_pid=0, control_path='/fixture/private/control')
    manager.store.append_output(row['id'], 'retained fixture output')
    manager.store.finish(row['id'], state=state, termination='fixture')
    return row


@pytest.mark.parametrize('state', ['stopped', 'error', 'interrupted'])
def test_recent_sessions_refresh_is_owned_and_does_not_reconnect(terminal, state):
    app, client, manager, opener = terminal
    own = retained(manager, state=state)
    foreign = retained(manager, owner='another-user')
    with patch.object(manager, 'start_session') as start:
        response = client.get('/tools/remote-terminal/sessions')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    rows = response.json['sessions']
    assert [row['id'] for row in rows] == [own['id']]
    assert rows[0]['state'] == state
    assert rows[0]['source_host_id'] == 'previous-host'
    assert rows[0]['remote_username'] == 'operator'
    assert '_control_path' not in rows[0] and '_owner_pid' not in rows[0]
    assert '/fixture/private/control' not in response.get_data(as_text=True)
    assert manager.store.get_session(foreign['id']) is not None
    assert manager.store.get_session(own['id'])['state'] == state
    start.assert_not_called()
    opener.assert_not_called()


def test_recent_sessions_refresh_honors_revoked_tool_permission(terminal):
    app, client, manager, opener = terminal
    retained(manager)
    @app.before_request
    def restricted_actor():
        g.current_user = {'id': 'test-user', 'username': 'operator', 'is_admin': False}
        g.allowed_tool_ids = set()
    assert client.get('/tools/remote-terminal/sessions').status_code == 403
    opener.assert_not_called()


def test_empty_recent_sessions_refresh_remains_empty(terminal):
    app, client, manager, opener = terminal
    response = client.get('/tools/remote-terminal/sessions')
    assert response.status_code == 200 and response.json == {'sessions': []}
    opener.assert_not_called()


def test_refresh_keeps_live_shell_older_than_recent_history_page(terminal):
    app, client, manager, opener = terminal
    old = manager.store.create_session(user_id='test-user', username='fixture', title='Old active shell',
        host='active-fixture.test', port=22, remote_username='operator', record_transcript=False)
    for _ in range(25):
        retained(manager)
    # The fixture has no owner runtime; retain its simulated live state while
    # exercising real bounded store queries and the route's merge behavior.
    with patch.object(manager, '_reconcile_orphaned_sessions'):
        response = client.get('/tools/remote-terminal/sessions')
    ids = [row['id'] for row in response.json['sessions']]
    assert response.status_code == 200 and old['id'] in ids
    assert len(ids) == len(set(ids)) == 25
    assert next(row for row in response.json['sessions'] if row['id'] == old['id'])['state'] == 'connecting'
    opener.assert_not_called()
