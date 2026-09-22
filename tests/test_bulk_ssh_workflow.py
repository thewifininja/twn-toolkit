"""Library edits must preserve explicit run choices without launching SSH."""
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from flask import template_rendered
from werkzeug.datastructures import MultiDict

from twn_toolkit import create_app
from twn_toolkit.ssh_commandlets import SSHHostMatrixStore


@pytest.fixture
def workspace(tmp_path):
    app = create_app(instance_path=str(tmp_path))
    app.config['TESTING'] = True
    client = app.test_client()
    client.post('/tools/multi-ssh', data={
        'action': 'save_host_matrix', 'host_matrix_name': 'Lab',
        'matrix': 'Host | Site\nswitch.example | lab',
    })
    for name in ('First', 'Second'):
        client.post('/tools/multi-ssh', data={
            'action': 'save_matrix_action', 'host_matrix_original_name': 'Lab',
            'matrix_action_name': name, 'commands': 'show {{ site }}',
        })
    return app, client, SSHHostMatrixStore(str(tmp_path))


@contextmanager
def rendered(app):
    context = {}
    def capture(sender, template, context: dict, **extra):
        captured.update(context)
    captured = context
    with template_rendered.connected_to(capture, app):
        yield context


def edit(**changes):
    return dict(action='save_matrix_action', workspace='actions',
                host_matrix_original_name='Lab', matrix_action_original_name='First',
                matrix_action_name='First', commands='show current editor',
                selected_actions=['Second', 'First'], **changes)


def test_save_add_preserves_order_rename_and_requires_new_review(workspace):
    app, client, store = workspace
    data = edit()
    data.update(action='save_matrix_action_and_add', matrix_action_name='Renamed')
    with (
        rendered(app) as context,
        patch('twn_toolkit.ssh_routes.run_ssh_host_plans') as execute,
        patch('twn_toolkit.ssh_routes._enqueue_ssh') as enqueue,
    ):
        response = client.post('/tools/multi-ssh', data=data)
    assert response.status_code == 200
    assert context['active_workspace'] == 'run'
    assert [a['name'] for a in context['selected_run_actions']] == ['Second', 'Renamed']
    assert not context['preview_token']
    assert context['results'] is None
    execute.assert_not_called()
    enqueue.assert_not_called()
    data.update(matrix_action_original_name='Renamed', selected_actions=['Second'])
    with rendered(app) as context:
        client.post('/tools/multi-ssh', data=data)
    assert [a['name'] for a in context['selected_run_actions']] == ['Second', 'Renamed']


def test_save_add_invalid_keeps_editor_and_run(workspace):
    app, client, store = workspace
    data = edit()
    data.update(action='save_matrix_action_and_add', commands='show {{ missing }}')
    with rendered(app) as context:
        client.post('/tools/multi-ssh', data=data)
    assert context['error']
    assert context['active_workspace'] == 'actions'
    assert context['action_editor']['commands'] == data['commands']
    assert [a['name'] for a in context['selected_run_actions']] == ['Second', 'First']
    assert store.get('Lab')['actions'][0]['commands'] == 'show {{ site }}'


def test_action_copy_uses_current_edits_and_rejects_collision(workspace):
    app, client, store = workspace
    data = edit()
    data.update(action='save_matrix_action_copy', copy_name='My copy')
    with rendered(app) as context:
        client.post('/tools/multi-ssh?matrix_action=First', data=data)
    assert context['selected_action']['name'] == 'My copy'
    actions = {a['name']: a for a in store.get('Lab')['actions']}
    assert actions['First']['commands'] == 'show {{ site }}'
    assert actions['My copy']['commands'] == 'show current editor'
    assert [a['name'] for a in context['selected_run_actions']] == ['Second', 'First']
    assert context['action_editor']['original_name'] == 'My copy'
    data.update(copy_name='second', commands='must not overwrite')
    with rendered(app) as context:
        client.post('/tools/multi-ssh', data=data)
    assert context['error']
    assert len(store.get('Lab')['actions']) == 3
    assert store.get('Lab')['actions'][1]['commands'] == 'show {{ site }}'


@pytest.mark.parametrize('include_actions', [True, False])
def test_matrix_copy_current_contents_optional_actions_and_independent_identity(workspace, include_actions):
    app, client, store = workspace
    original = store.get('Lab')
    with rendered(app) as context:
        client.post('/tools/multi-ssh', data={
            'action': 'save_host_matrix_copy', 'host_matrix_original_name': 'Lab',
            'host_matrix_name': 'Uncommitted rename', 'copy_name': 'Copy',
            'matrix': 'Host | Site\nnew.example | edited',
            'host_matrix_description': 'Current description',
            'copy_actions': 'on' if include_actions else '',
            'selected_actions': ['Second'],
            'mso_id': 'source-identity-must-not-be-reused', 'mso_enabled': 'true',
        })
    assert not context['error']
    saved = store.get('Copy')
    assert 'new.example' in saved['matrix']
    assert saved['description'] == 'Current description'
    assert len(saved['actions']) == (2 if include_actions else 0)
    assert store.get('Lab') == original
    assert context['selected_run_actions'] == []
    metadata = {p['name']: p['mso'] for p in store.mso_store().profiles(metadata=True)}
    assert metadata['Copy']['id'] != metadata['Lab']['id']
    assert not metadata['Copy']['enabled']
    with rendered(app) as context:
        client.post('/tools/multi-ssh', data={
            'action': 'save_host_matrix_copy', 'host_matrix_original_name': 'Lab',
            'copy_name': 'copy', 'matrix': 'Host\ncollision.example',
        })
    assert context['error']
    assert store.get('Copy') == saved


def test_explicit_selection_survives_save_and_editor_navigation(workspace):
    app, client, store = workspace
    with rendered(app) as context:
        client.post('/tools/multi-ssh', data=edit())
    assert [a['name'] for a in context['selected_run_actions']] == ['Second', 'First']
    with rendered(app) as context:
        client.get('/tools/multi-ssh', query_string=MultiDict([
            ('host_matrix', 'Lab'), ('new_action', '1'),
            ('selected_actions', 'Second'), ('selected_actions', 'First'),
            ('selected_actions', 'deleted'), ('selected_actions', 'Second'),
        ]))
    assert [a['name'] for a in context['selected_run_actions']] == ['Second', 'First']
    with rendered(app) as context:
        client.get('/tools/multi-ssh?host_matrix=Lab')
    assert context['selected_run_actions'] == []


def test_new_action_save_selects_saved_action_despite_editor_query(workspace):
    app, client, store = workspace
    data = edit()
    data.update(matrix_action_original_name='', matrix_action_name='New action')
    with rendered(app) as context:
        client.post('/tools/multi-ssh?new_action=1&matrix_action=First', data=data)
    assert not context['error']
    assert context['selected_action']['name'] == 'New action'
    assert context['action_editor']['original_name'] == 'New action'
