"""Composition only: definitions can be created/selected without evaluating or arming."""
import json
from unittest.mock import patch
import pytest
from twn_toolkit import create_app
from twn_toolkit.automation import AutomationStore
from twn_toolkit.auth import AuthStore

@pytest.fixture
def setup(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    return app, AutomationStore(str(tmp_path), app.secret_key)

FORMS = {
    'condition': {'condition_name':'Fixture condition', 'condition_type':'ping.multi', 'condition_targets':'192.0.2.1', 'condition_timeout':'1', 'condition_probe_count':'3', 'condition_failure_mode':'all', 'condition_failure_count':'1'},
    'schedule': {'schedule_name':'Fixture schedule', 'schedule_timezone':'UTC', 'schedule_missed_policy':'skip', 'schedule_rules_json':json.dumps([{'id':'monday','type':'weekly','weekdays':[0],'time':'15:00'}])},
    'action': {'action_name':'Fixture action', 'action_type':'email.send', 'email_to':'fixture@example.test', 'email_subject':'Fixture', 'email_body':'Not sent'},
}

def create(client, kind, **extra):
    return client.post(f'/automations/{kind}s/save', data={**FORMS[kind], 'response_mode':'builder', **extra}, headers={'Accept':'application/json'})

@pytest.mark.parametrize('kind', FORMS)
def test_create_returns_minimal_choice_without_running(setup, kind):
    app, store = setup
    response = create(app.test_client(), kind)
    assert response.status_code == 201, response.data
    item = response.json['definition']
    assert set(item) == {'kind','id','name','type'} and item['kind'] == kind
    assert response.headers['Cache-Control'] == 'no-store'
    assert store.all() == []
    assert b'Not sent' not in response.data
    duplicate = create(app.test_client(), kind)
    assert duplicate.status_code == 400 and 'error' in duplicate.json
    editing = create(app.test_client(), kind, **{f'{kind}_definition_id':item['id']})
    assert editing.status_code == 400


def test_parent_save_keeps_new_choices_order_and_stays_paused(setup):
    app, store = setup; client = app.test_client()
    condition = create(client, 'condition').json['definition']['id']
    first = create(client, 'action').json['definition']['id']
    second = create(client, 'action', action_name='Second action').json['definition']['id']
    response = client.post('/automations/save', data={'name':'Retained parent draft', 'run_mode':'condition', 'condition_definition_id':condition, 'interval_seconds':'30','trigger_after':'3','recover_after':'3','cooldown_seconds':'300','action_stages_json':json.dumps([{'id':'stage-first','name':'Ordered stage','delay_seconds':7,'action_definition_ids':[second,first]}])})
    assert response.status_code == 302, response.data
    saved = store.all()[0]
    assert not saved['enabled']
    assert saved['action_stages'][0]['action_definition_ids'] == [second,first]
    assert store.recent_runs(saved['id']) == []
    page = client.get(response.location)
    assert page.status_code == 200
    assert b'>Paused</span>' in page.data


def test_choices_projection_never_opens_definition_config(setup):
    app, store = setup; client = app.test_client()
    for kind in FORMS: assert create(client, kind).status_code == 201
    store.ensure_manual_trigger_definition()
    with patch.object(AutomationStore, 'get_action_definition', side_effect=AssertionError('No config access')), patch.object(AutomationStore, 'get_condition_definition', side_effect=AssertionError('No config access')):
        response = client.get('/automations/builder/choices')
    assert response.status_code == 200 and response.headers['Cache-Control'] == 'no-store'
    assert all(len(response.json[key]) == 1 for key in ('conditions','schedules','actions'))
    assert all(set(item) == {'id','name','type'} for rows in response.json.values() for item in rows)


def test_json_mode_requires_both_explicit_flags_and_keeps_native_fallback(setup):
    app, _ = setup; client = app.test_client()
    response = client.post('/automations/actions/save', data={**FORMS['action'],'response_mode':'builder'})
    assert response.status_code == 302
    response = client.post('/automations/actions/save', data={**FORMS['action'],'action_name':'Other'}, headers={'Accept':'application/json'})
    assert response.status_code == 302
    page = client.get('/automations', environ_overrides={'SCRIPT_NAME':'/agents/example/ui'})
    assert b'data-builder-choices-url="/agents/example/ui/automations/builder/choices"' in page.data
    assert b'action="/agents/example/ui/automations/actions/save"' in page.data


def test_new_endpoints_still_require_admin(setup):
    app, _ = setup; auth = AuthStore(app.instance_path)
    auth.create_user('owner','TemporaryPassword123!',is_admin=True)
    auth.create_user('viewer','TemporaryPassword123!',is_admin=False)
    app.testing = False; client = app.test_client()
    assert '/login' in client.get('/automations/builder/choices').location
    client.post('/login', data={'username':'viewer','password':'TemporaryPassword123!'})
    assert client.get('/automations/builder/choices').status_code == 403
    for kind in FORMS: assert create(client, kind).status_code == 403


def test_paused_schedule_explains_why_no_next_occurrence(setup):
    app, store = setup; client = app.test_client()
    schedule = create(client, 'schedule').json['definition']['id']
    action = create(client, 'action').json['definition']['id']
    response = client.post('/automations/save', data={'name':'Paused calendar', 'run_mode':'schedule','schedule_definition_id':schedule,'action_stages_json':json.dumps([{'id':'stage','name':'Notice','action_definition_ids':[action]}])})
    assert response.status_code == 302
    page = client.get(response.location)
    assert b'Paused \xe2\x80\x94 arm to schedule' in page.data
    assert b'Unavailable saved condition' not in page.data
    assert not store.all()[0]['enabled']


@pytest.mark.parametrize('mode,field', [('condition','condition_definition_id'),('schedule','schedule_definition_id')])
def test_failed_parent_save_retains_unavailable_reference_for_explicit_removal(setup, mode, field):
    app, _ = setup; client = app.test_client()
    action = create(client, 'action').json['definition']['id']
    response = client.post('/automations/save', data={'name':'Retained draft','run_mode':mode,field:'removed-reference','action_stages_json':json.dumps([{'id':'stage','name':'Preserved stage','action_definition_ids':[action]}])})
    assert response.status_code == 400
    assert b'Unavailable saved' in response.data
    assert b'value="removed-reference"' in response.data
    assert b'Retained draft' in response.data and b'Preserved stage' in response.data


@pytest.mark.parametrize('populated', [False, True])
def test_fresh_builder_has_no_phantom_empty_condition_selection(setup, populated):
    app, _ = setup; client = app.test_client()
    if populated:
        for kind in FORMS: assert create(client, kind).status_code == 201
    page = client.get('/automations')
    assert page.status_code == 200
    assert b'Unavailable saved condition' not in page.data
    assert b'name="condition_definition_id" value=""' not in page.data
