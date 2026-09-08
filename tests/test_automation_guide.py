import json
from unittest.mock import patch

import pytest
from itsdangerous import URLSafeTimedSerializer

from twn_toolkit import create_app
from twn_toolkit.automation import AutomationStore
from twn_toolkit.automation_guide import prepare_guide, save_guide_atomically
from twn_toolkit.auth import AuthStore


@pytest.fixture
def setup(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    store = AutomationStore(str(tmp_path), app.secret_key)
    form = {'name':'Guided fixture','source_kind':'manual','action_kind':'new_ssh',
            'ssh_hosts':'192.0.2.1','username':'fixture','password':'SecretFixturePassword',
            'commands':'show clock','port':'22','command_timeout':'30'}
    return app, store, form


def preview(app, form):
    result = app.test_client().post('/automations/guided/preview', data=form)
    assert result.status_code == 200, result.data
    return result.json


@pytest.mark.parametrize('mode', ['manual','ping','daily'])
def test_review_is_read_only_and_creation_is_paused_and_encrypted(setup, mode):
    app, store, form = setup
    form.update(source_kind=mode, targets='192.0.2.1',timezone='UTC',daily_time='09:00')
    with patch('twn_toolkit.automation_types.actions.run_ssh_host_plans', side_effect=AssertionError('must not execute')):
        reviewed = preview(app, form)
        assert not store.all() and not store.action_definitions() and not store.source_definitions()
        assert store.job_stats()['queued_jobs'] == 0
        assert form['password'] not in json.dumps(reviewed)
        assert all(key in reviewed['review'] for key in ['when','doing','recovery','next_run','commands','settings'])
        response = app.test_client().post('/automations/guided/create', data={**form,'review_token':reviewed['review_token'],'confirm_review':'on'})
    assert response.status_code == 201
    item = store.get(response.json['automation_id'])
    assert not item['enabled'] and item['state'] == 'disabled'
    assert len(store.action_definitions()) == 1 and len(store.source_definitions()) == 1
    assert form['password'].encode() not in store.path.read_bytes()
    assert item['created_by'] == 'test-user'


@pytest.mark.parametrize('change', ['commands','password','port','source_kind','name'])
def test_changed_input_cannot_reuse_review(setup, change):
    app, store, form = setup
    review = preview(app, form)
    updates = {'commands':'show version','password':'different','port':'2222','source_kind':'ping','name':'Other name'}
    form.update(targets='192.0.2.1');form[change] = updates[change]
    response = app.test_client().post('/automations/guided/create',data={**form,'review_token':review['review_token'],'confirm_review':'on'})
    assert response.status_code == 400 and not store.all()
    assert not store.action_definitions() and not store.source_definitions()


def test_confirmation_expiry_and_owner_are_required(setup):
    app, store, form = setup
    reviewed = preview(app, form)
    client = app.test_client()
    assert client.post('/automations/guided/create',data={**form,'review_token':reviewed['review_token']}).status_code == 400
    serializer = URLSafeTimedSerializer(app.secret_key,salt='automation-guide-v1')
    context = serializer.loads(reviewed['review_token']);context['user'] = 'other-owner'
    assert client.post('/automations/guided/create',data={**form,'review_token':serializer.dumps(context),'confirm_review':'on'}).status_code == 400
    with patch('itsdangerous.timed.TimestampSigner.get_timestamp',return_value=1):
        expired = serializer.dumps(context)
    assert client.post('/automations/guided/create',data={**form,'review_token':expired,'confirm_review':'on'}).status_code == 400
    assert not store.all()


def test_failed_creation_rolls_back_inline_objects(setup):
    _, store, form = setup
    values, _, _ = prepare_guide(store, form)
    aid = save_guide_atomically(store, values, 'owner')
    # A duplicate automation name but new inline-object names reaches final INSERT validation.
    with store._connect() as db:
        db.execute("UPDATE automation_conditions SET name='Existing source'")
        db.execute("UPDATE automation_actions SET name='Existing action'")
    with pytest.raises(ValueError, match='already exists'):
        save_guide_atomically(store, values, 'owner')
    assert len(store.all()) == len(store.source_definitions()) == len(store.action_definitions()) == 1
    assert store.get(aid)['state'] == 'disabled'


def test_saved_action_drift_is_checked_inside_creation_transaction(setup):
    _, store, form = setup
    values, _, _ = prepare_guide(store, form)
    action = values['actions'][0]
    action_id = store.save_action_definition(name='Saved',type_id=action['type'],config=action['config'])
    form.update(action_kind='saved',action_id=action_id)
    values, _, _ = prepare_guide(store, form)
    store.save_action_definition(name='Saved',type_id=action['type'],config={**action['config'],'commands':'show version'},definition_id=action_id)
    with pytest.raises(ValueError,match='changed after review'):
        save_guide_atomically(store, values, 'owner')
    assert not store.all() and not store.source_definitions()


def test_guided_fleet_and_request_bounds(setup):
    app, store, form = setup
    form['ssh_hosts'] = '\n'.join(f'192.0.2.{n}' for n in range(1,22))
    response = app.test_client().post('/automations/guided/preview',data=form)
    assert response.status_code == 400 and b'advanced editor' in response.data
    assert app.test_client().post('/automations/guided/preview',data={'commands':'x'*300_000}).status_code == 413
    assert not store.all()


def test_guide_requires_authenticated_admin(setup):
    app, _, _ = setup
    auth = AuthStore(app.instance_path)
    auth.create_user('owner','TemporaryPassword123!',is_admin=True)
    auth.create_user('viewer','TemporaryPassword123!',is_admin=False)
    app.testing = False;client = app.test_client()
    assert client.get('/automations/guided').status_code == 302
    client.post('/login',data={'username':'viewer','password':'TemporaryPassword123!'})
    for path in ['/automations/guided','/automations/guided/preview','/automations/guided/create']:
        assert (client.get(path) if path.endswith('guided') else client.post(path)).status_code == 403


def test_saved_objects_are_reused_without_duplicates(setup):
    app, store, form = setup
    values, _, _ = prepare_guide(store, form)
    save_guide_atomically(store, values, 'owner')
    source = store.source_definitions()[0];action = store.action_definitions()[0]
    form.update(name='Reuse fixture',source_kind='saved',source_id=source['id'],action_kind='saved',action_id=action['id'])
    reviewed = preview(app, form)
    response = app.test_client().post('/automations/guided/create',data={**form,'review_token':reviewed['review_token'],'confirm_review':'on'})
    assert response.status_code == 201
    assert len(store.source_definitions()) == len(store.action_definitions()) == 1
    assert len(store.all()) == 2


def test_legacy_saved_action_is_normalized_consistently(setup):
    _, store, form = setup
    values, _, _ = prepare_guide(store, form)
    action = values['actions'][0]
    ident = store.save_action_definition(name='Legacy',type_id=action['type'],config=action['config'])
    config = dict(action['config']);config.pop('target_count',None);config.pop('variables',None)
    with store._connect() as db:
        db.execute('UPDATE automation_actions SET config_encrypted=? WHERE id=?',(store._encrypt(config),ident))
    form.update(action_kind='saved',action_id=ident)
    values, _, _ = prepare_guide(store, form)
    assert not store.get(save_guide_atomically(store, values, 'owner'))['enabled']


def test_review_never_contains_saved_password(setup):
    app, store, form = setup
    values, _, _ = prepare_guide(store, form)
    action = values['actions'][0]
    ident = store.save_action_definition(name='Saved secret',type_id=action['type'],config=action['config'])
    form.update(action_kind='saved',action_id=ident,password='')
    result = preview(app, form)
    assert 'SecretFixturePassword' not in json.dumps(result)
    assert app.test_client().get('/automations/guided').status_code == 200
    assert b'SecretFixturePassword' not in app.test_client().get('/automations/guided').data


@pytest.mark.parametrize('kind,phrase', [('system.startup','next host boot'),('network.interface_change','remain stable')])
def test_saved_event_trigger_review_describes_its_actual_semantics(setup, kind, phrase):
    app, store, form = setup
    ident = store.save_condition_definition(name='Event',type_id=kind,config={})
    form.update(source_kind='saved',source_id=ident)
    result = preview(app, form)
    assert phrase in result['review']['when']
    assert 'consecutive met checks' not in result['review']['when']
