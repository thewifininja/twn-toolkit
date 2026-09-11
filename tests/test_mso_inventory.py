from twn_toolkit.mso import MsoStore
from test_mso import node, profile, sync


def test_receipt_requires_next_exchange_and_rescans_reset_cursor(tmp_path):
    hub = node(tmp_path / 'hub', 'mainframe')
    agent = node(tmp_path / 'agent', 'agent')
    hub.save(profile(), enabled=True)
    response = sync(hub, agent)
    first = hub.inventory()
    assert first['peers'][agent.node]['cursor'] == 0
    assert first['objects'][0]['revision'] == response['cursor']
    sync(hub, agent)
    assert hub.inventory()['peers'][agent.node]['cursor'] == response['cursor']
    request = agent.request()
    request['cursor'] = 0
    hub.exchange(agent.node, request)
    assert hub.inventory()['peers'][agent.node]['cursor'] == 0


def test_inventory_omits_local_objects_and_all_definition_fields(tmp_path):
    hub = node(tmp_path, 'mainframe')
    hub.save(profile('Private local'))
    hub.save(profile('Shared'), enabled=True)
    inventory = hub.inventory()
    assert [item['name'] for item in inventory['objects']] == ['Shared']
    assert set(inventory['objects'][0]) == {'id', 'name', 'kind', 'revision', 'state', 'deleted'}
    assert '192.0.2.1' not in str(inventory)


def test_failed_exchange_does_not_advance_peer_receipt(tmp_path):
    import pytest
    hub = node(tmp_path / 'hub', 'mainframe')
    agent = node(tmp_path / 'agent', 'agent')
    hub.save(profile(), enabled=True)
    sync(hub, agent)
    before = hub.inventory()['peers']
    request = agent.request()
    request['proposals'] = [{'kind': 'invalid'}]
    with pytest.raises(ValueError):
        hub.exchange(agent.node, request)
    assert hub.inventory()['peers'] == before


def test_success_timestamp_survives_later_sync_error(tmp_path):
    store = MsoStore(tmp_path)
    assert store.sync_status()['last_success'] == 0
    success = store.sync_status('')['last_success']
    assert success > 0
    assert store.sync_status('Offline') == {'error': 'Offline', 'last_success': success}


def test_peer_health_does_not_imply_receipt(tmp_path):
    hub = node(tmp_path / 'hub', 'mainframe')
    agent = node(tmp_path / 'agent', 'agent')
    hub.save(profile(), enabled=True)
    status = agent.peer_status()
    status.update(error='Projection needs review', conflicts=2)
    hub.record_peer_status(agent.node, status)
    peer = hub.inventory()['peers'][agent.node]
    assert peer['cursor'] == 0 and peer['checked_at'] == 0
    assert peer['error'] == 'Projection needs review' and peer['conflicts'] == 2
    assert 'ping.profile' in peer['advertised_types']
    assert peer['types'] == []


def test_manual_sync_only_wakes_agent_worker(tmp_path):
    import pytest
    for role in ['standalone', 'mainframe', 'agent']:
        store = node(tmp_path / role, role)
        if role == 'agent':
            store.request_sync()
            marker = store.instance / 'mso-sync-requested'
            assert marker.exists() and marker.stat().st_mode & 0o777 == 0o600
        else:
            with pytest.raises(ValueError):
                store.request_sync()


def test_mainframe_tabs_are_role_specific_and_inventory_search_works(tmp_path):
    from twn_toolkit.app import create_app
    for role, tab in [('mainframe', 'agents'), ('agent', 'mso'), ('standalone', 'settings')]:
        store = node(tmp_path / role, role)
        app = create_app(str(store.instance))
        app.testing = True
        client = app.test_client()
        page = client.get('/mainframe')
        assert page.status_code == 200
        assert f'data-initial-tab="{tab}"'.encode() in page.data
        assert (b'data-workspace-tab="agents"' in page.data) == (role == 'mainframe')
        assert (b'data-workspace-tab="mso"' in page.data) == (role != 'standalone')
        if role != 'standalone':
            store.save(profile('Distinct WAN'), enabled=True)
            assert b'Distinct WAN' in client.get('/mainframe?tab=mso&q=Distinct').data
            assert b'Distinct WAN' not in client.get('/mainframe?tab=mso&q=missing').data
        else:
            assert client.post('/mainframe/mso/sync').status_code == 404


def test_inventory_does_not_decrypt_credentials(tmp_path, monkeypatch):
    store = node(tmp_path, 'mainframe')
    store.save(profile(), enabled=True)
    monkeypatch.setattr(store, '_load', lambda value: (_ for _ in ()).throw(AssertionError('Must not decrypt inventory payloads')))
    assert store.inventory()['objects'][0]['name'] == 'WAN'


def test_mso_failure_keeps_administration_settings_available(tmp_path, monkeypatch):
    import sqlite3
    from twn_toolkit.app import create_app
    node(tmp_path, 'mainframe')
    app = create_app(str(tmp_path))
    app.testing = True
    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError('Unavailable')
    monkeypatch.setattr(MsoStore, 'inventory', unavailable)
    response = app.test_client().get('/mainframe?tab=settings')
    assert response.status_code == 200
    assert b'data-initial-tab="settings"' in response.data
    assert b'The MSO store is unavailable' in response.data


def test_nonadmin_cannot_read_inventory_or_request_sync(tmp_path):
    from twn_toolkit.app import create_app
    from twn_toolkit.auth import AuthStore
    node(tmp_path, 'mainframe')
    app = create_app(str(tmp_path))
    auth = AuthStore(str(tmp_path))
    auth.create_user('admin', 'TestAdminPassword123!', is_admin=True)
    auth.create_user('operator', 'TestOperatorPassword123!', is_admin=False)
    client = app.test_client()
    client.post('/login', data={'username': 'operator', 'password': 'TestOperatorPassword123!'})
    assert client.get('/mainframe?tab=mso').status_code == 403
    assert client.post('/mainframe/mso/sync').status_code == 403


def test_detach_clears_old_fleet_receipt_and_health(tmp_path):
    hub = node(tmp_path / 'hub', 'mainframe')
    agent = node(tmp_path / 'agent', 'agent')
    hub.save(profile(), enabled=True)
    sync(hub, agent)
    sync(hub, agent)
    hub.record_peer_status(agent.node, agent.peer_status())
    hub.sync_status('')
    assert hub.inventory()['peers']
    hub.detach()
    assert hub.inventory()['peers'] == {}
    assert hub.sync_status() == {'error': '', 'last_success': 0}
