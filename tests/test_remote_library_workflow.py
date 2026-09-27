"""Bulk operations preserve unrelated state and fail atomically across selections."""
import pytest

from twn_toolkit.app import create_app
from twn_toolkit.remote_connections import RemoteConnectionError, RemoteConnectionStore
from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.remote_mso_bridge import metadata


@pytest.fixture
def store(tmp_path):
    return RemoteConnectionStore(str(tmp_path), 'fixture-secret')


def host(store, name, protocol='ssh', folder_id='', owner='test-user'):
    return store.save_host(user_id=owner, name=name, host='host.example.test', port=22 if protocol == 'ssh' else 23,
                           protocol=protocol, folder_id=folder_id, credential_id='', credential_mode='inherit',
                           allow_unknown_hosts=False, allow_legacy_algorithms=False, notes='Keep my notes')


def test_bulk_network_settings_leave_other_fields_and_unselected_hosts_alone(store):
    first, second, untouched = [host(store, name) for name in ('One', 'Two', 'Untouched')]
    store.bulk_update(user_id='test-user', host_ids=[first['id'], second['id']], folder_ids=[],
                      port=2222, allow_unknown_hosts=True, allow_legacy_algorithms=True, visibility='global')
    for item in (first, second):
        actual = store.get_host(item['id'], user_id='test-user')
        assert (actual['port'], actual['allow_unknown_hosts'], actual['allow_legacy_algorithms'], actual['visibility']) == (2222, True, True, 'global')
        assert actual['notes'] == 'Keep my notes' and actual['credential_mode'] == 'inherit'
    assert store.get_host(untouched['id'], user_id='test-user')['port'] == 22
    store.bulk_update(user_id='test-user', host_ids=[first['id']], folder_ids=[], allow_unknown_hosts=False)
    actual = store.get_host(first['id'], user_id='test-user')
    assert actual['port'] == 2222 and actual['allow_unknown_hosts'] is False and actual['allow_legacy_algorithms'] is True


@pytest.mark.parametrize('changes', [dict(port=0), dict(port=65536), dict(port=True), dict(port=22.5), dict(port='22'), dict(allow_unknown_hosts='false'), dict(allow_legacy_algorithms=1), dict(visibility='invalid')])
def test_invalid_change_rolls_back_rename_and_every_host(store, changes):
    item = host(store, 'Original')
    with pytest.raises(RemoteConnectionError):
        store.bulk_update(user_id='test-user', host_ids=[item['id']], folder_ids=[], name='Must not survive', **changes)
    assert store.get_host(item['id'], user_id='test-user')['name'] == 'Original'


def test_protocol_mismatch_missing_selection_and_root_inheritance_roll_back(store):
    first, telnet = host(store, 'SSH'), host(store, 'Telnet', 'telnet')
    with pytest.raises(RemoteConnectionError, match='only SSH'):
        store.bulk_update(user_id='test-user', host_ids=[first['id'], telnet['id']], folder_ids=[], port=2222, allow_unknown_hosts=True)
    assert store.get_host(first['id'], user_id='test-user')['port'] == 22
    with pytest.raises(RemoteConnectionError):
        store.bulk_update(user_id='test-user', host_ids=[first['id'], 'deleted'], folder_ids=[], port=2222)
    folder = store.create_folder(user_id='test-user', name='Root')
    with pytest.raises(RemoteConnectionError, match='root folder'):
        store.bulk_update(user_id='test-user', host_ids=[first['id']], folder_ids=[folder['id']], visibility='inherit')
    assert store.get_host(first['id'], user_id='test-user')['visibility'] == first['visibility']
    with pytest.raises(RemoteConnectionError, match='only SSH or Telnet'):
        store.bulk_update(user_id='test-user', host_ids=[first['id']], folder_ids=[folder['id']], port=2222)


def test_rename_is_narrow_unique_and_preserves_folder_structure(store):
    root = store.create_folder(user_id='test-user', name='Root')
    folder = store.create_folder(user_id='test-user', name='Child', parent_id=root['id'])
    item, other = host(store, 'Original', folder_id=folder['id']), host(store, 'Taken', folder_id=folder['id'])
    store.bulk_update(user_id='test-user', host_ids=[], folder_ids=[folder['id']], name='New folder')
    assert store.get_folder(folder['id'], user_id='test-user')['parent_id'] == root['id']
    store.bulk_update(user_id='test-user', host_ids=[item['id']], folder_ids=[], name='New host')
    actual = store.get_host(item['id'], user_id='test-user')
    assert actual['folder_id'] == folder['id'] and actual['notes'] == 'Keep my notes'
    with pytest.raises(RemoteConnectionError):
        store.bulk_update(user_id='test-user', host_ids=[item['id']], folder_ids=[], name='Taken')
    with pytest.raises(RemoteConnectionError, match='one item'):
        store.bulk_update(user_id='test-user', host_ids=[item['id'], other['id']], folder_ids=[], name='Same name')


def test_bulk_visibility_cannot_reach_another_owners_private_descendants(store):
    folder = store.create_folder(user_id='owner', name='Shared')
    store.set_visibility('folder', folder['id'], user_id='owner', visibility='global')
    child = host(store, 'Private', folder_id=folder['id'], owner='owner')
    store.set_visibility('host', child['id'], user_id='owner', visibility='private')
    with pytest.raises(RemoteConnectionError, match='private'):
        store.bulk_update(user_id='admin', is_admin=True, host_ids=[], folder_ids=[folder['id']], visibility='admins_only')
    assert store.get_folder(folder['id'], user_id='owner')['visibility'] == 'global'


@pytest.fixture
def web(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    settings = DistributedSettingsStore(tmp_path)
    settings.save({**settings.get(), 'role': 'mainframe'})
    try:
        yield app.test_client(), app.extensions['remote_connection_store']
    finally:
        app.extensions['remote_session_manager'].close()


def bulk(client, **payload):
    return client.post('/tools/remote-terminal/library/bulk', json=payload)


def test_bulk_mso_dependencies_stale_edits_and_withdrawal_order(web):
    client, store = web
    root = store.create_folder(user_id='test-user', name='Root', credential_mode='none')
    folder = store.create_folder(user_id='test-user', name='Child', parent_id=root['id'])
    first = host(store, 'Host', 'telnet', folder['id'])
    ids = dict(host_ids=[first['id']], folder_ids=[root['id'], folder['id']])
    result = bulk(client, **ids, visibility='global', mso_enabled=True)
    assert result.status_code == 200, result.get_json()
    library = result.get_json()['library']; revision = library['mso_revision']
    assert all(item['mso']['enabled'] for item in library['hosts'] + library['folders'])
    changed = bulk(client, host_ids=[first['id']], folder_ids=[], name='Renamed', mso_revision=revision)
    assert changed.status_code == 200, changed.get_json()
    rejected = bulk(client, **ids, mso_enabled=False, mso_revision=revision)
    assert rejected.status_code == 409
    fresh = client.get('/tools/remote-terminal/library').get_json()['library']
    assert all(item['mso']['enabled'] for item in fresh['hosts'] + fresh['folders'])
    rejected = bulk(client, host_ids=[], folder_ids=[root['id']], mso_enabled=False, mso_revision=fresh['mso_revision'])
    assert rejected.status_code == 409
    result = bulk(client, **ids, mso_enabled=False, mso_revision=fresh['mso_revision'])
    assert result.status_code == 200, result.get_json()
    assert not any(item['mso']['enabled'] for item in result.get_json()['library']['hosts'] + result.get_json()['library']['folders'])


def test_bulk_mso_private_dependency_rolls_back_other_changes(web):
    client, store = web
    root = store.create_folder(user_id='test-user', name='Private root')
    item = host(store, 'Host', folder_id=root['id'])
    result = bulk(client, host_ids=[item['id']], folder_ids=[], visibility='global', port=2222, mso_enabled=True)
    assert result.status_code == 409, result.get_json()
    actual = store.get_host(item['id'], user_id='test-user')
    assert actual['port'] == 22 and actual['visibility'] == item['visibility']
    assert not metadata(store, store.library_for_user('test-user'))['hosts'][0]['mso']['enabled']
