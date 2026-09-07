from __future__ import annotations

import pytest

from twn_toolkit.app import create_app
from twn_toolkit.audit import AuditStore
from twn_toolkit.remote_connections import RemoteConnectionError, RemoteConnectionStore


@pytest.fixture
def store(tmp_path):
    return RemoteConnectionStore(str(tmp_path), 'fixture-secret')


def seed(store, owner='owner'):
    folder = store.create_folder(user_id=owner, name='Shared folder')
    credential = store.save_credential(user_id=owner, name='Shared login', remote_username='operator', password='private-fixture-password')
    host = store.save_host(user_id=owner, name='Shared host', host='switch.example.test', port=22,
                           folder_id=folder['id'], credential_id=credential['id'], credential_mode='credential',
                           allow_unknown_hosts=False, allow_legacy_algorithms=False)
    for kind, item in [('folder',folder), ('credential',credential), ('host',host)]:
        store.set_visibility(kind,item['id'],user_id=owner,visibility='admins_only')
    return folder,credential,host


@pytest.mark.parametrize('visibility',['admins_only','global','private'])
@pytest.mark.parametrize('actor,admin',[('owner',False),('administrator',True),('operator',False)])
def test_store_management_policy_and_owner_preservation(store,visibility,actor,admin):
    folder,credential,host=seed(store)
    for kind,item in [('folder',folder),('credential',credential),('host',host)]:
        store.set_visibility(kind,item['id'],user_id='owner',visibility=visibility)
    allowed=actor=='owner' or (admin and visibility!='private')
    visible=store.library_for_user(actor,is_admin=admin)
    for collection in visible.values():
        for item in collection:
            assert item['can_manage']==allowed
    def edit():
        store.update_folder(folder['id'],user_id=actor,is_admin=admin,name='Renamed folder',parent_id='')
        store.save_credential(credential_id=credential['id'],user_id=actor,is_admin=admin,
                              name='Renamed login',remote_username='operator',password='')
        store.bulk_update(user_id=actor,is_admin=admin,host_ids=[host['id']],folder_ids=[],destination_id='')
        store.delete_host(host['id'],user_id=actor,is_admin=admin)
        store.delete_credential(credential['id'],user_id=actor,is_admin=admin)
        store.delete_folder(folder['id'],user_id=actor,is_admin=admin)
    if allowed:
        edit()
        assert store.library_for_user('owner')=={'folders':[],'credentials':[],'hosts':[]}
    else:
        with pytest.raises(RemoteConnectionError):edit()
        assert store.get_folder(folder['id'],user_id='owner')['name']=='Shared folder'


def test_shared_management_does_not_reach_private_dependencies(store):
    folder,credential,host=seed(store)
    store.set_visibility('credential',credential['id'],user_id='owner',visibility='private')
    with pytest.raises(RemoteConnectionError,match='private'):
        store.delete_host(host['id'],user_id='admin',is_admin=True)
    assert store.get_host(host['id'],user_id='owner')
    store.set_visibility('credential',credential['id'],user_id='owner',visibility='admins_only')
    store.set_visibility('host',host['id'],user_id='owner',visibility='private')
    with pytest.raises(RemoteConnectionError,match='private'):
        store.save_credential(credential_id=credential['id'],user_id='admin',is_admin=True,
                              name='Changed',remote_username='attacker',password='replacement')
    with pytest.raises(RemoteConnectionError,match='private'):
        store.set_visibility('folder',folder['id'],user_id='admin',is_admin=True,visibility='global')
    assert store.get_folder(folder['id'],user_id='owner')['visibility']=='admins_only'
    # A folder label does not change private descendants' policies.
    store.update_folder(folder['id'],user_id='admin',is_admin=True,name='Renamed',parent_id='')
    assert store.get_folder(folder['id'],user_id='owner')['user_id']=='owner'


def test_bulk_owner_boundary_and_private_visibility_are_atomic(store):
    first,_,host=seed(store)
    other,_,other_host=seed(store,'other')
    with pytest.raises(RemoteConnectionError,match="one owner's"):
        store.bulk_update(user_id='admin',is_admin=True,host_ids=[host['id'],other_host['id']],folder_ids=[],destination_id='')
    with pytest.raises(RemoteConnectionError,match="same owner's"):
        store.bulk_update(user_id='admin',is_admin=True,host_ids=[host['id']],folder_ids=[],destination_id=other['id'])
    assert store.get_host(host['id'],user_id='owner')['folder_id']==first['id']
    with pytest.raises(RemoteConnectionError,match='Only the owner'):
        store.set_visibility('host',host['id'],user_id='admin',is_admin=True,visibility='private')


@pytest.mark.parametrize('delegated',[False,True])
def test_routes_manage_shared_items_preserve_actor_and_rollback_invalid_visibility(tmp_path,delegated):
    app=create_app(str(tmp_path));app.testing=True
    app.config['DISTRIBUTED_AGENT_DISPATCH']=delegated
    client=app.test_client();store=app.extensions['remote_connection_store']
    folder,credential,host=seed(store)
    environ={'twn.delegated_user':{'id':'delegated-admin','username':'Mainframe editor','is_admin':True}} if delegated else {}
    actor='delegated-admin' if delegated else 'test-user'
    try:
        response=client.patch(f"/tools/remote-terminal/folders/{folder['id']}",json={'name':'New name','parent_id':'','visibility':'invalid'},environ_overrides=environ)
        assert response.status_code==400
        assert store.get_folder(folder['id'],user_id='owner')['name']=='Shared folder'
        response=client.patch(f"/tools/remote-terminal/folders/{folder['id']}",json={'name':'New name','parent_id':'','visibility':'global'},environ_overrides=environ)
        assert response.status_code==200,response.get_json()
        item=response.get_json()['library']['folders'][0]
        assert item['can_manage'] and not item['owned'] and item['user_id']=='owner'
        response=client.patch(f"/tools/remote-terminal/hosts/{host['id']}",json={
            'name':'Edited host','host':'new-switch.example.test','port':22,'folder_id':folder['id'],
            'credential_mode':'saved','credential_id':credential['id'],'visibility':'admins_only',
        },environ_overrides=environ)
        assert response.status_code==200,response.get_json()
        updated=store.get_host(host['id'],user_id='owner')
        assert updated['name']=='Edited host' and updated['user_id']=='owner'
        events=AuditStore(str(tmp_path)).recent(20)
        event=next(item for item in events if item['action']=='remote_terminal.host_updated')
        assert event['user_id']==actor
        assert event['details']['owner id']=='owner'
        assert 'private-fixture-password' not in str(events)
        response=client.patch(f"/tools/remote-terminal/credentials/{credential['id']}",json={
            'name':'Updated login','username':'new-operator','password':'','visibility':'global',
        },environ_overrides=environ)
        assert response.status_code==200,response.get_json()
        assert store.resolve_credential(credential['id'],user_id='owner')['password']=='private-fixture-password'
    finally:
        app.extensions['remote_session_manager'].close()


def test_shared_host_can_replace_scoped_secret_without_changing_owner(store):
    folder,credential,host=seed(store)
    updated=store.save_host(user_id='admin',is_admin=True,host_id=host['id'],
        name='Shared host',host='switch.example.test',port=22,folder_id=folder['id'],credential_id='',
        allow_unknown_hosts=False,allow_legacy_algorithms=False,
        host_credential={'name':'Host login','username':'operator','password':'replacement-secret'})
    assert updated['user_id']=='owner'
    library=store.library_for_user('admin',is_admin=True)
    new=next(item for item in library['credentials'] if item['id']==updated['credential_id'])
    assert new['visibility']=='admins_only' and new['can_manage'] and not new['owned']
    assert 'replacement-secret' not in str(library)
    store.delete_host(host['id'],user_id='admin',is_admin=True)
    assert not any(item['id']==new['id'] for item in store.library_for_user('owner')['credentials'])


def test_mutation_transaction_rolls_back_related_changes(store):
    folder,_,_=seed(store)
    with pytest.raises(RuntimeError):
        with store.transaction():
            store.update_folder(folder['id'],user_id='admin',is_admin=True,name='Temporary',parent_id='')
            raise RuntimeError('fixture failure after mutation')
    assert store.get_folder(folder['id'],user_id='owner')['name']=='Shared folder'


def test_nested_failed_edit_does_not_commit_partial_changes(store):
    folder,_,_=seed(store)
    with store.transaction():
        with pytest.raises(RuntimeError):
            with store.transaction():
                store.update_folder(folder['id'],user_id='admin',is_admin=True,name='Failed edit',parent_id='')
                raise RuntimeError('fixture')
        assert store.get_folder(folder['id'],user_id='owner')['name']=='Shared folder'
    assert store.get_folder(folder['id'],user_id='owner')['name']=='Shared folder'
