import pytest
from twn_toolkit.remote_connections import RemoteConnectionStore, RemoteConnectionError
from twn_toolkit.remote_mso_policy import sharing_dependencies


@pytest.fixture
def store(tmp_path):
    return RemoteConnectionStore(str(tmp_path), 'fixture-instance-key')


def folder(store, name, parent='', visibility='global'):
    item=store.create_folder(user_id='owner',name=name,parent_id=parent,credential_mode='none')
    store.set_visibility('folder',item['id'],user_id='owner',visibility=visibility)
    return item


def host(store, parent='', visibility='global', credential=''):
    item=store.save_host(user_id='owner',name='Host',host='192.0.2.1',port=22,protocol='ssh' if credential else 'telnet',
        folder_id=parent,credential_id=credential,credential_mode='credential' if credential else 'none',
        allow_unknown_hosts=False,allow_legacy_algorithms=False)
    store.set_visibility('host',item['id'],user_id='owner',visibility=visibility)
    return item


def plan(store, kind, identifier, **kwargs):
    return sharing_dependencies(store,kind,identifier,user_id=kwargs.pop('user_id','owner'),**kwargs)


def test_global_host_requires_full_nonprivate_path(store):
    root=folder(store,'Root');child=folder(store,'Child',root['id'],'inherit')
    item=host(store,child['id'])
    assert {(v['kind'],v['id']) for v in plan(store,'host',item['id'])}=={
        ('folder',root['id']),('folder',child['id']),('host',item['id'])}
    store.set_visibility('folder',root['id'],user_id='owner',visibility='private')
    with pytest.raises(RemoteConnectionError,match='Private'):
        plan(store,'host',item['id'])
    assert store.get_folder(root['id'],user_id='owner')['visibility']=='private'


def test_shared_folder_does_not_publish_private_children(store):
    root=folder(store,'Root');child=folder(store,'Private child',root['id'],'private')
    item=host(store,root['id'],'private')
    assert plan(store,'folder',root['id'])==[{'kind':'folder','id':root['id'],'visibility':'global'}]
    for kind,key in [('folder',child['id']),('host',item['id'])]:
        with pytest.raises(RemoteConnectionError,match='Private'):
            plan(store,kind,key)


def test_private_credential_is_not_automatically_made_public(store):
    credential=store.save_credential(user_id='owner',name='Login',remote_username='operator',password='fixture-secret')
    item=host(store,credential=credential['id'])
    with pytest.raises(RemoteConnectionError,match='Private'):
        plan(store,'host',item['id'])
    store.set_visibility('credential',credential['id'],user_id='owner',visibility='admins_only')
    dependencies=plan(store,'host',item['id'])
    assert ('credential',credential['id']) in {(v['kind'],v['id']) for v in dependencies}
    assert 'fixture-secret' not in repr(dependencies)


def test_admin_cannot_share_another_users_private_dependency(store):
    root=folder(store,'Private root',visibility='private');item=host(store,root['id'])
    with pytest.raises(RemoteConnectionError,match='Private'):
        plan(store,'host',item['id'],user_id='admin',is_admin=True)


def test_global_visibility_does_not_grant_other_users_management(store):
    item=host(store)
    with pytest.raises(RemoteConnectionError,match='not manageable'):
        plan(store,'host',item['id'],user_id='another-user')
    assert plan(store,'host',item['id'],user_id='admin',is_admin=True)[0]['visibility']=='global'
