from pathlib import Path
import pytest
from twn_toolkit.auth import load_or_create_secret_key
from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.remote_connections import RemoteConnectionStore
from twn_toolkit.remote_mso_bridge import set_sharing, sync_local, project, metadata
from twn_toolkit.mso import MsoStore


def node(path, role):
    settings=DistributedSettingsStore(path)
    settings.save({**settings.get(),'role':role,'agent_mainframe_url':'https://main.example:7443'})
    return RemoteConnectionStore(str(path),load_or_create_secret_key(str(path)))


def sync(main,agent):
    hub=MsoStore(main.instance_path);peer=MsoStore(agent.instance_path)
    for _ in range(12):
        request=peer.request();response=hub.exchange(peer.node,request);peer.receive(response,request)
        if not request['proposals'] and len(response['objects'])<4:break


def create(store):
    credential=store.save_credential(user_id='owner',name='Login',remote_username='operator',password='terminal-secret-fixture')
    store.set_visibility('credential',credential['id'],user_id='owner',visibility='global')
    root=store.create_folder(user_id='owner',name='Datacenter',credential_mode='credential',credential_id=credential['id'])
    store.set_visibility('folder',root['id'],user_id='owner',visibility='global')
    child=store.create_folder(user_id='owner',name='Core',parent_id=root['id'])
    store.set_visibility('folder',child['id'],user_id='owner',visibility='inherit')
    host=store.save_host(user_id='owner',name='Switch',host='192.0.2.1',port=22,folder_id=child['id'],credential_id='',credential_mode='inherit',allow_unknown_hosts=False,allow_legacy_algorithms=False)
    return root,child,host,credential


def test_terminal_full_path_credentials_rename_and_withdrawal(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    root,child,host,credential=create(agent)
    set_sharing(agent,'host',host['id'],True,user_id='owner')
    sync(main,agent)
    library=main.library_for_user('admin',is_admin=True)
    assert [p['name'] for p in library['hosts']]==['Switch']
    assert {p['name'] for p in library['folders']}=={'Datacenter','Core'}
    received=library['hosts'][0]
    assert received['effective_credential_name']=='Login'
    agent.update_folder(root['id'],user_id='owner',name='Campus',parent_id='',credential_mode='credential',credential_id=credential['id'])
    sync(main,agent)
    assert {p['name'] for p in main.library_for_user('admin',is_admin=True)['folders']}=={'Campus','Core'}
    for path in [main.instance_path,agent.instance_path]:
        for p in path.glob('*.sqlite3*'):
            assert b'terminal-secret-fixture' not in p.read_bytes()
    set_sharing(agent,'host',host['id'],False,user_id='owner')
    sync(main,agent)
    assert not main.library_for_user('admin',is_admin=True)['hosts']
    assert agent.get_host(host['id'],user_id='owner')


def test_bidirectional_folder_conflict_requires_review(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    root,child,host,credential=create(agent)
    set_sharing(agent,'host',host['id'],True,user_id='owner');sync(main,agent)
    replica=next(p for p in main.library_for_user('admin',is_admin=True)['folders'] if p['name']=='Datacenter')
    main.update_folder(replica['id'],user_id='admin',is_admin=True,name='Main edit',parent_id='',credential_mode='credential',credential_id=replica['credential_id'])
    agent.update_folder(root['id'],user_id='owner',name='Offline edit',parent_id='',credential_mode='credential',credential_id=credential['id'])
    sync(main,agent)
    mso=MsoStore(agent.instance_path,'terminal.folder')
    conflict=next(p for p in mso.profiles(metadata=True) if p['mso']['conflict'])
    assert conflict['title']=='Offline edit'
    mso.resolve(conflict['mso']['id'],'fleet',conflict['mso']['version'])
    assert agent.get_folder(root['id'],user_id='owner')['name']=='Main edit'


def test_terminal_http_share_and_private_change_are_atomic(tmp_path):
    from twn_toolkit.app import create_app
    from twn_toolkit.auth import AuthStore
    store=node(tmp_path,'mainframe')
    auth=AuthStore(tmp_path);auth.create_user('reviewer','Temporary fixture password',is_admin=True)
    app=create_app(str(tmp_path));client=app.test_client();client.post('/login',data={'username':'reviewer','password':'Temporary fixture password'})
    response=client.post('/tools/remote-terminal/folders',json={'name':'Shared root','visibility':'global','credential_mode':'none','mso_enabled':True})
    assert response.status_code==201,response.get_json()
    data=response.get_json()['library'];root=data['folders'][0]
    assert root['mso']['enabled']
    response=client.patch('/tools/remote-terminal/folders/'+root['id'],json={'name':'Secret root','visibility':'private','credential_mode':'none','mso_enabled':True,'mso_revision':data['mso_revision']})
    assert response.status_code==409
    saved=client.get('/tools/remote-terminal/library').get_json()['library']
    assert saved['folders'][0]['name']=='Shared root' and saved['folders'][0]['visibility']=='global'
    response=client.patch('/tools/remote-terminal/folders/'+root['id'],json={'name':'New name','visibility':'global','credential_mode':'none','mso_enabled':True,'mso_revision':data['mso_revision']})
    assert response.status_code==200,response.get_json()
    response=client.patch('/tools/remote-terminal/folders/'+root['id'],json={'name':'Stale name','visibility':'global','credential_mode':'none','mso_enabled':True,'mso_revision':data['mso_revision']})
    assert response.status_code==409


def test_private_dependency_blocks_shared_http_host_without_creating_it(tmp_path):
    from twn_toolkit.app import create_app
    from twn_toolkit.auth import AuthStore
    store=node(tmp_path,'mainframe')
    auth=AuthStore(tmp_path);auth.create_user('reviewer','Temporary fixture password',is_admin=True)
    app=create_app(str(tmp_path));client=app.test_client();client.post('/login',data={'username':'reviewer','password':'Temporary fixture password'})
    response=client.post('/tools/remote-terminal/folders',json={'name':'Private root','visibility':'private','credential_mode':'none'})
    data=response.get_json()['library'];root=data['folders'][0]
    response=client.post('/tools/remote-terminal/hosts',json={'name':'Public host','host':'192.0.2.1','port':23,'protocol':'telnet','credential_mode':'none','folder_id':root['id'],'visibility':'global','mso_enabled':True,'mso_revision':data['mso_revision']})
    assert response.status_code==409,response.get_json()
    assert not client.get('/tools/remote-terminal/library').get_json()['library']['hosts']


def test_folder_move_shares_new_path_before_publishing_child(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    root,child,host,credential=create(agent)
    set_sharing(agent,'host',host['id'],True,user_id='owner');sync(main,agent)
    destination=agent.create_folder(user_id='owner',name='New campus',credential_mode='none')
    agent.set_visibility('folder',destination['id'],user_id='owner',visibility='global')
    agent.update_folder(root['id'],user_id='owner',name='Datacenter',parent_id=destination['id'],credential_mode='credential',credential_id=credential['id'])
    set_sharing(agent,'folder',root['id'],True,user_id='owner')
    sync(main,agent)
    assert not any(p['mso']['conflict'] for p in MsoStore(agent.instance_path,'terminal.folder').profiles(metadata=True))
    folders=main.library_for_user('admin',is_admin=True)['folders']
    top=next(p for p in folders if p['name']=='New campus')
    assert next(p for p in folders if p['name']=='Datacenter')['parent_id']==top['id']


def test_admin_can_add_to_received_folder_without_account_mapping(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    root,child,host,credential=create(agent)
    set_sharing(agent,'host',host['id'],True,user_id='owner');sync(main,agent)
    received=next(p for p in main.library_for_user('admin',is_admin=True)['folders'] if p['name']=='Core')
    created=main.create_folder(user_id='admin',is_admin=True,name='New branch',parent_id=received['id'])
    main.set_visibility('folder',created['id'],user_id='admin',is_admin=True,visibility='inherit')
    set_sharing(main,'folder',created['id'],True,user_id='admin',is_admin=True)
    sync(main,agent)
    assert any(p['name']=='New branch' for p in agent.library_for_user('owner')['folders'])


def test_scoped_credential_withdraws_with_its_host(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    host=agent.save_host(user_id='owner',name='Scoped host',host='192.0.2.1',port=22,folder_id='',credential_id='',allow_unknown_hosts=False,allow_legacy_algorithms=False,
        host_credential={'name':'Scoped login','username':'operator','password':'scoped-secret-fixture'})
    agent.set_visibility('host',host['id'],user_id='owner',visibility='global')
    agent.set_visibility('credential',host['credential_id'],user_id='owner',visibility='global')
    set_sharing(agent,'host',host['id'],True,user_id='owner');sync(main,agent)
    assert len(main.library_for_user('admin',is_admin=True)['credentials'])==1
    set_sharing(agent,'host',host['id'],False,user_id='owner');sync(main,agent)
    library=main.library_for_user('admin',is_admin=True)
    assert not library['hosts'] and not library['credentials']
    assert len(agent.library_for_user('owner')['hosts'])==1


def test_conflicted_dependency_blocks_new_connection_secret_resolution(tmp_path):
    from twn_toolkit.remote_connections import RemoteConnectionError
    from twn_toolkit.remote_mso_bridge import require_usable
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    root,child,host,credential=create(agent)
    set_sharing(agent,'host',host['id'],True,user_id='owner');sync(main,agent)
    replica=main.library_for_user('admin',is_admin=True)['credentials'][0]
    main.save_credential(user_id='admin',is_admin=True,credential_id=replica['id'],name='Login',remote_username='operator',password='main-secret')
    agent.save_credential(user_id='owner',credential_id=credential['id'],name='Login',remote_username='operator',password='agent-secret')
    sync(main,agent)
    with pytest.raises(RemoteConnectionError,match='MSO conflict'):
        require_usable(agent,'host',host['id'])
    with pytest.raises(RemoteConnectionError,match='MSO conflict'):
        agent.resolve_credential(credential['id'],user_id='owner',host_id=host['id'])
    mso=MsoStore(agent.instance_path,'terminal.credential')
    conflict=mso.profiles(metadata=True)[0]
    mso.resolve(conflict['mso']['id'],'fleet',conflict['mso']['version'])
    assert agent.resolve_credential(credential['id'],user_id='owner',host_id=host['id'])['password']=='main-secret'


def test_leaving_fleet_keeps_native_library_and_removes_publication_links(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    root,child,host,credential=create(agent)
    set_sharing(agent,'host',host['id'],True,user_id='owner');sync(main,agent)
    before=agent.library_for_user('owner')
    settings=DistributedSettingsStore(agent.instance_path)
    settings.save({**settings.get(),'role':'standalone'})
    assert agent.library_for_user('owner')==before
    with agent._connect() as db:
        assert db.execute('SELECT count(*) FROM remote_mso_links').fetchone()[0]==0
    settings.save({**settings.get(),'role':'agent','agent_mainframe_url':'https://main.example:7443'})
    assert not MsoStore(agent.instance_path).request()['proposals']
    set_sharing(agent,'host',host['id'],True,user_id='owner')
    assert MsoStore(agent.instance_path).request()['proposals']


def test_offline_withdrawal_conflict_can_restore_fleet_copy(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    root,child,host,credential=create(agent)
    set_sharing(agent,'host',host['id'],True,user_id='owner');sync(main,agent)
    replica=main.library_for_user('admin',is_admin=True)['hosts'][0]
    main.save_host(user_id='admin',is_admin=True,host_id=replica['id'],name='Fleet rename',host=replica['host'],port=22,folder_id=replica['folder_id'],credential_id='',credential_mode='inherit',allow_unknown_hosts=False,allow_legacy_algorithms=False)
    set_sharing(agent,'host',host['id'],False,user_id='owner')
    sync(main,agent)
    mso=MsoStore(agent.instance_path,'terminal.host')
    conflict=next(p for p in mso.profiles(metadata=True) if p['mso']['conflict'])
    assert conflict['mso']['deleted']
    mso.resolve(conflict['mso']['id'],'fleet',conflict['mso']['version'])
    assert agent.get_host(host['id'],user_id='owner')['name']=='Fleet rename'
    assert metadata(agent,agent.library_for_user('owner'))['hosts'][0]['mso']['enabled']


def test_received_library_portable_backup_keeps_opaque_owner_and_local_import(tmp_path):
    from twn_toolkit.auth import AuthStore
    from twn_toolkit.configuration_backup_stores import RemoteConnectionBackupStore
    from twn_toolkit.backup_source_reads import bounded_backup_store, bounded_source_reads
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    root,child,host,credential=create(agent)
    set_sharing(agent,'host',host['id'],True,user_id='owner');sync(main,agent)
    adapter=RemoteConnectionBackupStore(main,AuthStore(main.instance_path))
    with bounded_source_reads(2_000_000), bounded_backup_store(adapter) as bounded:
        exported=bounded.all()
    assert len(exported)==1 and exported[0]['mso_owner']
    restored=node(tmp_path/'restored','standalone')
    backup=RemoteConnectionBackupStore(restored,AuthStore(restored.instance_path))
    backup.replace_all(exported)
    library=restored.library_for_user('admin',is_admin=True)
    assert library['hosts'][0]['user_id']=='mso:'+exported[0]['mso_owner']
    assert restored.resolve_credential(library['credentials'][0]['id'],user_id='admin',is_admin=True)['password']=='terminal-secret-fixture'
    with restored._connect() as db:
        assert db.execute('SELECT count(*) FROM remote_mso_links').fetchone()[0]==0
    snapshot=adapter.backup_snapshot()
    with main._connect() as db:db.execute('DELETE FROM remote_mso_links')
    adapter.restore_backup_snapshot(snapshot)
    with main._connect() as db:assert db.execute('SELECT count(*) FROM remote_mso_links').fetchone()[0]==4


def test_relative_instance_path_resolves_shared_credentials(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    store=node(Path('agent'),'agent')
    credential=store.save_credential(user_id='owner',name='Login',remote_username='operator',password='relative-secret')
    store.set_visibility('credential',credential['id'],user_id='owner',visibility='global')
    set_sharing(store,'credential',credential['id'],True,user_id='owner')
    sync_local(store.instance_path)
    assert store.resolve_credential(credential['id'],user_id='owner')['password']=='relative-secret'
    assert metadata(store,store.library_for_user('owner'))['credentials'][0]['mso']['enabled']
