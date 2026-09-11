"""MSO tool-library adapters and protected credential migration."""
import json
import pytest
from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.mso import MsoStore
from twn_toolkit.profiles import RadiusProfileStore
from twn_toolkit.profile_secrets import transform_profiles


@pytest.mark.parametrize('kind,payload,field', [
    ('servers', {'name':'Primary','host':'192.0.2.20','port':1812,'secret':'radius-secret-fixture'}, 'secret'),
    ('credentials', {'name':'Operator','username':'tester','password':'radius-password-fixture'}, 'password'),
])
def test_radius_legacy_secret_migrates_and_syncs_both_directions(tmp_path, kind, payload, field):
    main=tmp_path/'main';agent=tmp_path/'agent'
    for path,role in [(main,'mainframe'),(agent,'agent')]:
        settings=DistributedSettingsStore(path)
        settings.save({**settings.get(),'role':role,'agent_mainframe_url':'https://main.example:7443'})
    filename=f'radius_{kind}_profiles.json'
    protected=transform_profiles([payload],agent,filename,(field,),encrypt=True)
    (agent/filename).write_text(json.dumps(protected))
    store=RadiusProfileStore(str(agent),kind)
    assert store.get(payload['name'])==payload
    shared=store.mso_store().save(payload,enabled=True)
    hub=MsoStore(main);peer=MsoStore(agent)
    request=peer.request();peer.receive(hub.exchange(peer.node,request),request)
    received=RadiusProfileStore(str(main),kind).get(payload['name'])
    assert received==payload
    changed={**payload,field:'changed-secret-fixture'}
    RadiusProfileStore(str(main),kind).mso_store().save(changed)
    request=peer.request();peer.receive(hub.exchange(peer.node,request),request)
    assert store.get(payload['name'])==changed
    assert store.mso_store().profiles(metadata=True)[0]['mso']['id']==shared['mso']['id']
    for path in [main,agent]:
        for db in path.glob('mso.sqlite3*'):
            assert payload[field].encode() not in db.read_bytes()
            assert b'changed-secret-fixture' not in db.read_bytes()

@pytest.mark.parametrize('kind,payload', [
    ('fortigate.profile', {'name':'Appliance','host':'https://192.0.2.10','api_key':'private-api-fixture','verify_tls':True,'default_vdom':'root'}),
    ('fortiauthenticator.profile', {'name':'Appliance','host':'https://192.0.2.10','username':'api','password':'private-password-fixture','verify_tls':True,'timeout':20}),
])
def test_appliance_default_is_local_and_rename_preserves_identity(tmp_path, kind, payload):
    from twn_toolkit.mso_types import LIST_TYPES
    from twn_toolkit.mso_secrets import LEGACY_SECRET_FIELDS
    stores=[]
    for role in ['mainframe','agent']:
        path=tmp_path/role
        settings=DistributedSettingsStore(path)
        settings.save({**settings.get(),'role':role,'agent_mainframe_url':'https://main.example:7443'})
        stores.append(MsoStore(path,kind))
    main,agent=stores
    spec=LIST_TYPES[kind]
    # Use a separate legacy instance so its first read exercises file-context decryption.
    legacy=tmp_path/'legacy';legacy.mkdir()
    values=transform_profiles([payload],legacy,spec.filename,LEGACY_SECRET_FIELDS[kind],encrypt=True)
    (legacy/spec.filename).write_text(json.dumps(values))
    assert MsoStore(legacy,kind).profiles()==[payload]
    saved=main.save({**payload,'is_default':True},enabled=True)
    request=agent.request();response=main.exchange(agent.node,request)
    assert 'is_default' not in response['objects'][0]['payload']
    agent.receive(response,request)
    assert not agent.profiles()[0]['is_default']
    agent.save({**payload,'name':'Renamed','is_default':True},'Appliance')
    request=agent.request();agent.receive(main.exchange(agent.node,request),request)
    assert main.profiles()[0]['name']=='Renamed'
    assert main.profiles()[0]['is_default']
    assert main.profiles(metadata=True)[0]['mso']['id']==saved['mso']['id']
    main.save({**payload,'name':'Local default','is_default':True})
    assert sum(bool(p.get('is_default')) for p in main.profiles())==1
    assert agent.profiles()[0]['is_default']

@pytest.mark.parametrize('endpoint,kind,payload', [
    ('/profiles','fortigate.profile',{'name':'Appliance','host':'https://192.0.2.10','api_key':'http-secret-fixture','default_vdom':'root','verify_tls':'on'}),
    ('/fortiauthenticator/profiles','fortiauthenticator.profile',{'name':'Appliance','host':'https://192.0.2.10','username':'api','password':'http-secret-fixture','timeout':'20','verify_tls':'on'}),
    ('/tools/radius-test/profiles/servers','radius.servers',{'name':'Appliance','host':'192.0.2.10','port':'1812','secret':'http-secret-fixture'}),
    ('/tools/radius-test/profiles/credentials','radius.credentials',{'name':'Appliance','username':'tester','password':'http-secret-fixture'}),
])
def test_shared_library_http_save_rename_and_stale_guard(tmp_path, endpoint, kind, payload):
    from twn_toolkit.app import create_app
    from twn_toolkit.auth import AuthStore
    settings=DistributedSettingsStore(tmp_path)
    settings.save({**settings.get(),'role':'mainframe'})
    auth=AuthStore(tmp_path);auth.create_user('reviewer','Temporary fixture password',is_admin=True)
    app=create_app(str(tmp_path));client=app.test_client()
    client.post('/login',data={'username':'reviewer','password':'Temporary fixture password'})
    response=client.post(endpoint,data={**payload,'mso_kind':kind,'mso_enabled':'true'})
    assert response.status_code in (200,302)
    saved=MsoStore(tmp_path,kind).profiles(metadata=True)[0]
    assert saved['mso']['enabled']
    identity=saved['mso']['id']
    data={**payload,'name':'Renamed','original_name':'Appliance','mso_kind':kind,'mso_enabled':'true','mso_id':identity,'mso_version':saved['mso']['version']}
    response=client.post(endpoint,data=data)
    assert response.status_code in (200,302)
    assert MsoStore(tmp_path,kind).profiles(metadata=True)[0]['name']=='Renamed'
    stale={**data,'name':'Stale','original_name':'Renamed'}
    response=client.post(endpoint,data=stale)
    assert response.status_code in (302,409)
    assert MsoStore(tmp_path,kind).profiles(metadata=True)[0]['name']=='Renamed'
    if response.is_json:assert b'http-secret-fixture' not in response.data


def test_shared_matrix_action_save_is_guarded_and_replicates_as_one_library(tmp_path):
    from twn_toolkit.app import create_app
    from twn_toolkit.auth import AuthStore
    from twn_toolkit.ssh_commandlets import SSHHostMatrixStore
    settings=DistributedSettingsStore(tmp_path)
    settings.save({**settings.get(),'role':'mainframe'})
    auth=AuthStore(tmp_path);auth.create_user('reviewer','Temporary fixture password',is_admin=True)
    app=create_app(str(tmp_path));client=app.test_client()
    client.post('/login',data={'username':'reviewer','password':'Temporary fixture password'})
    response=client.post('/tools/multi-ssh',data={'action':'save_host_matrix','host_matrix_name':'Routers','matrix':'Host,Name\n192.0.2.1,Router','mso_kind':'ssh.matrix','mso_enabled':'true'})
    store=SSHHostMatrixStore(tmp_path);saved=store.mso_store().profiles(metadata=True)[0]
    assert saved['mso']['enabled']
    data={'action':'save_matrix_action','host_matrix_original_name':'Routers','matrix_action_name':'Read version','commands':'show version','command_timeout':'30','mso_kind':'ssh.matrix','mso_id':saved['mso']['id'],'mso_version':saved['mso']['version']}
    client.post('/tools/multi-ssh',data=data)
    assert store.get('Routers')['actions'][0]['commands']=='show version'
    client.post('/tools/multi-ssh',data={**data,'matrix_action_name':'Stale action'})
    assert [a['name'] for a in store.get('Routers')['actions']]==['Read version']
    agent=tmp_path/'peer';config=DistributedSettingsStore(agent);config.save({**config.get(),'role':'agent','agent_mainframe_url':'https://main.example:7443'})
    hub=MsoStore(tmp_path);peer=MsoStore(agent)
    request=peer.request();peer.receive(hub.exchange(peer.node,request),request)
    received=SSHHostMatrixStore(agent).get('Routers')
    assert received==store.get('Routers')
    for path in [tmp_path,agent]:
        for file in path.glob('mso.sqlite3*'):
            assert b'show version' not in file.read_bytes()
