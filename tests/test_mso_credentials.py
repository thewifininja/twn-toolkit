"""Credential secrecy, UUID dependencies and offline delivery invariants."""
import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from twn_toolkit.distributed_agents import DistributedSettingsStore
from twn_toolkit.mso import MsoStore, MsoConflict
from twn_toolkit.profiles import SNMPCredentialProfileStore, SNMPHostProfileStore

CREDENTIAL='snmp.credentials'
HOST='snmp.hosts'


def node(path, role):
    settings=DistributedSettingsStore(path)
    settings.save({**settings.get(),'role':role,'agent_mainframe_url':'https://main.example:7443'})
    return MsoStore(path)


def credential(name='Access', secret='community-sensitive-fixture'):
    return dict(name=name,version='v2c',community=secret)


def host(name='Device', access='Access'):
    return dict(name=name,host='192.0.2.1',port=161,timeout=1,retries=1,credential_name=access)


def sync(main, agent):
    for _ in range(8):
        req=agent.request();response=main.exchange(agent.node,req);agent.receive(response,req)
        if not agent.request()['proposals'] and len(response['objects'])<4:break


def one(store):
    return store.profiles(metadata=True)[0]


def test_host_enables_credential_and_rename_keeps_stable_reference(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    creds=MsoStore(agent.instance,CREDENTIAL);hosts=MsoStore(agent.instance,HOST)
    cred=creds.save(credential())
    saved=hosts.save(host(),enabled=True)
    proposal=agent.request()['proposals']
    assert [p['kind'] for p in proposal]==[CREDENTIAL,HOST]
    assert proposal[1]['payload']['credential_id']==cred['mso']['id']
    assert 'credential_name' not in proposal[1]['payload']
    sync(main,agent)
    destination=SNMPHostProfileStore(main.instance)
    assert destination.get('Device')['credential_name']=='Access'
    assert SNMPCredentialProfileStore(main.instance).get('Access')['community']==credential()['community']
    creds.save(credential('Renamed'),'Access')
    sync(main,agent)
    assert destination.get('Device')['credential_name']=='Renamed'
    assert one(MsoStore(main.instance,HOST))['mso']['id']==saved['mso']['id']
    with pytest.raises(MsoConflict,match='Shared hosts'):
        creds.save(credential('Renamed'),enabled=False)
    with pytest.raises(MsoConflict,match='Hosts still use'):
        creds.delete('Renamed')
    # Host removal is delivered before credential withdrawal, even offline.
    hosts.save(host(access='Renamed'),enabled=False)
    creds.save(credential('Renamed'),enabled=False)
    assert [p['kind'] for p in agent.request()['proposals']]==[HOST,CREDENTIAL]
    sync(main,agent)
    assert destination.all()==[]
    assert SNMPHostProfileStore(agent.instance).get('Device')['credential_name']=='Renamed'
    assert not one(creds)['mso']['enabled']


def test_hub_rejects_host_with_local_or_missing_credential_and_credential_removal(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    creds=MsoStore(agent.instance,CREDENTIAL);hosts=MsoStore(agent.instance,HOST)
    creds.save(credential());hosts.save(host(),enabled=True)
    req=agent.request();host_proposal=req['proposals'][1]
    bad={**req,'proposals':[host_proposal]}
    response=main.exchange(agent.node,bad)
    assert not response['acknowledgements'][0]['accepted']
    assert not MsoStore(main.instance,HOST).profiles()
    sync(main,agent)
    raw={**agent.request(),'proposals':[dict(operation=str(uuid.uuid4()),id=one(creds)['mso']['id'],kind=CREDENTIAL,base=one(creds)['mso']['revision'],payload=credential(),deleted=True,version=2)]}
    response=main.exchange(agent.node,raw)
    assert not response['acknowledgements'][0]['accepted']
    assert 'Shared hosts' in response['acknowledgements'][0]['error']
    assert one(MsoStore(main.instance,CREDENTIAL))['community']==credential()['community']


def test_collision_never_selects_same_named_unrelated_secret(tmp_path):
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    SNMPCredentialProfileStore(agent.instance).upsert(credential(secret='unrelated-local-secret'))
    MsoStore(main.instance,CREDENTIAL).save(credential())
    MsoStore(main.instance,HOST).save(host(),enabled=True)
    sync(main,agent)
    assert SNMPHostProfileStore(agent.instance).get('Device')['credential_name']==''
    assert SNMPCredentialProfileStore(agent.instance).get('Access')['community']=='unrelated-local-secret'
    conflict=next(p for p in MsoStore(agent.instance,CREDENTIAL).profiles(metadata=True) if p['mso']['conflict'])
    info=conflict['mso'];MsoStore(agent.instance,CREDENTIAL).resolve(info['id'],'local',info['version'])
    sync(main,agent)
    received=SNMPHostProfileStore(agent.instance).get('Device')
    assert received['credential_name']!='Access'
    assert SNMPCredentialProfileStore(agent.instance).get(received['credential_name'])['community']==credential()['community']


def test_encrypted_pending_hub_and_conflict_records_and_no_html_leak(tmp_path):
    from twn_toolkit.app import create_app
    from twn_toolkit.auth import AuthStore
    main=node(tmp_path/'main','mainframe');agent=node(tmp_path/'agent','agent')
    a=MsoStore(agent.instance,CREDENTIAL);m=MsoStore(main.instance,CREDENTIAL)
    a.save(credential(),enabled=True);agent.request()
    sync(main,agent)
    a.save(credential(secret='offline-secret-fixture'))
    m.save(credential(secret='main-secret-fixture'))
    sync(main,agent)
    conflict=one(a);assert conflict['mso']['conflict']
    version=conflict['mso']['version'];sync(main,agent);assert one(a)['mso']['version']==version
    for instance in [main.instance,agent.instance]:
        for path in instance.glob('mso.sqlite3*'):
            content=path.read_bytes()
            for secret in ['community-sensitive-fixture','offline-secret-fixture','main-secret-fixture']:
                assert secret.encode() not in content
    auth=AuthStore(agent.instance);auth.create_user('reviewer','Temporary admin password',is_admin=True)
    app=create_app(str(agent.instance));client=app.test_client();client.post('/login',data={'username':'reviewer','password':'Temporary admin password'})
    for url in ['/tools/snmp-test','/tools/mso/conflicts']:
        response=client.get(url);assert response.status_code==200
        for secret in ['community-sensitive-fixture','offline-secret-fixture','main-secret-fixture']:
            assert secret.encode() not in response.data
    assert b'Stored secret' in client.get('/tools/mso/conflicts').data
    snapshot=a.backup_snapshot();a.restore_backup_snapshot(snapshot)
    assert one(a)['community']=='offline-secret-fixture'
    assert 'offline-secret-fixture' not in json.dumps(snapshot)


def test_legacy_host_binding_migrates_before_credential_rename_and_detach(tmp_path):
    # Existing protected JSON uses its original filename/name encryption context.
    from twn_toolkit.profile_secrets import transform_profiles
    secret=credential()
    protected=transform_profiles([secret],tmp_path,'snmp_credentials_profiles.json',('community',),encrypt=True)
    (tmp_path/'snmp_credentials_profiles.json').write_text(json.dumps(protected))
    (tmp_path/'snmp_host_profiles.json').write_text(json.dumps([host()]))
    main=node(tmp_path,'mainframe');creds=MsoStore(tmp_path,CREDENTIAL)
    creds.save(credential('Renamed'),'Access')
    assert SNMPHostProfileStore(tmp_path).get('Device')['credential_name']=='Renamed'
    MsoStore(tmp_path,HOST).save(host(access='Renamed'),enabled=True)
    main.detach()
    assert SNMPHostProfileStore(tmp_path).get('Device')['credential_name']=='Renamed'
    assert SNMPCredentialProfileStore(tmp_path).get('Renamed')['community']==secret['community']
    assert not one(MsoStore(tmp_path,HOST))['mso']['enabled']
    assert not one(creds)['mso']['enabled']


def test_portable_credential_replace_and_private_rollback_preserve_local_host_binding(tmp_path):
    creds=SNMPCredentialProfileStore(tmp_path);hosts=SNMPHostProfileStore(tmp_path)
    creds.upsert(credential());hosts.upsert(host())
    snapshot=creds.backup_snapshot()
    creds.replace_all([credential(secret='replacement-fixture-secret')])
    assert hosts.get('Device')['credential_name']=='Access'
    creds.restore_backup_snapshot(snapshot)
    assert hosts.get('Device')['credential_name']=='Access'
    assert creds.get('Access')['community']==credential()['community']
    assert 'credential_id' not in hosts.all()[0]


def test_host_export_bounds_credential_reference_before_loading_it(tmp_path):
    from twn_toolkit.backup_source_reads import bounded_source_reads, SourceReadLimit
    creds=SNMPCredentialProfileStore(tmp_path);creds.upsert(credential())
    hosts=SNMPHostProfileStore(tmp_path);hosts.upsert(host())
    with sqlite3.connect(creds.mso_store().path) as db:
        db.execute("UPDATE mso_objects SET payload=zeroblob(?) WHERE kind='snmp.credentials'",(2*1024*1024,))
    with bounded_source_reads(1024*1024), pytest.raises(SourceReadLimit,match='reference exceeds'):
        hosts.all()
