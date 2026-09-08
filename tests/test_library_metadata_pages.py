import json
import sqlite3

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.remote_connections import RemoteConnectionStore


def populate_metadata(store, count=1000, *, owner='owner', deep=False):
    secret = store._cipher.encrypt(b'fixture-secret').decode()
    with sqlite3.connect(store.path) as db:
        db.executemany('INSERT INTO remote_connection_folders (id,user_id,name,parent_id,credential_mode,credential_id,visibility,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
            [('f'+str(i),owner,'Folder '+str(i).zfill(5),'f'+str(i-1) if deep and i else '',
              'inherit' if i else 'credential', '' if i else 'c0', ('global','admins_only','private')[i%3],1,1) for i in range(count)])
        db.executemany('INSERT INTO remote_connection_credentials (id,user_id,name,remote_username,secret_encrypted,visibility,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)',
            [('c'+str(i),owner,'Credential '+str(i).zfill(5),'api',secret,('global','admins_only','private')[i%3],1,1) for i in range(count)])
        db.execute("INSERT INTO remote_connection_hosts (id,user_id,name,host,port,folder_id,credential_id,credential_mode,visibility,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   ('host',owner,'Deep host','192.0.2.1',22,'f'+str(count-1),'','inherit','global',1,1))


@pytest.mark.parametrize('user,admin',[('owner',False),('other',False),('administrator',True)])
def test_metadata_pages_preserve_full_visible_index(tmp_path,user,admin):
    store=RemoteConnectionStore(str(tmp_path),'fixture-key');populate_metadata(store)
    complete=store.library_for_user(user,is_admin=admin)
    first=store.library_for_user(user,is_admin=admin,metadata_page=1)
    seen_folders,seen_credentials=[],[]
    for page in range(1,first['metadata_pagination']['pages']+1):
        data=store.library_for_user(user,is_admin=admin,metadata_page=page)
        seen_folders.extend(row['id'] for row in data['folders'] if not row['context_only'])
        seen_credentials.extend(row['id'] for row in data['credentials'] if not row['context_only'])
        assert len(data['folders'])<=400 and len(data['credentials'])<=1101
    assert seen_folders==[row['id'] for row in complete['folders']]
    assert seen_credentials==[row['id'] for row in complete['credentials']]
    assert first['hosts']==complete['hosts']
    assert 'fixture-secret' not in json.dumps(first)


def test_metadata_search_never_discloses_hidden_parent_or_focused_credential(tmp_path):
    store=RemoteConnectionStore(str(tmp_path),'fixture-key');populate_metadata(store,3)
    data=store.library_for_user('other',metadata_page=1,metadata_query='00002',metadata_credential_id='c2')
    assert data['metadata_pagination']['folders_matched']==data['metadata_pagination']['credentials_matched']==0
    assert data['hosts'][0]['folder_id']==''
    assert not data['folders'] and not data['credentials']
    assert 'Folder 00002' not in json.dumps(data)


@pytest.fixture
def browser(tmp_path):
    app=create_app(str(tmp_path))
    user=AuthStore(str(tmp_path)).create_user('owner','TemporaryPassword123!',is_admin=True)
    client=app.test_client();client.post('/login',data={'username':'owner','password':'TemporaryPassword123!'})
    yield app,client,user
    app.extensions['remote_session_manager'].close()


def test_deep_ten_thousand_metadata_http_is_bounded_and_searches_all_rows(browser):
    app,client,user=browser
    populate_metadata(app.extensions['remote_connection_store'],10000,owner=user['id'],deep=True)
    response=client.get('/tools/remote-terminal/library')
    assert response.status_code==200
    data=response.json['library']
    assert data['metadata_pagination']['folders_total']==data['metadata_pagination']['credentials_total']==10000
    assert len(response.data)<250_000
    assert data['hosts'][0]['effective_credential_id']=='c0'
    found=client.get('/tools/remote-terminal/library?metadata_query=09999').json['library']
    assert found['metadata_pagination']['folders_matched']==found['metadata_pagination']['credentials_matched']==1
    assert {row['id'] for row in found['folders'] if not row['context_only']}=={'f9999'}
    assert {row['id'] for row in found['credentials'] if not row['context_only']}=={'c9999'}
    assert found['hosts'][0]['folder_id']=='f9999'
    assert 'f9998' in {row['id'] for row in found['folders']}


def test_credential_mutations_keep_identity_and_access_when_outside_metadata_page(browser):
    app,client,user=browser;populate_metadata(app.extensions['remote_connection_store'],250,owner=user['id'])
    url='/tools/remote-terminal/credentials'
    response=client.post(url+'?metadata_query=not-matching',json={'name':'New saved identity','username':'api','password':'new-fixture','visibility':'private'})
    assert response.status_code==201
    identifier=response.json['credential_id']
    saved=next(row for row in response.json['library']['credentials'] if row['id']==identifier)
    assert saved['context_only'] and saved['owned'] and saved['can_manage']
    updated=client.patch(url+'/'+identifier+'?metadata_page=1',json={'name':'Updated identity','username':'api','password':'','visibility':'private'})
    assert updated.status_code==200
    assert updated.json['credential_id']==identifier
    assert any(row['id']==identifier for row in updated.json['library']['credentials'])
    copied=client.post(url+'/'+identifier+'/duplicate?metadata_query=not-matching')
    assert copied.status_code==201
    assert copied.json['credential_id']!=identifier
    assert any(row['id']==copied.json['credential_id'] for row in copied.json['library']['credentials'])


def test_credential_inheritance_visits_a_deep_path_once():
    visits=[]
    class Folder(dict):
        def get(self,key,*args):
            if key=='parent_id':visits.append(self['id'])
            return super().get(key,*args)
    folders=[Folder(id=str(i),user_id='owner',name='Folder '+str(i),parent_id=str(i-1) if i else '',
                    credential_mode='inherit' if i else 'credential',credential_id='' if i else 'credential') for i in range(5000)]
    RemoteConnectionStore._annotate_effective_credentials(list(reversed(folders)),[],[{'id':'credential','name':'Saved','username':'api'}])
    assert len(visits)<=5000
    assert all(row['effective_credential_id']=='credential' for row in folders)
