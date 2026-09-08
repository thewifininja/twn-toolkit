import concurrent.futures
import sqlite3
import pytest
from twn_toolkit.remote_connections import RemoteConnectionStore, RemoteConnectionError
from tests.test_library_metadata_pages import populate_metadata

@pytest.fixture
def store(tmp_path):
 return RemoteConnectionStore(str(tmp_path),'fixture-key')

def counts(store):
 with store._connect() as db:
  return tuple(db.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in ('remote_connection_folders','remote_connection_hosts','remote_connection_credentials'))

def test_deep_ten_thousand_item_copy_is_complete_and_preserves_inheritance(store):
 populate_metadata(store,9999,deep=True)
 steps=[]
 def progress():
  steps.append(1)
  return len(steps)>5000
 with store.transaction(),store._connect() as db:
  # Bound SQLite work as well as Python recursion; a reversed recursive join
  # used to scan the owner's entire folder index once per tree level.
  db.set_progress_handler(progress,1000)
  try:copied=store.duplicate_folder('f0',user_id='owner')
  finally:db.set_progress_handler(None,0)
 assert counts(store)==(19998,2,9999)
 library=store.library_for_user('owner')
 assert all(row['effective_credential_id']=='c0' for row in library['hosts'])
 assert copied['name']=='Folder 00000 copy'

@pytest.mark.parametrize('deep',[False,True])
def test_oversized_copy_rejects_before_any_write(store,deep):
 populate_metadata(store,10001,deep=deep)
 if not deep:
  with store._connect() as db:db.execute("UPDATE remote_connection_folders SET parent_id='f0' WHERE id!='f0'")
 before=counts(store)
 with pytest.raises(RemoteConnectionError,match='10,000'):store.duplicate_folder('f0',user_id='owner')
 assert counts(store)==before

def test_cycle_rejects_without_partial_copy(store):
 populate_metadata(store,3,deep=True)
 with store._connect() as db:db.execute("UPDATE remote_connection_folders SET parent_id='f2' WHERE id='f0'")
 with pytest.raises(RemoteConnectionError,match='cycle'):store.duplicate_folder('f0',user_id='owner')
 assert counts(store)==(3,1,3)

def test_failed_child_insert_rolls_back_entire_copy(store):
 populate_metadata(store,3,deep=True)
 with store._connect() as db:
  db.execute("CREATE TRIGGER reject_copy BEFORE INSERT ON remote_connection_folders WHEN NEW.name='Folder 00001' BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
 with pytest.raises(sqlite3.IntegrityError,match='fixture failure'):store.duplicate_folder('f0',user_id='owner')
 assert counts(store)==(3,1,3)

def test_copy_preserves_scoped_secret_without_decryption_and_all_host_settings(store,monkeypatch):
 populate_metadata(store,3,deep=True)
 with store._connect() as db:
  db.execute("UPDATE remote_connection_credentials SET scope_host_id='host',visibility='private' WHERE id='c2'")
  db.execute("UPDATE remote_connection_hosts SET credential_id='c2',credential_mode='credential',allow_unknown_hosts=1,allow_legacy_algorithms=1,notes='Keep notes' WHERE id='host'")
 def forbidden(*args,**kwargs):raise AssertionError('Copy should not decrypt secrets')
 monkeypatch.setattr(store,'resolve_credential',forbidden)
 store.duplicate_folder('f0',user_id='owner')
 with store._connect() as db:
  source=dict(db.execute("SELECT * FROM remote_connection_hosts WHERE id='host'").fetchone())
  copied=dict(db.execute("SELECT * FROM remote_connection_hosts WHERE id!='host'").fetchone())
  first=dict(db.execute("SELECT * FROM remote_connection_credentials WHERE id='c2'").fetchone())
  second=dict(db.execute('SELECT * FROM remote_connection_credentials WHERE id=?',(copied['credential_id'],)).fetchone())
 assert second['id']!=first['id'] and second['scope_host_id']==copied['id']
 assert second['secret_encrypted']==first['secret_encrypted'] and second['visibility']=='private'
 assert second['name']=='Credential 00002 copy'
 for key in source:
  if key not in ('id','folder_id','credential_id','created_at','updated_at'):assert copied[key]==source[key]
 assert counts(store)==(6,2,4)

@pytest.mark.parametrize('kind',['missing','foreign','wrong_scope','folder_scope'])
def test_invalid_secret_dependency_rejects_atomically(store,kind):
 populate_metadata(store,3,deep=True)
 with store._connect() as db:
  if kind=='missing':db.execute("UPDATE remote_connection_hosts SET credential_id='absent' WHERE id='host'")
  elif kind=='foreign':db.execute("UPDATE remote_connection_credentials SET user_id='other' WHERE id='c0'")
  elif kind=='wrong_scope':
   db.execute("UPDATE remote_connection_hosts SET credential_id='c2' WHERE id='host'");db.execute("UPDATE remote_connection_credentials SET scope_host_id='another-host' WHERE id='c2'")
  else:db.execute("UPDATE remote_connection_credentials SET scope_host_id='host' WHERE id='c0'")
 with pytest.raises(RemoteConnectionError):store.duplicate_folder('f0',user_id='owner')
 assert counts(store)==(3,1,3)

def test_foreign_children_are_excluded_and_nonowner_cannot_copy(store):
 populate_metadata(store,3,deep=True)
 with store._connect() as db:db.execute("UPDATE remote_connection_folders SET user_id='other' WHERE id='f2'")
 with pytest.raises(RemoteConnectionError):store.duplicate_folder('f0',user_id='other')
 store.duplicate_folder('f0',user_id='owner')
 assert counts(store)==(5,1,3)

def test_concurrent_copies_choose_distinct_names_and_complete_trees(store):
 populate_metadata(store,20,deep=True)
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  copies=list(pool.map(lambda _:store.duplicate_folder('f0',user_id='owner'),range(2)))
 assert {row['name'] for row in copies}=={'Folder 00000 copy','Folder 00000 copy 2'}
 assert counts(store)==(60,3,20)

@pytest.mark.parametrize('parent',['absent','foreign'])
def test_unavailable_parent_rejects_without_copy(store,parent):
 populate_metadata(store,3,deep=True)
 with store._connect() as db:
  if parent=='foreign':
   db.execute("UPDATE remote_connection_folders SET user_id='other',parent_id='' WHERE id='f2'")
   db.execute("UPDATE remote_connection_folders SET parent_id='f2' WHERE id='f0'")
  else:db.execute("UPDATE remote_connection_folders SET parent_id='absent' WHERE id='f0'")
 with pytest.raises(RemoteConnectionError):store.duplicate_folder('f0',user_id='owner')
 assert counts(store)==(3,1,3)

@pytest.mark.parametrize('hidden',['','folder','host'])
def test_deep_shared_policy_checks_each_descendant_once_and_rejects_private_leaves(hidden):
 from twn_toolkit.remote_connection_management import _check_shared_dependencies
 visits=[]
 class Folder(dict):
  def __getitem__(self,key):
   if key=='parent_id':visits.append(self['id'])
   return super().__getitem__(key)
 folders=[Folder(id=str(i),user_id='owner',parent_id=str(i-1) if i else '',credential_mode='inherit') for i in range(10000)]
 hosts=[{'id':'host','user_id':'owner','folder_id':'9999'}]
 class Store:
  def library_for_user(self,owner):return {'folders':folders,'hosts':hosts,'credentials':[]}
 visible={'folder':{f['id']:f for f in folders},'host':{'host':hosts[0]},'credential':{}}
 if hidden:visible[hidden].pop('9999' if hidden=='folder' else 'host')
 def check():_check_shared_dependencies(Store(),{'credential_mode':'none'},[('folder',folders[0]),('folder',folders[1])],visible,'owner')
 if hidden:
  with pytest.raises(RemoteConnectionError,match='private items'):check()
 else:check()
 assert len(visits)<=10002


def test_ten_thousand_item_copy_reserves_distinct_scoped_names_from_one_index(store):
 populate_metadata(store,1)
 with store._connect() as db:
  secret=db.execute("SELECT secret_encrypted FROM remote_connection_credentials WHERE id='c0'").fetchone()[0]
  db.execute('DELETE FROM remote_connection_hosts')
  db.executemany('INSERT INTO remote_connection_credentials (id,user_id,name,remote_username,secret_encrypted,scope_host_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)',
   [('c'+str(i),'owner','Login copy '+str(i),'api',secret,'h'+str(i),1,1) for i in range(1,10000)])
  db.executemany('INSERT INTO remote_connection_hosts (id,user_id,name,host,port,folder_id,credential_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
   [('h'+str(i),'owner','Host '+str(i),'192.0.2.1',22,'f0','c'+str(i),1,1) for i in range(1,10000)])
 store.duplicate_folder('f0',user_id='owner')
 assert counts(store)==(2,19998,19999)
 with store._connect() as db:
  assert db.execute('SELECT count(DISTINCT lower(name)) FROM remote_connection_credentials').fetchone()[0]==19999
  assert db.execute("SELECT count(*) FROM remote_connection_hosts h JOIN remote_connection_credentials c ON c.id=h.credential_id WHERE c.scope_host_id=h.id").fetchone()[0]==19998


@pytest.mark.parametrize('size,status',[(3,201),(10001,400)])
def test_folder_copy_http_returns_bounded_success_or_atomic_limit_error(tmp_path,size,status):
 from twn_toolkit import create_app
 app=create_app(str(tmp_path));app.testing=True
 try:
  store=app.extensions['remote_connection_store'];populate_metadata(store,size,owner='test-user',deep=True)
  response=app.test_client().post('/tools/remote-terminal/folders/f0/duplicate')
  assert response.status_code==status
  assert len(response.data)<250_000
  assert counts(store)==((size*2,2,size) if status==201 else (size,1,size))
  if status==400:assert '10,000' in response.json['error']
  else:assert response.json['library']['metadata_pagination']['folders_total']==6
 finally:app.extensions['remote_session_manager'].close()
