"""Durable Remote Terminal publication links and idempotent local projections."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from contextlib import contextmanager

from .remote_mso_policy import sharing_dependencies, COLLECTIONS
from .remote_connections import RemoteConnectionError, RemoteConnectionStore
from .file_transactions import file_transaction

KINDS = {key: 'terminal.' + key for key in COLLECTIONS}
REVERSE = {value: key for key, value in KINDS.items()}


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS remote_mso_links (
        resource_type TEXT NOT NULL, native_id TEXT NOT NULL, mso_id TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1, fingerprint TEXT NOT NULL DEFAULT '',
        version INTEGER NOT NULL DEFAULT 0, owner TEXT NOT NULL,
        PRIMARY KEY(resource_type,native_id))''')
    if 'edit_version' not in {r['name'] for r in db.execute('PRAGMA table_info(remote_mso_links)')}:
        db.execute('ALTER TABLE remote_mso_links ADD COLUMN edit_version INTEGER NOT NULL DEFAULT 1')


def digest(payload):
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _native(db, kind, identifier):
    return db.execute(f'SELECT * FROM remote_connection_{COLLECTIONS[kind]} WHERE id=?', (identifier,)).fetchone()


def _reference(db, kind, identifier):
    if not identifier:
        return ''
    row = db.execute('SELECT mso_id FROM remote_mso_links WHERE resource_type=? AND native_id=? AND enabled=1',(kind,identifier)).fetchone()
    if not row:
        raise RemoteConnectionError('Share the required folder or credential before sharing this object.')
    return row['mso_id']


def capture(store, db, link, *, withdrawn=None):
    kind = link['resource_type']
    native = _native(db,kind,link['native_id'])
    if not native:
        return None
    row = dict(native)
    value = {'name':link['mso_id'],'title':row['name'],'owner':link['owner'],
             'visibility':row['visibility']}
    if kind == 'folder':
        value.update(parent_id=_reference(db,'folder',row['parent_id']),
                     credential_mode=row['credential_mode'], credential_id=_reference(db,'credential',row['credential_id']))
    elif kind == 'credential':
        value.update(username=row['remote_username'],password=store._cipher.decrypt(row['secret_encrypted'].encode()).decode(),
                     scope_host_id=(withdrawn.get('scope_host_id','') if withdrawn is not None else _reference(db,'host',row['scope_host_id'])))
    else:
        value.update({key:row[key] for key in ('host','port','protocol','credential_mode','notes')})
        value.update(folder_id=_reference(db,'folder',row['folder_id']),credential_id=_reference(db,'credential',row['credential_id']),
                     allow_unknown_hosts=bool(row['allow_unknown_hosts']),allow_legacy_algorithms=bool(row['allow_legacy_algorithms']))
    return value


def set_sharing(store, kind, identifier, enabled, *, user_id, is_admin=False):
    from .distributed_agents import DistributedSettingsStore, DistributedIdentityStore
    if type(enabled) is not bool:
        raise RemoteConnectionError('MSO must be on or off.')
    if enabled and DistributedSettingsStore(store.instance_path).get()['role']=='standalone':
        raise RemoteConnectionError('Connect to a Mainframe before enabling MSO.')
    with store.transaction(), store._connect() as db:
        initialize(db)
        if not enabled:
            library=store.library_for_user(user_id,is_admin=is_admin)
            target=next((p for p in library[COLLECTIONS[kind]] if p['id']==identifier and p['can_manage']),None)
            if not target:
                raise RemoteConnectionError('Saved library item not found or not manageable.')
            for row in db.execute('SELECT * FROM remote_mso_links WHERE enabled=1').fetchall():
                if row['resource_type']==kind and row['native_id']==identifier:
                    continue
                native=_native(db,row['resource_type'],row['native_id'])
                if native and kind=='host' and row['resource_type']=='credential' and native['scope_host_id']==identifier:
                    db.execute('UPDATE remote_mso_links SET enabled=0 WHERE mso_id=?',(row['mso_id'],))
                    continue
                if native and _depends(row['resource_type'],dict(native),kind,identifier):
                    raise RemoteConnectionError('Shared terminal objects still use this dependency. Reassign them or turn off their MSO first.')
            db.execute('UPDATE remote_mso_links SET enabled=0 WHERE resource_type=? AND native_id=?',(kind,identifier))
            return
        dependencies=sharing_dependencies(store,kind,identifier,user_id=user_id,is_admin=is_admin)
        node=DistributedIdentityStore(store.instance_path).load_or_create()['device_id']
        for item in dependencies:
            native=_native(db,item['kind'],item['id'])
            owner=native['user_id'][4:] if native['user_id'].startswith('mso:') else str(uuid.uuid5(uuid.NAMESPACE_URL,node+':'+native['user_id']))
            old=db.execute('SELECT * FROM remote_mso_links WHERE resource_type=? AND native_id=?',(item['kind'],item['id'])).fetchone()
            if old and not old['enabled']:
                raise RemoteConnectionError('Wait for the previous MSO withdrawal to sync before sharing again.')
            db.execute('INSERT OR IGNORE INTO remote_mso_links(resource_type,native_id,mso_id,owner) VALUES (?,?,?,?)',
                       (item['kind'],item['id'],str(uuid.uuid4()),owner))


def _depends(kind, payload, target_kind, target_id):
    keys = {'folder': [('parent_id','folder'),('credential_id','credential')],
            'host':[('folder_id','folder'),('credential_id','credential')],
            'credential':[('scope_host_id','host')]}[kind]
    return any(ref_kind==target_kind and payload.get(key)==target_id for key,ref_kind in keys)


def metadata(store, library):
    with store._connect() as db:
        initialize(db)
        links={(r['resource_type'],r['native_id']):r for r in db.execute('SELECT * FROM remote_mso_links')}
    states={}
    path=store.instance_path/'mso.sqlite3'
    if path.exists():
        with sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro',uri=True) as source:
            states={row[0]:{'conflict':bool(row[1]),'pending':bool(row[2])} for row in source.execute("SELECT id,conflict!='',dirty FROM mso_objects WHERE kind LIKE 'terminal.%'")}
    for kind,collection in COLLECTIONS.items():
        for item in library[collection]:
            link=links.get((kind,item['id']))
            item['mso']={'enabled':bool(link and link['enabled']), 'version':link['edit_version'] if link else 0,
                         'id':link['mso_id'] if link else '', **(states.get(link['mso_id'],{}) if link else {})}
    library['mso_revision']=digest(sorted((r['mso_id'],r['edit_version'],r['enabled']) for r in links.values()))
    return library


def validate_changes(store, before, revision, expected_revision):
    """Run inside the native mutation transaction; reject stale and private edits."""
    with store._connect() as db:
        initialize(db)
        for link in db.execute('SELECT * FROM remote_mso_links WHERE enabled=1').fetchall():
            key=(link['resource_type'],link['native_id'])
            if key not in before:
                continue
            old=before[key]
            native=_native(db,link['resource_type'],link['native_id'])
            if old == (dict(native) if native else None):
                continue
            require_usable(store,link['resource_type'],link['native_id'],action='editing')
            if revision != expected_revision:
                raise RemoteConnectionError('This shared terminal object changed. Reload the library before editing it.')
            db.execute('UPDATE remote_mso_links SET edit_version=edit_version+1 WHERE mso_id=?',(link['mso_id'],))
            if native:
                sharing_dependencies(store,link['resource_type'],link['native_id'],user_id=native['user_id'])
        # A changed ancestor can change the effective visibility of unchanged children.
        for link in db.execute('SELECT * FROM remote_mso_links WHERE enabled=1').fetchall():
            native=_native(db,link['resource_type'],link['native_id'])
            if native:
                set_sharing(store,link['resource_type'],link['native_id'],True,user_id=native['user_id'])


def before_mutation(store):
    with store._connect() as db:
        initialize(db)
        return {(row['resource_type'],row['native_id']):dict(native) if (native:=_native(db,row['resource_type'],row['native_id'])) else None
                for row in db.execute('SELECT * FROM remote_mso_links WHERE enabled=1').fetchall()}


def _store(instance):
    from .auth import load_or_create_secret_key
    return RemoteConnectionStore(str(instance),load_or_create_secret_key(str(instance)))


def sync_local(instance):
    """Publish changed native objects. Fingerprints make interrupted retries safe."""
    from .mso import MsoStore
    from .distributed_agents import DistributedSettingsStore
    instance=Path(instance)
    if not (instance/'remote_connections.sqlite3').exists() or DistributedSettingsStore(instance).get()['role']=='standalone':
        return
    with file_transaction(instance/'distributed_settings.json'):
        store=_store(instance)
        with store.transaction(),store._connect() as db:
            initialize(db)
            links=db.execute('SELECT * FROM remote_mso_links').fetchall()
            # Credentials first; parents before child folders; hosts last.
            def rank(link):
                native=_native(db,link['resource_type'],link['native_id'])
                if not link['enabled'] or not native:
                    return (3, {'host':0,'folder':1,'credential':2}[link['resource_type']],link['native_id'])
                depth=0;seen=set();parent=native['parent_id'] if link['resource_type']=='folder' else ''
                while parent and parent not in seen:
                    seen.add(parent);depth+=1;p=_native(db,'folder',parent);parent=p['parent_id'] if p else ''
                return ({'credential':0,'folder':1,'host':2}[link['resource_type']],depth,link['native_id'])
            for link in sorted(links,key=rank):
                mso=MsoStore(instance,KINDS[link['resource_type']])
                current=mso.profile(link['mso_id'])
                native=_native(db,link['resource_type'],link['native_id'])
                if not link['enabled'] or not native:
                    if current:
                        mso.delete(current['name'])
                    with mso._tx() as tx:
                        withdrawal=tx.execute('SELECT deleted,dirty,conflict FROM mso_objects WHERE id=?',(link['mso_id'],)).fetchone()
                    if not withdrawal or (withdrawal['deleted'] and not withdrawal['dirty'] and not withdrawal['conflict']):
                        db.execute('DELETE FROM remote_mso_links WHERE mso_id=?',(link['mso_id'],))
                    continue
                if not current:
                    with mso._tx() as tx:
                        tombstone=tx.execute('SELECT deleted FROM mso_objects WHERE id=?',(link['mso_id'],)).fetchone()
                    if tombstone and tombstone['deleted']:
                        continue  # Project the acknowledged withdrawal before publishing.
                payload=capture(store,db,link);fingerprint=digest(payload)
                if current and current['mso']['conflict']:
                    continue
                if current and digest({k:v for k,v in current.items() if k!='mso'})==fingerprint:
                    db.execute('UPDATE remote_mso_links SET fingerprint=?,version=? WHERE mso_id=?',(fingerprint,current['mso']['version'],link['mso_id']))
                    continue
                if fingerprint==link['fingerprint']:
                    continue  # Incoming changes are projected after the exchange.
                if not current and link['version']:
                    with mso._tx() as tx:
                        previous=tx.execute('SELECT deleted FROM mso_objects WHERE id=?',(link['mso_id'],)).fetchone()
                    if not previous:
                        db.execute('DELETE FROM remote_mso_links WHERE mso_id=?',(link['mso_id'],))
                    continue
                if not current:
                    with mso._tx() as tx:
                        tx.execute('INSERT OR IGNORE INTO mso_objects(id,kind,payload,origin) VALUES (?,?,?,?)',
                                   (link['mso_id'],mso.kind,mso._dump(payload),mso.node))
                    saved=mso.save(payload,enabled=True)
                elif current['mso']['version']!=link['version'] and digest({k:v for k,v in current.items() if k!='mso'})!=link['fingerprint']:
                    with mso._tx() as tx:
                        row=tx.execute('SELECT * FROM mso_objects WHERE id=?',(link['mso_id'],)).fetchone()
                        remote={'id':row['id'],'kind':row['kind'],'payload':mso._load(row['payload']),
                                'revision':row['revision'],'deleted':False,'origin':row['origin']}
                        tx.execute('UPDATE mso_objects SET payload=?,conflict=?,dirty=1,version=version+1 WHERE id=?',
                                   (mso._dump(payload),mso._dump({'remote':remote,'error':'The terminal object changed while local edits were pending.'}),row['id']))
                    saved=mso.profile(link['mso_id'])
                else:
                    saved=mso.save(payload,enabled=True,expected=current['mso']['version'])
                db.execute('UPDATE remote_mso_links SET fingerprint=?,version=? WHERE mso_id=?',(fingerprint,saved['mso']['version'],link['mso_id']))


def project(instance):
    """Apply complete dependencies only, preserving edits not yet published."""
    from .mso import MsoStore
    import time
    instance=Path(instance)
    from .distributed_agents import DistributedSettingsStore
    if not (instance/'remote_connections.sqlite3').exists() or DistributedSettingsStore(instance).get()['role']=='standalone':
        return
    with file_transaction(instance/'distributed_settings.json'):
        mso=MsoStore(instance)
        with mso._tx() as tx:
            rows=[dict(row) for row in tx.execute("SELECT * FROM mso_objects WHERE kind LIKE 'terminal.%'")]
            for row in rows:
                row['payload']=mso._load(row['payload'])
        by_id={row['id']:row for row in rows}
        store=_store(instance)
        with store.transaction(),store._connect() as db:
            initialize(db)
            for _ in range(min(len(rows),32)+1):
                progressed=False
                for row in rows:
                    if row['conflict'] or row['dirty']:
                        continue
                    kind=REVERSE[row['kind']];payload=row['payload']
                    link=db.execute('SELECT * FROM remote_mso_links WHERE mso_id=?',(row['id'],)).fetchone()
                    native=_native(db,kind,link['native_id']) if link else None
                    if link and not link['enabled']:
                        if not row['deleted'] and row['version']>link['version']:
                            db.execute('UPDATE remote_mso_links SET enabled=1 WHERE mso_id=?',(row['id'],))
                            link=db.execute('SELECT * FROM remote_mso_links WHERE mso_id=?',(row['id'],)).fetchone()
                        else:
                            continue
                    if link and native:
                        try:
                            if digest(capture(store,db,link,withdrawn=payload if row['deleted'] else None))!=link['fingerprint']:
                                continue
                        except RemoteConnectionError:
                            continue
                    if row['deleted']:
                        if not link:
                            continue
                        dependents=[(k,dict(p)) for k in COLLECTIONS for p in db.execute(f'SELECT * FROM remote_connection_{COLLECTIONS[k]}')
                                    if not (kind=='host' and k=='credential') and _depends(k,dict(p),kind,link['native_id'])]
                        if any(db.execute('SELECT 1 FROM remote_mso_links WHERE resource_type=? AND native_id=? AND enabled=1',(k,p['id'])).fetchone() for k,p in dependents):
                            continue
                        if not dependents:
                            db.execute(f'DELETE FROM remote_connection_{COLLECTIONS[kind]} WHERE id=?',(link['native_id'],))
                        db.execute('DELETE FROM remote_mso_links WHERE mso_id=?',(row['id'],));progressed=True
                        continue
                    if not row['enabled']:
                        continue
                    dependencies={'folder':[('parent_id','folder'),('credential_id','credential')],
                                  'host':[('folder_id','folder'),('credential_id','credential')],
                                  'credential':[]}[kind]
                    refs={};ready=True
                    for key,ref_kind in dependencies:
                        identifier=payload.get(key,'')
                        if not identifier:
                            refs[key]='';continue
                        dependency=by_id.get(identifier)
                        target=db.execute('SELECT native_id FROM remote_mso_links WHERE mso_id=? AND enabled=1',(identifier,)).fetchone()
                        if not dependency or dependency['deleted'] or dependency['conflict'] or not target or not _native(db,ref_kind,target['native_id']):
                            ready=False;break
                        refs[key]=target['native_id']
                    if not ready:
                        continue
                    native_id=link['native_id'] if link else row['id']
                    owner=native['user_id'] if native else 'mso:'+payload['owner']
                    if not native:
                        for related in db.execute('SELECT * FROM remote_mso_links WHERE owner=?',(payload['owner'],)).fetchall():
                            owned=_native(db,related['resource_type'],related['native_id'])
                            if owned:
                                owner=owned['user_id']
                                if not owner.startswith('mso:'):break
                    values={'id':native_id,'user_id':owner,'name':payload['title'],'visibility':payload['visibility'],
                            'created_at':native['created_at'] if native else time.time(),'updated_at':time.time()}
                    if kind=='credential':
                        scope=payload.get('scope_host_id','')
                        target=db.execute('SELECT native_id FROM remote_mso_links WHERE mso_id=?',(scope,)).fetchone() if scope else None
                        values.update(remote_username=payload['username'],secret_encrypted=store._encrypt_secret(payload['password']),scope_host_id=target['native_id'] if target else scope)
                    elif kind=='folder':
                        values.update(refs,credential_mode=payload['credential_mode'])
                    else:
                        values.update(refs,**{key:payload[key] for key in ('host','port','protocol','credential_mode','notes','allow_unknown_hosts','allow_legacy_algorithms')})
                    if link and link['version']==row['version'] and link['fingerprint']==digest(payload):
                        continue
                    columns=','.join(values);marks=','.join('?' for _ in values)
                    updates=','.join(f'{key}=excluded.{key}' for key in values if key!='id')
                    db.execute(f'INSERT INTO remote_connection_{COLLECTIONS[kind]}({columns}) VALUES ({marks}) ON CONFLICT(id) DO UPDATE SET {updates}',tuple(values.values()))
                    db.execute('INSERT INTO remote_mso_links(resource_type,native_id,mso_id,owner,fingerprint,version) VALUES (?,?,?,?,?,?) ON CONFLICT(mso_id) DO UPDATE SET fingerprint=excluded.fingerprint,version=excluded.version,edit_version=remote_mso_links.edit_version+1',
                               (kind,native_id,row['id'],payload['owner'],digest(payload),row['version']))
                    progressed=True
                if not progressed:
                    break


def synchronize_before(method):
    from functools import wraps
    @wraps(method)
    def run(store,*args,**kwargs):
        sync_local(store.instance)
        result=method(store,*args,**kwargs)
        project(store.instance)
        return result
    return run


def synchronize_after(method):
    from functools import wraps
    @wraps(method)
    def run(store,*args,**kwargs):
        result=method(store,*args,**kwargs)
        project(store.instance)
        return result
    return run


def require_local_library(store):
    with store._connect() as db:
        initialize(db)
        if db.execute('SELECT 1 FROM remote_mso_links LIMIT 1').fetchone():
            raise RemoteConnectionError('Withdraw Remote Terminal MSOs and let their removals sync before replacing or clearing this library.')


def creation_owner(store, user_id, is_admin, *, folder_id='', credential_id=''):
    if not is_admin or not (folder_id or credential_id):
        return user_id
    with store._connect() as db:
        initialize(db)
        owners=set()
        for kind,identifier in [('folder',folder_id),('credential',credential_id)]:
            if not identifier:continue
            native=_native(db,kind,identifier)
            if not native:raise RemoteConnectionError('Saved dependency not found.')
            if native['user_id']!=user_id:
                link=db.execute('SELECT 1 FROM remote_mso_links WHERE resource_type=? AND native_id=? AND enabled=1',(kind,identifier)).fetchone()
                visible=store.library_for_user(user_id,is_admin=True)
                if not link or not any(p['id']==identifier and p['can_manage'] for p in visible[COLLECTIONS[kind]]):
                    raise RemoteConnectionError('Choose a dependency in your own library or a manageable MSO library.')
            owners.add(native['user_id'])
        if len(owners)>1:raise RemoteConnectionError('Choose folders and credentials from the same owner library.')
        return next(iter(owners),user_id)


def require_usable(store, kind, identifier, *, action="connecting"):
    """Check shared dependencies before opening a connection or decrypting a secret."""
    from .distributed_agents import DistributedSettingsStore
    if DistributedSettingsStore(store.instance_path).get()['role']=='standalone':
        return
    path=store.instance_path/'mso.sqlite3'
    if not path.exists():
        return
    with store._connect() as db, sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro',uri=True) as mso:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='remote_mso_links'").fetchone():
            return  # Portable export snapshots intentionally omit publication state.
        pending=[(kind,identifier)];seen=set()
        while pending:
            current,identifier=pending.pop()
            if not identifier or (current,identifier) in seen:
                continue
            seen.add((current,identifier))
            native=_native(db,current,identifier)
            link=db.execute('SELECT * FROM remote_mso_links WHERE resource_type=? AND native_id=? AND enabled=1',(current,identifier)).fetchone()
            if link:
                row=mso.execute('SELECT deleted,conflict FROM mso_objects WHERE id=?',(link['mso_id'],)).fetchone()
                if row and (row[0] or row[1]):
                    raise RemoteConnectionError('Resolve the MSO conflict or finish synchronizing this terminal object before '+action+'.')
            if not native:
                continue
            if current=='host':pending.append(('folder',native['folder_id']))
            if current=='folder':pending.append(('folder',native['parent_id']))
            if current in {'host','folder'}:pending.append(('credential',native['credential_id']))


@contextmanager
def detaching_library(instance):
    """Keep native data while discarding publication links with the role change."""
    if not (Path(instance)/'remote_connections.sqlite3').exists():
        yield
        return
    store=_store(instance)
    with store.transaction(), store._connect() as db:
        db.execute('DELETE FROM remote_mso_links')
        yield
