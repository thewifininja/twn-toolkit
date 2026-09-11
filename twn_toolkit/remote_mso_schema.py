"""Explicit wire schema and dependency checks for Remote Terminal objects."""
import uuid
from .remote_connections import RemoteConnectionStore


def validate(kind,payload):
    def text(key,limit=1000):
        value=payload.get(key)
        if not isinstance(value,str) or len(value)>limit:
            raise ValueError('Invalid shared terminal field: '+key)
        return value
    def identity(key,optional=False):
        value=text(key,100)
        if optional and not value:return value
        if str(uuid.UUID(value))!=value:raise ValueError('Invalid terminal reference identity.')
        return value
    name=identity('name');owner=identity('owner')
    title=RemoteConnectionStore._name(text('title',100),'Name')
    visibility=text('visibility',20)
    if visibility not in {'global','admins_only','inherit'} or kind=='terminal.credential' and visibility=='inherit':
        raise ValueError('Private terminal objects cannot be shared.')
    result={'name':name,'title':title,'owner':owner,'visibility':visibility}
    if kind=='terminal.credential':
        username=RemoteConnectionStore._username(text('username',255));password=text('password',4096)
        if not password:raise ValueError('A terminal credential requires a password.')
        return {**result,'username':username,'password':password,'scope_host_id':identity('scope_host_id',True)}
    mode=text('credential_mode',20)
    if mode not in {'inherit','credential','none'}:raise ValueError('Invalid credential inheritance mode.')
    credential=identity('credential_id',True)
    if (mode=='credential') != bool(credential):raise ValueError('Invalid terminal credential reference.')
    result.update(credential_mode=mode,credential_id=credential)
    if kind=='terminal.folder':
        parent=identity('parent_id',True)
        if not parent and visibility=='inherit':raise ValueError('A root folder must choose an explicit visibility.')
        if parent==name:raise ValueError('A folder cannot contain itself.')
        return {**result,'parent_id':parent}
    protocol=text('protocol',10)
    if protocol not in {'ssh','telnet'}:raise ValueError('Serial console definitions stay local.')
    port=payload.get('port')
    if type(port) is not int or not 1<=port<=65535:raise ValueError('Invalid terminal port.')
    for key in ('allow_unknown_hosts','allow_legacy_algorithms'):
        if type(payload.get(key)) is not bool:raise ValueError('Invalid SSH option.')
    return {**result,'host':RemoteConnectionStore._hostname(text('host',253)), 'port':port,'protocol':protocol,
            'folder_id':identity('folder_id',True),'notes':text('notes'),
            'allow_unknown_hosts':payload['allow_unknown_hosts'],'allow_legacy_algorithms':payload['allow_legacy_algorithms']}


def dependency_error(store,db,proposal,payload):
    from .remote_mso_bridge import REVERSE,_depends
    kind=proposal['kind']
    if kind not in REVERSE:return ''
    if proposal['deleted']:
        for row in db.execute("SELECT * FROM mso_hub WHERE kind LIKE 'terminal.%' AND deleted=0 AND id!=?",(proposal['id'],)):
            if row['kind']!='terminal.credential' and _depends(REVERSE[row['kind']],store._load(row['payload']),REVERSE[kind],proposal['id']):
                return 'Shared terminal objects still use this dependency.'
        return ''
    if payload['name']!=proposal['id']:return 'Terminal object identity cannot change.'
    keys={'terminal.folder':[('parent_id','terminal.folder'),('credential_id','terminal.credential')],
          'terminal.host':[('folder_id','terminal.folder'),('credential_id','terminal.credential')],
          'terminal.credential':[]}[kind]
    for key,ref_kind in keys:
        identifier=payload[key]
        if not identifier:continue
        row=db.execute('SELECT * FROM mso_hub WHERE id=? AND deleted=0',(identifier,)).fetchone()
        if not row or row['kind']!=ref_kind or store._load(row['payload'])['owner']!=payload['owner']:
            return 'Share the required folder or credential in the same owner library first.'
    if kind=='terminal.host' and payload['credential_id']:
        row=db.execute('SELECT payload FROM mso_hub WHERE id=?',(payload['credential_id'],)).fetchone()
        scoped=store._load(row['payload']).get('scope_host_id','')
        if scoped and scoped!=proposal['id']:return 'This credential is scoped to another host.'
    if kind=='terminal.folder':
        parent=payload['parent_id'];seen={proposal['id']}
        while parent:
            if parent in seen:return 'Shared folder moves cannot create a cycle.'
            seen.add(parent)
            row=db.execute("SELECT payload FROM mso_hub WHERE id=? AND kind='terminal.folder' AND deleted=0",(parent,)).fetchone()
            parent=store._load(row['payload'])['parent_id'] if row else ''
    return ''
