"""Stable SNMP references and fleet dependency invariants."""
CREDENTIAL = 'snmp.credentials'
HOST = 'snmp.hosts'
ORDER = "CASE WHEN kind='snmp.credentials' AND deleted=0 THEN 0 WHEN kind='snmp.credentials' THEN 2 ELSE 1 END,rowid"


def prepare_host(store, db, payload, active):
    from .mso import MsoConflict, validate
    store._migrate(db, CREDENTIAL)
    payload = dict(payload)
    identifier = payload.get('credential_id')
    if not identifier:
        credential = next((r for r in db.execute("SELECT * FROM mso_objects WHERE kind=? AND deleted=0", (CREDENTIAL,))
                           if store._load(r['payload'])['name'] == payload.get('credential_name')), None)
    else:
        credential = db.execute("SELECT * FROM mso_objects WHERE id=? AND kind=? AND deleted=0", (identifier, CREDENTIAL)).fetchone()
    if not credential:
        if active:
            raise ValueError('Select an available SNMP credential before sharing this host.')
        return payload
    if active:
        if credential['conflict']:
            raise MsoConflict('Resolve the selected credential conflict before sharing this host.')
        validate(CREDENTIAL, store._load(credential['payload']))
        if not credential['enabled']:
            db.execute('UPDATE mso_objects SET enabled=1,dirty=1,version=version+1 WHERE id=?', (credential['id'],))
    payload['credential_id'] = credential['id']
    payload.pop('credential_name', None)
    return payload


def project_host(store, db, payload):
    payload = dict(payload)
    identifier = payload.pop('credential_id', '')
    if identifier:
        from .backup_source_reads import current_source_budget, source_json_loads, SourceReadLimit
        credential = db.execute("SELECT length(CAST(payload AS BLOB)) AS size,conflict FROM mso_objects WHERE id=? AND kind=? AND deleted=0", (identifier, CREDENTIAL)).fetchone()
        payload['credential_name'] = ''
        if credential and not credential['conflict']:
            budget = current_source_budget()
            if budget is not None:
                if credential['size'] > budget[0]:
                    raise SourceReadLimit('Selected SNMP credential reference exceeds the read limit. Export fewer groups.')
                budget[0] -= credential['size']
            # Resolve the public name without decrypting secret fields for a host export.
            raw = db.execute('SELECT payload FROM mso_objects WHERE id=?', (identifier,)).fetchone()[0]
            payload['credential_name'] = source_json_loads(raw)['name']
        # Never bind by a received display name, including during partial delivery.
    return payload


def has_references(store, db, identifier, *, shared_only=False, hub=False):
    table = 'mso_hub' if hub else 'mso_objects'
    condition = ' AND enabled=1' if shared_only and not hub else ''
    return any(store._load(r['payload']).get('credential_id') == identifier
               for r in db.execute(f'SELECT payload FROM {table} WHERE kind=? AND deleted=0{condition}', (HOST,)))


def remap_references(store, db, identities):
    for row in db.execute('SELECT id,payload FROM mso_objects WHERE kind=? AND deleted=0', (HOST,)).fetchall():
        payload = store._load(row['payload'])
        reference = payload.get('credential_id')
        if reference in identities:
            payload['credential_id'] = identities[reference]
            db.execute('UPDATE mso_objects SET payload=?,version=version+1 WHERE id=?', (store._dump(payload), row['id']))


def hub_dependency_error(store, db, proposal, payload):
    if proposal['kind'] == HOST and not proposal['deleted']:
        credential = db.execute('SELECT kind,deleted FROM mso_hub WHERE id=?', (payload['credential_id'],)).fetchone()
        if not credential or credential['kind'] != CREDENTIAL or credential['deleted']:
            return 'The referenced credential must be shared before this host.'
    if proposal['kind'] == CREDENTIAL and proposal['deleted'] and has_references(store, db, proposal['id'], hub=True):
        return 'Shared hosts still use this credential. Reassign them or turn off their MSO first.'
    return ''


def credential_ids(store, db):
    return {store._load(row['payload'])['name']: row['id'] for row in db.execute('SELECT id,payload FROM mso_objects WHERE kind=? AND deleted=0', (CREDENTIAL,))}


def remap_replaced_credentials(store, db, previous):
    current = credential_ids(store, db)
    remap_references(store, db, {identifier: current[name] for name, identifier in previous.items() if name in current})
