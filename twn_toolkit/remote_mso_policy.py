"""Remote Terminal sharing eligibility, without changing local visibility.

This preflight returns the required objects, including the entire ancestor path.
The replication adapter must consume it in the same transaction as publication.
It never reads a password or interprets usernames as cross-instance identities.
"""
from .remote_connections import RemoteConnectionError

COLLECTIONS = {'folder': 'folders', 'host': 'hosts', 'credential': 'credentials'}
SHARED_VISIBILITIES = {'global', 'admins_only'}


def sharing_dependencies(store, resource_type, resource_id, *, user_id, is_admin=False):
    """Return manageable, nonprivate dependencies; never include descendants."""
    if resource_type not in COLLECTIONS:
        raise RemoteConnectionError('Unknown Remote Terminal resource type.')
    with store.transaction():
        library = store.library_for_user(user_id, is_admin=is_admin)
        index = {kind: {item['id']: item for item in library[collection]}
                 for kind, collection in COLLECTIONS.items()}
        root = index[resource_type].get(resource_id)
        if not root or not root.get('can_manage'):
            raise RemoteConnectionError('Saved library item not found or not manageable.')
        owner = root['user_id']
        # Read the owner's complete ancestry after authorizing the requested item.
        # Filter each dependency independently; an admin grant cannot reveal a
        # private ancestor or credential merely because its child is shared.
        owner_library = store.library_for_user(owner)
        owned = {kind: {item['id']: item for item in owner_library[collection]}
                 for kind, collection in COLLECTIONS.items()}
        pending = [(resource_type, resource_id)]
        visited = set()
        result = []
        while pending:
            kind, identifier = pending.pop()
            if not identifier or (kind, identifier) in visited:
                continue
            visited.add((kind, identifier))
            item = owned[kind].get(identifier)
            visible = index[kind].get(identifier)
            if not item or item['user_id'] != owner or not visible or not visible.get('can_manage'):
                raise RemoteConnectionError('Sharing requires manageable folders and credentials in the same owner library. Private dependencies remain local.')
            visibility = item.get('effective_visibility', item.get('visibility'))
            if visibility not in SHARED_VISIBILITIES:
                raise RemoteConnectionError('Private terminal objects stay local. Choose Global or Admins Only before enabling MSO, including for required folders and credentials.')
            if kind == 'host' and item.get('protocol') not in {'ssh', 'telnet'}:
                raise RemoteConnectionError('Serial console definitions stay local to their hardware.')
            # Public metadata only: the publisher resolves credentials separately.
            result.append({'kind': kind, 'id': identifier, 'visibility': visibility})
            if len(result) > 5000:
                raise RemoteConnectionError('Too many Remote Terminal sharing dependencies.')
            if kind == 'folder':
                pending.append(('folder', item.get('parent_id', '')))
            elif kind == 'host':
                pending.append(('folder', item.get('folder_id', '')))
            else:
                pending.append(('host', item.get('scope_host_id', '')))
            if kind in {'folder', 'host'}:
                pending.append(('credential', item.get('effective_credential_id', '')))
        return result
