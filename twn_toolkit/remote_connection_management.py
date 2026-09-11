"""Actor authorization around owner-scoped Remote Terminal persistence.

A management grant does not transfer ownership. Related objects must remain
within that owner's library and private dependencies cannot be edited indirectly.
"""
from __future__ import annotations

from functools import wraps
from inspect import signature


_COLLECTIONS = {"folder": "folders", "host": "hosts", "credential": "credentials"}


def managed_mutation(resource_type, identifier):
    def decorate(method):
        parameters = signature(method)

        @wraps(method)
        def authorized(store, *args, is_admin=False, **kwargs):
            from .remote_connections import RemoteConnectionError

            bound = parameters.bind(store, *args, **kwargs)
            bound.apply_defaults()
            values = bound.arguments
            actor_id = values["user_id"]
            kind = values["resource_type"] if resource_type == "dynamic" else resource_type
            targets = ([("host", key) for key in values["host_ids"]]
                       + [("folder", key) for key in values["folder_ids"]]) if kind == "bulk" else [(kind, values[identifier])]
            targets = [(kind, key) for kind, key in targets if key]
            with store.transaction():
                if targets:
                    with store._connect() as connection:
                        owner_rows = [connection.execute(
                            f"SELECT user_id FROM remote_connection_{_COLLECTIONS[target_kind]} WHERE id = ?",
                            (key,),
                        ).fetchone() for target_kind, key in targets if target_kind in _COLLECTIONS]
                    if len(owner_rows) != len(targets) or any(row is None for row in owner_rows):
                        raise RemoteConnectionError("Saved library item not found or not manageable.")
                    if all(row["user_id"] == actor_id for row in owner_rows):
                        return method(*bound.args, **bound.kwargs)
                    if not is_admin:
                        raise RemoteConnectionError("Saved library item not found or not manageable.")
                    visible = store.library_for_user(actor_id, is_admin=is_admin)
                    index = {kind: {item["id"]: item for item in visible[collection]}
                             for kind, collection in _COLLECTIONS.items()}
                    items = []
                    for target_kind, key in targets:
                        item = index.get(target_kind, {}).get(key)
                        if not item or not item["can_manage"]:
                            raise RemoteConnectionError("Saved library item not found or not manageable.")
                        items.append((target_kind, item))
                    owners = {item["user_id"] for _, item in items}
                    if len(owners) != 1:
                        raise RemoteConnectionError("Edit items from one owner's library at a time. Ownership is not transferred by a bulk edit.")
                    owner_id = owners.pop()
                    if owner_id != actor_id:
                        _check_shared_dependencies(store, values, items, index, owner_id)
                    values["user_id"] = owner_id
                if not targets and method.__name__ == 'save_host':
                    from .remote_mso_bridge import creation_owner
                    values['user_id'] = creation_owner(store, actor_id, is_admin,
                        folder_id=values.get('folder_id',''), credential_id=values.get('credential_id',''))
                result = method(*bound.args, **bound.kwargs)
                if values["user_id"] != actor_id and method.__name__ == "save_host":
                    scoped_id = result.get("credential_id")
                    if scoped_id and result.get("credential_scope_host_id") == result["id"] and (not targets or scoped_id not in index["credential"]):
                        # A newly supplied host-specific secret follows its shared host.
                        # Existing private credentials were rejected before mutation.
                        with store._connect() as connection:
                            connection.execute("UPDATE remote_connection_credentials SET visibility = ? WHERE id = ?",
                                               (result["effective_visibility"], scoped_id))
                return result

        return authorized
    return decorate


def _check_shared_dependencies(store, values, items, visible, owner_id):
    from .remote_connections import RemoteConnectionError

    if values.get("visibility") == "private":
        raise RemoteConnectionError("Only the owner can make a shared item private.")

    owned = store.library_for_user(owner_id)
    owner_index = {kind: {item["id"]: item for item in owned[collection]}
                   for kind, collection in _COLLECTIONS.items()}

    def require_visible(kind, key):
        if key and (key not in visible[kind] or visible[kind][key]["user_id"] != owner_id):
            raise RemoteConnectionError("This change requires a manageable item in the same owner's library; private items remain protected.")

    for name, kind in [("parent_id", "folder"), ("folder_id", "folder"),
                       ("destination_id", "folder"), ("credential_id", "credential"),
                       ("scope_host_id", "host")]:
        # credential_id/host_id can identify the item itself, which is already checked.
        require_visible(kind, values.get(name))

    children = {}
    hosts_by_folder = {}
    checked_folders = set()
    for folder in owned["folders"]:
        children.setdefault(folder["parent_id"], []).append(folder["id"])
    for host in owned["hosts"]:
        hosts_by_folder.setdefault(host["folder_id"], []).append(host["id"])

    for kind, public in items:
        item = owner_index[kind][public["id"]]
        if kind in {"host", "folder"}:
            require_visible("credential", item.get("effective_credential_id"))
            require_visible("folder", item.get("folder_id" if kind == "host" else "parent_id"))
        if kind == "host":
            # Replacing a host-specific credential also deletes its old record.
            require_visible("credential", item.get("credential_id"))
        if kind == "credential":
            require_visible("host", item.get("scope_host_id"))
            for dependent_kind in ("host", "folder"):
                for dependent in owner_index[dependent_kind].values():
                    if item["id"] in {dependent.get("credential_id"), dependent.get("effective_credential_id")}:
                        require_visible(dependent_kind, dependent["id"])
        if kind == "folder":
            policy_change = any(
                name in values and values[name] is not None and values[name] != item.get(name)
                for name in ("parent_id", "credential_mode", "visibility")
            ) or values.get("destination_id") is not None or (
                values.get("credential_mode") == "credential" and values.get("credential_id") != item.get("credential_id")
            )
            if policy_change:
                pending = [item["id"]]
                while pending:
                    folder_id = pending.pop()
                    if folder_id in checked_folders:
                        continue
                    checked_folders.add(folder_id)
                    require_visible("folder", folder_id)
                    for host_id in hosts_by_folder.get(folder_id, []):
                        require_visible("host", host_id)
                    pending.extend(children.get(folder_id, []))
