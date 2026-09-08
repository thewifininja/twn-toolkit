from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Iterator

from cryptography.fernet import Fernet, InvalidToken

from .remote_connection_management import managed_mutation
from .duplication import DuplicateNameIndex, duplicate_name
from .serial_console import serial_settings


class RemoteConnectionError(ValueError):
    pass


_transactions: ContextVar[dict[str, sqlite3.Connection]] = ContextVar("remote_library_transactions", default={})


VISIBILITY_VALUES = {"global", "admins_only", "private"}
VISIBILITY_MODES = VISIBILITY_VALUES | {"inherit"}


class RemoteConnectionStore:
    """Per-operator folders, remote hosts, and encrypted credential records."""

    def __init__(self, instance_path: str, secret_key: str) -> None:
        self.instance_path = Path(instance_path)
        self.instance_path.mkdir(parents=True, exist_ok=True)
        self.path = self.instance_path / "remote_connections.sqlite3"
        encryption_key = base64.urlsafe_b64encode(
            hashlib.sha256(
                f"twn-remote-connections-v1:{secret_key}".encode("utf-8")
            ).digest()
        )
        self._cipher = Fernet(encryption_key)
        with self._connect():
            pass
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def library_for_user(
        self, user_id: str, *, is_admin: bool = False,
        host_page: int | None = None, host_query: str = "",
        metadata_page: int | None = None, metadata_query: str = "", metadata_credential_id: str = "",
    ) -> dict[str, Any]:
        if metadata_page is not None and host_page is None:
            host_page = 1
        with self._connect() as connection:
            folders = connection.execute(
                "SELECT * FROM remote_connection_folders ORDER BY name COLLATE NOCASE"
            ).fetchall()
            credentials = connection.execute(
                """
                SELECT c.*, COALESCE(host_counts.usage_count, 0) AS usage_count,
                       COALESCE(folder_counts.usage_count, 0) AS folder_usage_count,
                       COALESCE(scoped.name, '') AS scoped_host_name
                FROM remote_connection_credentials c
                LEFT JOIN (
                    SELECT user_id, credential_id, COUNT(*) AS usage_count
                    FROM remote_connection_hosts WHERE credential_id != ''
                    GROUP BY user_id, credential_id
                ) host_counts ON host_counts.user_id=c.user_id AND host_counts.credential_id=c.id
                LEFT JOIN (
                    SELECT user_id, credential_id, COUNT(*) AS usage_count
                    FROM remote_connection_folders WHERE credential_id != ''
                    GROUP BY user_id, credential_id
                ) folder_counts ON folder_counts.user_id=c.user_id AND folder_counts.credential_id=c.id
                LEFT JOIN remote_connection_hosts scoped
                  ON scoped.id = c.scope_host_id AND scoped.user_id = c.user_id
                WHERE c.user_id=? OR c.visibility='global' OR (c.visibility='admins_only' AND ?)
                ORDER BY c.name COLLATE NOCASE
                """, (user_id, int(is_admin))
            ).fetchall()
            folder_items = [self._folder(row) for row in folders]
            credential_items = [self._public_credential(row) for row in credentials]
            self._annotate_effective_visibility(folder_items, [])
            visible_credentials = [item for item in credential_items if self._visibility_allows(
                item, user_id=user_id, is_admin=is_admin)]
            self._annotate_effective_credentials(folder_items, [], visible_credentials)
            folder_map = {item["id"]: item for item in folder_items}
            credential_map = {item["id"]: item for item in visible_credentials}

            def visible(owner, visibility, folder_id):
                parent = folder_map.get(folder_id, {})
                effective = (parent.get("effective_visibility", "admins_only")
                             if parent.get("user_id") == owner else "admins_only")
                return self._visibility_allows(
                    {"user_id": owner, "visibility": effective if visibility == "inherit" else visibility},
                    user_id=user_id, is_admin=is_admin)

            query = str(host_query).strip()[:200].casefold()

            def matches(name, protocol, address, label, path, notes, mode, credential_id, folder_id):
                folder = folder_map.get(folder_id, {})
                credential = credential_map.get(credential_id, {}) if mode == "credential" else {}
                inherited = folder if mode == "inherit" else {}
                folder_visible = self._visibility_allows(folder, user_id=user_id, is_admin=is_admin)
                source = folder_map.get(inherited.get("credential_source_folder_id"), {})
                source_name = inherited.get("credential_source_folder_name") if self._visibility_allows(source, user_id=user_id, is_admin=is_admin) else "Shared policy"
                text = " ".join(str(value or "") for value in (
                    name, protocol, address, label, path, notes,
                    credential.get("username"), credential.get("name"),
                    inherited.get("effective_remote_username"), inherited.get("effective_credential_name"),
                    source_name if mode == "inherit" else "", folder.get("name") if folder_visible else ""))
                return query in text.casefold()

            sql = """
                SELECT h.*, c.name AS credential_name,
                       c.remote_username AS remote_username,
                       c.scope_host_id AS credential_scope_host_id
                FROM remote_connection_hosts h
                LEFT JOIN remote_connection_credentials c
                  ON c.id = h.credential_id AND c.user_id = h.user_id
            """
            pagination = None
            parameters = ()
            if host_page is not None:
                # Evaluate inheritance against one resolved folder/credential index.
                # SQLite filters and counts before materializing host dictionaries.
                connection.create_function("remote_host_visible", 3, visible)
                connection.create_function("remote_host_matches", 9, matches)
                where = "remote_host_visible(h.user_id, h.visibility, h.folder_id)"
                total = connection.execute(
                    "SELECT COUNT(*) FROM remote_connection_hosts h WHERE " + where).fetchone()[0]
                if query:
                    where += " AND remote_host_matches(h.name,h.protocol,h.host,h.console_device_label,h.console_device_path,h.notes,h.credential_mode,h.credential_id,h.folder_id)"
                matched = connection.execute(
                    "SELECT COUNT(*) FROM remote_connection_hosts h WHERE " + where).fetchone()[0] if query else total
                pages = max(1, (matched + 99) // 100)
                page = min(max(1, int(host_page)), pages)
                sql += " WHERE " + where + " ORDER BY h.name COLLATE NOCASE, h.id LIMIT ? OFFSET ?"
                parameters = (100, (page - 1) * 100)
                pagination = {"page": page, "pages": pages, "page_size": 100,
                              "total": total, "matched": matched, "query": str(host_query).strip()[:200]}
            else:
                sql += " ORDER BY h.name COLLATE NOCASE, h.id"
            hosts = connection.execute(sql, parameters).fetchall()
        folder_items = [self._folder(row) for row in folders]
        credential_items = [self._public_credential(row) for row in credentials]
        host_items = [self._host(row) for row in hosts]
        all_folder_items = folder_items
        self._annotate_effective_visibility(folder_items, host_items)
        folder_items = [
            item for item in folder_items
            if self._visibility_allows(item, user_id=user_id, is_admin=is_admin)
        ]
        credential_items = [
            item for item in credential_items
            if self._visibility_allows(item, user_id=user_id, is_admin=is_admin)
        ]
        host_items = [
            item for item in host_items
            if self._visibility_allows(item, user_id=user_id, is_admin=is_admin)
        ]
        self._annotate_effective_credentials(
            all_folder_items, host_items, credential_items
        )
        visible_folder_ids = {str(item["id"]) for item in folder_items}
        for folder in folder_items:
            if str(folder.get("parent_id", "")) not in visible_folder_ids:
                folder["parent_id"] = ""
        for host in host_items:
            if str(host.get("folder_id", "")) not in visible_folder_ids:
                host["folder_id"] = ""
                if host.get("credential_source_folder_name"):
                    host["credential_source_folder_name"] = "Shared policy"

        visible_credential_ids = {
            str(item["id"]) for item in credential_items
        }
        for host in host_items:
            credential_id = str(host.get("effective_credential_id", ""))
            host["credential_available"] = not credential_id or credential_id in visible_credential_ids
        for collection in (folder_items, credential_items, host_items):
            for item in collection:
                item["owned"] = str(item["user_id"]) == user_id
                item["can_manage"] = item["owned"] or (is_admin and self._visibility_allows(item, user_id=user_id, is_admin=True))
        result = {"folders": folder_items, "credentials": credential_items, "hosts": host_items}
        if pagination is not None:
            result["pagination"] = pagination
        if metadata_page is not None:
            self._page_library_metadata(result, metadata_page, metadata_query, metadata_credential_id)
        return result


    @staticmethod
    def _page_library_metadata(library, requested_page, requested_query, credential_focus=""):
        query = str(requested_query).strip()[:200]
        folded = query.casefold()
        folders, credentials, hosts = library['folders'], library['credentials'], library['hosts']
        folder_map = {row['id']: row for row in folders}
        matched_folders = [row for row in folders if folded in row['name'].casefold()]
        matched_credentials = [row for row in credentials if folded in ' '.join(str(row.get(key, '')) for key in ('name','username','scoped_host_name')).casefold()]
        pages = max(1, (max(len(matched_folders), len(matched_credentials))+99)//100)
        page = min(max(1, int(requested_page)), pages)
        start = (page-1)*100
        folder_ids = {row['id'] for row in matched_folders[start:start+100]}
        credential_ids = {row['id'] for row in matched_credentials[start:start+100]}
        retained_folders = folder_ids | {row['folder_id'] for row in hosts if row['folder_id'] in folder_map}
        # Direct parents preserve current edit choices. Do not send an unbounded
        # ancestry chain merely because one displayed host is deeply nested.
        retained_folders |= {folder_map[identifier]['parent_id'] for identifier in list(retained_folders) if folder_map[identifier]['parent_id'] in folder_map}
        selected_folders = [row for row in folders if row['id'] in retained_folders]
        related_credentials = {credential_focus} | {str(row.get(key, '')) for row in [*hosts, *selected_folders] for key in ('credential_id','effective_credential_id')}
        library['folders'] = [{**row, 'parent_name': folder_map.get(row['parent_id'], {}).get('name', ''), 'context_only': row['id'] not in folder_ids} for row in selected_folders]
        library['credentials'] = [{**row, 'context_only': row['id'] not in credential_ids} for row in credentials if row['id'] in credential_ids | related_credentials]
        library['metadata_pagination'] = {'page':page, 'pages':pages, 'page_size':100, 'query':query,
            'folders_total':len(folders), 'folders_matched':len(matched_folders),
            'credentials_total':len(credentials), 'credentials_matched':len(matched_credentials)}

    def get_host(
        self, host_id: str, *, user_id: str, is_admin: bool = False
    ) -> dict[str, Any] | None:
        """Return one visible host without rebuilding the complete library."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT h.*, c.name AS credential_name,
                       c.remote_username AS remote_username,
                       c.scope_host_id AS credential_scope_host_id
                FROM remote_connection_hosts h
                LEFT JOIN remote_connection_credentials c
                  ON c.id = h.credential_id AND c.user_id = h.user_id
                WHERE h.id = ?
                """,
                (host_id,),
            ).fetchone()
            if not row:
                return None
            host = self._host(row)
            folders = self._folder_lineage(
                connection,
                folder_id=str(host["folder_id"]),
                owner_id=str(host["user_id"]),
            )
            credential_ids = {
                str(host["credential_id"]),
                *(str(folder["credential_id"]) for folder in folders),
            }
            credential_ids.discard("")
            credentials: list[dict[str, Any]] = []
            if credential_ids:
                placeholders = ", ".join("?" for _ in credential_ids)
                rows = connection.execute(
                    f"""
                    SELECT id, user_id, visibility, name, remote_username
                    FROM remote_connection_credentials
                    WHERE id IN ({placeholders})
                    """,
                    tuple(credential_ids),
                ).fetchall()
                credentials = [
                    {
                        "id": str(item["id"]),
                        "user_id": str(item["user_id"]),
                        "visibility": str(item["visibility"]),
                        "name": str(item["name"]),
                        "username": str(item["remote_username"]),
                    }
                    for item in rows
                ]

        self._annotate_effective_visibility(folders, [host])
        if not self._visibility_allows(host, user_id=user_id, is_admin=is_admin):
            return None
        visible_folder_ids = {
            str(folder["id"])
            for folder in folders
            if self._visibility_allows(folder, user_id=user_id, is_admin=is_admin)
        }
        visible_credentials = [
            credential
            for credential in credentials
            if self._visibility_allows(
                credential, user_id=user_id, is_admin=is_admin
            )
        ]
        self._annotate_effective_credentials(folders, [host], visible_credentials)
        visible_credential_ids = {
            str(credential["id"]) for credential in visible_credentials
        }
        credential_id = str(host.get("effective_credential_id", ""))
        host["credential_available"] = (
            not credential_id or credential_id in visible_credential_ids
        )
        if str(host.get("folder_id", "")) not in visible_folder_ids:
            host["folder_id"] = ""
            if host.get("credential_source_folder_name"):
                host["credential_source_folder_name"] = "Shared policy"
        host["owned"] = str(host["user_id"]) == user_id
        host["can_manage"] = host["owned"] or is_admin
        return host

    def resolve_credential(
        self,
        credential_id: str,
        *,
        user_id: str,
        host_id: str = "",
        is_admin: bool = False,
    ) -> dict[str, str]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM remote_connection_credentials WHERE id = ?",
                (credential_id,),
            ).fetchone()
        if not row or not self._visibility_allows(
            {
                "user_id": str(row["user_id"]),
                "visibility": str(row["visibility"]),
            },
            user_id=user_id,
            is_admin=is_admin,
        ):
            raise RemoteConnectionError("Select a valid saved credential.")
        scope_host_id = str(row["scope_host_id"])
        if scope_host_id and scope_host_id != host_id:
            raise RemoteConnectionError(
                "That credential is restricted to its assigned saved host."
            )
        if host_id:
            owner_host = self.get_host(
                host_id, user_id=str(row["user_id"])
            )
            credential_is_narrower = (
                str(row["user_id"]) != user_id
                and owner_host
                and self._visibility_rank(
                    owner_host.get("effective_visibility", "private")
                )
                > self._visibility_rank(row["visibility"])
            )
            if not owner_host or credential_is_narrower:
                raise RemoteConnectionError(
                    "This host is more broadly available than its credential."
                )
        try:
            password = self._cipher.decrypt(
                str(row["secret_encrypted"]).encode("ascii")
            ).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError("Could not decrypt the saved remote credential.") from exc
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "username": str(row["remote_username"]),
            "password": password,
        }

    @managed_mutation("dynamic", "resource_id")
    def set_visibility(
        self,
        resource_type: str,
        resource_id: str,
        *,
        user_id: str,
        visibility: str,
    ) -> None:
        tables = {
            "folder": "remote_connection_folders",
            "host": "remote_connection_hosts",
            "credential": "remote_connection_credentials",
        }
        table = tables.get(str(resource_type))
        if not table:
            raise RemoteConnectionError("Unknown Remote Terminal resource type.")
        clean = self._clean_visibility(
            visibility, allow_inherit=resource_type in {"folder", "host"}
        )
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT parent_id FROM {table} WHERE id = ? AND user_id = ?"
                if resource_type == "folder"
                else f"SELECT id FROM {table} WHERE id = ? AND user_id = ?",
                (resource_id, user_id),
            ).fetchone()
            if not row:
                raise RemoteConnectionError("Saved library item not found.")
            if resource_type == "folder" and clean == "inherit" and not row["parent_id"]:
                raise RemoteConnectionError(
                    "A root folder must choose Global, Admins Only, or Private."
                )
            connection.execute(
                f"UPDATE {table} SET visibility = ?, updated_at = ? "
                "WHERE id = ? AND user_id = ?",
                (clean, time.time(), resource_id, user_id),
            )

    def create_folder(
        self,
        *,
        user_id: str,
        name: str,
        parent_id: str = "",
        credential_mode: str = "inherit",
        credential_id: str = "",
    ) -> dict[str, Any]:
        clean_name = self._name(name, "Folder name")
        folder_id = f"rf_{secrets.token_hex(10)}"
        now = time.time()
        with self._connect() as connection:
            self._require_folder(connection, parent_id, user_id, allow_root=True)
            self._require_unique_folder_name(
                connection, user_id, parent_id, clean_name
            )
            clean_mode, clean_credential_id = self._folder_credential_assignment(
                connection, user_id, credential_mode, credential_id
            )
            connection.execute(
                """
                INSERT INTO remote_connection_folders
                    (id, user_id, name, parent_id, credential_mode,
                     credential_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    folder_id,
                    user_id,
                    clean_name,
                    parent_id,
                    clean_mode,
                    clean_credential_id,
                    now,
                    now,
                ),
            )
        return self.get_folder(folder_id, user_id=user_id)  # type: ignore[return-value]

    def get_folder(self, folder_id: str, *, user_id: str, is_admin: bool = False) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM remote_connection_folders WHERE id = ?", (folder_id,)).fetchone()
            if not row:
                return None
            folder = self._folder(row)
            lineage = self._folder_lineage(connection, folder_id=folder_id, owner_id=folder["user_id"])
            self._annotate_effective_visibility(lineage, [])
            folder = next(item for item in lineage if item["id"] == folder_id)
        if not self._visibility_allows(folder, user_id=user_id, is_admin=is_admin):
            return None
        folder["owned"] = folder["user_id"] == user_id
        folder["can_manage"] = folder["owned"] or is_admin
        return folder

    @managed_mutation("folder", "folder_id")
    def update_folder(
        self,
        folder_id: str,
        *,
        user_id: str,
        name: str,
        parent_id: str,
        credential_mode: str | None = None,
        credential_id: str = "",
    ) -> dict[str, Any]:
        clean_name = self._name(name, "Folder name")
        with self._connect() as connection:
            existing = self._require_folder(connection, folder_id, user_id)
            self._require_folder(connection, parent_id, user_id, allow_root=True)
            if parent_id == folder_id or self._folder_descends_from(
                connection, parent_id, folder_id, user_id
            ):
                raise RemoteConnectionError("A folder cannot be moved inside itself.")
            self._require_unique_folder_name(
                connection, user_id, parent_id, clean_name, exclude_id=folder_id
            )
            if credential_mode is None:
                clean_mode = str(existing["credential_mode"])
                clean_credential_id = str(existing["credential_id"])
            else:
                clean_mode, clean_credential_id = self._folder_credential_assignment(
                    connection, user_id, credential_mode, credential_id
                )
            connection.execute(
                """
                UPDATE remote_connection_folders
                SET name = ?, parent_id = ?, credential_mode = ?,
                    credential_id = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (
                    clean_name,
                    parent_id,
                    clean_mode,
                    clean_credential_id,
                    time.time(),
                    folder_id,
                    user_id,
                ),
            )
        return self.get_folder(str(existing["id"]), user_id=user_id)  # type: ignore[return-value]

    def duplicate_folder(self, folder_id: str, *, user_id: str) -> dict[str, Any]:
        # One snapshot and transaction: an interrupted or rejected copy must not
        # leave a partial tree. The recursive SQL uses UNION to terminate cycles.
        limit = 10_000
        with self.transaction(), self._connect() as connection:
            source = self._require_folder(connection, folder_id, user_id)
            self._require_folder(connection, str(source["parent_id"]), user_id, allow_root=True)
            subtree = """
                WITH RECURSIVE subtree(id) AS (
                    SELECT id FROM remote_connection_folders WHERE id=? AND user_id=?
                    UNION
                    SELECT f.id FROM subtree s CROSS JOIN remote_connection_folders f
                    WHERE f.parent_id=s.id AND f.user_id=?
                    LIMIT 10001
                )
            """
            parameters = (folder_id, user_id, user_id)
            folders = connection.execute(
                subtree + "SELECT f.* FROM subtree s CROSS JOIN remote_connection_folders f WHERE f.id=s.id LIMIT ?",
                (*parameters, limit + 1),
            ).fetchall()
            hosts = connection.execute(
                subtree + "SELECT h.* FROM subtree s CROSS JOIN remote_connection_hosts h WHERE h.folder_id=s.id AND h.user_id=? LIMIT ?",
                (*parameters, user_id, limit + 1),
            ).fetchall()
            if len(folders) + len(hosts) > limit:
                raise RemoteConnectionError(
                    "Duplicate no more than 10,000 folders and hosts at once. Choose a smaller folder."
                )
            folder_ids = {str(row['id']): 'rf_' + secrets.token_hex(10) for row in folders}
            if str(source['parent_id']) in folder_ids:
                raise RemoteConnectionError("Repair the folder's parent cycle before duplicating it.")
            credential_ids = {str(row['credential_id']) for row in [*folders, *hosts] if row['credential_id']}
            credentials = {}
            for identifier in credential_ids:
                credentials[identifier] = dict(self._require_credential_row(connection, identifier, user_id))
            for row in folders:
                credential = credentials.get(str(row['credential_id']))
                if credential and credential['scope_host_id']:
                    raise RemoteConnectionError("A folder cannot use a host-restricted credential.")
            for row in hosts:
                credential = credentials.get(str(row['credential_id']))
                if credential and credential['scope_host_id'] not in ('', row['id']):
                    raise RemoteConnectionError("A saved host has a credential restricted to another host.")
            sibling_names = [row[0] for row in connection.execute(
                "SELECT name FROM remote_connection_folders WHERE user_id=? AND parent_id=?",
                (user_id, source['parent_id']),
            )]
            root_name = duplicate_name(str(source['name']), sibling_names)
            credential_names = DuplicateNameIndex(row[0] for row in connection.execute(
                "SELECT name FROM remote_connection_credentials WHERE user_id=?", (user_id,)
            ))
            now = time.time()

            def insert(table, original, **changes):
                row = {**dict(original), **changes, 'created_at': now, 'updated_at': now}
                columns = ','.join('"' + key.replace('"', '""') + '"' for key in row)
                placeholders = ','.join('?' for _ in row)
                connection.execute(f'INSERT INTO {table} ({columns}) VALUES ({placeholders})', tuple(row.values()))

            for row in folders:
                identifier = str(row['id'])
                insert('remote_connection_folders', row, id=folder_ids[identifier],
                       name=root_name if identifier == folder_id else row['name'],
                       parent_id=folder_ids.get(str(row['parent_id']), str(row['parent_id'])))
            for row in hosts:
                identifier = 'rh_' + secrets.token_hex(10)
                credential_id = str(row['credential_id'])
                credential = credentials.get(credential_id)
                if credential and credential['scope_host_id']:
                    credential_id = 'rc_' + secrets.token_hex(10)
                    name = credential_names.reserve(str(credential['name']))
                    insert('remote_connection_credentials', credential, id=credential_id,
                           scope_host_id=identifier, name=name)
                insert('remote_connection_hosts', row, id=identifier,
                       folder_id=folder_ids[str(row['folder_id'])], credential_id=credential_id)
            copied = self.get_folder(folder_ids[folder_id], user_id=user_id)
            assert copied is not None
            return copied

    @managed_mutation("folder", "folder_id")
    def delete_folder(self, folder_id: str, *, user_id: str) -> None:
        with self._connect() as connection:
            self._require_folder(connection, folder_id, user_id)
            child_count = connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM remote_connection_folders WHERE user_id = ? AND parent_id = ?) +
                  (SELECT COUNT(*) FROM remote_connection_hosts WHERE user_id = ? AND folder_id = ?)
                """,
                (user_id, folder_id, user_id, folder_id),
            ).fetchone()[0]
            if int(child_count):
                raise RemoteConnectionError(
                    "Move or delete the items in this folder before deleting it."
                )
            connection.execute(
                "DELETE FROM remote_connection_folders WHERE id = ? AND user_id = ?",
                (folder_id, user_id),
            )

    @managed_mutation("credential", "credential_id")
    def save_credential(
        self,
        *,
        user_id: str,
        name: str,
        remote_username: str,
        password: str,
        credential_id: str = "",
        scope_host_id: str = "",
    ) -> dict[str, Any]:
        clean_name = self._name(name, "Credential name")
        clean_username = self._username(remote_username)
        now = time.time()
        with self._connect() as connection:
            self._require_unique_credential_name(
                connection, user_id, clean_name, exclude_id=credential_id
            )
            if scope_host_id:
                self._require_host_row(connection, scope_host_id, user_id)
            if credential_id:
                existing = self._require_credential_row(
                    connection, credential_id, user_id
                )
                encrypted = str(existing["secret_encrypted"])
                if password:
                    encrypted = self._encrypt_secret(password)
                connection.execute(
                    """
                    UPDATE remote_connection_credentials
                    SET name = ?, remote_username = ?, secret_encrypted = ?,
                        scope_host_id = ?, updated_at = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (
                        clean_name,
                        clean_username,
                        encrypted,
                        scope_host_id,
                        now,
                        credential_id,
                        user_id,
                    ),
                )
            else:
                if not password:
                    raise RemoteConnectionError("Enter the remote password.")
                credential_id = f"rc_{secrets.token_hex(10)}"
                connection.execute(
                    """
                    INSERT INTO remote_connection_credentials
                        (id, user_id, name, remote_username, secret_encrypted,
                         scope_host_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        credential_id,
                        user_id,
                        clean_name,
                        clean_username,
                        self._encrypt_secret(password),
                        scope_host_id,
                        now,
                        now,
                    ),
                )
        return self._credential_by_id(credential_id, user_id=user_id)

    def duplicate_credential(
        self, credential_id: str, *, user_id: str
    ) -> dict[str, Any]:
        with self._connect() as connection:
            source = self._require_credential_row(
                connection, credential_id, user_id
            )
            names = [
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM remote_connection_credentials WHERE user_id = ?",
                    (user_id,),
                )
            ]
            copied_id = f"rc_{secrets.token_hex(10)}"
            now = time.time()
            connection.execute(
                """
                INSERT INTO remote_connection_credentials
                    (id, user_id, name, remote_username, secret_encrypted,
                     scope_host_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, '', ?, ?)
                """,
                (
                    copied_id,
                    user_id,
                    duplicate_name(str(source["name"]), names),
                    source["remote_username"],
                    source["secret_encrypted"],
                    now,
                    now,
                ),
            )
        return self._credential_by_id(copied_id, user_id=user_id)

    @managed_mutation("credential", "credential_id")
    def delete_credential(self, credential_id: str, *, user_id: str) -> None:
        with self._connect() as connection:
            self._require_credential_row(connection, credential_id, user_id)
            use_count = connection.execute(
                """
                SELECT COUNT(*) FROM remote_connection_hosts
                WHERE user_id = ? AND credential_id = ?
                """,
                (user_id, credential_id),
            ).fetchone()[0]
            if int(use_count):
                raise RemoteConnectionError(
                    "Assign another credential to its saved host before deleting it."
                )
            folder_use_count = connection.execute(
                """
                SELECT COUNT(*) FROM remote_connection_folders
                WHERE user_id = ? AND credential_id = ?
                """,
                (user_id, credential_id),
            ).fetchone()[0]
            if int(folder_use_count):
                raise RemoteConnectionError(
                    "Change the folders using this credential before deleting it."
                )
            connection.execute(
                "DELETE FROM remote_connection_credentials WHERE id = ? AND user_id = ?",
                (credential_id, user_id),
            )

    @managed_mutation("host", "host_id")
    def save_host(
        self,
        *,
        user_id: str,
        name: str,
        host: str,
        port: int,
        folder_id: str,
        credential_id: str,
        allow_unknown_hosts: bool,
        allow_legacy_algorithms: bool,
        notes: str = "",
        host_id: str = "",
        host_credential: dict[str, str] | None = None,
        protocol: str = "ssh",
        credential_mode: str = "credential",
        console_device_id: str = "",
        console_device_path: str = "",
        console_device_label: str = "",
        console_baud_rate: int = 9600,
        console_data_bits: int = 8,
        console_parity: str = "none",
        console_stop_bits: str = "1",
        console_flow_control: str = "none",
    ) -> dict[str, Any]:
        clean_name = self._name(name, "Host name")
        clean_notes = str(notes).strip()[:1000]
        clean_protocol = str(protocol).strip().lower()
        if clean_protocol not in {"ssh", "telnet", "console"}:
            raise RemoteConnectionError("Choose SSH, Telnet, or Console.")
        if clean_protocol == "console":
            clean_device_id = self._console_device_id(console_device_id)
            clean_device_path = self._console_device_path(console_device_path)
            clean_device_label = self._name(
                console_device_label or clean_device_path, "Console device label"
            )
            settings = serial_settings(
                baud_rate=console_baud_rate,
                data_bits=console_data_bits,
                parity=console_parity,
                stop_bits=console_stop_bits,
                flow_control=console_flow_control,
            )
            clean_host = clean_device_path
            clean_port = 0
            credential_mode = "none"
            credential_id = ""
            host_credential = None
            allow_unknown_hosts = False
            allow_legacy_algorithms = False
        else:
            clean_host = self._hostname(host)
            clean_port = int(port)
            if not 1 <= clean_port <= 65535:
                raise RemoteConnectionError("Port must be between 1 and 65535.")
            clean_device_id = clean_device_path = clean_device_label = ""
            settings = serial_settings()
        now = time.time()
        is_update = bool(host_id)
        with self._connect() as connection:
            self._require_folder(connection, folder_id, user_id, allow_root=True)
            self._require_unique_host_name(
                connection, user_id, folder_id, clean_name, exclude_id=host_id
            )
            old_scoped_credential_id = ""
            if host_id:
                existing = self._require_host_row(connection, host_id, user_id)
                existing_credential_id = str(existing["credential_id"])
                if existing_credential_id:
                    old_credential = self._require_credential_row(
                        connection, existing_credential_id, user_id
                    )
                    if str(old_credential["scope_host_id"]) == host_id:
                        old_scoped_credential_id = str(old_credential["id"])
            else:
                host_id = f"rh_{secrets.token_hex(10)}"

            if host_credential is not None:
                credential_mode = "credential"
                credential_name = self._name(
                    host_credential.get("name", "") or f"{clean_name} credentials",
                    "Credential name",
                )
                remote_username = self._username(
                    host_credential.get("username", "")
                )
                password = str(host_credential.get("password", ""))
                if old_scoped_credential_id:
                    self._require_unique_credential_name(
                        connection, user_id, credential_name,
                        exclude_id=old_scoped_credential_id,
                    )
                else:
                    existing_credential_names = [
                        str(row[0])
                        for row in connection.execute(
                            "SELECT name FROM remote_connection_credentials WHERE user_id = ?",
                            (user_id,),
                        )
                    ]
                    if credential_name.casefold() in {
                        name.casefold() for name in existing_credential_names
                    }:
                        credential_name = duplicate_name(
                            credential_name, existing_credential_names
                        )
                if old_scoped_credential_id:
                    old = self._require_credential_row(
                        connection, old_scoped_credential_id, user_id
                    )
                    encrypted = str(old["secret_encrypted"])
                    if password:
                        encrypted = self._encrypt_secret(password)
                    connection.execute(
                        """
                        UPDATE remote_connection_credentials
                        SET name = ?, remote_username = ?, secret_encrypted = ?, updated_at = ?
                        WHERE id = ? AND user_id = ?
                        """,
                        (
                            credential_name,
                            remote_username,
                            encrypted,
                            now,
                            old_scoped_credential_id,
                            user_id,
                        ),
                    )
                    credential_id = old_scoped_credential_id
                else:
                    if not password:
                        raise RemoteConnectionError("Enter the remote password.")
                    credential_id = f"rc_{secrets.token_hex(10)}"
                    connection.execute(
                        """
                        INSERT INTO remote_connection_credentials
                            (id, user_id, name, remote_username, secret_encrypted,
                             scope_host_id, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            credential_id,
                            user_id,
                            credential_name,
                            remote_username,
                            self._encrypt_secret(password),
                            host_id,
                            now,
                            now,
                        ),
                    )
            else:
                credential_mode = str(credential_mode).strip().lower()
                if credential_mode == "inherit":
                    credential_id = ""
                elif credential_mode == "none":
                    credential_id = ""
                    if clean_protocol not in {"telnet", "console"}:
                        raise RemoteConnectionError(
                            "Saved SSH hosts must inherit or use a credential."
                        )
                elif credential_mode == "credential" and credential_id:
                    credential = self._require_credential_row(
                        connection, credential_id, user_id
                    )
                    if str(credential["scope_host_id"]) not in {"", host_id}:
                        raise RemoteConnectionError(
                            "Select a shared credential or this host's own credential."
                        )
                elif credential_mode == "credential" and clean_protocol != "telnet":
                    raise RemoteConnectionError(
                        "Assign a credential to saved SSH hosts."
                    )
                elif credential_mode != "credential":
                    raise RemoteConnectionError(
                        "Choose inherited, saved, host-specific, or no credentials."
                    )

            values = (
                clean_name,
                clean_host,
                clean_port,
                clean_protocol,
                folder_id,
                credential_mode,
                credential_id,
                int(bool(allow_unknown_hosts) and clean_protocol == "ssh"),
                int(bool(allow_legacy_algorithms) and clean_protocol == "ssh"),
                clean_notes,
                clean_device_id,
                clean_device_path,
                clean_device_label,
                int(settings["baud_rate"]),
                int(settings["data_bits"]),
                str(settings["parity"]),
                str(settings["stop_bits"]),
                str(settings["flow_control"]),
                now,
            )
            if is_update:
                connection.execute(
                    """
                    UPDATE remote_connection_hosts
                    SET name = ?, host = ?, port = ?, protocol = ?, folder_id = ?,
                        credential_mode = ?, credential_id = ?, allow_unknown_hosts = ?,
                        allow_legacy_algorithms = ?, notes = ?, console_device_id = ?,
                        console_device_path = ?, console_device_label = ?,
                        console_baud_rate = ?, console_data_bits = ?, console_parity = ?,
                        console_stop_bits = ?, console_flow_control = ?, updated_at = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (*values, host_id, user_id),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO remote_connection_hosts
                        (id, user_id, name, host, port, protocol, folder_id,
                         credential_mode, credential_id,
                         allow_unknown_hosts, allow_legacy_algorithms, notes,
                         console_device_id, console_device_path, console_device_label,
                         console_baud_rate, console_data_bits, console_parity,
                         console_stop_bits, console_flow_control,
                         created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (host_id, user_id, *values[:-1], now, now),
                )
            if (
                old_scoped_credential_id
                and credential_id != old_scoped_credential_id
            ):
                connection.execute(
                    """
                    DELETE FROM remote_connection_credentials
                    WHERE id = ? AND user_id = ?
                    """,
                    (old_scoped_credential_id, user_id),
                )
        return self.get_host(host_id, user_id=user_id)  # type: ignore[return-value]

    def duplicate_host(self, host_id: str, *, user_id: str) -> dict[str, Any]:
        source = self.get_host(host_id, user_id=user_id)
        if not source:
            raise RemoteConnectionError("Saved host not found.")
        with self._connect() as connection:
            names = [
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT name FROM remote_connection_hosts
                    WHERE user_id = ? AND folder_id = ?
                    """,
                    (user_id, source["folder_id"]),
                )
            ]
        copied_name = duplicate_name(str(source["name"]), names)
        host_credential = None
        credential_id = str(source["credential_id"])
        if source["credential_scope_host_id"] == host_id:
            resolved = self.resolve_credential(
                credential_id, user_id=user_id, host_id=host_id
            )
            host_credential = {
                "name": f"{copied_name} credentials",
                "username": resolved["username"],
                "password": resolved["password"],
            }
            credential_id = ""
        copied = self.save_host(
            user_id=user_id,
            name=copied_name,
            host=str(source["host"]),
            port=int(source["port"]),
            folder_id=str(source["folder_id"]),
            credential_id=credential_id,
            allow_unknown_hosts=bool(source["allow_unknown_hosts"]),
            allow_legacy_algorithms=bool(source["allow_legacy_algorithms"]),
            notes=str(source["notes"]),
            host_credential=host_credential,
            protocol=str(source.get("protocol", "ssh")),
            credential_mode=str(source.get("credential_mode", "credential")),
            console_device_id=str(source.get("console_device_id", "")),
            console_device_path=str(source.get("console_device_path", "")),
            console_device_label=str(source.get("console_device_label", "")),
            console_baud_rate=int(source.get("console_baud_rate", 9600)),
            console_data_bits=int(source.get("console_data_bits", 8)),
            console_parity=str(source.get("console_parity", "none")),
            console_stop_bits=str(source.get("console_stop_bits", "1")),
            console_flow_control=str(source.get("console_flow_control", "none")),
        )
        self.set_visibility(
            "host", str(copied["id"]), user_id=user_id,
            visibility=str(source["visibility"]),
        )
        copied = self.get_host(str(copied["id"]), user_id=user_id)
        if copied and copied.get("credential_scope_host_id") == copied.get("id"):
            self.set_visibility(
                "credential", str(copied["credential_id"]), user_id=user_id,
                visibility=str(copied["effective_visibility"]),
            )
        return copied  # type: ignore[return-value]

    def import_hosts(
        self,
        *,
        user_id: str,
        folder_id: str,
        hosts: list[dict[str, Any]],
    ) -> int:
        """Atomically add a reviewed host list with folder credential inheritance."""
        if not hosts:
            raise RemoteConnectionError("Add at least one host to import.")
        if len(hosts) > 1000:
            raise RemoteConnectionError("Import no more than 1,000 hosts at once.")

        prepared: list[dict[str, Any]] = []
        for index, item in enumerate(hosts, start=1):
            row_number = int(item.get("row", index))
            try:
                protocol = str(item.get("protocol", "ssh")).strip().lower()
                if protocol not in {"ssh", "telnet"}:
                    raise RemoteConnectionError("Choose SSH or Telnet.")
                port = int(item.get("port", 23 if protocol == "telnet" else 22))
                if not 1 <= port <= 65535:
                    raise RemoteConnectionError("Port must be between 1 and 65535.")
                prepared.append(
                    {
                        "row": row_number,
                        "name": self._name(item.get("name", ""), "Host name"),
                        "host": self._hostname(item.get("host", "")),
                        "protocol": protocol,
                        "port": port,
                    }
                )
            except (RemoteConnectionError, TypeError, ValueError) as exc:
                raise RemoteConnectionError(f"Row {row_number}: {exc}") from exc

        now = time.time()
        with self._connect() as connection:
            self._require_folder(connection, folder_id, user_id, allow_root=True)
            for item in prepared:
                try:
                    self._require_unique_host_name(
                        connection, user_id, folder_id, str(item["name"])
                    )
                except RemoteConnectionError as exc:
                    raise RemoteConnectionError(
                        f"Row {item['row']}: {exc}"
                    ) from exc
                connection.execute(
                    """
                    INSERT INTO remote_connection_hosts
                        (id, user_id, name, host, port, protocol, folder_id,
                         credential_mode, credential_id,
                         allow_unknown_hosts, allow_legacy_algorithms, notes,
                         created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'inherit', '', 0, 0, '', ?, ?)
                    """,
                    (
                        f"rh_{secrets.token_hex(10)}",
                        user_id,
                        item["name"],
                        item["host"],
                        item["port"],
                        item["protocol"],
                        folder_id,
                        now,
                        now,
                    ),
                )
        return len(prepared)

    @managed_mutation("host", "host_id")
    def delete_host(self, host_id: str, *, user_id: str) -> None:
        with self._connect() as connection:
            host = self._require_host_row(connection, host_id, user_id)
            credential_id = str(host["credential_id"])
            credential = (
                self._require_credential_row(connection, credential_id, user_id)
                if credential_id
                else None
            )
            connection.execute(
                "DELETE FROM remote_connection_hosts WHERE id = ? AND user_id = ?",
                (host_id, user_id),
            )
            if credential is not None and str(credential["scope_host_id"]) == host_id:
                connection.execute(
                    "DELETE FROM remote_connection_credentials WHERE id = ? AND user_id = ?",
                    (credential["id"], user_id),
                )

    @managed_mutation("bulk", "")
    def bulk_update(
        self,
        *,
        user_id: str,
        host_ids: list[str],
        folder_ids: list[str],
        destination_id: str | None = None,
        credential_mode: str | None = None,
        credential_id: str = "",
    ) -> dict[str, int]:
        clean_host_ids = list(dict.fromkeys(str(item) for item in host_ids if item))
        clean_folder_ids = list(
            dict.fromkeys(str(item) for item in folder_ids if item)
        )
        if not clean_host_ids and not clean_folder_ids:
            raise RemoteConnectionError("Select at least one host or folder.")
        if len(clean_host_ids) + len(clean_folder_ids) > 500:
            raise RemoteConnectionError("Select no more than 500 items at once.")
        if destination_id is None and credential_mode is None:
            raise RemoteConnectionError("Choose a location or credential change.")

        now = time.time()
        with self._connect() as connection:
            hosts = [
                self._require_host_row(connection, host_id, user_id)
                for host_id in clean_host_ids
            ]
            folders = [
                self._require_folder(connection, folder_id, user_id)
                for folder_id in clean_folder_ids
            ]

            if destination_id is not None:
                self._require_folder(
                    connection, destination_id, user_id, allow_root=True
                )
                for folder in folders:
                    folder_id = str(folder["id"])
                    if destination_id == folder_id or self._folder_descends_from(
                        connection, destination_id, folder_id, user_id
                    ):
                        raise RemoteConnectionError(
                            f"'{folder['name']}' cannot be moved inside itself."
                        )
                    self._require_unique_folder_name(
                        connection,
                        user_id,
                        destination_id,
                        str(folder["name"]),
                        exclude_id=folder_id,
                    )
                    connection.execute(
                        """
                        UPDATE remote_connection_folders
                        SET parent_id = ?, updated_at = ?
                        WHERE id = ? AND user_id = ?
                        """,
                        (destination_id, now, folder_id, user_id),
                    )
                for host in hosts:
                    host_id = str(host["id"])
                    self._require_unique_host_name(
                        connection,
                        user_id,
                        destination_id,
                        str(host["name"]),
                        exclude_id=host_id,
                    )
                    connection.execute(
                        """
                        UPDATE remote_connection_hosts
                        SET folder_id = ?, updated_at = ?
                        WHERE id = ? AND user_id = ?
                        """,
                        (destination_id, now, host_id, user_id),
                    )

            if credential_mode is not None:
                clean_mode, clean_credential_id = self._folder_credential_assignment(
                    connection, user_id, credential_mode, credential_id
                )
                for folder in folders:
                    connection.execute(
                        """
                        UPDATE remote_connection_folders
                        SET credential_mode = ?, credential_id = ?, updated_at = ?
                        WHERE id = ? AND user_id = ?
                        """,
                        (
                            clean_mode,
                            clean_credential_id,
                            now,
                            folder["id"],
                            user_id,
                        ),
                    )
                for host in hosts:
                    host_mode = clean_mode
                    if str(host["protocol"]) == "console":
                        host_mode = "none"
                        clean_host_credential_id = ""
                    else:
                        clean_host_credential_id = clean_credential_id
                    if host_mode == "none" and str(host["protocol"]) not in {"telnet", "console"}:
                        raise RemoteConnectionError(
                            "No credential can only be assigned to Telnet hosts."
                        )
                    old_credential_id = str(host["credential_id"])
                    old_credential = (
                        self._require_credential_row(
                            connection, old_credential_id, user_id
                        )
                        if old_credential_id
                        else None
                    )
                    connection.execute(
                        """
                        UPDATE remote_connection_hosts
                        SET credential_mode = ?, credential_id = ?, updated_at = ?
                        WHERE id = ? AND user_id = ?
                        """,
                        (
                            host_mode,
                            clean_host_credential_id,
                            now,
                            host["id"],
                            user_id,
                        ),
                    )
                    if (
                        old_credential is not None
                        and str(old_credential["scope_host_id"]) == str(host["id"])
                        and old_credential_id != clean_host_credential_id
                    ):
                        connection.execute(
                            """
                            DELETE FROM remote_connection_credentials
                            WHERE id = ? AND user_id = ?
                            """,
                            (old_credential_id, user_id),
                        )
        return {"hosts": len(clean_host_ids), "folders": len(clean_folder_ids)}

    def clear(self) -> None:
        for path in (
            self.path,
            self.path.with_name(f"{self.path.name}-wal"),
            self.path.with_name(f"{self.path.name}-shm"),
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _folder_lineage(
        self,
        connection: sqlite3.Connection,
        *,
        folder_id: str,
        owner_id: str,
    ) -> list[dict[str, Any]]:
        """Fetch only the folders that can affect one host's policy."""
        folders: list[dict[str, Any]] = []
        seen: set[str] = set()
        current_id = folder_id
        while current_id and current_id not in seen:
            row = connection.execute(
                """
                SELECT * FROM remote_connection_folders
                WHERE id = ? AND user_id = ?
                """,
                (current_id, owner_id),
            ).fetchone()
            if not row:
                break
            folder = self._folder(row)
            folders.append(folder)
            seen.add(current_id)
            current_id = str(folder["parent_id"])
        return folders

    def _credential_by_id(
        self, credential_id: str, *, user_id: str
    ) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT c.*,
                       (SELECT COUNT(*) FROM remote_connection_hosts h
                        WHERE h.credential_id = c.id AND h.user_id = c.user_id)
                         AS usage_count,
                       (SELECT COUNT(*) FROM remote_connection_folders f
                        WHERE f.credential_id = c.id AND f.user_id = c.user_id)
                         AS folder_usage_count,
                       COALESCE(scoped.name, '') AS scoped_host_name
                FROM remote_connection_credentials c
                LEFT JOIN remote_connection_hosts scoped
                  ON scoped.id = c.scope_host_id AND scoped.user_id = c.user_id
                WHERE c.id = ? AND c.user_id = ?
                """,
                (credential_id, user_id),
            ).fetchone()
        if not row:  # pragma: no cover
            raise RuntimeError("Saved credential could not be read.")
        return self._public_credential(row)

    def _encrypt_secret(self, password: str) -> str:
        if not password:
            raise RemoteConnectionError("Enter the password.")
        if len(password.encode("utf-8")) > 16 * 1024:
            raise RemoteConnectionError("The password is too large.")
        return self._cipher.encrypt(password.encode("utf-8")).decode("ascii")

    @classmethod
    def _folder_credential_assignment(
        cls,
        connection: sqlite3.Connection,
        user_id: str,
        credential_mode: object,
        credential_id: object,
    ) -> tuple[str, str]:
        clean_mode = str(credential_mode).strip().lower()
        if clean_mode not in {"inherit", "credential", "none"}:
            raise RemoteConnectionError(
                "Choose inherited, saved, or no credentials."
            )
        if clean_mode != "credential":
            return clean_mode, ""
        clean_credential_id = str(credential_id).strip()
        if not clean_credential_id:
            raise RemoteConnectionError("Choose a saved credential.")
        credential = cls._require_credential_row(
            connection, clean_credential_id, user_id
        )
        if str(credential["scope_host_id"]):
            raise RemoteConnectionError(
                "Folder inheritance requires a shared credential."
            )
        return clean_mode, clean_credential_id

    @staticmethod
    def _clean_visibility(value: object, *, allow_inherit: bool = False) -> str:
        clean = str(value).strip().lower()
        allowed = VISIBILITY_MODES if allow_inherit else VISIBILITY_VALUES
        if clean not in allowed:
            choices = "Global, Admins Only, Private" + (", or Inherit" if allow_inherit else "")
            raise RemoteConnectionError(f"Choose {choices}.")
        return clean

    @classmethod
    def _annotate_effective_visibility(
        cls,
        folders: list[dict[str, Any]],
        hosts: list[dict[str, Any]],
    ) -> None:
        folder_map = {str(item["id"]): item for item in folders}
        resolved: dict[str, str] = {}
        for folder in folders:
            current = folder
            path = []
            visited = set()
            effective = "admins_only"
            while current:
                identifier = str(current["id"])
                if identifier in resolved:
                    effective = resolved[identifier]
                    break
                if identifier in visited:
                    effective = "private"
                    break
                visited.add(identifier)
                path.append(current)
                visibility = str(current.get("visibility", "private"))
                if visibility != "inherit":
                    effective = visibility
                    break
                parent = folder_map.get(str(current.get("parent_id", "")))
                current = parent if parent and parent.get("user_id") == current.get("user_id") else None
            for item in path:
                resolved[str(item["id"])] = effective
                item["effective_visibility"] = effective
        for host in hosts:
            current = str(host.get("visibility", "inherit"))
            parent = folder_map.get(str(host.get("folder_id", "")))
            host["effective_visibility"] = (
                str(parent.get("effective_visibility", "admins_only"))
                if current == "inherit"
                and parent
                and parent.get("user_id") == host.get("user_id")
                else "admins_only"
                if current == "inherit"
                else current
            )

    @staticmethod
    def _visibility_allows(
        item: dict[str, Any], *, user_id: str, is_admin: bool
    ) -> bool:
        if str(item.get("user_id", "")) == user_id:
            return True
        visibility = str(
            item.get("effective_visibility", item.get("visibility", "private"))
        )
        return visibility == "global" or (visibility == "admins_only" and is_admin)

    @staticmethod
    def _visibility_rank(value: object) -> int:
        return {
            "private": 1,
            "admins_only": 2,
            "global": 3,

        }.get(str(value), 0)

    @staticmethod
    def _annotate_effective_credentials(
        folders: list[dict[str, Any]],
        hosts: list[dict[str, Any]],
        credentials: list[dict[str, Any]],
    ) -> None:
        folder_map = {str(folder["id"]): folder for folder in folders}
        credential_map = {
            str(credential["id"]): credential for credential in credentials
        }
        folder_cache: dict[str, tuple[str, str, str]] = {}

        def resolve_folder(folder_id: str) -> tuple[str, str, str]:
            current = folder_map.get(folder_id)
            path = []
            visited = set()
            result = ("", "", "")
            while current:
                identifier = str(current['id'])
                if identifier in folder_cache:
                    result = folder_cache[identifier]
                    break
                if identifier in visited:
                    break
                visited.add(identifier)
                path.append(identifier)
                mode = str(current.get('credential_mode', 'inherit'))
                if mode in {'credential', 'none'}:
                    result = (str(current.get('credential_id', '')) if mode == 'credential' else '', identifier, str(current['name']))
                    break
                parent = folder_map.get(str(current.get('parent_id', '')))
                current = parent if parent and parent.get('user_id') == current.get('user_id') else None
            for identifier in path:
                folder_cache[identifier] = result
            return result

        def apply_effective(
            item: dict[str, Any], credential_id: str, source_id: str, source_name: str
        ) -> None:
            credential = credential_map.get(credential_id, {})
            item["effective_credential_id"] = credential_id
            item["effective_credential_name"] = str(credential.get("name", ""))
            item["effective_remote_username"] = str(
                credential.get("username", "")
            )
            item["credential_source_folder_id"] = source_id
            item["credential_source_folder_name"] = source_name

        for folder in folders:
            effective_id, source_id, source_name = resolve_folder(str(folder["id"]))
            apply_effective(folder, effective_id, source_id, source_name)

        for host in hosts:
            if str(host.get("protocol", "ssh")) == "console":
                apply_effective(host, "", "", "")
                host["credential_source"] = "none"
                continue
            mode = str(host.get("credential_mode", "credential"))
            if mode == "credential":
                effective_id = str(host.get("credential_id", ""))
                source_id = ""
                source_name = ""
                source = "host" if effective_id else "none"
            elif mode == "inherit":
                effective_id, source_id, source_name = resolve_folder(
                    str(host.get("folder_id", ""))
                )
                source = "folder" if effective_id else "none"
            else:
                effective_id = source_id = source_name = ""
                source = "none"
            apply_effective(host, effective_id, source_id, source_name)
            host["credential_source"] = source

    @staticmethod
    def _name(value: object, label: str) -> str:
        clean = " ".join(str(value).strip().split())
        if not 1 <= len(clean) <= 100:
            raise RemoteConnectionError(f"{label} must be 1–100 characters.")
        return clean

    @staticmethod
    def _username(value: object) -> str:
        clean = str(value).strip()
        if not clean or len(clean) > 128 or any(char in "\r\n\x00" for char in clean):
            raise RemoteConnectionError("Enter a valid username.")
        return clean

    @staticmethod
    def _hostname(value: object) -> str:
        clean = str(value).strip()
        if (
            not clean
            or len(clean) > 255
            or any(character.isspace() for character in clean)
            or "://" in clean
        ):
            raise RemoteConnectionError("Enter a valid host name or IP address.")
        return clean

    @staticmethod
    def _console_device_id(value: object) -> str:
        clean = str(value).strip()
        if (
            not clean
            or len(clean) > 128
            or any(not (char.isalnum() or char in "_-") for char in clean)
        ):
            raise RemoteConnectionError("Choose an attached console device.")
        return clean

    @staticmethod
    def _console_device_path(value: object) -> str:
        clean = str(value).strip()
        if (
            not clean.startswith("/dev/")
            or len(clean) > 512
            or any(char in "\r\n\x00" for char in clean)
        ):
            raise RemoteConnectionError("Choose a valid local console device.")
        return clean

    @staticmethod
    def _folder(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "user_id": str(row["user_id"]),
            "visibility": str(row["visibility"]),
            "name": str(row["name"]),
            "parent_id": str(row["parent_id"]),
            "credential_mode": str(row["credential_mode"]),
            "credential_id": str(row["credential_id"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    @staticmethod
    def _public_credential(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "user_id": str(row["user_id"]),
            "visibility": str(row["visibility"]),
            "name": str(row["name"]),
            "username": str(row["remote_username"]),
            "scope_host_id": str(row["scope_host_id"]),
            "scoped_host_name": str(row["scoped_host_name"]),
            "usage_count": int(row["usage_count"]),
            "folder_usage_count": int(row["folder_usage_count"]),
            "has_secret": bool(row["secret_encrypted"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    @staticmethod
    def _host(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "user_id": str(row["user_id"]),
            "visibility": str(row["visibility"]),
            "name": str(row["name"]),
            "host": str(row["host"]),
            "port": int(row["port"]),
            "protocol": str(row["protocol"]),
            "folder_id": str(row["folder_id"]),
            "credential_mode": str(row["credential_mode"]),
            "credential_id": str(row["credential_id"]),
            "credential_name": str(row["credential_name"] or ""),
            "remote_username": str(row["remote_username"] or ""),
            "credential_scope_host_id": str(
                row["credential_scope_host_id"] or ""
            ),
            "allow_unknown_hosts": bool(row["allow_unknown_hosts"]),
            "allow_legacy_algorithms": bool(row["allow_legacy_algorithms"]),
            "notes": str(row["notes"]),
            "console_device_id": str(row["console_device_id"]),
            "console_device_path": str(row["console_device_path"]),
            "console_device_label": str(row["console_device_label"]),
            "console_baud_rate": int(row["console_baud_rate"]),
            "console_data_bits": int(row["console_data_bits"]),
            "console_parity": str(row["console_parity"]),
            "console_stop_bits": str(
                serial_settings(stop_bits=row["console_stop_bits"])["stop_bits"]
            ),
            "console_flow_control": str(row["console_flow_control"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    @staticmethod
    def _require_folder(
        connection: sqlite3.Connection,
        folder_id: str,
        user_id: str,
        *,
        allow_root: bool = False,
    ) -> sqlite3.Row | None:
        if not folder_id and allow_root:
            return None
        row = connection.execute(
            "SELECT * FROM remote_connection_folders WHERE id = ? AND user_id = ?",
            (folder_id, user_id),
        ).fetchone()
        if not row:
            raise RemoteConnectionError("Saved folder not found.")
        return row

    @staticmethod
    def _require_host_row(
        connection: sqlite3.Connection, host_id: str, user_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM remote_connection_hosts WHERE id = ? AND user_id = ?",
            (host_id, user_id),
        ).fetchone()
        if not row:
            raise RemoteConnectionError("Saved host not found.")
        return row

    @staticmethod
    def _require_credential_row(
        connection: sqlite3.Connection, credential_id: str, user_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM remote_connection_credentials
            WHERE id = ? AND user_id = ?
            """,
            (credential_id, user_id),
        ).fetchone()
        if not row:
            raise RemoteConnectionError("Saved credential not found.")
        return row

    @staticmethod
    def _require_unique_folder_name(
        connection: sqlite3.Connection,
        user_id: str,
        parent_id: str,
        name: str,
        *,
        exclude_id: str = "",
    ) -> None:
        row = connection.execute(
            """
            SELECT id FROM remote_connection_folders
            WHERE user_id = ? AND parent_id = ? AND name = ? COLLATE NOCASE
              AND id != ?
            """,
            (user_id, parent_id, name, exclude_id),
        ).fetchone()
        if row:
            raise RemoteConnectionError("That folder name is already used here.")

    @staticmethod
    def _require_unique_host_name(
        connection: sqlite3.Connection,
        user_id: str,
        folder_id: str,
        name: str,
        *,
        exclude_id: str = "",
    ) -> None:
        row = connection.execute(
            """
            SELECT id FROM remote_connection_hosts
            WHERE user_id = ? AND folder_id = ? AND name = ? COLLATE NOCASE
              AND id != ?
            """,
            (user_id, folder_id, name, exclude_id),
        ).fetchone()
        if row:
            raise RemoteConnectionError("That host name is already used here.")

    @staticmethod
    def _require_unique_credential_name(
        connection: sqlite3.Connection,
        user_id: str,
        name: str,
        *,
        exclude_id: str = "",
    ) -> None:
        row = connection.execute(
            """
            SELECT id FROM remote_connection_credentials
            WHERE user_id = ? AND name = ? COLLATE NOCASE AND id != ?
            """,
            (user_id, name, exclude_id),
        ).fetchone()
        if row:
            raise RemoteConnectionError("That credential name is already used.")

    @staticmethod
    def _folder_descends_from(
        connection: sqlite3.Connection,
        candidate_id: str,
        ancestor_id: str,
        user_id: str,
    ) -> bool:
        current = candidate_id
        visited: set[str] = set()
        while current and current not in visited:
            if current == ancestor_id:
                return True
            visited.add(current)
            row = connection.execute(
                """
                SELECT parent_id FROM remote_connection_folders
                WHERE id = ? AND user_id = ?
                """,
                (current, user_id),
            ).fetchone()
            current = str(row["parent_id"]) if row else ""
        return False

    @contextmanager
    def transaction(self):
        """Keep permission checks and a complete library mutation atomic."""
        key = str(self.path.resolve())
        if key in _transactions.get():
            connection = _transactions.get()[key]
            savepoint = "library_" + secrets.token_hex(8)
            connection.execute(f"SAVEPOINT {savepoint}")
            try:
                yield
            except Exception:
                connection.execute(f"ROLLBACK TO {savepoint}")
                raise
            finally:
                connection.execute(f"RELEASE {savepoint}")
            return
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            token = _transactions.set({**_transactions.get(), key: connection})
            try:
                yield
            finally:
                _transactions.reset(token)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        existing = _transactions.get().get(str(self.path.resolve()))
        if existing is not None:
            yield existing
            return
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 10000")
            self._initialize(connection)
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
            for path in (
                self.path,
                self.path.with_name(f"{self.path.name}-wal"),
                self.path.with_name(f"{self.path.name}-shm"),
            ):
                try:
                    os.chmod(path, 0o600)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS remote_connection_folders (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                parent_id TEXT NOT NULL DEFAULT '',
                credential_mode TEXT NOT NULL DEFAULT 'inherit',
                credential_id TEXT NOT NULL DEFAULT '',
                visibility TEXT NOT NULL DEFAULT 'private',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS remote_connection_folders_owner
                ON remote_connection_folders(user_id, parent_id, name);

            CREATE TABLE IF NOT EXISTS remote_connection_credentials (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                remote_username TEXT NOT NULL,
                secret_encrypted TEXT NOT NULL,
                scope_host_id TEXT NOT NULL DEFAULT '',
                visibility TEXT NOT NULL DEFAULT 'private',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS remote_connection_credentials_owner
                ON remote_connection_credentials(user_id, name);

            CREATE TABLE IF NOT EXISTS remote_connection_hosts (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'ssh',
                folder_id TEXT NOT NULL DEFAULT '',
                credential_mode TEXT NOT NULL DEFAULT 'credential',
                credential_id TEXT NOT NULL,
                visibility TEXT NOT NULL DEFAULT 'inherit',
                allow_unknown_hosts INTEGER NOT NULL DEFAULT 0,
                allow_legacy_algorithms INTEGER NOT NULL DEFAULT 0,
                notes TEXT NOT NULL DEFAULT '',
                console_device_id TEXT NOT NULL DEFAULT '',
                console_device_path TEXT NOT NULL DEFAULT '',
                console_device_label TEXT NOT NULL DEFAULT '',
                console_baud_rate INTEGER NOT NULL DEFAULT 9600,
                console_data_bits INTEGER NOT NULL DEFAULT 8,
                console_parity TEXT NOT NULL DEFAULT 'none',
                console_stop_bits TEXT NOT NULL DEFAULT '1',
                console_flow_control TEXT NOT NULL DEFAULT 'none',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS remote_connection_hosts_owner
                ON remote_connection_hosts(user_id, folder_id, name);
            """
        )
        # Gunicorn workers can initialize this store concurrently on the first
        # boot after an upgrade. Serialize the inspect-and-alter sequence so a
        # second worker re-reads the completed schema instead of attempting the
        # same ALTER TABLE and failing with a duplicate-column error.
        connection.execute("BEGIN IMMEDIATE")
        try:
            host_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(remote_connection_hosts)"
                )
            }
            if "protocol" not in host_columns:
                connection.execute(
                    "ALTER TABLE remote_connection_hosts "
                    "ADD COLUMN protocol TEXT NOT NULL DEFAULT 'ssh'"
                )
            if "credential_mode" not in host_columns:
                connection.execute(
                    "ALTER TABLE remote_connection_hosts "
                    "ADD COLUMN credential_mode TEXT NOT NULL DEFAULT 'credential'"
                )
                connection.execute(
                    """
                    UPDATE remote_connection_hosts
                    SET credential_mode = CASE
                        WHEN credential_id = '' THEN 'none'
                        ELSE 'credential'
                    END
                    """
                )
            console_columns = {
                "console_device_id": "TEXT NOT NULL DEFAULT ''",
                "console_device_path": "TEXT NOT NULL DEFAULT ''",
                "console_device_label": "TEXT NOT NULL DEFAULT ''",
                "console_baud_rate": "INTEGER NOT NULL DEFAULT 9600",
                "console_data_bits": "INTEGER NOT NULL DEFAULT 8",
                "console_parity": "TEXT NOT NULL DEFAULT 'none'",
                "console_stop_bits": "TEXT NOT NULL DEFAULT '1'",
                "console_flow_control": "TEXT NOT NULL DEFAULT 'none'",
            }
            for column, definition in console_columns.items():
                if column not in host_columns:
                    connection.execute(
                        f"ALTER TABLE remote_connection_hosts ADD COLUMN {column} {definition}"
                    )
            folder_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(remote_connection_folders)"
                )
            }
            if "credential_mode" not in folder_columns:
                connection.execute(
                    "ALTER TABLE remote_connection_folders "
                    "ADD COLUMN credential_mode TEXT NOT NULL DEFAULT 'inherit'"
                )
            if "credential_id" not in folder_columns:
                connection.execute(
                    "ALTER TABLE remote_connection_folders "
                    "ADD COLUMN credential_id TEXT NOT NULL DEFAULT ''"
                )
            for table in (
                "remote_connection_folders",
                "remote_connection_credentials",
                "remote_connection_hosts",
            ):
                columns = {
                    str(row["name"])
                    for row in connection.execute(f"PRAGMA table_info({table})")
                }
                if "visibility" not in columns:
                    connection.execute(
                        f"ALTER TABLE {table} "
                        "ADD COLUMN visibility TEXT NOT NULL DEFAULT 'admins_only'"
                    )

        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()


__all__ = ["RemoteConnectionError", "RemoteConnectionStore"]
