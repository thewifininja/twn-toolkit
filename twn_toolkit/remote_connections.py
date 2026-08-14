from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from cryptography.fernet import Fernet, InvalidToken

from .duplication import duplicate_name


class RemoteConnectionError(ValueError):
    pass


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

    def library_for_user(self, user_id: str) -> dict[str, list[dict[str, Any]]]:
        with self._connect() as connection:
            folders = connection.execute(
                "SELECT * FROM remote_connection_folders WHERE user_id = ? ORDER BY name COLLATE NOCASE",
                (user_id,),
            ).fetchall()
            credentials = connection.execute(
                """
                SELECT c.*,
                       COUNT(h.id) AS usage_count,
                       COALESCE(scoped.name, '') AS scoped_host_name
                FROM remote_connection_credentials c
                LEFT JOIN remote_connection_hosts h
                  ON h.credential_id = c.id AND h.user_id = c.user_id
                LEFT JOIN remote_connection_hosts scoped
                  ON scoped.id = c.scope_host_id AND scoped.user_id = c.user_id
                WHERE c.user_id = ?
                GROUP BY c.id
                ORDER BY c.name COLLATE NOCASE
                """,
                (user_id,),
            ).fetchall()
            hosts = connection.execute(
                """
                SELECT h.*, c.name AS credential_name,
                       c.remote_username AS remote_username,
                       c.scope_host_id AS credential_scope_host_id
                FROM remote_connection_hosts h
                LEFT JOIN remote_connection_credentials c
                  ON c.id = h.credential_id AND c.user_id = h.user_id
                WHERE h.user_id = ?
                ORDER BY h.name COLLATE NOCASE
                """,
                (user_id,),
            ).fetchall()
        return {
            "folders": [self._folder(row) for row in folders],
            "credentials": [self._public_credential(row) for row in credentials],
            "hosts": [self._host(row) for row in hosts],
        }

    def get_host(self, host_id: str, *, user_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT h.*, c.name AS credential_name,
                       c.remote_username AS remote_username,
                       c.scope_host_id AS credential_scope_host_id
                FROM remote_connection_hosts h
                LEFT JOIN remote_connection_credentials c
                  ON c.id = h.credential_id AND c.user_id = h.user_id
                WHERE h.id = ? AND h.user_id = ?
                """,
                (host_id, user_id),
            ).fetchone()
        return self._host(row) if row else None

    def resolve_credential(
        self, credential_id: str, *, user_id: str, host_id: str = ""
    ) -> dict[str, str]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM remote_connection_credentials
                WHERE id = ? AND user_id = ?
                """,
                (credential_id, user_id),
            ).fetchone()
        if not row:
            raise RemoteConnectionError("Select a valid saved credential.")
        scope_host_id = str(row["scope_host_id"])
        if scope_host_id and scope_host_id != host_id:
            raise RemoteConnectionError(
                "That credential is restricted to its assigned saved host."
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

    def create_folder(
        self, *, user_id: str, name: str, parent_id: str = ""
    ) -> dict[str, Any]:
        clean_name = self._name(name, "Folder name")
        folder_id = f"rf_{secrets.token_hex(10)}"
        now = time.time()
        with self._connect() as connection:
            self._require_folder(connection, parent_id, user_id, allow_root=True)
            self._require_unique_folder_name(
                connection, user_id, parent_id, clean_name
            )
            connection.execute(
                """
                INSERT INTO remote_connection_folders
                    (id, user_id, name, parent_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (folder_id, user_id, clean_name, parent_id, now, now),
            )
        return self.get_folder(folder_id, user_id=user_id)  # type: ignore[return-value]

    def get_folder(self, folder_id: str, *, user_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM remote_connection_folders WHERE id = ? AND user_id = ?",
                (folder_id, user_id),
            ).fetchone()
        return self._folder(row) if row else None

    def update_folder(
        self, folder_id: str, *, user_id: str, name: str, parent_id: str
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
            connection.execute(
                """
                UPDATE remote_connection_folders
                SET name = ?, parent_id = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (clean_name, parent_id, time.time(), folder_id, user_id),
            )
        return self.get_folder(str(existing["id"]), user_id=user_id)  # type: ignore[return-value]

    def duplicate_folder(self, folder_id: str, *, user_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            source = self._require_folder(connection, folder_id, user_id)
            sibling_names = [
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT name FROM remote_connection_folders
                    WHERE user_id = ? AND parent_id = ?
                    """,
                    (user_id, source["parent_id"]),
                )
            ]
        copied = self.create_folder(
            user_id=user_id,
            name=duplicate_name(str(source["name"]), sibling_names),
            parent_id=str(source["parent_id"]),
        )
        self._copy_folder_children(
            source_id=folder_id, destination_id=str(copied["id"]), user_id=user_id
        )
        return copied

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
            connection.execute(
                "DELETE FROM remote_connection_credentials WHERE id = ? AND user_id = ?",
                (credential_id, user_id),
            )

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
    ) -> dict[str, Any]:
        clean_name = self._name(name, "Host name")
        clean_host = self._hostname(host)
        clean_notes = str(notes).strip()[:1000]
        clean_protocol = str(protocol).strip().lower()
        if clean_protocol not in {"ssh", "telnet"}:
            raise RemoteConnectionError("Choose SSH or Telnet.")
        if not 1 <= int(port) <= 65535:
            raise RemoteConnectionError("Port must be between 1 and 65535.")
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
                credential_name = self._name(
                    host_credential.get("name", "") or f"{clean_name} credentials",
                    "Credential name",
                )
                remote_username = self._username(
                    host_credential.get("username", "")
                )
                password = str(host_credential.get("password", ""))
                self._require_unique_credential_name(
                    connection,
                    user_id,
                    credential_name,
                    exclude_id=old_scoped_credential_id,
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
                if credential_id:
                    credential = self._require_credential_row(
                        connection, credential_id, user_id
                    )
                    if str(credential["scope_host_id"]) not in {"", host_id}:
                        raise RemoteConnectionError(
                            "Select a shared credential or this host's own credential."
                        )
                elif clean_protocol != "telnet":
                    raise RemoteConnectionError(
                        "Assign a credential to saved SSH hosts."
                    )

            values = (
                clean_name,
                clean_host,
                int(port),
                clean_protocol,
                folder_id,
                credential_id,
                int(bool(allow_unknown_hosts) and clean_protocol == "ssh"),
                int(bool(allow_legacy_algorithms) and clean_protocol == "ssh"),
                clean_notes,
                now,
            )
            if is_update:
                connection.execute(
                    """
                    UPDATE remote_connection_hosts
                    SET name = ?, host = ?, port = ?, protocol = ?, folder_id = ?,
                        credential_id = ?, allow_unknown_hosts = ?,
                        allow_legacy_algorithms = ?, notes = ?, updated_at = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (*values, host_id, user_id),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO remote_connection_hosts
                        (id, user_id, name, host, port, protocol, folder_id, credential_id,
                         allow_unknown_hosts, allow_legacy_algorithms, notes,
                         created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        return self.save_host(
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
        )

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

    def _copy_folder_children(
        self, *, source_id: str, destination_id: str, user_id: str
    ) -> None:
        library = self.library_for_user(user_id)
        for host in [item for item in library["hosts"] if item["folder_id"] == source_id]:
            host_credential = None
            credential_id = str(host["credential_id"])
            if host["credential_scope_host_id"] == host["id"]:
                resolved = self.resolve_credential(
                    credential_id, user_id=user_id, host_id=str(host["id"])
                )
                existing_credential_names = [
                    str(item["name"])
                    for item in self.library_for_user(user_id)["credentials"]
                ]
                host_credential = {
                    "name": duplicate_name(
                        str(host["credential_name"]), existing_credential_names
                    ),
                    "username": resolved["username"],
                    "password": resolved["password"],
                }
                credential_id = ""
            self.save_host(
                user_id=user_id,
                name=str(host["name"]),
                host=str(host["host"]),
                port=int(host["port"]),
                folder_id=destination_id,
                credential_id=credential_id,
                allow_unknown_hosts=bool(host["allow_unknown_hosts"]),
                allow_legacy_algorithms=bool(host["allow_legacy_algorithms"]),
                notes=str(host["notes"]),
                host_credential=host_credential,
                protocol=str(host.get("protocol", "ssh")),
            )
        for folder in [item for item in library["folders"] if item["parent_id"] == source_id]:
            copied_folder = self.create_folder(
                user_id=user_id,
                name=str(folder["name"]),
                parent_id=destination_id,
            )
            self._copy_folder_children(
                source_id=str(folder["id"]),
                destination_id=str(copied_folder["id"]),
                user_id=user_id,
            )

    def _credential_by_id(
        self, credential_id: str, *, user_id: str
    ) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT c.*,
                       COUNT(h.id) AS usage_count,
                       COALESCE(scoped.name, '') AS scoped_host_name
                FROM remote_connection_credentials c
                LEFT JOIN remote_connection_hosts h
                  ON h.credential_id = c.id AND h.user_id = c.user_id
                LEFT JOIN remote_connection_hosts scoped
                  ON scoped.id = c.scope_host_id AND scoped.user_id = c.user_id
                WHERE c.id = ? AND c.user_id = ?
                GROUP BY c.id
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
    def _folder(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "parent_id": str(row["parent_id"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    @staticmethod
    def _public_credential(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "username": str(row["remote_username"]),
            "scope_host_id": str(row["scope_host_id"]),
            "scoped_host_name": str(row["scoped_host_name"]),
            "usage_count": int(row["usage_count"]),
            "has_secret": bool(row["secret_encrypted"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    @staticmethod
    def _host(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "host": str(row["host"]),
            "port": int(row["port"]),
            "protocol": str(row["protocol"]),
            "folder_id": str(row["folder_id"]),
            "credential_id": str(row["credential_id"]),
            "credential_name": str(row["credential_name"] or ""),
            "remote_username": str(row["remote_username"] or ""),
            "credential_scope_host_id": str(
                row["credential_scope_host_id"] or ""
            ),
            "allow_unknown_hosts": bool(row["allow_unknown_hosts"]),
            "allow_legacy_algorithms": bool(row["allow_legacy_algorithms"]),
            "notes": str(row["notes"]),
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
    def _connect(self) -> Iterator[sqlite3.Connection]:
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
                credential_id TEXT NOT NULL,
                allow_unknown_hosts INTEGER NOT NULL DEFAULT 0,
                allow_legacy_algorithms INTEGER NOT NULL DEFAULT 0,
                notes TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS remote_connection_hosts_owner
                ON remote_connection_hosts(user_id, folder_id, name);
            """
        )
        columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(remote_connection_hosts)"
            )
        }
        if "protocol" not in columns:
            connection.execute(
                "ALTER TABLE remote_connection_hosts "
                "ADD COLUMN protocol TEXT NOT NULL DEFAULT 'ssh'"
            )


__all__ = ["RemoteConnectionError", "RemoteConnectionStore"]
