from __future__ import annotations

from copy import deepcopy
import json
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from .auth import AuthStore
from .file_transactions import file_transaction
from .certificate_automation import (
    CertificateAutomationStore,
    VALID_KEY_SIZES,
    normalize_certificate_identity,
    validate_ca_bundle,
    validate_enrollment_url,
    validate_template_identifier,
)
from .remote_connections import RemoteConnectionStore
from .serial_console import serial_settings
from .smtp_tools import SMTPSettingsStore
from .time_settings import TimeSettingsStore


class SingleRecordBackupStore:
    """Adapt one validated settings object to the backup list-store contract."""

    def __init__(
        self,
        *,
        label: str,
        read: Callable[[], dict[str, Any]],
        write: Callable[[dict[str, Any]], Any],
        clear: Callable[[], Any],
        transaction_path: Path,
    ) -> None:
        self.label = label
        self._read = read
        self._write = write
        self._clear = clear
        self.transaction_path = transaction_path

    def all(self) -> list[dict[str, Any]]:
        return [{"name": self.label, "settings": deepcopy(self._read())}]

    def replace_all(self, values: list[dict[str, Any]]) -> None:
        with file_transaction(self.transaction_path):
            if not values:
                self.clear()
                return
            if len(values) != 1 or not isinstance(values[0].get("settings"), dict):
                raise ValueError(f"{self.label} backup data is invalid.")
            self._write(deepcopy(values[0]["settings"]))

    def clear(self) -> None:
        with file_transaction(self.transaction_path):
            self._clear()


class TimeSettingsBackupStore(SingleRecordBackupStore):
    def __init__(self, store: TimeSettingsStore) -> None:
        super().__init__(
            label="Toolkit timezone",
            read=store.get,
            write=lambda settings: store.save(settings.get("timezone", "")),
            clear=lambda: store.path.unlink(missing_ok=True),
            transaction_path=store.path,
        )
        self.store = store

    def all(self) -> list[dict[str, Any]]:
        return super().all() if self.store.path.exists() else []

    def count(self) -> int:
        return int(self.store.path.exists())


class SMTPSettingsBackupStore(SingleRecordBackupStore):
    def __init__(self, store: SMTPSettingsStore) -> None:
        def read() -> dict[str, Any]:
            settings = store.get(include_password=True)
            return {
                key: value
                for key, value in settings.items()
                if key not in {"configured", "has_password"}
            }

        def write(settings: dict[str, Any]) -> None:
            password = str(settings.pop("password", ""))
            if settings.get("host") or settings.get("from_address"):
                store.save(settings, password=password, clear_password=not password)
            else:
                store.path.unlink(missing_ok=True)

        super().__init__(
            label="SMTP delivery",
            read=read,
            write=write,
            clear=lambda: store.path.unlink(missing_ok=True),
            transaction_path=store.path,
        )
        self.store = store

    def all(self) -> list[dict[str, Any]]:
        return super().all() if self.store.path.exists() else []

    def count(self) -> int:
        return int(self.store.path.exists())


class AccessProfilesBackupStore:
    def __init__(self, store: AuthStore) -> None:
        self.store = store
        self.transaction_path = store.path

    def all(self) -> list[dict[str, Any]]:
        return self.store.access_profiles()

    def count(self) -> int:
        return len(self.store.access_profiles())

    def replace_all(self, values: list[dict[str, Any]]) -> None:
        self.store.replace_access_profiles(values)

    def clear(self) -> None:
        self.store.replace_access_profiles([])

    def backup_snapshot(self) -> dict[str, Any]:
        return deepcopy(self.store._read())

    def restore_backup_snapshot(self, snapshot: dict[str, Any]) -> None:
        self.store._write(deepcopy(snapshot))


class RemoteConnectionBackupStore:
    """Export owner-name keyed remote libraries with plaintext only inside the outer cipher."""

    def __init__(
        self,
        store: RemoteConnectionStore,
        auth_store: AuthStore,
    ) -> None:
        self.store = store
        self.auth_store = auth_store

    def all(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for user in self.auth_store.users():
            user_id = str(user["id"])
            library = self.store.library_for_user(user_id)
            library = {
                key: [item for item in items if item.get("owned")]
                for key, items in library.items()
            }
            if not any(library.values()):
                continue
            credentials = []
            for credential in library["credentials"]:
                resolved = self.store.resolve_credential(
                    str(credential["id"]),
                    user_id=user_id,
                    host_id=str(credential["scope_host_id"]),
                )
                credentials.append(
                    {
                        "id": credential["id"],
                        "name": credential["name"],
                        "username": resolved["username"],
                        "password": resolved["password"],
                        "scope_host_id": credential["scope_host_id"],
                        "visibility": credential["visibility"],
                    }
                )
            records.append(
                {
                    "name": str(user["username"]),
                    "owner_username": str(user["username"]),
                    "folders": library["folders"],
                    "credentials": credentials,
                    "hosts": library["hosts"],
                }
            )
        return records

    def count(self) -> int:
        return sum(
            any(self.store.library_for_user(str(user["id"])).values())
            for user in self.auth_store.users()
        )

    def replace_all(self, values: list[dict[str, Any]]) -> None:
        users = {
            str(user["username"]).casefold(): user
            for user in self.auth_store.users()
        }
        prepared: list[dict[str, Any]] = []
        seen_owners: set[str] = set()
        for library in values:
            if not isinstance(library, dict):
                raise ValueError("Remote Terminal backup data is invalid.")
            owner = str(
                library.get("owner_username") or library.get("name") or ""
            ).strip()
            folded_owner = owner.casefold()
            if not owner or folded_owner in seen_owners:
                raise ValueError("Remote Terminal backup owners must be unique.")
            seen_owners.add(folded_owner)
            local_user = users.get(folded_owner)
            if not local_user:
                raise ValueError(
                    f"Create or map local user {owner} before importing their Remote Terminal library."
                )
            prepared.append(
                self._prepare_library(library, str(local_user["id"]))
            )

        with self.store._connect() as connection:
            connection.execute("DELETE FROM remote_connection_hosts")
            connection.execute("DELETE FROM remote_connection_credentials")
            connection.execute("DELETE FROM remote_connection_folders")
            for library in prepared:
                for folder in library["folders"]:
                    connection.execute(
                        """
                        INSERT INTO remote_connection_folders
                            (id, user_id, name, parent_id, credential_mode,
                             credential_id, visibility, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        folder,
                    )
                for credential in library["credentials"]:
                    connection.execute(
                        """
                        INSERT INTO remote_connection_credentials
                            (id, user_id, name, remote_username, secret_encrypted,
                             scope_host_id, visibility, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        credential,
                    )
                for host in library["hosts"]:
                    connection.execute(
                        """
                        INSERT INTO remote_connection_hosts
                            (id, user_id, name, host, port, protocol, folder_id,
                             credential_mode, credential_id, visibility,
                             allow_unknown_hosts,
                             allow_legacy_algorithms, notes, console_device_id,
                             console_device_path, console_device_label,
                             console_baud_rate, console_data_bits, console_parity,
                             console_stop_bits, console_flow_control,
                             created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        host,
                    )

    def clear(self) -> None:
        self.store.clear()

    def backup_snapshot(self) -> dict[str, list[dict[str, Any]]]:
        with self.store._connect() as connection:
            return {
                "folders": [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM remote_connection_folders"
                    )
                ],
                "credentials": [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM remote_connection_credentials"
                    )
                ],
                "hosts": [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM remote_connection_hosts"
                    )
                ],
            }

    def restore_backup_snapshot(
        self, snapshot: dict[str, list[dict[str, Any]]]
    ) -> None:
        with self.store._connect() as connection:
            connection.execute("DELETE FROM remote_connection_hosts")
            connection.execute("DELETE FROM remote_connection_credentials")
            connection.execute("DELETE FROM remote_connection_folders")
            self._insert_snapshot_rows(
                connection, "remote_connection_folders", snapshot["folders"]
            )
            self._insert_snapshot_rows(
                connection,
                "remote_connection_credentials",
                snapshot["credentials"],
            )
            self._insert_snapshot_rows(
                connection, "remote_connection_hosts", snapshot["hosts"]
            )

    @staticmethod
    def _insert_snapshot_rows(
        connection: Any, table: str, rows: list[dict[str, Any]]
    ) -> None:
        for row in rows:
            columns = list(row)
            connection.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _ in columns)})",
                tuple(row[column] for column in columns),
            )

    def _prepare_library(
        self, library: dict[str, Any], user_id: str
    ) -> dict[str, list[tuple[Any, ...]]]:
        raw_folders = library.get("folders", [])
        raw_credentials = library.get("credentials", [])
        raw_hosts = library.get("hosts", [])
        if not all(
            isinstance(collection, list)
            for collection in (raw_folders, raw_credentials, raw_hosts)
        ):
            raise ValueError("Remote Terminal backup collections are invalid.")
        if len(raw_folders) > 10_000 or len(raw_credentials) > 10_000 or len(raw_hosts) > 50_000:
            raise ValueError("Remote Terminal backup contains too many records.")

        now = time.time()
        folder_ids = {
            str(item.get("id", "")): f"rf_{secrets.token_hex(10)}"
            for item in raw_folders
            if isinstance(item, dict) and str(item.get("id", ""))
        }
        credential_ids = {
            str(item.get("id", "")): f"rc_{secrets.token_hex(10)}"
            for item in raw_credentials
            if isinstance(item, dict) and str(item.get("id", ""))
        }
        host_ids = {
            str(item.get("id", "")): f"rh_{secrets.token_hex(10)}"
            for item in raw_hosts
            if isinstance(item, dict) and str(item.get("id", ""))
        }
        if len(folder_ids) != len(raw_folders) or len(credential_ids) != len(raw_credentials) or len(host_ids) != len(raw_hosts):
            raise ValueError("Remote Terminal backup record IDs must be present and unique.")
        scoped_credentials = {
            str(item["id"])
            for item in raw_credentials
            if str(item.get("scope_host_id", ""))
        }

        folder_rows: list[tuple[Any, ...]] = []
        folder_names: set[tuple[str, str]] = set()
        parents: dict[str, str] = {}
        for item in raw_folders:
            old_id = str(item["id"])
            old_parent = str(item.get("parent_id", ""))
            if old_parent and old_parent not in folder_ids:
                raise ValueError("Remote Terminal backup contains a missing parent folder.")
            name = self.store._name(item.get("name", ""), "Folder name")
            parent_id = folder_ids.get(old_parent, "")
            credential_mode = str(
                item.get("credential_mode", "inherit")
            ).strip().lower()
            old_credential = str(item.get("credential_id", ""))
            if credential_mode not in {"inherit", "credential", "none"}:
                raise ValueError("Remote Terminal folder credential mode is invalid.")
            if credential_mode == "credential":
                if old_credential not in credential_ids:
                    raise ValueError(
                        "Remote Terminal folder references a missing credential."
                    )
                if old_credential in scoped_credentials:
                    raise ValueError(
                        "Remote Terminal folders require shared credentials."
                    )
            else:
                old_credential = ""
            unique_key = (parent_id, name.casefold())
            if unique_key in folder_names:
                raise ValueError("Remote Terminal folders must be unique within a parent.")
            folder_names.add(unique_key)
            parents[old_id] = old_parent
            visibility = self.store._clean_visibility(
                item.get("visibility", "admins_only"), allow_inherit=True
            )
            if visibility == "inherit" and not parent_id:
                raise ValueError("A root Remote Terminal folder cannot inherit visibility.")
            folder_rows.append(
                (
                    folder_ids[old_id],
                    user_id,
                    name,
                    parent_id,
                    credential_mode,
                    credential_ids.get(old_credential, ""),
                    visibility,
                    now,
                    now,
                )
            )
        for folder_id in parents:
            seen: set[str] = set()
            cursor = folder_id
            while cursor:
                if cursor in seen:
                    raise ValueError("Remote Terminal backup contains a folder cycle.")
                seen.add(cursor)
                cursor = parents.get(cursor, "")

        credential_rows: list[tuple[Any, ...]] = []
        credential_names: set[str] = set()
        for item in raw_credentials:
            old_id = str(item["id"])
            name = self.store._name(item.get("name", ""), "Credential name")
            if name.casefold() in credential_names:
                raise ValueError("Remote Terminal credential names must be unique.")
            credential_names.add(name.casefold())
            username = self.store._username(item.get("username", ""))
            password = str(item.get("password", ""))
            encrypted = self.store._encrypt_secret(password)
            old_scope = str(item.get("scope_host_id", ""))
            if old_scope and old_scope not in host_ids:
                raise ValueError("Remote Terminal credential references a missing host.")
            visibility = self.store._clean_visibility(
                item.get("visibility", "admins_only")
            )
            credential_rows.append(
                (
                    credential_ids[old_id], user_id, name, username, encrypted,
                    host_ids.get(old_scope, ""), visibility,
                    now, now,
                )
            )

        host_rows: list[tuple[Any, ...]] = []
        host_names: set[tuple[str, str]] = set()
        host_credentials: dict[str, str] = {}
        for item in raw_hosts:
            old_id = str(item["id"])
            old_folder = str(item.get("folder_id", ""))
            old_credential = str(item.get("credential_id", ""))
            if old_folder and old_folder not in folder_ids:
                raise ValueError("Remote Terminal host references a missing folder.")
            name = self.store._name(item.get("name", ""), "Host name")
            folder_id = folder_ids.get(old_folder, "")
            unique_key = (folder_id, name.casefold())
            if unique_key in host_names:
                raise ValueError("Remote Terminal host names must be unique within a folder.")
            host_names.add(unique_key)
            protocol = str(item.get("protocol", "ssh")).strip().lower()
            if protocol not in {"ssh", "telnet", "console"}:
                raise ValueError("Remote Terminal protocol must be SSH, Telnet, or Console.")
            if protocol == "console":
                console_device_id = self.store._console_device_id(
                    item.get("console_device_id", "")
                )
                console_device_path = self.store._console_device_path(
                    item.get("console_device_path", item.get("host", ""))
                )
                console_device_label = self.store._name(
                    item.get("console_device_label", "") or console_device_path,
                    "Console device label",
                )
                console = serial_settings(
                    baud_rate=item.get("console_baud_rate", 9600),
                    data_bits=item.get("console_data_bits", 8),
                    parity=item.get("console_parity", "none"),
                    stop_bits=item.get("console_stop_bits", 1),
                    flow_control=item.get("console_flow_control", "none"),
                )
                host = console_device_path
            else:
                host = self.store._hostname(item.get("host", ""))
                console_device_id = console_device_path = console_device_label = ""
                console = serial_settings()
            credential_mode = str(
                item.get(
                    "credential_mode",
                    "credential" if old_credential else "none",
                )
            ).strip().lower()
            if protocol == "console":
                credential_mode = "none"
                old_credential = ""
            if credential_mode not in {"inherit", "credential", "none"}:
                raise ValueError("Remote Terminal host credential mode is invalid.")
            if credential_mode == "credential" and old_credential not in credential_ids:
                if not (protocol == "telnet" and not old_credential):
                    raise ValueError(
                        "Remote Terminal host references a missing credential."
                    )
            elif credential_mode == "none" and protocol not in {"telnet", "console"}:
                raise ValueError(
                    "Remote Terminal SSH hosts must inherit or use a credential."
                )
            if credential_mode != "credential":
                old_credential = ""
            try:
                port = int(item.get("port", 23 if protocol == "telnet" else 22))
            except (TypeError, ValueError) as exc:
                raise ValueError("Remote Terminal ports must be whole numbers.") from exc
            if protocol == "console":
                port = 0
            elif not 1 <= port <= 65535:
                raise ValueError("Remote Terminal ports must be 1–65535.")
            notes = str(item.get("notes", "")).strip()[:1000]
            host_credentials[old_id] = old_credential
            visibility = self.store._clean_visibility(
                item.get("visibility", "admins_only"), allow_inherit=True
            )
            host_rows.append(
                (
                    host_ids[old_id], user_id, name, host, port, protocol, folder_id,
                    credential_mode,
                    credential_ids.get(old_credential, ""),
                    visibility,
                    int(bool(item.get("allow_unknown_hosts")) and protocol == "ssh"),
                    int(bool(item.get("allow_legacy_algorithms")) and protocol == "ssh"),
                    notes,
                    console_device_id,
                    console_device_path,
                    console_device_label,
                    int(console["baud_rate"]),
                    int(console["data_bits"]),
                    str(console["parity"]),
                    str(console["stop_bits"]),
                    str(console["flow_control"]),
                    now,
                    now,
                )
            )
        for item in raw_credentials:
            old_scope = str(item.get("scope_host_id", ""))
            if old_scope and host_credentials.get(old_scope) != str(item["id"]):
                raise ValueError("A host-specific credential is not assigned to its host.")
        return {"folders": folder_rows, "credentials": credential_rows, "hosts": host_rows}


class CertificateAutomationProfilesBackupStore:
    """Export reusable PKI configuration while excluding issued key material."""

    def __init__(self, store: CertificateAutomationStore) -> None:
        self.store = store

    def all(self) -> list[dict[str, Any]]:
        credentials = []
        for credential in self.store.credential_profiles():
            full = self.store.credential_profile(
                str(credential["id"]), include_password=True
            )
            if full:
                credentials.append(
                    {
                        "id": full["id"],
                        "name": full["name"],
                        "username": full["username"],
                        "password": full.get("password", ""),
                    }
                )
        servers = [
            {
                key: value
                for key, value in server.items()
                if key not in {"credential_name", "has_ca_bundle"}
            }
            for server in self.store.server_profiles()
        ]
        templates = [
            {key: value for key, value in template.items() if key != "server_name"}
            for template in self.store.template_profiles()
        ]
        managed = [
            {
                "id": item["id"],
                "name": item["name"],
                "server_id": item["server_id"],
                "template_id": item["template_id"],
                "common_name": item["common_name"],
                "dns_names": item["dns_names"],
            }
            for item in self.store.managed_certificates()
        ]
        return [
            {"name": "PKI credentials", "records": credentials},
            {"name": "PKI servers", "records": servers},
            {"name": "Certificate templates", "records": templates},
            {"name": "Managed certificate definitions", "records": managed},
        ]

    def count(self) -> int:
        return sum(
            (
                len(self.store.credential_profiles()),
                len(self.store.server_profiles()),
                len(self.store.template_profiles()),
                len(self.store.managed_certificates()),
            )
        )

    def replace_all(self, values: list[dict[str, Any]]) -> None:
        self.import_records(values, "merge")

    @staticmethod
    def record_count(values: list[dict[str, Any]]) -> int:
        return sum(
            len(item.get("records", []))
            for item in values
            if isinstance(item, dict) and isinstance(item.get("records"), list)
        )

    def import_records(
        self, values: list[dict[str, Any]], import_mode: str
    ) -> int:
        if import_mode != "merge":
            raise ValueError(
                "Certificate Automation profiles support Combine only so existing issued certificates remain intact."
            )
        groups = {
            str(item.get("name", "")): item.get("records")
            for item in values
            if isinstance(item, dict)
        }
        expected = {
            "PKI credentials",
            "PKI servers",
            "Certificate templates",
            "Managed certificate definitions",
        }
        if set(groups) != expected or not all(
            isinstance(groups[name], list) for name in expected
        ):
            raise ValueError("Certificate Automation backup data is incomplete.")
        credentials = groups["PKI credentials"]
        servers = groups["PKI servers"]
        templates = groups["Certificate templates"]
        managed = groups["Managed certificate definitions"]
        if any(len(group) > 10_000 for group in (credentials, servers, templates, managed)):
            raise ValueError("Certificate Automation backup contains too many profiles.")

        now = time.time()
        with self.store._connect() as connection:
            credential_ids: dict[str, str] = {}
            seen: set[str] = set()
            for item in credentials:
                old_id = self._record_id(item, "PKI credential")
                name = self._profile_name(item.get("name"))
                if name.casefold() in seen:
                    raise ValueError("PKI credential profile names must be unique.")
                seen.add(name.casefold())
                username = str(item.get("username", "")).strip()
                password = str(item.get("password", ""))
                if not username or len(username) > 320 or not password:
                    raise ValueError("PKI credential backup data is invalid.")
                existing = connection.execute(
                    "SELECT id, created_at FROM pki_credentials WHERE name = ? COLLATE NOCASE",
                    (name,),
                ).fetchone()
                local_id = str(existing["id"]) if existing else self.store._new_id()
                credential_ids[old_id] = local_id
                connection.execute(
                    """
                    INSERT INTO pki_credentials
                        (id, name, username, password_encrypted, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                        username = excluded.username,
                        password_encrypted = excluded.password_encrypted,
                        updated_at = excluded.updated_at
                    """,
                    (
                        local_id, name, username, self.store._encrypt(password),
                        float(existing["created_at"]) if existing else now, now,
                    ),
                )

            server_ids: dict[str, str] = {}
            seen.clear()
            for item in servers:
                old_id = self._record_id(item, "PKI server")
                name = self._profile_name(item.get("name"))
                if name.casefold() in seen:
                    raise ValueError("PKI server profile names must be unique.")
                seen.add(name.casefold())
                if str(item.get("provider", "")) != "adcs_web_enrollment":
                    raise ValueError("The PKI provider in this backup is not supported.")
                enrollment_url = validate_enrollment_url(
                    str(item.get("enrollment_url", ""))
                )
                old_credential = str(item.get("credential_id") or "")
                if old_credential and old_credential not in credential_ids:
                    raise ValueError("PKI server references a missing credential.")
                ca_bundle = str(item.get("ca_bundle_pem", ""))
                if ca_bundle:
                    ca_bundle = validate_ca_bundle(ca_bundle.encode("ascii"))
                strategy = str(item.get("retrieval_strategy", "same_endpoint"))
                if strategy not in {"same_endpoint", "resolved_ipv4"}:
                    raise ValueError("PKI retrieval strategy is invalid.")
                timeout = float(item.get("timeout", 15))
                if not 2 <= timeout <= 60:
                    raise ValueError("PKI timeout must be between 2 and 60 seconds.")
                existing = connection.execute(
                    "SELECT id, created_at FROM pki_servers WHERE name = ? COLLATE NOCASE",
                    (name,),
                ).fetchone()
                local_id = str(existing["id"]) if existing else self.store._new_id()
                server_ids[old_id] = local_id
                connection.execute(
                    """
                    INSERT INTO pki_servers
                        (id, name, provider, enrollment_url, credential_id,
                         ca_bundle_pem, verify_tls, retrieval_strategy, timeout,
                         created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                        provider = excluded.provider,
                        enrollment_url = excluded.enrollment_url,
                        credential_id = excluded.credential_id,
                        ca_bundle_pem = excluded.ca_bundle_pem,
                        verify_tls = excluded.verify_tls,
                        retrieval_strategy = excluded.retrieval_strategy,
                        timeout = excluded.timeout, updated_at = excluded.updated_at
                    """,
                    (
                        local_id, name, "adcs_web_enrollment", enrollment_url,
                        credential_ids.get(old_credential) or None, ca_bundle,
                        int(bool(item.get("verify_tls", True))), strategy, timeout,
                        float(existing["created_at"]) if existing else now, now,
                    ),
                )

            template_ids: dict[str, str] = {}
            seen.clear()
            for item in templates:
                old_id = self._record_id(item, "certificate template")
                name = self._profile_name(item.get("name"))
                if name.casefold() in seen:
                    raise ValueError("Certificate template names must be unique.")
                seen.add(name.casefold())
                old_server = str(item.get("server_id", ""))
                if old_server not in server_ids:
                    raise ValueError("Certificate template references a missing server.")
                identifier = validate_template_identifier(
                    str(item.get("template_identifier", ""))
                )
                key_size = int(item.get("key_size", 2048))
                renewal_days = int(item.get("renewal_days", 30))
                if key_size not in VALID_KEY_SIZES or not 1 <= renewal_days <= 365:
                    raise ValueError("Certificate template backup settings are invalid.")
                existing = connection.execute(
                    "SELECT id, created_at FROM pki_templates WHERE name = ? COLLATE NOCASE",
                    (name,),
                ).fetchone()
                local_id = str(existing["id"]) if existing else self.store._new_id()
                template_ids[old_id] = local_id
                connection.execute(
                    """
                    INSERT INTO pki_templates
                        (id, name, server_id, template_identifier, key_size,
                         renewal_days, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                        server_id = excluded.server_id,
                        template_identifier = excluded.template_identifier,
                        key_size = excluded.key_size,
                        renewal_days = excluded.renewal_days,
                        updated_at = excluded.updated_at
                    """,
                    (
                        local_id, name, server_ids[old_server], identifier,
                        key_size, renewal_days,
                        float(existing["created_at"]) if existing else now, now,
                    ),
                )

            seen.clear()
            for item in managed:
                self._record_id(item, "managed certificate")
                name = self._profile_name(item.get("name"))
                if name.casefold() in seen:
                    raise ValueError("Managed certificate names must be unique.")
                seen.add(name.casefold())
                old_server = str(item.get("server_id", ""))
                old_template = str(item.get("template_id", ""))
                if old_server not in server_ids or old_template not in template_ids:
                    raise ValueError("Managed certificate references a missing profile.")
                common_name, dns_names = normalize_certificate_identity(
                    str(item.get("common_name", "")), item.get("dns_names", [])
                )
                existing = connection.execute(
                    "SELECT id, current_version_id, created_at FROM managed_certificates WHERE name = ? COLLATE NOCASE",
                    (name,),
                ).fetchone()
                local_id = str(existing["id"]) if existing else self.store._new_id()
                connection.execute(
                    """
                    INSERT INTO managed_certificates
                        (id, name, server_id, template_id, common_name,
                         dns_names_json, current_version_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                        server_id = excluded.server_id,
                        template_id = excluded.template_id,
                        common_name = excluded.common_name,
                        dns_names_json = excluded.dns_names_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        local_id, name, server_ids[old_server],
                        template_ids[old_template], common_name,
                        json.dumps(dns_names),
                        str(existing["current_version_id"]) if existing and existing["current_version_id"] else None,
                        float(existing["created_at"]) if existing else now, now,
                    ),
                )
        return sum(len(group) for group in (credentials, servers, templates, managed))

    def clear(self) -> None:
        self.store.clear()

    def backup_snapshot(self) -> dict[str, list[dict[str, Any]]]:
        with self.store._connect() as connection:
            return {
                table: [
                    dict(row)
                    for row in connection.execute(f"SELECT * FROM {table}")
                ]
                for table in (
                    "pki_credentials",
                    "pki_servers",
                    "pki_templates",
                    "managed_certificates",
                )
            }

    def restore_backup_snapshot(
        self, snapshot: dict[str, list[dict[str, Any]]]
    ) -> None:
        with self.store._connect() as connection:
            for table in (
                "managed_certificates",
                "pki_templates",
                "pki_servers",
                "pki_credentials",
            ):
                snapshot_ids = {str(row["id"]) for row in snapshot[table]}
                current_ids = {
                    str(row[0])
                    for row in connection.execute(f"SELECT id FROM {table}")
                }
                added_ids = current_ids - snapshot_ids
                if added_ids:
                    connection.execute(
                        f"DELETE FROM {table} WHERE id IN "
                        f"({', '.join('?' for _ in added_ids)})",
                        tuple(added_ids),
                    )
            for table in (
                "pki_credentials",
                "pki_servers",
                "pki_templates",
                "managed_certificates",
            ):
                self._upsert_snapshot_rows(connection, table, snapshot[table])

    @staticmethod
    def _upsert_snapshot_rows(
        connection: Any, table: str, rows: list[dict[str, Any]]
    ) -> None:
        for row in rows:
            columns = list(row)
            updated = [column for column in columns if column != "id"]
            connection.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _ in columns)}) "
                f"ON CONFLICT(id) DO UPDATE SET "
                + ", ".join(
                    f"{column} = excluded.{column}" for column in updated
                ),
                tuple(row[column] for column in columns),
            )

    @staticmethod
    def _record_id(item: Any, label: str) -> str:
        if not isinstance(item, dict) or not str(item.get("id", "")).strip():
            raise ValueError(f"{label.title()} backup data is invalid.")
        return str(item["id"])

    @staticmethod
    def _profile_name(value: Any) -> str:
        name = str(value or "").strip()
        if not name or len(name) > 100:
            raise ValueError("Certificate profile names must be 1–100 characters.")
        return name
