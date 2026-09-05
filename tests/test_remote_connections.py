from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest

from twn_toolkit.remote_connections import (
    RemoteConnectionError,
    RemoteConnectionStore,
)


class RemoteConnectionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = RemoteConnectionStore(self.directory.name, "test-secret-key")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_credentials_are_encrypted_write_only_and_owner_scoped(self) -> None:
        credential = self.store.save_credential(
            user_id="operator-one",
            name="Network admin",
            remote_username="netadmin",
            password="not-in-plaintext",
        )

        self.assertTrue(credential["has_secret"])
        self.assertNotIn("password", credential)
        self.assertNotIn("secret_encrypted", credential)
        self.assertNotIn(
            b"not-in-plaintext",
            self.store.path.read_bytes(),
        )
        self.assertEqual(
            self.store.resolve_credential(
                credential["id"], user_id="operator-one"
            )["password"],
            "not-in-plaintext",
        )
        with self.assertRaises(RemoteConnectionError):
            self.store.resolve_credential(
                credential["id"], user_id="operator-two"
            )

    def test_existing_library_migrates_to_explicit_credential_modes(self) -> None:
        self.store.clear()
        with sqlite3.connect(self.store.path) as connection:
            connection.executescript(
                """
                CREATE TABLE remote_connection_folders (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
                    parent_id TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE remote_connection_credentials (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
                    remote_username TEXT NOT NULL, secret_encrypted TEXT NOT NULL,
                    scope_host_id TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE remote_connection_hosts (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
                    host TEXT NOT NULL, port INTEGER NOT NULL,
                    protocol TEXT NOT NULL DEFAULT 'ssh', folder_id TEXT NOT NULL DEFAULT '',
                    credential_id TEXT NOT NULL, allow_unknown_hosts INTEGER NOT NULL DEFAULT 0,
                    allow_legacy_algorithms INTEGER NOT NULL DEFAULT 0,
                    notes TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                INSERT INTO remote_connection_folders
                    VALUES ('folder', 'operator', 'Branches', '', 1, 1);
                INSERT INTO remote_connection_credentials
                    VALUES ('credential', 'operator', 'Admin', 'admin', 'encrypted', '', 1, 1);
                INSERT INTO remote_connection_hosts
                    VALUES ('ssh-host', 'operator', 'SSH', '192.0.2.10', 22, 'ssh',
                            'folder', 'credential', 0, 0, '', 1, 1);
                INSERT INTO remote_connection_hosts
                    VALUES ('telnet-host', 'operator', 'Telnet', '192.0.2.11', 23, 'telnet',
                            'folder', '', 0, 0, '', 1, 1);
                """
            )

        migrated = RemoteConnectionStore(self.directory.name, "test-secret-key")
        library = migrated.library_for_user("operator")
        ssh_host = next(item for item in library["hosts"] if item["id"] == "ssh-host")
        telnet_host = next(item for item in library["hosts"] if item["id"] == "telnet-host")

        self.assertEqual(library["folders"][0]["credential_mode"], "inherit")
        self.assertEqual(library["folders"][0]["visibility"], "admins_only")
        self.assertEqual(library["credentials"][0]["visibility"], "admins_only")
        self.assertTrue(all(item["visibility"] == "admins_only" for item in library["hosts"]))
        self.assertEqual(ssh_host["credential_mode"], "credential")
        self.assertEqual(telnet_host["credential_mode"], "none")

    def test_visibility_allows_global_and_admin_only_use_without_secret_disclosure(self) -> None:
        credential = self.store.save_credential(
            user_id="owner",
            name="Shared admin",
            remote_username="admin",
            password="shared-secret",
        )
        self.store.set_visibility(
            "credential",
            credential["id"],
            user_id="owner",
            visibility="global",
        )
        folder = self.store.create_folder(
            user_id="owner", name="Shared", credential_mode="credential",
            credential_id=credential["id"],
        )
        self.store.set_visibility(
            "folder", folder["id"], user_id="owner", visibility="global"
        )
        host = self.store.save_host(
            user_id="owner", name="Switch", host="192.0.2.10", port=22,
            folder_id=folder["id"], credential_id="", credential_mode="inherit",
            allow_unknown_hosts=False, allow_legacy_algorithms=False,
        )
        self.store.set_visibility(
            "host", host["id"], user_id="owner", visibility="inherit"
        )

        shared = self.store.library_for_user("operator")
        self.assertEqual([item["name"] for item in shared["hosts"]], ["Switch"])
        self.assertEqual([item["name"] for item in shared["credentials"]], ["Shared admin"])
        self.assertNotIn("password", shared["credentials"][0])
        self.assertEqual(
            self.store.resolve_credential(
                credential["id"], user_id="operator", host_id=host["id"]
            )["password"],
            "shared-secret",
        )

        self.store.set_visibility(
            "credential",
            credential["id"],
            user_id="owner",
            visibility="admins_only",
        )
        self.assertEqual(
            self.store.library_for_user("operator")["credentials"], []
        )
        self.assertEqual(
            len(self.store.library_for_user("administrator", is_admin=True)["credentials"]),
            1,
        )
        with self.assertRaises(RemoteConnectionError):
            self.store.resolve_credential(
                credential["id"], user_id="operator", host_id=host["id"]
            )

    def test_top_level_inherited_visibility_defaults_to_admins_only(self) -> None:
        host = self.store.save_host(
            user_id="owner",
            name="Top-level switch",
            host="192.0.2.10",
            port=23,
            protocol="telnet",
            folder_id="",
            credential_id="",
            credential_mode="none",
            allow_unknown_hosts=False,
            allow_legacy_algorithms=False,
        )
        self.store.set_visibility(
            "host", host["id"], user_id="owner", visibility="inherit"
        )

        self.assertEqual(self.store.library_for_user("operator")["hosts"], [])
        visible = self.store.library_for_user("administrator", is_admin=True)["hosts"]
        self.assertEqual([item["name"] for item in visible], ["Top-level switch"])
        self.assertEqual(visible[0]["effective_visibility"], "admins_only")

    def test_concurrent_workers_serialize_schema_migration(self) -> None:
        self.store.clear()
        with sqlite3.connect(self.store.path) as connection:
            connection.executescript(
                """
                CREATE TABLE remote_connection_folders (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
                    parent_id TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE remote_connection_credentials (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
                    remote_username TEXT NOT NULL, secret_encrypted TEXT NOT NULL,
                    scope_host_id TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE remote_connection_hosts (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
                    host TEXT NOT NULL, port INTEGER NOT NULL,
                    protocol TEXT NOT NULL DEFAULT 'ssh', folder_id TEXT NOT NULL DEFAULT '',
                    credential_id TEXT NOT NULL, allow_unknown_hosts INTEGER NOT NULL DEFAULT 0,
                    allow_legacy_algorithms INTEGER NOT NULL DEFAULT 0,
                    notes TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )

        migration_reads = threading.Barrier(2)
        errors: list[Exception] = []

        def initialize_worker() -> None:
            connection = sqlite3.connect(self.store.path, timeout=5)
            connection.row_factory = sqlite3.Row
            # The fixture store already selected WAL mode. Re-selecting it in
            # both test threads races before the schema initializer's own
            # transaction boundary and can hide a test failure as a thread
            # warning. The concurrent operation under test starts below.
            connection.execute("PRAGMA busy_timeout = 5000")

            def pause_on_legacy_schema_read(statement: str) -> None:
                normalized = statement.strip().lower()
                if normalized == "pragma table_info(remote_connection_hosts)":
                    try:
                        migration_reads.wait(timeout=0.25)
                    except threading.BrokenBarrierError:
                        pass

            connection.set_trace_callback(pause_on_legacy_schema_read)
            try:
                RemoteConnectionStore._initialize(connection)
            except Exception as exc:  # pragma: no cover - assertion reports details
                errors.append(exc)
            finally:
                connection.close()

        workers = [threading.Thread(target=initialize_worker) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=5)

        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(errors, [])
        with sqlite3.connect(self.store.path) as connection:
            host_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(remote_connection_hosts)"
                )
            }
            folder_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(remote_connection_folders)"
                )
            }
        self.assertIn("credential_mode", host_columns)
        self.assertIn("credential_mode", folder_columns)
        self.assertIn("credential_id", folder_columns)

    def test_nested_folders_hosts_and_shared_credentials(self) -> None:
        credential = self.store.save_credential(
            user_id="operator",
            name="Shared admin",
            remote_username="admin",
            password="secret",
        )
        datacenter = self.store.create_folder(
            user_id="operator", name="Datacenter"
        )
        core = self.store.create_folder(
            user_id="operator", name="Core", parent_id=datacenter["id"]
        )
        host = self.store.save_host(
            user_id="operator",
            name="Core 01",
            host="192.0.2.10",
            port=22,
            folder_id=core["id"],
            credential_id=credential["id"],
            allow_unknown_hosts=True,
            allow_legacy_algorithms=False,
            notes="Primary core",
        )

        library = self.store.library_for_user("operator")
        self.assertEqual(len(library["folders"]), 2)
        self.assertEqual(library["hosts"][0]["credential_name"], "Shared admin")
        self.assertEqual(host["folder_id"], core["id"])
        with self.assertRaises(RemoteConnectionError):
            self.store.update_folder(
                datacenter["id"],
                user_id="operator",
                name="Datacenter",
                parent_id=core["id"],
            )
        with self.assertRaises(RemoteConnectionError):
            self.store.delete_credential(credential["id"], user_id="operator")

    def test_console_connection_is_credential_free_and_duplicates_line_settings(self) -> None:
        saved = self.store.save_host(
            user_id="operator",
            name="IDF switch console",
            host="/dev/cu.usbserial-ABC",
            port=0,
            protocol="console",
            folder_id="",
            credential_id="",
            credential_mode="inherit",
            allow_unknown_hosts=True,
            allow_legacy_algorithms=True,
            console_device_id="console_abc123",
            console_device_path="/dev/cu.usbserial-ABC",
            console_device_label="USB Serial Adapter",
            console_baud_rate=115200,
            console_data_bits=8,
            console_parity="none",
            console_stop_bits="1",
            console_flow_control="hardware",
        )
        copied = self.store.duplicate_host(saved["id"], user_id="operator")

        self.assertEqual(saved["protocol"], "console")
        self.assertEqual(saved["credential_mode"], "none")
        self.assertEqual(saved["credential_id"], "")
        self.assertFalse(saved["allow_unknown_hosts"])
        self.assertFalse(saved["allow_legacy_algorithms"])
        self.assertEqual(copied["console_device_id"], "console_abc123")
        self.assertEqual(copied["console_baud_rate"], 115200)
        self.assertEqual(copied["console_flow_control"], "hardware")

    def test_host_specific_credentials_clone_and_delete_with_the_host(self) -> None:
        host = self.store.save_host(
            user_id="operator",
            name="Firewall",
            host="firewall.example",
            port=2222,
            folder_id="",
            credential_id="",
            allow_unknown_hosts=False,
            allow_legacy_algorithms=True,
            host_credential={
                "name": "Firewall only",
                "username": "fwadmin",
                "password": "host-secret",
            },
        )
        copied = self.store.duplicate_host(host["id"], user_id="operator")
        library = self.store.library_for_user("operator")

        self.assertEqual(copied["name"], "Firewall copy")
        self.assertNotEqual(copied["credential_id"], host["credential_id"])
        self.assertEqual(len(library["credentials"]), 2)
        with self.assertRaises(RemoteConnectionError):
            self.store.resolve_credential(
                host["credential_id"],
                user_id="operator",
                host_id=copied["id"],
            )

        self.store.delete_host(host["id"], user_id="operator")
        remaining = self.store.library_for_user("operator")
        self.assertEqual(len(remaining["hosts"]), 1)
        self.assertEqual(len(remaining["credentials"]), 1)

    def test_new_host_specific_credential_names_are_disambiguated(self) -> None:
        hosts = []
        for name, address in (("Admin one", "192.0.2.10"), ("Global one", "192.0.2.11")):
            hosts.append(self.store.save_host(
                user_id="operator", name=name, host=address, port=22,
                folder_id="", credential_id="", allow_unknown_hosts=False,
                allow_legacy_algorithms=False, host_credential={
                    "name": "Host credentials", "username": "admin",
                    "password": f"{name}-secret",
                },
            ))

        library = self.store.library_for_user("operator")
        self.assertEqual(
            [item["name"] for item in library["credentials"]],
            ["Host credentials", "Host credentials copy"],
        )
        self.assertNotEqual(hosts[0]["credential_id"], hosts[1]["credential_id"])


    def test_telnet_host_preserves_protocol_and_ignores_ssh_options(self) -> None:
        credential = self.store.save_credential(
            user_id="operator",
            name="Legacy console",
            remote_username="operator",
            password="legacy-secret",
        )
        host = self.store.save_host(
            user_id="operator",
            name="Legacy switch",
            host="192.0.2.23",
            port=23,
            protocol="telnet",
            folder_id="",
            credential_id=credential["id"],
            allow_unknown_hosts=True,
            allow_legacy_algorithms=True,
        )
        copied = self.store.duplicate_host(host["id"], user_id="operator")

        self.assertEqual(host["protocol"], "telnet")
        self.assertEqual(copied["protocol"], "telnet")
        self.assertFalse(host["allow_unknown_hosts"])
        self.assertFalse(host["allow_legacy_algorithms"])

    def test_telnet_host_can_be_saved_without_a_credential(self) -> None:
        host = self.store.save_host(
            user_id="operator",
            name="Manual login switch",
            host="192.0.2.24",
            port=23,
            protocol="telnet",
            folder_id="",
            credential_id="",
            allow_unknown_hosts=False,
            allow_legacy_algorithms=False,
        )
        copied = self.store.duplicate_host(host["id"], user_id="operator")

        self.assertEqual(host["credential_id"], "")
        self.assertEqual(host["remote_username"], "")
        self.assertEqual(copied["credential_id"], "")
        self.assertEqual(len(self.store.library_for_user("operator")["hosts"]), 2)
        self.store.delete_host(host["id"], user_id="operator")

        with self.assertRaisesRegex(RemoteConnectionError, "saved SSH hosts"):
            self.store.save_host(
                user_id="operator",
                name="Invalid SSH host",
                host="192.0.2.25",
                port=22,
                protocol="ssh",
                folder_id="",
                credential_id="",
                allow_unknown_hosts=False,
                allow_legacy_algorithms=False,
            )

    def test_duplicate_folder_copies_nested_hosts(self) -> None:
        credential = self.store.save_credential(
            user_id="operator",
            name="Shared",
            remote_username="admin",
            password="secret",
        )
        parent = self.store.create_folder(user_id="operator", name="Customer")
        child = self.store.create_folder(
            user_id="operator", name="Switches", parent_id=parent["id"]
        )
        self.store.save_host(
            user_id="operator",
            name="Access 01",
            host="192.0.2.50",
            port=22,
            folder_id=child["id"],
            credential_id=credential["id"],
            allow_unknown_hosts=False,
            allow_legacy_algorithms=False,
        )

        copied = self.store.duplicate_folder(parent["id"], user_id="operator")
        library = self.store.library_for_user("operator")
        copied_child = next(
            folder
            for folder in library["folders"]
            if folder["parent_id"] == copied["id"]
        )
        copied_host = next(
            host
            for host in library["hosts"]
            if host["folder_id"] == copied_child["id"]
        )
        self.assertEqual(copied["name"], "Customer copy")
        self.assertEqual(copied_child["name"], "Switches")
        self.assertEqual(copied_host["name"], "Access 01")

    def test_hosts_inherit_nearest_folder_credential_and_can_override_it(self) -> None:
        parent_credential = self.store.save_credential(
            user_id="operator",
            name="Parent admin",
            remote_username="parent-admin",
            password="parent-secret",
        )
        override_credential = self.store.save_credential(
            user_id="operator",
            name="Override admin",
            remote_username="override-admin",
            password="override-secret",
        )
        parent = self.store.create_folder(
            user_id="operator",
            name="Customer",
            credential_mode="credential",
            credential_id=parent_credential["id"],
        )
        child = self.store.create_folder(
            user_id="operator", name="Switches", parent_id=parent["id"]
        )
        inherited = self.store.save_host(
            user_id="operator",
            name="Access 01",
            host="192.0.2.71",
            port=22,
            folder_id=child["id"],
            credential_id="",
            credential_mode="inherit",
            allow_unknown_hosts=False,
            allow_legacy_algorithms=False,
        )
        overridden = self.store.save_host(
            user_id="operator",
            name="Access 02",
            host="192.0.2.72",
            port=22,
            folder_id=child["id"],
            credential_id=override_credential["id"],
            allow_unknown_hosts=False,
            allow_legacy_algorithms=False,
        )

        library = self.store.library_for_user("operator")
        inherited = next(item for item in library["hosts"] if item["id"] == inherited["id"])
        overridden = next(item for item in library["hosts"] if item["id"] == overridden["id"])
        child = next(item for item in library["folders"] if item["id"] == child["id"])

        self.assertEqual(inherited["effective_credential_id"], parent_credential["id"])
        self.assertEqual(inherited["effective_remote_username"], "parent-admin")
        self.assertEqual(inherited["credential_source_folder_name"], "Customer")
        self.assertEqual(overridden["effective_credential_id"], override_credential["id"])
        self.assertEqual(overridden["credential_source"], "host")
        self.assertEqual(child["effective_credential_name"], "Parent admin")

        self.store.update_folder(
            child["id"],
            user_id="operator",
            name="Switches",
            parent_id=parent["id"],
            credential_mode="none",
        )
        stopped = self.store.get_host(inherited["id"], user_id="operator")
        self.assertEqual(stopped["effective_credential_id"], "")

    def test_bulk_update_moves_items_and_changes_inheritance_atomically(self) -> None:
        credential = self.store.save_credential(
            user_id="operator",
            name="Operations",
            remote_username="ops",
            password="secret",
        )
        source = self.store.create_folder(user_id="operator", name="Source")
        destination = self.store.create_folder(user_id="operator", name="Destination")
        child = self.store.create_folder(
            user_id="operator", name="Child", parent_id=source["id"]
        )
        host = self.store.save_host(
            user_id="operator",
            name="Switch 01",
            host="192.0.2.80",
            port=22,
            folder_id=source["id"],
            credential_id=credential["id"],
            allow_unknown_hosts=False,
            allow_legacy_algorithms=False,
        )

        changed = self.store.bulk_update(
            user_id="operator",
            host_ids=[host["id"]],
            folder_ids=[child["id"]],
            destination_id=destination["id"],
            credential_mode="inherit",
        )
        library = self.store.library_for_user("operator")
        moved_host = next(item for item in library["hosts"] if item["id"] == host["id"])
        moved_child = next(item for item in library["folders"] if item["id"] == child["id"])

        self.assertEqual(changed, {"hosts": 1, "folders": 1})
        self.assertEqual(moved_host["folder_id"], destination["id"])
        self.assertEqual(moved_host["credential_mode"], "inherit")
        self.assertEqual(moved_child["parent_id"], destination["id"])
        self.assertEqual(moved_child["credential_mode"], "inherit")

        with self.assertRaisesRegex(RemoteConnectionError, "inside itself"):
            self.store.bulk_update(
                user_id="operator",
                host_ids=[],
                folder_ids=[destination["id"]],
                destination_id=child["id"],
            )
        unchanged = self.store.get_folder(destination["id"], user_id="operator")
        self.assertEqual(unchanged["parent_id"], "")

    def test_host_import_is_atomic_and_defaults_to_folder_inheritance(self) -> None:
        folder = self.store.create_folder(user_id="operator", name="Campus")

        imported = self.store.import_hosts(
            user_id="operator",
            folder_id=folder["id"],
            hosts=[
                {
                    "row": 2,
                    "name": "Core switch",
                    "host": "192.0.2.10",
                    "protocol": "ssh",
                    "port": 22,
                },
                {
                    "row": 3,
                    "name": "Legacy console",
                    "host": "192.0.2.11",
                    "protocol": "telnet",
                    "port": 2323,
                },
            ],
        )
        library = self.store.library_for_user("operator")

        self.assertEqual(imported, 2)
        self.assertEqual(len(library["hosts"]), 2)
        self.assertTrue(
            all(item["folder_id"] == folder["id"] for item in library["hosts"])
        )
        self.assertTrue(
            all(item["credential_mode"] == "inherit" for item in library["hosts"])
        )
        self.assertEqual(
            next(item for item in library["hosts"] if item["name"] == "Legacy console")["port"],
            2323,
        )

        with self.assertRaisesRegex(RemoteConnectionError, "Row 5"):
            self.store.import_hosts(
                user_id="operator",
                folder_id=folder["id"],
                hosts=[
                    {
                        "row": 4,
                        "name": "Access switch",
                        "host": "192.0.2.12",
                        "protocol": "ssh",
                        "port": 22,
                    },
                    {
                        "row": 5,
                        "name": "Core switch",
                        "host": "192.0.2.13",
                        "protocol": "ssh",
                        "port": 22,
                    },
                ],
            )
        self.assertEqual(
            len(self.store.library_for_user("operator")["hosts"]), 2
        )


if __name__ == "__main__":
    unittest.main()
