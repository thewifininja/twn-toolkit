from __future__ import annotations

import tempfile
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


if __name__ == "__main__":
    unittest.main()
