from __future__ import annotations

import tempfile
import unittest

from twn_toolkit.profile_backup import (
    build_backup_catalog,
    build_profile_backup,
    decrypt_backup,
    encrypt_backup,
    import_backup_items,
    merge_profiles_by_name,
    selected_backup_items,
    validate_profile_backup,
)
from twn_toolkit.dashboard_layout import DashboardLayoutStore


class ProfileBackupTests(unittest.TestCase):
    def test_catalog_contains_sensitive_and_plain_profile_groups(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            catalog = build_backup_catalog(instance)

        ids = {item["id"]: item for item in catalog}
        self.assertTrue(ids["fortigate_profiles"]["sensitive"])
        self.assertFalse(ids["ping_profiles"]["sensitive"])
        self.assertFalse(ids["dashboard_layout"]["sensitive"])

    def test_catalog_has_stable_order_and_unique_ids(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            catalog = build_backup_catalog(instance)

        ids = [item["id"] for item in catalog]
        self.assertEqual(
            ids,
            [
                "fortigate_profiles",
                "fortiauthenticator_profiles",
                "ping_profiles",
                "dns_host_profiles",
                "dns_server_profiles",
                "radius_server_profiles",
                "radius_credential_profiles",
                "radius_attribute_profiles",
                "snmp_credential_profiles",
                "snmp_host_profiles",
                "snmp_oid_profiles",
                "port_scan_host_profiles",
                "port_scan_port_profiles",
                "ntp_host_profiles",
                "traceroute_host_profiles",
                "automation_definitions",
                "dashboard_layout",
            ],
        )
        self.assertEqual(len(ids), len(set(ids)))

    def test_dashboard_layout_backup_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as destination:
            DashboardLayoutStore(source)._write(
                {"version": 1, "order": ["snmp", "ping"], "hidden": ["ping"]}
            )
            source_item = selected_backup_items(
                build_backup_catalog(source), {"dashboard_layout"}
            )
            backup = build_profile_backup(source_item)
            destination_item = selected_backup_items(
                build_backup_catalog(destination), {"dashboard_layout"}
            )
            imported = import_backup_items(
                backup["items"], destination_item, "replace"
            )
            restored = DashboardLayoutStore(destination).get(["ping", "snmp"])

        self.assertEqual(imported, [("Dashboard layout", 1)])
        self.assertEqual(restored["order"], ["snmp", "ping"])
        self.assertEqual(restored["hidden"], ["ping"])

    def test_encrypt_decrypt_round_trip_and_wrong_password_message(self) -> None:
        encrypted = encrypt_backup(b'{"format": "twn-toolkit-profile-backup", "version": 1, "items": {}}', "correct")

        self.assertEqual(encrypted["format"], "twn-toolkit-encrypted-profile-backup")
        self.assertEqual(decrypt_backup(encrypted, "correct")["items"], {})
        with self.assertRaisesRegex(ValueError, "password is incorrect"):
            decrypt_backup(encrypted, "wrong")

    def test_build_and_validate_plain_backup(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            catalog = build_backup_catalog(instance)
            selected = selected_backup_items(catalog, {"ping_profiles"})
            selected[0]["store"].replace_all([{"name": "WAN", "targets": "1.1.1.1"}])

            backup = build_profile_backup(selected)
            validate_profile_backup(backup)

        self.assertEqual(backup["format"], "twn-toolkit-profile-backup")
        self.assertEqual(backup["items"]["ping_profiles"][0]["name"], "WAN")

    def test_merge_profiles_by_name_replaces_overlaps_and_moves_default(self) -> None:
        merged = merge_profiles_by_name(
            [
                {"name": "Old", "is_default": True},
                {"name": "Overlap", "host": "old"},
            ],
            [
                {"name": "Overlap", "host": "new"},
                {"name": "Imported", "is_default": True},
            ],
        )

        by_name = {profile["name"]: profile for profile in merged}
        self.assertEqual(by_name["Overlap"]["host"], "new")
        self.assertFalse(by_name["Old"]["is_default"])
        self.assertTrue(by_name["Imported"]["is_default"])

    def test_import_backup_items_can_merge_or_replace(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            catalog = build_backup_catalog(instance)
            selected = selected_backup_items(catalog, {"ping_profiles"})
            store = selected[0]["store"]
            store.replace_all([{"name": "Existing", "targets": "192.0.2.1"}])

            imported = import_backup_items(
                {"ping_profiles": [{"name": "Imported", "targets": "192.0.2.2"}]},
                selected,
                "merge",
            )

            self.assertEqual(imported, [("Ping profiles", 2)])
            self.assertEqual(
                [profile["name"] for profile in store.all()],
                ["Existing", "Imported"],
            )

            imported = import_backup_items(
                {"ping_profiles": [{"name": "Replacement", "targets": "192.0.2.3"}]},
                selected,
                "replace",
            )

            self.assertEqual(imported, [("Ping profiles", 1)])
            self.assertEqual([profile["name"] for profile in store.all()], ["Replacement"])


if __name__ == "__main__":
    unittest.main()
