from __future__ import annotations

import json
import tempfile
import unittest

from twn_toolkit.profile_backup import (
    CONFIGURATION_BACKUP_FORMAT,
    ConfigurationImportStore,
    ENCRYPTED_CONFIGURATION_BACKUP_FORMAT,
    LEGACY_BACKUP_FORMAT,
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
                "wol_target_profiles",
                "lldp_personas",
                "ssh_commandlets",
                "ssh_host_matrices",
                "automation_definitions",
                "dashboard_layout",
                "remote_connection_library",
                "certificate_automation_profiles",
                "access_profiles",
                "smtp_settings",
                "time_settings",
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

        self.assertEqual(encrypted["format"], ENCRYPTED_CONFIGURATION_BACKUP_FORMAT)
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

        self.assertEqual(backup["format"], CONFIGURATION_BACKUP_FORMAT)
        self.assertEqual(backup["version"], 2)
        self.assertEqual(backup["groups"][0]["record_count"], 1)
        self.assertEqual(backup["items"]["ping_profiles"][0]["name"], "WAN")

    def test_legacy_v1_plain_and_encrypted_backups_remain_readable(self) -> None:
        legacy = {
            "format": LEGACY_BACKUP_FORMAT,
            "version": 1,
            "items": {"ping_profiles": [{"name": "WAN"}]},
        }
        validate_profile_backup(legacy)
        encrypted = encrypt_backup(json.dumps(legacy).encode("utf-8"), "password")
        encrypted["format"] = "twn-toolkit-encrypted-profile-backup"
        encrypted["version"] = 1
        restored = decrypt_backup(encrypted, "password")
        self.assertEqual(restored, legacy)

    def test_v2_manifest_rejects_tampered_group_counts(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            selected = selected_backup_items(
                build_backup_catalog(instance), {"ping_profiles"}
            )
            backup = build_profile_backup(selected)
        backup["groups"][0]["record_count"] += 1
        with self.assertRaisesRegex(ValueError, "count does not match"):
            validate_profile_backup(backup)

    def test_import_preview_staging_is_encrypted_and_user_bound(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ConfigurationImportStore(instance, "installation secret")
            backup = {
                "format": LEGACY_BACKUP_FORMAT,
                "version": 1,
                "items": {
                    "fortigate_profiles": [
                        {"name": "Secret device", "api_key": "not-plaintext"}
                    ]
                },
            }
            token = store.create(
                backup,
                user_id="admin-one",
                encrypted_input=True,
                import_mode="merge",
            )
            staged = next(store.directory.glob("*.token")).read_bytes()

            self.assertNotIn(b"not-plaintext", staged)
            self.assertEqual(
                store.get(token, user_id="admin-one")["backup"], backup
            )
            with self.assertRaisesRegex(ValueError, "expired"):
                store.get(token, user_id="admin-two")

    def test_invalid_non_object_backup_fails_cleanly(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not look"):
            validate_profile_backup([])  # type: ignore[arg-type]

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

    def test_import_rolls_back_a_completed_group_when_a_later_group_fails(self) -> None:
        class MemoryStore:
            def __init__(self, values, *, fail=False):
                self.values = values
                self.fail = fail

            def all(self):
                return self.values

            def replace_all(self, values):
                if self.fail:
                    self.fail = False
                    raise ValueError("planned failure")
                self.values = values

        first = MemoryStore([{"name": "Original"}])
        second = MemoryStore([{"name": "Second original"}], fail=True)
        items = [
            {
                "id": "first",
                "label": "First",
                "store": first,
                "supports_merge": True,
                "supports_replace": True,
            },
            {
                "id": "second",
                "label": "Second",
                "store": second,
                "supports_merge": True,
                "supports_replace": True,
            },
        ]

        with self.assertRaisesRegex(ValueError, "planned failure"):
            import_backup_items(
                {
                    "first": [{"name": "Imported"}],
                    "second": [{"name": "Failure"}],
                },
                items,
                "replace",
            )

        self.assertEqual(first.all(), [{"name": "Original"}])


if __name__ == "__main__":
    unittest.main()
