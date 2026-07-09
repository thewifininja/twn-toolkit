from __future__ import annotations

import stat
import tempfile
import unittest

from twn_toolkit.profiles import (
    DNSProfileStore,
    PingProfileStore,
    ProfileStore,
    SNMPOidProfileStore,
)


class ProfileStoreTests(unittest.TestCase):
    def test_profile_store_preserves_default_profile_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = ProfileStore(instance)

            store.upsert({"name": "Primary", "is_default": True})
            store.upsert({"name": "Secondary", "is_default": True})

            profiles = {profile["name"]: profile for profile in store.all()}
            self.assertFalse(profiles["Primary"]["is_default"])
            self.assertTrue(profiles["Secondary"]["is_default"])

    def test_named_list_store_can_rename_and_report_missing_deletes(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = PingProfileStore(instance)

            store.upsert({"name": "Old", "targets": "192.0.2.1"})
            store.upsert({"name": "New", "targets": "192.0.2.2"}, original_name="Old")

            self.assertIsNone(store.get("Old"))
            self.assertEqual(store.get("New")["targets"], "192.0.2.2")
            self.assertTrue(store.delete("New"))
            self.assertFalse(store.delete("New"))

    def test_specialized_stores_keep_their_existing_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = DNSProfileStore(instance, "servers")

            store.upsert({"name": "Resolvers", "servers": "1.1.1.1"})

            self.assertEqual(store.path.name, "dns_servers_profiles.json")
            self.assertTrue(store.path.exists())

    def test_store_files_are_owner_readable_only(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = PingProfileStore(instance)

            store.replace_all([{"name": "WAN", "targets": "1.1.1.1"}])

            mode = stat.S_IMODE(store.path.stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_snmp_oid_profiles_include_defaults_when_first_saved(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = SNMPOidProfileStore(instance)

            defaults = store.all()
            store.upsert({"name": "Custom", "source": "System Name = 1.3.6.1.2.1.1.5.0"})

            self.assertGreaterEqual(len(defaults), 2)
            self.assertEqual(
                [profile["name"] for profile in store.all()],
                ["Custom", "Interface Summary", "System Identity"],
            )


if __name__ == "__main__":
    unittest.main()
