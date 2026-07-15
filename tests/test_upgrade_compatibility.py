from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.auth import AuthStore, load_or_create_secret_key
from twn_toolkit.automation import AutomationStore
from twn_toolkit.migrations import MigrationManager
from twn_toolkit.profiles import PingProfileStore, ProfileStore


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "releases" / "v0.9.1"


def restore_release_fixture(instance: Path) -> None:
    for name in (
        "auth.json",
        "ping_profiles.json",
        "profiles.json",
        "schema_migrations.json",
        "session_secret",
    ):
        shutil.copy2(FIXTURE_ROOT / name, instance / name)
    for database_name, dump_name in (
        ("activity.sqlite3", "activity.sql"),
        ("audit.sqlite3", "audit.sql"),
        ("automations.sqlite3", "automations.sql"),
    ):
        connection = sqlite3.connect(instance / database_name)
        try:
            connection.executescript((FIXTURE_ROOT / dump_name).read_text(encoding="utf-8"))
        finally:
            connection.close()


class PriorReleaseUpgradeTests(unittest.TestCase):
    def test_v091_instance_upgrades_without_losing_saved_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = Path(temporary)
            restore_release_fixture(instance)

            app = create_app(instance_path=str(instance))
            app.config["TESTING"] = True

            user = AuthStore(str(instance)).authenticate(
                "fixture-admin", "Fixture password 123!"
            )
            fortigate_profile = ProfileStore(str(instance)).get("Legacy Gate")
            ping_profile = PingProfileStore(str(instance)).get("Legacy WAN")
            activity = ActivityStore(str(instance)).summary()
            audit_event = AuditStore(str(instance)).recent(1)[0]
            automation_store = AutomationStore(
                str(instance), load_or_create_secret_key(str(instance))
            )
            automations = automation_store.all(include_secrets=True)

            self.assertIsNotNone(user)
            self.assertTrue(user["is_admin"])
            self.assertEqual(fortigate_profile["api_key"], "fixture-api-key")
            self.assertEqual(ping_profile["targets"][0]["host"], "192.0.2.1")
            self.assertEqual(activity["counters"]["actions"]["total"], 1)
            self.assertEqual(activity["counters"]["snmp"]["polls"], 1)
            self.assertEqual(activity["recent"][0]["title"], "Legacy SNMP test")
            self.assertEqual(audit_event["endpoint"], "legacy_save")
            self.assertEqual(audit_event["details"], {})
            self.assertEqual(len(automations), 1)
            self.assertEqual(automations[0]["name"], "Legacy manual collection")
            self.assertEqual(
                automations[0]["actions"][0]["config"]["password"],
                "fixture-ssh-password",
            )
            self.assertEqual(
                [item["version"] for item in automation_store.migration_status()],
                ["automation-1", "automation-2", "automation-3"],
            )
            self.assertEqual(
                json.loads((instance / "schema_migrations.json").read_text())[0][
                    "version"
                ],
                1,
            )

            for database in instance.glob("*.sqlite3"):
                connection = sqlite3.connect(database)
                try:
                    self.assertEqual(
                        connection.execute("PRAGMA quick_check").fetchone()[0],
                        "ok",
                        database.name,
                    )
                finally:
                    connection.close()

            PingProfileStore(str(instance)).upsert(
                {"name": "Post-upgrade", "targets": [], "interval": 10}
            )
            AuditStore(str(instance)).record(
                username="fixture-admin",
                method="POST",
                endpoint="post_upgrade",
                path="/post-upgrade",
                status_code=200,
                action="upgrade.write_verified",
                summary="Verified a post-upgrade write.",
            )
            self.assertIsNotNone(PingProfileStore(str(instance)).get("Post-upgrade"))
            self.assertEqual(
                AuditStore(str(instance)).recent(1)[0]["action"],
                "upgrade.write_verified",
            )

    def test_failed_migration_restores_pre_change_databases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = Path(temporary)
            database = instance / "state.sqlite3"
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY, value TEXT)")
                connection.execute("INSERT INTO item VALUES(1, 'before')")
                connection.commit()
            finally:
                connection.close()

            def fail_after_change(path: Path) -> None:
                changed = sqlite3.connect(path / "state.sqlite3")
                try:
                    changed.execute("ALTER TABLE item ADD COLUMN unsafe TEXT")
                    changed.execute("UPDATE item SET value = 'after', unsafe = 'partial'")
                    changed.commit()
                finally:
                    changed.close()
                raise RuntimeError("simulated migration failure")

            manager = MigrationManager(str(instance))
            with self.assertRaisesRegex(RuntimeError, "simulated migration failure"):
                manager.run([(9, "failing fixture migration", fail_after_change)])

            connection = sqlite3.connect(database)
            try:
                columns = [
                    row[1] for row in connection.execute("PRAGMA table_info(item)")
                ]
                value = connection.execute("SELECT value FROM item WHERE id = 1").fetchone()[0]
                self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
            finally:
                connection.close()

            self.assertEqual(columns, ["id", "value"])
            self.assertEqual(value, "before")
            self.assertEqual(manager.applied(), [])
            self.assertTrue(
                list((instance / "migration_backups").glob("v9-*/*state.sqlite3"))
            )


if __name__ == "__main__":
    unittest.main()
