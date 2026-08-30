from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.auth import AuthStore, load_or_create_secret_key
from twn_toolkit.automation import AutomationStore
from twn_toolkit.migrations import MigrationManager
from twn_toolkit.profiles import PingProfileStore, ProfileStore
from twn_toolkit.ssh_commandlets import SSHCommandletStore, SSHHostMatrixStore


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "releases" / "v0.9.1"
V0212_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "releases" / "v0.21.2"


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
    def test_v0212_bulk_ssh_profiles_migrate_to_matrix_owned_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = Path(temporary)
            shutil.copy2(
                V0212_FIXTURE_ROOT / "ssh_commandlets.json",
                instance / "ssh_commandlets.json",
            )

            matrices = SSHHostMatrixStore(str(instance)).all()
            commandlets = {
                item["name"]: item for item in SSHCommandletStore(str(instance)).all()
            }
            stored_commandlets = json.loads(
                (instance / "ssh_commandlets.json").read_text(encoding="utf-8")
            )

            self.assertEqual(len(matrices), 1)
            self.assertEqual(matrices[0]["name"], "Inspect branch interfaces targets")
            self.assertEqual(matrices[0]["target_count"], 2)
            self.assertEqual(
                [action["name"] for action in matrices[0]["actions"]],
                ["Inspect branch interfaces"],
            )
            self.assertEqual(
                commandlets["Inspect branch interfaces"]["matrix_names"],
                ["Inspect branch interfaces targets"],
            )
            self.assertEqual(commandlets["Collect system status"]["matrix_names"], [])
            self.assertTrue(
                all("target_matrix" not in item for item in stored_commandlets)
            )

    def test_interrupted_v0212_bulk_ssh_migration_is_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = Path(temporary)
            source = V0212_FIXTURE_ROOT / "ssh_commandlets.json"
            commandlet_path = instance / "ssh_commandlets.json"
            shutil.copy2(source, commandlet_path)
            original_replace = os.replace

            def interrupt_commandlet_commit(source_path: str, target_path: str) -> None:
                if Path(target_path).name == "ssh_commandlets.json":
                    raise OSError("simulated interruption")
                original_replace(source_path, target_path)

            with (
                patch(
                    "twn_toolkit.profiles.os.replace",
                    side_effect=interrupt_commandlet_commit,
                ),
                self.assertRaisesRegex(OSError, "simulated interruption"),
            ):
                SSHCommandletStore(str(instance)).all()

            preserved = json.loads(commandlet_path.read_text(encoding="utf-8"))
            self.assertIn("target_matrix", preserved[0])

            matrices = SSHHostMatrixStore(str(instance)).all()
            self.assertEqual(len(matrices), 1)
            self.assertEqual(
                [action["name"] for action in matrices[0]["actions"]],
                ["Inspect branch interfaces"],
            )
            self.assertEqual(
                len(SSHHostMatrixStore(str(instance)).all()),
                1,
            )

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
                [
                    "automation-1",
                    "automation-2",
                    "automation-3",
                    "automation-4",
                    "automation-5",
                    "automation-6",
                    "automation-7",
                ],
            )
            self.assertEqual(
                [
                    item["version"]
                    for item in json.loads(
                        (instance / "schema_migrations.json").read_text()
                    )
                ],
                [1, 2, 3],
            )
            migration_backups = list(
                (instance / "migration_backups").glob(
                    "v2-*/automations.sqlite3"
                )
            )
            self.assertEqual(len(migration_backups), 1)
            startup_migration_backups = list(
                (instance / "migration_backups").glob(
                    "v3-*/automations.sqlite3"
                )
            )
            self.assertEqual(len(startup_migration_backups), 1)

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
