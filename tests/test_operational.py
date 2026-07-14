from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.audit import AuditStore, audit_changes
from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.migrations import MigrationManager
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.pidfiles import remove_own_pid_file, write_pid_file
from twn_toolkit.supervisor_worker import _heartbeat_fresh


class OperationalHardeningTests(unittest.TestCase):
    def test_pid_file_cleanup_does_not_remove_another_worker_owner(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            path = Path(instance) / "worker.pid"
            write_pid_file(str(path))
            self.assertTrue(path.exists())
            path.write_text("999999\n", encoding="utf-8")
            remove_own_pid_file(str(path))
            self.assertTrue(path.exists())
            write_pid_file(str(path))
            remove_own_pid_file(str(path))
            self.assertFalse(path.exists())

    def test_operational_settings_validate_and_persist(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = OperationalSettingsStore(instance)
            settings = store.save({"max_concurrent_automations": 8, "datastore_quota_gib": 20})
            self.assertEqual(settings["max_concurrent_automations"], 8)
            self.assertEqual(store.get()["datastore_quota_gib"], 20)
            with self.assertRaisesRegex(ValueError, "Concurrent"):
                store.save({"max_concurrent_automations": 0})

    def test_datastore_rejects_write_past_configured_quota(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = LocalDatastore(instance)
            constrained = {**OperationalSettingsStore(instance).get(), "datastore_quota_gib": 0, "minimum_free_gib": 0}
            with patch("twn_toolkit.operational.OperationalSettingsStore.get", return_value=constrained):
                with self.assertRaisesRegex(DatastoreError, "quota"):
                    store.save_upload("", "blocked.bin", __import__("io").BytesIO(b"x"))

    def test_audit_store_is_bounded_structured_and_secret_free(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = AuditStore(instance)
            store.record(
                user_id="1", username="admin", remote_ip="127.0.0.1",
                method="POST", endpoint="save", path="/settings/server",
                status_code=302, category="Administration", action="settings.updated",
                summary="Updated settings.", resource_type="settings",
                resource_id="server", resource_name="Server settings",
                details={
                    "visible": "retained",
                    "password": "never store me",
                    "nested": {"api-token": "also secret", "host": "192.0.2.1"},
                    "changes": [{"field": "port", "before": 5050, "after": 8443}],
                },
            )
            event = store.recent(1)[0]
            self.assertEqual(event["username"], "admin")
            self.assertEqual(event["summary"], "Updated settings.")
            self.assertEqual(event["details"]["visible"], "retained")
            self.assertEqual(event["details"]["password"], "[redacted]")
            self.assertEqual(event["details"]["nested"]["api-token"], "[redacted]")
            self.assertEqual(event["details"]["nested"]["host"], "192.0.2.1")
            self.assertNotIn(b"never store me", Path(store.path).read_bytes())
            self.assertNotIn(b"also secret", Path(store.path).read_bytes())

    def test_audit_changes_flattens_nested_fields_and_redacts_secrets(self) -> None:
        changes = audit_changes(
            {"configuration": {"timeout": 5, "password": "old"}},
            {"configuration": {"timeout": 10, "password": "new"}},
        )
        self.assertEqual(
            changes,
            [{"field": "configuration.timeout", "before": 5, "after": 10}],
        )

    def test_oversized_audit_detail_remains_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = AuditStore(instance)
            store.record(details={f"field_{index}": "x" * 1000 for index in range(100)})
            details = store.recent(1)[0]["details"]
            self.assertTrue(details["truncated"])
            self.assertIn("storage limit", details["notice"])

    def test_legacy_audit_database_gains_detail_columns(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            path = Path(instance) / "audit.sqlite3"
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    """
                    CREATE TABLE audit_events (
                        id TEXT PRIMARY KEY, recorded_at REAL NOT NULL, user_id TEXT NOT NULL,
                        username TEXT NOT NULL, remote_ip TEXT NOT NULL, method TEXT NOT NULL,
                        endpoint TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO audit_events VALUES ('old', 1, '1', 'admin', '127.0.0.1', 'POST', 'legacy', '/legacy', 302)"
                )
                connection.commit()
            finally:
                connection.close()

            event = AuditStore(instance).recent(1)[0]
            self.assertEqual(event["id"], "old")
            self.assertEqual(event["details"], {})

    def test_migration_manager_snapshots_existing_databases(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            database = Path(instance) / "example.sqlite3"
            connection = sqlite3.connect(database)
            try: connection.execute("CREATE TABLE item(id INTEGER)"); connection.commit()
            finally: connection.close()
            manager = MigrationManager(instance)
            self.assertEqual(manager.run([(7, "test migration", lambda _path: None)]), [7])
            self.assertEqual(manager.run([(7, "test migration", lambda _path: None)]), [])
            self.assertTrue(list((Path(instance) / "migration_backups").glob("v7-*/*sqlite3")))

    def test_diagnostics_and_operational_settings_routes(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance); app.testing = True; client = app.test_client()
            AuditStore(instance).record(
                username="admin", method="POST", endpoint="save",
                path="/settings/example", status_code=302,
                summary="Saved example settings.",
            )
            page = client.get("/settings/diagnostics")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"System diagnostics", page.data)
            self.assertIn(b'class="field-note audit-empty-detail"', page.data)
            response = client.post("/settings/operations", data={
                "max_concurrent_automations": "3", "max_queued_automations": "7",
                "skip_overlapping_automations": "on", "datastore_quota_gib": "12",
                "automation_artifact_quota_gib": "14", "minimum_free_gib": "1",
            })
            self.assertEqual(response.status_code, 302)
            self.assertEqual(OperationalSettingsStore(instance).get()["max_queued_automations"], 7)
            diagnostics = client.get("/settings/diagnostics")
            self.assertIn(b"Updated operational limits", diagnostics.data)
            self.assertIn(b"Changed settings", diagnostics.data)
            self.assertIn(b"max concurrent automations", diagnostics.data)

    def test_heartbeat_freshness(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            heartbeat = Path(instance) / "heartbeat.json"
            heartbeat.write_text(json.dumps({"updated_at": time.time()}))
            self.assertTrue(_heartbeat_fresh(heartbeat, 10))
            heartbeat.write_text(json.dumps({"updated_at": time.time() - 30}))
            self.assertFalse(_heartbeat_fresh(heartbeat, 10))


if __name__ == "__main__": unittest.main()
