from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.audit import AuditStore
from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.migrations import MigrationManager
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.supervisor_worker import _heartbeat_fresh


class OperationalHardeningTests(unittest.TestCase):
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
            store.record(user_id="1", username="admin", remote_ip="127.0.0.1", method="POST", endpoint="save", path="/settings/server", status_code=302)
            event = store.recent(1)[0]
            self.assertEqual(event["username"], "admin")
            self.assertNotIn("password", event)

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
            page = client.get("/settings/diagnostics")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"System diagnostics", page.data)
            response = client.post("/settings/operations", data={
                "max_concurrent_automations": "3", "max_queued_automations": "7",
                "skip_overlapping_automations": "on", "datastore_quota_gib": "12",
                "automation_artifact_quota_gib": "14", "minimum_free_gib": "1",
            })
            self.assertEqual(response.status_code, 302)
            self.assertEqual(OperationalSettingsStore(instance).get()["max_queued_automations"], 7)

    def test_heartbeat_freshness(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            heartbeat = Path(instance) / "heartbeat.json"
            heartbeat.write_text(json.dumps({"updated_at": time.time()}))
            self.assertTrue(_heartbeat_fresh(heartbeat, 10))
            heartbeat.write_text(json.dumps({"updated_at": time.time() - 30}))
            self.assertFalse(_heartbeat_fresh(heartbeat, 10))


if __name__ == "__main__": unittest.main()
