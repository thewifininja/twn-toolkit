from __future__ import annotations

import json
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.audit import AuditStore, audit_changes, audit_safe_snapshot
from twn_toolkit.auth import AuthStore
from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.migrations import MigrationManager
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.pidfiles import (
    acquire_singleton_lock,
    matching_daemon_pids,
    remove_own_pid_file,
    stop_matching_daemons,
    write_pid_file,
)
from twn_toolkit.supervisor_worker import (
    _heartbeat_fresh,
    matching_supervisor_pids,
)


class OperationalHardeningTests(unittest.TestCase):
    def test_ftp_worker_import_does_not_start_resource_tracker(self) -> None:
        probe = subprocess.run([
            sys.executable, "-c",
            "import twn_toolkit.ftp_worker; "
            "import multiprocessing.resource_tracker as tracker; "
            "print(tracker._resource_tracker._pid)",
        ], text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(probe.stdout.strip(), "None")

    def test_supervisor_lock_allows_only_one_owner_per_root(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            first = acquire_singleton_lock(Path(root), "supervisor")
            self.assertIsNotNone(first)
            try:
                self.assertIsNone(acquire_singleton_lock(Path(root), "supervisor"))
            finally:
                first.close()
            replacement = acquire_singleton_lock(Path(root), "supervisor")
            self.assertIsNotNone(replacement)
            replacement.close()

    def test_legacy_supervisor_matching_is_scoped_to_exact_installation(self) -> None:
        root = Path("/srv/twn")
        instance = root / "instance"
        output = "\n".join([
            "101 python -m twn_toolkit.supervisor_worker --instance /srv/twn/instance --root /srv/twn --daemon --pid-file /srv/twn/instance/twn-supervisor.pid",
            "102 python -m twn_toolkit.supervisor_worker --instance /srv/twn-test/instance --root /srv/twn-test --daemon --pid-file /srv/twn-test/instance/twn-supervisor.pid",
            "103 python -m twn_toolkit.ftp_worker --instance /srv/twn/instance --daemon",
        ])
        self.assertEqual(matching_supervisor_pids(output, root, instance), [101])

    def test_daemon_matching_is_scoped_by_module_and_instance(self) -> None:
        instance = Path("/srv/twn/instance")
        output = "\n".join([
            "201 python -m twn_toolkit.automation_worker --instance /srv/twn/instance --daemon --pid-file automation.pid",
            "202 python -m twn_toolkit.automation_worker --instance /srv/twn-test/instance --daemon --pid-file automation.pid",
            "203 python -m twn_toolkit.ftp_worker --instance /srv/twn/instance --daemon --pid-file ftp.pid",
        ])
        self.assertEqual(
            matching_daemon_pids(
                output, "twn_toolkit.automation_worker", instance,
            ),
            [201],
        )

    @mock.patch("twn_toolkit.pidfiles.time.sleep")
    @mock.patch("twn_toolkit.pidfiles.os.kill")
    @mock.patch("twn_toolkit.pidfiles.subprocess.run")
    def test_daemon_cleanup_keeps_canonical_process(
        self, run: mock.Mock, kill: mock.Mock, _sleep: mock.Mock,
    ) -> None:
        run.return_value.stdout = "\n".join([
            "301 python -m twn_toolkit.ftp_worker --instance /srv/twn/instance --daemon --pid-file ftp.pid",
            "302 python -m twn_toolkit.ftp_worker --instance /srv/twn/instance --daemon --pid-file ftp-old.pid",
        ])
        kill.side_effect = [None, ProcessLookupError]

        stopped = stop_matching_daemons(
            "twn_toolkit.ftp_worker", Path("/srv/twn/instance"), keep_pid=301,
        )

        self.assertEqual(stopped, [302])
        self.assertEqual(
            kill.call_args_list,
            [mock.call(302, signal.SIGTERM), mock.call(302, 0)],
        )

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

    def test_profile_audit_snapshot_retains_only_secret_configuration_state(self) -> None:
        snapshot = audit_safe_snapshot(
            {
                "name": "Lab",
                "host": "192.0.2.1",
                "api_key": "never store this",
                "password": "also secret",
                "community": "",
            }
        )
        self.assertEqual(
            snapshot,
            {
                "name": "Lab",
                "host": "192.0.2.1",
                "configured sensitive fields": ["api_key", "password"],
            },
        )
        self.assertNotIn("never store this", json.dumps(snapshot))

    def test_user_audit_uses_profile_names_and_retains_stable_ids(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            auth = AuthStore(instance)
            profile = auth.save_access_profile(
                name="Wireless operators",
                description="Wireless troubleshooting access",
                tool_ids=["tools.ping"],
            )
            app = create_app(instance); app.testing = True; client = app.test_client()
            response = client.post(
                "/settings/users",
                data={
                    "username": "profile-user",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                    "access_profile_id": profile["id"],
                },
            )
            event = next(
                item
                for item in AuditStore(instance).recent(10)
                if item["action"] == "user.created"
            )
            diagnostics = client.get("/settings/diagnostics")

            AuditStore(instance).record(
                username="legacy-admin", method="POST", endpoint="create_user",
                path="/settings/users", status_code=302,
                category="Administration", action="user.created",
                summary="Created a legacy audit user.",
                details={
                    "changes": [{
                        "field": "access profiles", "before": None,
                        "after": [profile["id"]],
                    }]
                },
            )
            legacy_diagnostics = client.get(
                "/settings/diagnostics?audit_q=legacy-admin"
            )

        self.assertEqual(response.status_code, 302)
        profile_change = next(
            change
            for change in event["details"]["changes"]
            if change["field"] == "access profiles"
        )
        self.assertEqual(
            profile_change["after"],
            [{"type": "access profile", "name": "Wireless operators", "id": profile["id"]}],
        )
        self.assertIn(b"Wireless operators", diagnostics.data)
        self.assertIn(profile["id"].encode(), diagnostics.data)
        self.assertIn(b"Created a legacy audit user.", legacy_diagnostics.data)
        self.assertIn(b"Wireless operators", legacy_diagnostics.data)

    def test_ping_audit_records_session_lifecycle_without_round_noise(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance); app.testing = True; client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )
            with patch(
                "twn_toolkit.ping_routes.ping_hosts",
                return_value=[{"host": "127.0.0.1", "reachable": True, "latency_ms": 1.0}],
            ):
                self.assertEqual(
                    client.post("/tools/ping/run", json={"hosts": "Loopback = 127.0.0.1"}).status_code,
                    200,
                )
            self.assertEqual(
                client.post("/tools/ping/validate", json={"hosts": "Loopback = 127.0.0.1"}).status_code,
                200,
            )
            client.post(
                "/tools/ping/activity",
                json={
                    "event": "start",
                    "run_id": "run-1",
                    "targets": 1,
                    "target_hosts": [{"label": "Loopback", "host": "127.0.0.1"}],
                },
            )
            client.post(
                "/tools/ping/activity",
                json={
                    "event": "checkpoint",
                    "run_id": "run-1",
                    "probes_sent": 30,
                    "replies_received": 30,
                },
            )
            client.post("/tools/ping/activity", json={"event": "final", "run_id": "run-1"})

            events = [
                event
                for event in AuditStore(instance).recent(10)
                if event["action"].startswith("ping.")
            ]

        self.assertEqual([event["action"] for event in events], [
            "ping.session_stopped",
            "ping.session_started",
        ])
        self.assertEqual(events[1]["details"]["target_count"], 1)
        self.assertEqual(
            events[1]["details"]["targets"],
            [{"host": "127.0.0.1", "label": "Loopback"}],
        )
        self.assertEqual(
            events[1]["details"]["actor role"], "System administrator"
        )
        self.assertEqual(events[1]["details"]["actor access profiles"], [])

    def test_unannotated_admin_post_is_not_audited(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance); app.testing = True; client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )
            # Use the persisted signed-in account instead of Flask's synthetic
            # testing administrator for this user-preference route.
            app.testing = False
            self.assertEqual(
                client.post("/settings/theme", json={"theme": "dark"}).status_code,
                200,
            )
            events = AuditStore(instance).recent(10)

        self.assertEqual(
            [event["action"] for event in events],
            ["authentication.setup_succeeded"],
        )

    def test_oversized_audit_detail_remains_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = AuditStore(instance)
            store.record(details={f"field_{index}": "x" * 1000 for index in range(100)})
            details = store.recent(1)[0]["details"]
            self.assertTrue(details["truncated"])
            self.assertIn("storage limit", details["notice"])

    def test_audit_search_is_paginated_and_matches_structured_fields(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = AuditStore(instance)
            for index in range(45):
                store.record(
                    username=f"operator-{index}", method="POST",
                    endpoint="save_item", path="/items", status_code=302,
                    category="Local storage", action="item.saved",
                    summary=f"Saved item {index}.",
                    resource_name=f"Switch {index}",
                    details={"destination": f"closet-{index}"},
                )
            store.record(
                username="percent-user", method="POST", endpoint="save_item",
                path="/items", status_code=302, summary="Reached 100% completion.",
            )

            first = store.search(page=1, per_page=40)
            second = store.search(page=2, per_page=40)
            resource_match = store.search("closet-17")
            literal_wildcard = store.search("100%")

        self.assertEqual(first["total"], 46)
        self.assertEqual(len(first["events"]), 40)
        self.assertEqual(first["total_pages"], 2)
        self.assertEqual((second["first_item"], second["last_item"]), (41, 46))
        self.assertEqual(len(second["events"]), 6)
        self.assertEqual(resource_match["total"], 1)
        self.assertEqual(resource_match["events"][0]["username"], "operator-17")
        self.assertEqual(literal_wildcard["total"], 1)

    def test_legacy_audit_database_uses_rollback_safe_detail_table(self) -> None:
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
            connection = sqlite3.connect(path)
            try:
                columns = {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(audit_events)")
                }
                self.assertEqual(len(columns), 9)
                connection.execute(
                    "INSERT INTO audit_events VALUES ('rollback', 2, '1', 'admin', '127.0.0.1', 'POST', 'legacy', '/rollback', 302)"
                )
                connection.commit()
            finally:
                connection.close()

    def test_preview_expanded_audit_schema_is_normalized_without_data_loss(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            path = Path(instance) / "audit.sqlite3"
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    """
                    CREATE TABLE audit_events (
                        id TEXT PRIMARY KEY, recorded_at REAL NOT NULL, user_id TEXT NOT NULL,
                        username TEXT NOT NULL, remote_ip TEXT NOT NULL, method TEXT NOT NULL,
                        endpoint TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL,
                        category TEXT NOT NULL DEFAULT '', action TEXT NOT NULL DEFAULT '',
                        summary TEXT NOT NULL DEFAULT '', resource_type TEXT NOT NULL DEFAULT '',
                        resource_id TEXT NOT NULL DEFAULT '', resource_name TEXT NOT NULL DEFAULT '',
                        detail_json TEXT NOT NULL DEFAULT '{}'
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO audit_events VALUES (
                        'preview', 1, '1', 'admin', '127.0.0.1', 'POST',
                        'save', '/settings', 302, 'Administration',
                        'settings.updated', 'Updated settings.', 'settings',
                        'server', 'Server settings', '{"visible":"retained"}'
                    )
                    """
                )
                connection.commit()
            finally:
                connection.close()

            event = AuditStore(instance).recent(1)[0]
            self.assertEqual(event["summary"], "Updated settings.")
            self.assertEqual(event["details"], {"visible": "retained"})
            connection = sqlite3.connect(path)
            try:
                columns = list(connection.execute("PRAGMA table_info(audit_events)"))
                self.assertEqual(len(columns), 9)
                connection.execute(
                    "INSERT INTO audit_events VALUES ('rollback', 2, '1', 'admin', '127.0.0.1', 'POST', 'legacy', '/rollback', 302)"
                )
                connection.commit()
            finally:
                connection.close()

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
            AuditStore(instance).record(
                username="searchable-operator", method="POST", endpoint="rename",
                path="/local/datastore/rename", status_code=302,
                category="Local storage", action="datastore.item_renamed",
                summary="Renamed a very distinctive folder.",
            )
            page = client.get("/settings/diagnostics")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"System diagnostics", page.data)
            self.assertIn(b'class="field-note audit-empty-detail"', page.data)
            self.assertIn(b"Search audit history", page.data)
            filtered = client.get(
                "/settings/diagnostics?audit_q=distinctive+folder"
            )
            self.assertIn(b"Renamed a very distinctive folder.", filtered.data)
            self.assertNotIn(b"Saved example settings.", filtered.data)
            self.assertIn(b"Showing 1", filtered.data)
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
