from __future__ import annotations

import io
import sqlite3
import tempfile
import unittest
from contextlib import closing

from twn_toolkit import create_app
from twn_toolkit.investigations import InvestigationError, InvestigationStore


class InvestigationMergeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = InvestigationStore(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _closed_case_with_evidence(self, title: str = "Branch evidence") -> dict:
        investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title=title,
        )
        self.store.add_note(
            investigation["id"],
            "operator-1",
            "nelson",
            "The uplink failed immediately after the change.",
        )
        self.store.add_evidence(
            investigation_id=investigation["id"],
            user_id="operator-1",
            username="nelson",
            filename="show interface.txt",
            content_type="text/plain",
            stream=io.BytesIO(b"port1: down\n"),
        )
        self.store.set_state(
            investigation["id"], "operator-1", "nelson", "completed"
        )
        self.store.set_report_contents(
            investigation["id"],
            "operator-1",
            event_ids=[],
            artifact_ids=[],
        )
        return self.store.get_for_user(investigation["id"], "operator-1")

    def test_merge_preserves_source_attribution_relationships_and_report_choices(self) -> None:
        source = self._closed_case_with_evidence()
        source_events_before = self.store.events_for_user(
            source["id"], "operator-1"
        )
        source_artifacts_before = self.store.artifacts_for_user(
            source["id"], "operator-1"
        )
        destination = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Primary outage",
        )

        preview = self.store.preview_case_merge(
            source_investigation_id=source["id"],
            destination_investigation_id=destination["id"],
            user_id="operator-1",
        )
        self.assertEqual(preview["new_event_count"], len(source_events_before))
        self.assertEqual(preview["new_artifact_count"], 1)
        self.assertEqual(preview["duplicate_event_count"], 0)
        self.assertEqual(preview["duplicate_artifact_count"], 0)
        self.assertEqual(preview["new_artifact_bytes"], len(b"port1: down\n"))

        result = self.store.merge_case(
            source_investigation_id=source["id"],
            destination_investigation_id=destination["id"],
            user_id="operator-1",
            username="nelson",
        )
        self.assertEqual(result["event_count"], len(source_events_before))
        self.assertEqual(result["artifact_count"], 1)
        self.assertEqual(result["destination"]["state"], "recording")

        destination_events = self.store.events_for_user(
            destination["id"], "operator-1"
        )
        copied_note = next(
            event
            for event in destination_events
            if event["summary"] == "The uplink failed immediately after the change."
        )
        self.assertEqual(copied_note["created_by_username"], "nelson")
        self.assertEqual(copied_note["report_placement"], "excluded")
        self.assertEqual(copied_note["origin_case_id"], source["id"])
        boundary = next(
            event
            for event in destination_events
            if event["event_type"] == "investigation.merged"
        )
        self.assertEqual(boundary["metrics"]["evidence_count"], 1)

        destination_artifacts = self.store.artifacts_for_user(
            destination["id"], "operator-1"
        )
        self.assertEqual(len(destination_artifacts), 1)
        copied_artifact = destination_artifacts[0]
        self.assertEqual(copied_artifact["report_placement"], "excluded")
        self.assertEqual(copied_artifact["origin_case_id"], source["id"])
        self.assertIsNotNone(copied_artifact["event_id"])
        self.assertEqual(
            self.store.datastore.file(copied_artifact["relative_path"]).read_bytes(),
            b"port1: down\n",
        )

        self.assertEqual(
            self.store.events_for_user(source["id"], "operator-1"),
            source_events_before,
        )
        self.assertEqual(
            self.store.artifacts_for_user(source["id"], "operator-1"),
            source_artifacts_before,
        )
        with self.assertRaisesRegex(InvestigationError, "already been merged"):
            self.store.merge_case(
                source_investigation_id=source["id"],
                destination_investigation_id=destination["id"],
                user_id="operator-1",
                username="nelson",
            )

    def test_chained_merge_skips_records_with_existing_origins(self) -> None:
        original = self._closed_case_with_evidence("Original branch case")
        intermediate = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Intermediate case",
        )
        original_result = self.store.merge_case(
            source_investigation_id=original["id"],
            destination_investigation_id=intermediate["id"],
            user_id="operator-1",
            username="nelson",
        )
        self.store.set_state(
            intermediate["id"], "operator-1", "nelson", "completed"
        )
        final = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Final case",
        )
        self.store.merge_case(
            source_investigation_id=original["id"],
            destination_investigation_id=final["id"],
            user_id="operator-1",
            username="nelson",
        )

        preview = self.store.preview_case_merge(
            source_investigation_id=intermediate["id"],
            destination_investigation_id=final["id"],
            user_id="operator-1",
        )
        self.assertEqual(
            preview["duplicate_event_count"], original_result["event_count"]
        )
        self.assertEqual(preview["duplicate_artifact_count"], 1)
        self.assertGreater(preview["new_event_count"], 0)
        self.assertEqual(preview["new_artifact_count"], 0)

        result = self.store.merge_case(
            source_investigation_id=intermediate["id"],
            destination_investigation_id=final["id"],
            user_id="operator-1",
            username="nelson",
        )
        self.assertEqual(result["artifact_count"], 0)
        artifacts = self.store.artifacts_for_user(final["id"], "operator-1")
        self.assertEqual(len(artifacts), 1)
        note_matches = [
            event
            for event in self.store.events_for_user(final["id"], "operator-1")
            if event["summary"] == "The uplink failed immediately after the change."
        ]
        self.assertEqual(len(note_matches), 1)

    def test_merge_rejects_open_source_non_owner_destination_and_changed_evidence(self) -> None:
        open_source = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Still open",
        )
        with self.assertRaisesRegex(InvestigationError, "Close the source"):
            self.store.preview_case_merge(
                source_investigation_id=open_source["id"],
                destination_investigation_id="missing",
                user_id="operator-1",
            )
        self.store.set_state(
            open_source["id"], "operator-1", "nelson", "completed"
        )

        shared_source = self.store.create(
            owner_user_id="operator-2",
            owner_username="morgan",
            title="Shared source",
        )
        self.store.set_state(
            shared_source["id"], "operator-2", "morgan", "completed"
        )

        other_destination = self.store.create(
            owner_user_id="operator-3",
            owner_username="alex",
            title="Someone else's destination",
        )
        self.store.add_participant(
            other_destination["id"],
            "operator-3",
            "alex",
            "operator-2",
            "morgan",
        )
        with self.assertRaisesRegex(InvestigationError, "own"):
            self.store.preview_case_merge(
                source_investigation_id=shared_source["id"],
                destination_investigation_id=other_destination["id"],
                user_id="operator-2",
            )

        owned_source = self._closed_case_with_evidence("Changed evidence source")
        destination = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Verification destination",
        )
        source_artifact = self.store.artifacts_for_user(
            owned_source["id"], "operator-1"
        )[0]
        self.store.datastore.file(source_artifact["relative_path"]).write_bytes(
            b"changed after retention\n"
        )
        destination_events_before = self.store.events_for_user(
            destination["id"], "operator-1"
        )
        with self.assertRaisesRegex(InvestigationError, "changed since"):
            self.store.merge_case(
                source_investigation_id=owned_source["id"],
                destination_investigation_id=destination["id"],
                user_id="operator-1",
                username="nelson",
            )
        self.assertEqual(
            self.store.events_for_user(destination["id"], "operator-1"),
            destination_events_before,
        )
        evidence_entries = self.store.datastore.list(
            f"{destination['datastore_path']}/Evidence"
        )["entries"]
        self.assertEqual(evidence_entries, [])

    def test_schema_upgrade_adds_merge_ledger(self) -> None:
        investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Existing case",
        )
        with closing(sqlite3.connect(self.store.path)) as connection, connection:
            connection.execute("DROP TABLE investigation_merges")
            connection.execute(
                "UPDATE investigation_meta SET value = '3' WHERE key = 'schema_version'"
            )
        migrated = InvestigationStore(self.temporary.name).get_for_user(
            investigation["id"], "operator-1"
        )
        self.assertEqual(migrated["title"], "Existing case")
        with closing(sqlite3.connect(self.store.path)) as connection:
            version = connection.execute(
                "SELECT value FROM investigation_meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name = 'investigation_merges'"
            ).fetchone()
        self.assertEqual(version, "4")
        self.assertIsNotNone(table)


class InvestigationMergeRouteTests(unittest.TestCase):
    def test_operator_reviews_and_confirms_case_merge(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Closed source"})
            store = InvestigationStore(instance)
            source = store.active_for_user("test-user")
            client.post(
                f"/investigations/{source['id']}/notes",
                data={"note": "Remote office lost upstream reachability."},
            )
            client.post(
                f"/investigations/{source['id']}/evidence",
                data={"files": (io.BytesIO(b"route output\n"), "route.txt")},
                content_type="multipart/form-data",
            )
            client.post(
                f"/investigations/{source['id']}/state",
                data={"state": "completed"},
            )
            client.post("/investigations", data={"title": "Open destination"})
            destination = store.active_for_user("test-user")

            source_page = client.get(f"/investigations/{source['id']}")
            self.assertIn(b"Merge this case", source_page.data)
            self.assertIn(b"Open destination", source_page.data)
            preview = client.get(
                f"/investigations/{source['id']}/merge",
                query_string={"destination_id": destination["id"]},
            )
            self.assertEqual(preview.status_code, 200)
            self.assertIn(b"Review case merge", preview.data)
            self.assertIn(b"The source remains a separate", preview.data)
            self.assertIn(b"Case participants and permissions are not copied", preview.data)

            merged = client.post(
                f"/investigations/{source['id']}/merge",
                data={"destination_id": destination["id"]},
                follow_redirects=True,
            )
            self.assertEqual(merged.status_code, 200)
            self.assertIn(b"Merged", merged.data)
            self.assertIn(b"Case merged", merged.data)
            self.assertIn(b"Remote office lost upstream reachability", merged.data)
            self.assertEqual(
                len(store.artifacts_for_user(destination["id"], "test-user")), 1
            )


if __name__ == "__main__":
    unittest.main()
