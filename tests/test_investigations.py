from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.investigations import InvestigationError, InvestigationStore


class InvestigationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = InvestigationStore(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_lifecycle_enforces_one_open_investigation_and_immutable_events(self) -> None:
        investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Branch outage",
            description="Intermittent reachability after maintenance.",
        )

        self.assertEqual(investigation["state"], "recording")
        self.assertEqual(investigation["event_count"], 1)
        self.assertTrue(
            Path(self.temporary.name, "datastore", investigation["datastore_path"], "Evidence").is_dir()
        )
        self.assertTrue(
            Path(self.temporary.name, "datastore", investigation["datastore_path"], "Reports").is_dir()
        )
        with self.assertRaisesRegex(InvestigationError, "Finish the current"):
            self.store.create(
                owner_user_id="operator-1",
                owner_username="nelson",
                title="Second issue",
            )

        first = self.store.record_for_active(
            user_id="operator-1",
            username="nelson",
            operation_id="dns-run-1",
            event_type="diagnostic.completed",
            tool_id="tools.dns_response",
            action="DNS lookup",
            outcome="succeeded",
            summary="Resolved one host.",
            targets={"hosts": ["example.com"]},
            parameters={"record_type": "A"},
            metrics={"successful": 1},
            details={"answers": ["192.0.2.10"]},
            started_at=10,
            completed_at=11,
        )
        duplicate = self.store.record_for_active(
            user_id="operator-1",
            username="nelson",
            operation_id="dns-run-1",
            event_type="diagnostic.completed",
            tool_id="tools.dns_response",
            action="DNS lookup",
            outcome="succeeded",
            summary="This duplicate must not replace retained evidence.",
            targets={},
            parameters={},
            metrics={},
            details={},
            started_at=12,
            completed_at=13,
        )
        self.assertEqual(first["id"], duplicate["id"])
        events = self.store.events_for_user(investigation["id"], "operator-1")
        retained = next(event for event in events if event["id"] == first["id"])
        self.assertEqual(retained["summary"], "Resolved one host.")
        self.assertEqual(retained["details"], {"answers": ["192.0.2.10"]})

        paused = self.store.set_state(
            investigation["id"], "operator-1", "nelson", "paused"
        )
        self.assertEqual(paused["state"], "paused")
        self.assertIsNone(
            self.store.record_for_active(
                user_id="operator-1",
                username="nelson",
                operation_id="not-recorded",
                event_type="diagnostic.completed",
                tool_id="tools.dns_response",
                action="DNS lookup",
                outcome="succeeded",
                summary="Paused event.",
                targets={},
                parameters={},
                metrics={},
                details={},
                started_at=14,
                completed_at=15,
            )
        )
        note = self.store.add_note(
            investigation["id"], "operator-1", "nelson", "Firewall changed at 09:45."
        )
        self.assertEqual(note["event_type"], "note.added")

        completed = self.store.set_state(
            investigation["id"], "operator-1", "nelson", "completed"
        )
        self.assertEqual(completed["state"], "completed")
        with self.assertRaisesRegex(InvestigationError, "cannot be changed"):
            self.store.add_note(
                investigation["id"], "operator-1", "nelson", "Too late"
            )
        next_investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Next issue",
        )
        self.assertEqual(next_investigation["state"], "recording")

    def test_investigations_are_owner_scoped_and_database_is_owner_only(self) -> None:
        investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Private investigation",
        )
        with self.assertRaisesRegex(InvestigationError, "not found"):
            self.store.get_for_user(investigation["id"], "operator-2")
        self.assertEqual(self.store.list_for_user("operator-2"), [])
        self.assertEqual(os.stat(self.store.path).st_mode & 0o777, 0o600)

    def test_evidence_is_hashed_and_collision_safe_in_managed_datastore_folder(self) -> None:
        investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Evidence test",
        )
        first = self.store.add_evidence(
            investigation_id=investigation["id"],
            user_id="operator-1",
            username="nelson",
            filename="show output.txt",
            content_type="text/plain",
            stream=io.BytesIO(b"first output"),
        )
        second = self.store.add_evidence(
            investigation_id=investigation["id"],
            user_id="operator-1",
            username="nelson",
            filename="show output.txt",
            content_type="text/plain",
            stream=io.BytesIO(b"second output"),
        )

        self.assertEqual(first["display_name"], "show output.txt")
        self.assertEqual(second["display_name"], "show output-2.txt")
        self.assertEqual(
            first["sha256"],
            "3b8e4d4df44b189b3a915baf5bb9907b2b7325ed5d3be82a81da00d196ce9d3f",
        )
        self.assertEqual(len(self.store.artifacts_for_user(investigation["id"], "operator-1")), 2)
        events = self.store.events_for_user(investigation["id"], "operator-1")
        self.assertEqual(sum(event["event_type"] == "evidence.added" for event in events), 2)


class InvestigationRouteTests(unittest.TestCase):
    def test_access_profiles_gate_routes_and_owner_scope_hides_other_journals(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )
            auth = AuthStore(instance)
            investigators = auth.save_access_profile(
                name="Investigators", tool_ids=["investigations.workspace"]
            )
            ping_only = auth.save_access_profile(
                name="Ping only", tool_ids=["tools.ping"]
            )
            auth.create_user(
                "alice",
                "a different long password",
                access_profile_ids=[investigators["id"]],
            )
            auth.create_user(
                "bob",
                "another different password",
                access_profile_ids=[investigators["id"]],
            )
            auth.create_user(
                "charlie",
                "yet another long password",
                access_profile_ids=[ping_only["id"]],
            )

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "alice", "password": "a different long password"},
            )
            client.post("/investigations", data={"title": "Alice private case"})
            investigation = InvestigationStore(instance).active_for_user(
                auth.get_user("alice")["id"]
            )
            self.assertIsNotNone(investigation)
            investigation_url = f"/investigations/{investigation['id']}"
            self.assertEqual(client.get(investigation_url).status_code, 200)
            self.assertNotIn(b"Open folder in Datastore", client.get(
                f"{investigation_url}/evidence"
            ).data)

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "bob", "password": "another different password"},
            )
            self.assertEqual(client.get(investigation_url).status_code, 404)

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "charlie", "password": "yet another long password"},
            )
            self.assertEqual(client.get("/investigations").status_code, 403)

    def test_vertical_slice_records_dns_notes_evidence_and_renders_report(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()

            page = client.get("/investigations")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Start an investigation", page.data)
            created = client.post(
                "/investigations",
                data={
                    "title": "Branch office outage",
                    "description": "Users report intermittent access.",
                },
            )
            self.assertEqual(created.status_code, 302)
            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            self.assertIsNotNone(investigation)
            investigation_id = str(investigation["id"])

            dns_result = {
                "host_label": "Portal",
                "host": "portal.example.com",
                "server_label": "Cloudflare",
                "server": "1.1.1.1",
                "record_type": "A",
                "status": "success",
                "answers": ["192.0.2.10"],
                "response_ms": 12.5,
            }
            with patch(
                "twn_toolkit.dns_routes.dns_lookup_matrix",
                return_value=[dns_result],
            ):
                response = client.post(
                    "/tools/dns-response",
                    data={
                        "hosts": "Portal = portal.example.com",
                        "servers": "Cloudflare = 1.1.1.1",
                        "record_type": "A",
                        "timeout": "3",
                        "mode": "compare",
                        "duration": "10",
                        "qps": "50",
                        "concurrency": "40",
                    },
                )
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Recorded in the active investigation", response.data)
            self.assertIn(b"Branch office outage", response.data)

            note = client.post(
                f"/investigations/{investigation_id}/notes",
                data={"note": "The firewall policy changed at 09:45."},
            )
            self.assertEqual(note.status_code, 302)
            upload = client.post(
                f"/investigations/{investigation_id}/evidence",
                data={"files": (io.BytesIO(b"show system status"), "status.txt")},
                content_type="multipart/form-data",
            )
            self.assertEqual(upload.status_code, 302)

            events = store.events_for_user(investigation_id, "test-user")
            dns_event = next(event for event in events if event["tool_id"] == "tools.dns_response")
            self.assertEqual(dns_event["outcome"], "succeeded")
            self.assertEqual(dns_event["details"]["results"], [dns_result])
            self.assertTrue(any(event["event_type"] == "note.added" for event in events))
            self.assertTrue(any(event["event_type"] == "evidence.added" for event in events))

            evidence = client.get(f"/investigations/{investigation_id}/evidence")
            self.assertEqual(evidence.status_code, 200)
            self.assertIn(b"status.txt", evidence.data)
            self.assertIn(b"SHA-256", evidence.data)
            artifact = store.artifacts_for_user(investigation_id, "test-user")[0]
            download = client.get(
                f"/investigations/{investigation_id}/evidence/{artifact['id']}/download"
            )
            self.assertEqual(download.data, b"show system status")
            self.assertIn("attachment", download.headers["Content-Disposition"])
            download.close()

            report = client.get(f"/investigations/{investigation_id}/report")
            self.assertEqual(report.status_code, 200)
            self.assertIn(b"Troubleshooting report", report.data)
            self.assertIn(b"portal.example.com", report.data)
            self.assertIn(b"192.0.2.10", report.data)
            self.assertIn(b"status.txt", report.data)

    def test_pause_stops_automatic_tool_recording_but_keeps_manual_context(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Paused journal"})
            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            investigation_id = str(investigation["id"])

            client.post(
                f"/investigations/{investigation_id}/state",
                data={"state": "paused"},
            )
            before = len(store.events_for_user(investigation_id, "test-user"))
            with patch(
                "twn_toolkit.dns_routes.dns_lookup_matrix",
                return_value=[{
                    "host_label": "", "host": "example.com", "server_label": "",
                    "server": "1.1.1.1", "record_type": "A", "status": "success",
                    "answers": ["192.0.2.1"], "response_ms": 1.0,
                }],
            ):
                response = client.post(
                    "/tools/dns-response",
                    data={
                        "hosts": "example.com", "servers": "1.1.1.1",
                        "record_type": "A", "timeout": "3", "mode": "compare",
                        "duration": "10", "qps": "50", "concurrency": "40",
                    },
                )
            self.assertNotIn(b"Recorded in the active investigation", response.data)
            self.assertIn(b"Recording paused for", response.data)
            self.assertEqual(
                len(store.events_for_user(investigation_id, "test-user")), before
            )
            client.post(
                f"/investigations/{investigation_id}/notes",
                data={"note": "Manual context remains intentional while paused."},
            )
            self.assertEqual(
                len(store.events_for_user(investigation_id, "test-user")), before + 1
            )


if __name__ == "__main__":
    unittest.main()
