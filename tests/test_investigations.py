from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
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
        with self.assertRaisesRegex(InvestigationError, "Close the current"):
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
        with self.assertRaisesRegex(InvestigationError, "paused mode"):
            self.store.set_state(
                investigation["id"], "operator-1", "nelson", "recording"
            )
        reopened = self.store.set_state(
            investigation["id"], "operator-1", "nelson", "paused"
        )
        self.assertEqual(reopened["state"], "paused")
        self.assertIsNone(reopened["ended_at"])
        reopened_event = self.store.events_for_user(
            investigation["id"], "operator-1"
        )[-1]
        self.assertEqual(reopened_event["event_type"], "investigation.reopened")
        self.assertEqual(
            reopened_event["parameters"],
            {"previous_state": "completed", "state": "paused"},
        )
        reopened_note = self.store.add_note(
            investigation["id"], "operator-1", "nelson", "Follow-up work began."
        )
        self.assertEqual(reopened_note["event_type"], "note.added")
        self.store.set_state(
            investigation["id"], "operator-1", "nelson", "completed"
        )
        next_investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Next issue",
        )
        self.assertEqual(next_investigation["state"], "recording")

        with self.assertRaisesRegex(
            InvestigationError, 'Close the current case "Next issue"'
        ):
            self.store.set_state(
                investigation["id"], "operator-1", "nelson", "paused"
            )
        self.assertEqual(
            self.store.get_for_user(investigation["id"], "operator-1")["state"],
            "completed",
        )

    def test_report_contents_are_atomic_and_editable_after_case_closes(self) -> None:
        investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Report selection",
        )
        diagnostic = self.store.record_for_active(
            user_id="operator-1",
            username="nelson",
            operation_id="dns-report-selection",
            event_type="diagnostic.completed",
            tool_id="tools.dns_response",
            action="DNS lookup",
            outcome="succeeded",
            summary="Retained diagnostic summary.",
            targets={"hosts": ["example.com"]},
            parameters={"record_type": "A"},
            metrics={"successful": 1, "failed": 0},
            details={"results": [{"host": "example.com"}]},
            started_at=10,
            completed_at=11,
        )
        artifact = self.store.add_evidence(
            investigation_id=investigation["id"],
            user_id="operator-1",
            username="nelson",
            filename="status.txt",
            content_type="text/plain",
            stream=io.BytesIO(b"retained evidence"),
        )
        self.store.set_state(
            investigation["id"], "operator-1", "nelson", "completed"
        )

        counts = self.store.set_report_contents(
            investigation["id"],
            "operator-1",
            event_ids=[diagnostic["id"], diagnostic["id"]],
            artifact_ids=[],
        )
        self.assertEqual(counts, {"included_events": 1, "included_artifacts": 0})
        events = self.store.events_for_user(investigation["id"], "operator-1")
        self.assertEqual(
            [event["id"] for event in events if event["report_placement"] == "main"],
            [diagnostic["id"]],
        )
        self.assertEqual(
            next(event for event in events if event["id"] == diagnostic["id"])[
                "summary"
            ],
            "Retained diagnostic summary.",
        )
        self.assertEqual(
            self.store.artifacts_for_user(investigation["id"], "operator-1")[0][
                "report_placement"
            ],
            "excluded",
        )

        with self.assertRaisesRegex(InvestigationError, "unknown journal event"):
            self.store.set_report_contents(
                investigation["id"],
                "operator-1",
                event_ids=["not-an-event"],
                artifact_ids=[artifact["id"]],
            )
        unchanged = self.store.events_for_user(investigation["id"], "operator-1")
        self.assertEqual(
            [event["id"] for event in unchanged if event["report_placement"] == "main"],
            [diagnostic["id"]],
        )

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
            self.assertIn(b"Start a case", page.data)
            self.assertIn(b"Case title", page.data)
            self.assertIn(b"Open case", page.data)
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
            self.assertIn(b"Recorded in the active case", response.data)
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
            self.assertIn(b"Back to investigations", report.data)
            self.assertIn(b"Case report", report.data)
            self.assertIn(b"Case timeline", report.data)
            self.assertIn(b"Detailed results R-01", report.data)
            self.assertIn(
                f'href="#report-result-{dns_event["id"]}"'.encode(), report.data
            )
            self.assertIn(b"portal.example.com", report.data)
            self.assertIn(b"192.0.2.10", report.data)
            self.assertIn(b"status.txt", report.data)

            pdf = client.get(
                f"/investigations/{investigation_id}/report.pdf"
            )
            self.assertEqual(pdf.status_code, 200)
            self.assertEqual(pdf.mimetype, "application/pdf")
            self.assertTrue(pdf.data.startswith(b"%PDF-"))
            self.assertIn(
                ".pdf",
                pdf.headers["Content-Disposition"],
            )

            package = client.get(
                f"/investigations/{investigation_id}/package.zip"
            )
            self.assertEqual(package.status_code, 200)
            self.assertEqual(package.mimetype, "application/zip")
            with zipfile.ZipFile(io.BytesIO(package.data)) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {"case-report.pdf", "evidence/status.txt", "manifest.json"},
                )
                packaged_pdf = archive.read("case-report.pdf")
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(archive.read("evidence/status.txt"), b"show system status")
            self.assertEqual(manifest["schema"], "twn.case-package.v1")
            self.assertEqual(manifest["case"]["id"], investigation_id)
            self.assertEqual(manifest["report"]["byte_count"], len(packaged_pdf))
            self.assertEqual(
                manifest["report"]["sha256"],
                hashlib.sha256(packaged_pdf).hexdigest(),
            )
            self.assertEqual(manifest["evidence"][0]["sha256"], artifact["sha256"])
            self.assertEqual(
                {item["id"] for item in manifest["timeline"]},
                {event["id"] for event in events},
            )

            completed = client.post(
                f"/investigations/{investigation_id}/state",
                data={"state": "completed"},
            )
            self.assertEqual(completed.status_code, 302)
            self.assertEqual(completed.headers["Location"], "/investigations")
            history = client.get(completed.headers["Location"])
            self.assertIn(b"Branch office outage", history.data)
            self.assertIn(b"Closed", history.data)

            curated = client.post(
                f"/investigations/{investigation_id}/report/contents",
                data={"event_id": dns_event["id"]},
            )
            self.assertEqual(curated.status_code, 302)
            curated_report = client.get(curated.headers["Location"])
            self.assertIn(b"Saved the case report contents.", curated_report.data)
            report_preview = curated_report.data.split(
                b'<article class="investigation-report"', 1
            )[1]
            self.assertIn(b"portal.example.com", report_preview)
            self.assertNotIn(b"The firewall policy changed at 09:45.", report_preview)
            self.assertNotIn(b"Evidence appendix", report_preview)

            curated_package = client.get(
                f"/investigations/{investigation_id}/package.zip"
            )
            with zipfile.ZipFile(io.BytesIO(curated_package.data)) as archive:
                curated_manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(
                    set(archive.namelist()), {"case-report.pdf", "manifest.json"}
                )
            self.assertEqual(
                [item["id"] for item in curated_manifest["timeline"]],
                [dns_event["id"]],
            )
            self.assertEqual(curated_manifest["evidence"], [])

            closed_case = client.get(
                f"/investigations/{investigation_id}"
            )
            self.assertIn(b"Reopen case", closed_case.data)
            reopened = client.post(
                f"/investigations/{investigation_id}/state",
                data={"state": "paused"},
            )
            self.assertEqual(reopened.status_code, 302)
            self.assertEqual(
                reopened.headers["Location"],
                f"/investigations/{investigation_id}",
            )
            reopened_case = client.get(reopened.headers["Location"])
            self.assertIn(
                b"Case reopened with automatic recording paused.",
                reopened_case.data,
            )
            self.assertIn(b"Resume recording", reopened_case.data)
            self.assertNotIn(b"Reopen case", reopened_case.data)
            reopened_record = store.get_for_user(investigation_id, "test-user")
            self.assertEqual(reopened_record["state"], "paused")
            self.assertIsNone(reopened_record["ended_at"])
            self.assertEqual(
                store.events_for_user(investigation_id, "test-user")[-1][
                    "event_type"
                ],
                "investigation.reopened",
            )

    def test_case_package_rejects_evidence_changed_outside_the_journal(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Changed evidence"})
            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            artifact = store.add_evidence(
                investigation_id=investigation["id"],
                user_id="test-user",
                username="test-user",
                filename="status.txt",
                content_type="text/plain",
                stream=io.BytesIO(b"original"),
            )
            store.datastore.file(artifact["relative_path"]).write_bytes(b"changed")

            response = client.get(
                f"/investigations/{investigation['id']}/package.zip"
            )

            self.assertEqual(response.status_code, 409)
            self.assertIn(b"has changed since upload", response.data)

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
            self.assertNotIn(b"Recorded in the active case", response.data)
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

    def test_finite_diagnostics_share_case_recording_and_report_presentations(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Network baseline"})
            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            investigation_id = str(investigation["id"])

            port_results = [
                {
                    "host": "192.0.2.10",
                    "label": "Core",
                    "port": 443,
                    "service": "https",
                    "status": "open",
                    "detail": "",
                    "elapsed_ms": 4.2,
                },
                {
                    "host": "192.0.2.10",
                    "label": "Core",
                    "port": 8443,
                    "service": "",
                    "status": "closed",
                    "detail": "Connection refused",
                    "elapsed_ms": 1.1,
                },
            ]
            with patch(
                "twn_toolkit.port_scanner_routes.scan_tcp_ports",
                return_value=port_results,
            ):
                port_page = client.post(
                    "/tools/port-scanner",
                    data={
                        "hosts": "Core = 192.0.2.10",
                        "ports": "443, 8443",
                        "timeout": "1",
                        "concurrency": "20",
                    },
                )
            self.assertIn(b"Recorded in the active case", port_page.data)

            trace_result = {
                "host": "example.com",
                "family": "IPv4",
                "method": "UDP",
                "raw_output": "trace output",
                "hops": [
                    {
                        "number": 1,
                        "responded": True,
                        "name": "gateway.local",
                        "addresses": ["192.0.2.1"],
                        "latencies_ms": [1.2, 1.4],
                        "average_ms": 1.3,
                        "loss_percent": 0,
                    }
                ],
                "hop_count": 1,
                "responding_hops": 1,
                "reached": True,
                "destination_addresses": ["93.184.216.34"],
            }
            with patch(
                "twn_toolkit.traceroute_routes.run_traceroute",
                return_value=trace_result,
            ):
                trace_page = client.post(
                    "/tools/traceroute",
                    data={
                        "host": "example.com",
                        "family": "auto",
                        "method": "udp",
                        "max_hops": "30",
                        "probes": "3",
                        "timeout": "2",
                    },
                )
            self.assertIn(b"Recorded in the active case", trace_page.data)

            ntp_result = {
                "host": "ntp.example",
                "label": "Primary",
                "port": 123,
                "resolved_address": "192.0.2.123",
                "status": "success",
                "successful_samples": 1,
                "total_samples": 1,
                "offset_ms": 0.5,
                "delay_ms": 10.2,
                "jitter_ms": 0.0,
                "stratum": 2,
                "version": 4,
                "leap_text": "No warning",
                "reference_id": "192.0.2.1",
                "reference_time": "2023-11-14T00:00:00.000Z",
                "root_delay_ms": 2.0,
                "root_dispersion_ms": 1.0,
                "precision_seconds": 0.000001,
                "synchronized": True,
                "samples": [
                    {
                        "status": "success",
                        "offset_ms": 0.5,
                        "delay_ms": 10.2,
                        "server_time": "2023-11-14T00:00:01.000Z",
                    }
                ],
            }
            with patch(
                "twn_toolkit.ntp_routes.test_ntp_servers",
                return_value=[ntp_result],
            ):
                ntp_page = client.post(
                    "/tools/ntp-test",
                    data={
                        "hosts": "Primary = ntp.example",
                        "port": "123",
                        "timeout": "3",
                        "samples": "1",
                    },
                )
            self.assertIn(b"Recorded in the active case", ntp_page.data)

            mtu_result = {
                "host": "example.test",
                "address": "192.0.2.1",
                "family": "IPv4",
                "mtu": 1400,
                "minimum": 576,
                "maximum": 1500,
                "overhead": 28,
                "conclusive": True,
                "probes": [
                    {
                        "mtu": 1400,
                        "payload": 1372,
                        "success": True,
                        "detail": "reply",
                    }
                ],
            }
            with patch(
                "twn_toolkit.path_mtu_routes.test_path_mtu",
                return_value=mtu_result,
            ):
                mtu_page = client.post(
                    "/tools/path-mtu",
                    data={
                        "host": "example.test",
                        "family": "auto",
                        "minimum": "576",
                        "maximum": "1500",
                        "timeout": "1",
                    },
                )
            self.assertIn(b"Recorded in the active case", mtu_page.data)

            speed = client.post(
                "/tools/speed-test/activity",
                json={
                    "download_bytes": 125_000_000,
                    "upload_bytes": 50_000_000,
                    "download_mbps": 125.5,
                    "upload_mbps": 50.25,
                    "latency_ms": 8.4,
                    "jitter_ms": 1.2,
                },
            )
            self.assertTrue(speed.get_json()["case_recorded"])

            events = store.events_for_user(investigation_id, "test-user")
            recorded_tools = {
                event["tool_id"]
                for event in events
                if event["tool_id"] != "investigations.workspace"
            }
            self.assertEqual(
                recorded_tools,
                {
                    "tools.port_scanner",
                    "tools.traceroute",
                    "tools.ntp_test",
                    "tools.path_mtu",
                    "tools.speed_test",
                },
            )
            report = client.get(f"/investigations/{investigation_id}/report")
            for value in (
                b"TCP port scan",
                b"gateway.local",
                b"Primary",
                b"1400 bytes",
                b"125.5 Mbps",
            ):
                self.assertIn(value, report.data)
            self.assertEqual(report.data.count(b"Detailed results R-"), 4)


if __name__ == "__main__":
    unittest.main()
