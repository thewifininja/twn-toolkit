from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.automation import AutomationStore
from twn_toolkit.automation_registry import ActionResult, ConditionResult
from twn_toolkit.auth import AuthStore
from twn_toolkit.investigations import InvestigationError, InvestigationStore
from twn_toolkit.live_tools import LiveToolStore
from twn_toolkit.packet_capture import PacketCaptureStore


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

    def test_investigations_are_explicitly_shared_and_database_is_owner_only(self) -> None:
        investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Private investigation",
        )
        with self.assertRaisesRegex(InvestigationError, "not found"):
            self.store.get_for_user(investigation["id"], "operator-2")
        self.assertEqual(self.store.list_for_user("operator-2"), [])

        participants = self.store.add_participant(
            investigation["id"],
            "operator-1",
            "nelson",
            "operator-2",
            "morgan",
        )
        self.assertEqual(
            [(item["username"], item["role"]) for item in participants],
            [("nelson", "owner"), ("morgan", "collaborator")],
        )
        shared = self.store.get_for_user(investigation["id"], "operator-2")
        self.assertEqual(shared["access_role"], "collaborator")
        self.assertEqual(shared["participant_count"], 2)
        self.assertEqual(
            self.store.active_for_user("operator-2")["id"], investigation["id"]
        )
        note = self.store.add_note(
            investigation["id"], "operator-2", "morgan", "Validated from WAN."
        )
        self.assertEqual(note["created_by_username"], "morgan")
        recorded = self.store.record_for_active(
            user_id="operator-2",
            username="morgan",
            operation_id="shared-dns-run",
            event_type="diagnostic.completed",
            tool_id="tools.dns_response",
            action="DNS lookup",
            outcome="succeeded",
            summary="Resolved from the collaborator session.",
            targets={"hosts": ["example.com"]},
            parameters={},
            metrics={"successful": 1},
            details={},
            started_at=20,
            completed_at=21,
        )
        self.assertEqual(recorded["created_by_user_id"], "operator-2")
        with self.assertRaisesRegex(InvestigationError, "Case not found"):
            self.store.set_state(
                investigation["id"], "operator-2", "morgan", "paused"
            )
        with self.assertRaisesRegex(InvestigationError, "current case"):
            self.store.create(
                owner_user_id="operator-2",
                owner_username="morgan",
                title="Conflicting case",
            )

        self.store.remove_participant(
            investigation["id"], "operator-1", "nelson", "operator-2"
        )
        with self.assertRaisesRegex(InvestigationError, "not found"):
            self.store.get_for_user(investigation["id"], "operator-2")
        retained = self.store.events_for_user(investigation["id"], "operator-1")
        self.assertEqual(
            next(event for event in retained if event["id"] == note["id"])[
                "created_by_username"
            ],
            "morgan",
        )
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

    def test_schema_upgrade_adds_existing_case_owners_as_participants(self) -> None:
        investigation = self.store.create(
            owner_user_id="operator-1",
            owner_username="nelson",
            title="Existing case",
        )
        with sqlite3.connect(self.store.path) as connection:
            connection.execute("DROP TABLE investigation_participants")
            connection.execute(
                "UPDATE investigation_meta SET value = '1' WHERE key = 'schema_version'"
            )
        migrated = InvestigationStore(self.temporary.name).get_for_user(
            investigation["id"], "operator-1"
        )
        self.assertEqual(migrated["access_role"], "owner")
        self.assertEqual(migrated["participant_count"], 1)


class InvestigationRouteTests(unittest.TestCase):
    def test_active_case_banner_adds_notes_without_leaving_the_tool_page(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Quick context"})
            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            investigation_id = str(investigation["id"])

            page = client.get("/tools/snmp-test")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'data-case-note-open', page.data)
            self.assertIn(b'data-case-note-dialog', page.data)
            self.assertIn(b'Add a quick note', page.data)
            self.assertIn(b'Quick context', page.data)

            response = client.post(
                f"/investigations/{investigation_id}/notes",
                data={
                    "note": "Packet loss began immediately after the uplink change.",
                    "next": "/tools/snmp-test?section=monitor",
                },
            )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(
                response.headers["Location"],
                "/tools/snmp-test?section=monitor",
            )
            events = store.events_for_user(investigation_id, "test-user")
            self.assertEqual(events[-1]["event_type"], "note.added")
            self.assertEqual(
                events[-1]["summary"],
                "Packet loss began immediately after the uplink change.",
            )

            unsafe = client.post(
                f"/investigations/{investigation_id}/notes",
                data={"note": "Unsafe redirect rejected.", "next": "https://example.com"},
            )
            self.assertEqual(unsafe.status_code, 302)
            self.assertEqual(
                unsafe.headers["Location"],
                f"/investigations/{investigation_id}",
            )

    def test_one_off_snmp_is_case_evidence_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Switch polling"})
            client.post(
                "/tools/snmp-test/profiles/credentials",
                data={
                    "name": "Production credential",
                    "version": "v2c",
                    "community": "private-community",
                },
            )
            client.post(
                "/tools/snmp-test/profiles/hosts",
                data={
                    "name": "Core Switch",
                    "host": "192.0.2.10",
                    "port": "161",
                    "timeout": "2",
                    "retries": "1",
                    "credential_name": "Production credential",
                },
            )
            client.post(
                "/tools/snmp-test/profiles/oids",
                data={
                    "name": "Identity",
                    "source": "System Name = 1.3.6.1.2.1.1.5.0",
                },
            )
            fake_results = [
                {
                    "host_name": "Core Switch",
                    "host": "192.0.2.10",
                    "port": 161,
                    "credential_name": "Production credential",
                    "profile_name": "Identity",
                    "status": "success",
                    "error": "",
                    "elapsed_ms": 8.1,
                    "rows": [
                        {
                            "label": "System Name",
                            "operation": "get",
                            "oid": "1.3.6.1.2.1.1.5.0",
                            "value": "core-1",
                            "value_type": "OctetString",
                            "response_ms": 7.9,
                        }
                    ],
                }
            ]
            with patch(
                "twn_toolkit.snmp_routes.run_snmp_tests", return_value=fake_results
            ):
                response = client.post(
                    "/tools/snmp-test",
                    data={
                        "host_names": "Core Switch",
                        "oid_profile_names": "Identity",
                    },
                )
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Recorded in", response.data)

            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            event = next(
                event
                for event in store.events_for_user(investigation["id"], "test-user")
                if event["tool_id"] == "tools.snmp_test"
            )
            serialized = json.dumps(event)
            self.assertEqual(event["metrics"]["returned_values"], 1)
            self.assertEqual(event["details"]["results"][0]["rows"][0]["value"], "core-1")
            self.assertNotIn("private-community", serialized)
            self.assertNotIn("credential_name", serialized)

            report = client.get(f"/investigations/{investigation['id']}/report")
            self.assertIn(b"OID profile", report.data)
            self.assertIn(b"core-1", report.data)

    def test_certificate_inspection_is_structured_case_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "TLS validation"})
            now = datetime.now(timezone.utc)
            result = {
                "host": "portal.example.org",
                "port": 443,
                "elapsed_ms": 18.4,
                "tls": {
                    "version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "cipher_protocol": "TLSv1.3",
                    "cipher_bits": 256,
                    "alpn": "h2",
                },
                "certificates": [
                    {
                        "position": 1,
                        "role": "Leaf",
                        "subject": "CN=portal.example.org",
                        "common_name": "portal.example.org",
                        "issuer": "CN=Example Issuing CA",
                        "serial_number": "A1",
                        "not_before": now - timedelta(days=1),
                        "not_after": now + timedelta(days=89),
                        "time_valid": True,
                        "not_yet_valid": False,
                        "expired": False,
                        "days_remaining": 89,
                        "is_ca": False,
                        "is_self_issued": False,
                        "san_dns": ["portal.example.org"],
                        "san_ip": [],
                        "san_uri": [],
                        "public_key": "EC secp256r1 (256 bits)",
                        "signature_algorithm": "ecdsa-with-SHA256",
                        "signature_hash": "sha256",
                        "sha256_fingerprint": "AA:BB",
                        "aia_issuers": [],
                        "ocsp_urls": [],
                    }
                ],
                "presented_count": 1,
                "chain_order_valid": True,
                "order_checks": [],
                "server_sent_self_issued_root": False,
                "likely_missing_intermediate": False,
                "hostname": {
                    "valid": True,
                    "source": "DNS Subject Alternative Name",
                    "matched": "portal.example.org",
                    "error": "",
                },
                "trust": {"valid": True, "error": ""},
                "overall_valid": True,
            }
            with patch(
                "twn_toolkit.certificate_routes.inspect_certificate_chain",
                return_value=result,
            ):
                response = client.post(
                    "/tools/certificate-inspector",
                    data={
                        "target": "portal.example.org",
                        "port": "443",
                        "timeout": "8",
                    },
                )
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Recorded in", response.data)

            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            event = next(
                event
                for event in store.events_for_user(investigation["id"], "test-user")
                if event["tool_id"] == "tools.certificate_inspector"
            )
            self.assertTrue(event["metrics"]["overall_valid"])
            self.assertEqual(
                event["details"]["result"]["certificates"][0]["not_after"],
                (now + timedelta(days=89)).isoformat(),
            )
            report = client.get(f"/investigations/{investigation['id']}/report")
            self.assertIn(b"Certificate inspection", report.data)
            self.assertIn(b"SHA-256", report.data)

    def test_snmp_bandwidth_monitor_records_lifecycle_and_rate_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Uplink saturation"})
            client.post(
                "/tools/snmp-test/profiles/credentials",
                data={"name": "Monitor", "version": "v2c", "community": "secret"},
            )
            client.post(
                "/tools/snmp-test/profiles/hosts",
                data={
                    "name": "Core",
                    "host": "192.0.2.10",
                    "port": "161",
                    "timeout": "2",
                    "retries": "1",
                    "credential_name": "Monitor",
                },
            )
            started = client.post(
                "/tools/snmp-test/interface-monitor/start",
                json={
                    "title": "WAN uplink",
                    "targets": [
                        {
                            "host_name": "Core",
                            "interface_index": 2,
                            "interface_label": "port2 — WAN",
                            "interface_speed_bps": 1_000_000_000,
                        }
                    ],
                    "interval": 5,
                },
            )
            self.assertEqual(started.status_code, 201)
            self.assertTrue(started.get_json()["case_recorded"])
            session = started.get_json()["session"]
            live_store = LiveToolStore(instance)
            created = float(session["created_at"])
            base_sample = {
                "host_name": "Core",
                "host": "192.0.2.10",
                "interface_index": 2,
                "elapsed_ms": 4.2,
                "counter_bits": 64,
                "speed_bps": 1_000_000_000,
                "admin_status": "up",
                "oper_status": "up",
                "sys_uptime": 100,
                "counter_discontinuity": 0,
                "input_errors": 0,
                "output_errors": 0,
                "input_discards": 0,
                "output_discards": 0,
                "poll_count": 1,
            }
            self.assertTrue(
                live_store.record_snmp_interface_round(
                    session["id"],
                    revision=1,
                    sampled_at=created + 1,
                    duration_ms=5,
                    results=[
                        {
                            "status": "success",
                            "sample": {
                                **base_sample,
                                "sampled_at_ms": int((created + 1) * 1000),
                                "input_octets": "1000",
                                "output_octets": "2000",
                            },
                        }
                    ],
                )
            )
            self.assertTrue(
                live_store.record_snmp_interface_round(
                    session["id"],
                    revision=1,
                    sampled_at=created + 6,
                    duration_ms=5,
                    results=[
                        {
                            "status": "success",
                            "sample": {
                                **base_sample,
                                "sampled_at_ms": int((created + 6) * 1000),
                                "sys_uptime": 600,
                                "input_octets": "2000",
                                "output_octets": "4000",
                            },
                        }
                    ],
                )
            )
            stopped = client.post(session["stop_url"])
            self.assertEqual(stopped.status_code, 200)

            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            events = [
                event
                for event in store.events_for_user(investigation["id"], "test-user")
                if event["tool_id"] == "tools.snmp_test"
            ]
            self.assertEqual(
                [event["event_type"] for event in events],
                ["snmp.monitor.started", "snmp.monitor.completed"],
            )
            completed = events[-1]
            target = completed["details"]["target_summaries"][0]
            self.assertEqual(target["peak_download_bps"], 3200.0)
            self.assertEqual(target["peak_upload_bps"], 1600.0)
            self.assertNotIn("secret", json.dumps(events))
            artifacts = store.artifacts_for_user(investigation["id"], "test-user")
            self.assertEqual(len(artifacts), 1)
            csv_data = store.datastore.file(artifacts[0]["relative_path"]).read_text()
            self.assertIn("download_bps", csv_data)
            self.assertIn("3200.0", csv_data)
            report = client.get(f"/investigations/{investigation['id']}/report")
            self.assertIn(b"SNMP bandwidth monitor stopped", report.data)
            self.assertIn(b"3.20 Kbps", report.data)

    def test_packet_capture_streams_pcap_into_case_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Packet evidence"})
            capability = {
                "available": True,
                "executable": "/usr/sbin/tcpdump",
                "detail": "tcpdump is available.",
            }
            interfaces = [{"index": 7, "name": "en7", "loopback": False}]
            with (
                patch("twn_toolkit.packet_capture.capture_capability", return_value=capability),
                patch("twn_toolkit.packet_capture.capture_interfaces", return_value=interfaces),
                patch("twn_toolkit.packet_capture._compile_capture_filter"),
                patch("twn_toolkit.packet_capture_routes.capture_capability", return_value=capability),
                patch("twn_toolkit.packet_capture_routes.capture_interfaces", return_value=interfaces),
                patch.object(PacketCaptureStore, "launch"),
            ):
                started = client.post(
                    "/tools/packet-capture/start",
                    data={
                        "interface": "en7",
                        "capture_filter": "port 443",
                        "duration_seconds": "60",
                        "packet_count": "0",
                        "max_size_mib": "25",
                        "snap_length": "0",
                        "promiscuous": "on",
                    },
                )
            self.assertEqual(started.status_code, 302)
            capture_store = PacketCaptureStore(instance)
            capture = capture_store.recent(1)[0]
            self.assertTrue(capture["investigation_id"])
            pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16
            output = capture_store.output_file(capture)
            output.write_bytes(pcap)
            capture_store.finish(
                capture["id"],
                status="completed",
                result={
                    "elapsed_seconds": 2,
                    "size_bytes": len(pcap),
                    "packet_count_captured": 0,
                    "termination_reason": "duration reached",
                },
            )
            status = client.get(f"/tools/packet-capture/{capture['id']}/status")
            self.assertEqual(status.status_code, 200)

            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            events = [
                event
                for event in store.events_for_user(investigation["id"], "test-user")
                if event["tool_id"] == "tools.packet_capture"
            ]
            self.assertEqual(
                [event["event_type"] for event in events],
                ["packet_capture.started", "packet_capture.completed"],
            )
            artifacts = store.artifacts_for_user(investigation["id"], "test-user")
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0]["content_type"], "application/vnd.tcpdump.pcap")
            self.assertEqual(
                store.datastore.file(artifacts[0]["relative_path"]).read_bytes(), pcap
            )
            report = client.get(f"/investigations/{investigation['id']}/report")
            self.assertIn(b"PCAP evidence", report.data)
            self.assertIn(artifacts[0]["display_name"].encode(), report.data)

    def test_multi_ping_records_lifecycle_summary_and_csv_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Intermittent branch"})
            investigation_store = InvestigationStore(instance)
            investigation = investigation_store.active_for_user("test-user")
            investigation_id = str(investigation["id"])
            capability = {
                "engine": "fping",
                "accelerated": True,
                "target_limit": 250,
                "detail": "available",
                "path": "/usr/bin/fping",
            }
            with patch(
                "twn_toolkit.ping_routes.ping_engine_capability",
                return_value=capability,
            ):
                started = client.post(
                    "/tools/ping/sessions",
                    json={
                        "hosts": "Router = 192.0.2.1\nCamera = 192.0.2.2",
                        "interval": 2,
                        "timeout": 1,
                        "title": "Branch reachability",
                    },
                )
            self.assertEqual(started.status_code, 201)
            self.assertTrue(started.get_json()["case_recorded"])
            session = started.get_json()["session"]
            self.assertEqual(session["investigation_id"], investigation_id)

            live_store = LiveToolStore(instance)
            sampled_at = float(session["created_at"]) + 1
            self.assertTrue(
                live_store.record_ping_round(
                    session["id"],
                    revision=1,
                    sampled_at=sampled_at,
                    duration_ms=10,
                    engine="fping",
                    results=[
                        {"host": "192.0.2.1", "reachable": True, "latency_ms": 2.1},
                        {"host": "192.0.2.2", "reachable": False, "latency_ms": None},
                    ],
                )
            )
            with patch(
                "twn_toolkit.ping_routes.ping_engine_capability",
                return_value=capability,
            ):
                updated = client.post(
                    session["targets_url"],
                    json={
                        "hosts": "Router = 192.0.2.1\nCamera = 192.0.2.2",
                        "interval": 5,
                        "timeout": 1,
                    },
                )
            self.assertEqual(updated.status_code, 200)
            self.assertTrue(
                live_store.record_ping_round(
                    session["id"],
                    revision=2,
                    sampled_at=sampled_at + 5,
                    duration_ms=11,
                    engine="fping",
                    results=[
                        {"host": "192.0.2.1", "reachable": False, "latency_ms": None},
                        {"host": "192.0.2.2", "reachable": False, "latency_ms": None},
                    ],
                )
            )
            paused = client.post(
                f"/investigations/{investigation_id}/state",
                data={"state": "paused"},
            )
            self.assertEqual(paused.status_code, 302)
            stopped = client.post(session["stop_url"])
            self.assertEqual(stopped.status_code, 200)

            events = investigation_store.events_for_user(
                investigation_id, "test-user"
            )
            ping_events = [event for event in events if event["tool_id"] == "tools.ping"]
            self.assertEqual(
                [event["event_type"] for event in ping_events],
                ["ping.session.started", "ping.session.completed"],
            )
            completed = ping_events[-1]
            self.assertIn("No replies were observed from Camera", completed["summary"])
            self.assertEqual(completed["parameters"]["configuration_revision_count"], 2)
            camera = next(
                target
                for target in completed["details"]["target_summaries"]
                if target["label"] == "Camera"
            )
            self.assertEqual(camera["observation"], "No replies observed")
            self.assertEqual(camera["reply_interruptions"], 0)
            router = next(
                target
                for target in completed["details"]["target_summaries"]
                if target["label"] == "Router"
            )
            self.assertEqual(router["reply_interruptions"], 1)

            artifacts = investigation_store.artifacts_for_user(
                investigation_id, "test-user"
            )
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0]["kind"], "generated")
            self.assertEqual(artifacts[0]["event_id"], completed["id"])
            csv_evidence = investigation_store.datastore.file(
                artifacts[0]["relative_path"]
            ).read_text()
            self.assertIn("configuration_revision", csv_evidence)
            self.assertIn("Camera,192.0.2.2,no,", csv_evidence)
            self.assertIn(",1,Router,192.0.2.1,yes,2.1", csv_evidence)
            self.assertIn(",2,Router,192.0.2.1,no,", csv_evidence)

            report = client.get(f"/investigations/{investigation_id}/report")
            self.assertIn(b"Ping stopped", report.data)
            self.assertIn(b"No replies observed", report.data)
            self.assertIn(b"Latency min / avg / max", report.data)
            self.assertIn(artifacts[0]["display_name"].encode(), report.data)

            package = client.get(f"/investigations/{investigation_id}/package.zip")
            self.assertEqual(package.status_code, 200)
            with zipfile.ZipFile(io.BytesIO(package.data)) as archive:
                self.assertIn(
                    f"evidence/{artifacts[0]['display_name']}",
                    archive.namelist(),
                )
                packaged_csv = archive.read(
                    f"evidence/{artifacts[0]['display_name']}"
                ).decode()
            self.assertEqual(packaged_csv, csv_evidence)

    def test_closing_case_stops_and_retains_attached_multi_ping(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Close with live ping"})
            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            started = client.post(
                "/tools/ping/sessions",
                json={"hosts": "192.0.2.9", "interval": 2, "timeout": 1},
            )
            session = started.get_json()["session"]

            closed = client.post(
                f"/investigations/{investigation['id']}/state",
                data={"state": "completed"},
            )

            self.assertEqual(closed.status_code, 302)
            self.assertEqual(
                LiveToolStore(instance).get_session(
                    session["id"], user_id="test-user"
                )["stop_reason"],
                "case_closed",
            )
            events = store.events_for_user(investigation["id"], "test-user")
            completed_ping = next(
                event
                for event in events
                if event["event_type"] == "ping.session.completed"
            )
            self.assertEqual(completed_ping["outcome"], "incomplete")
            self.assertIn("before any ping probes completed", completed_ping["summary"])
            self.assertEqual(
                len(store.artifacts_for_user(investigation["id"], "test-user")), 1
            )

    def test_access_profiles_gate_routes_and_explicit_case_collaboration(self) -> None:
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
            alice_id = auth.get_user("alice")["id"]
            bob_id = auth.get_user("bob")["id"]
            added = client.post(
                f"{investigation_url}/participants",
                data={"user_id": bob_id},
                follow_redirects=True,
            )
            self.assertEqual(added.status_code, 200)
            self.assertIn(b"Added bob to the case", added.data)
            self.assertIn(b"Case team", added.data)
            self.assertNotIn(b"Open folder in Datastore", client.get(
                f"{investigation_url}/evidence"
            ).data)

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "bob", "password": "another different password"},
            )
            shared = client.get(investigation_url)
            self.assertEqual(shared.status_code, 200)
            self.assertIn(b"Shared case", shared.data)
            self.assertIn(b"alice controls recording", shared.data)
            self.assertNotIn(b"Close case", shared.data)
            self.assertEqual(
                client.post(
                    f"{investigation_url}/notes",
                    data={"note": "Bob confirmed the failure from another VLAN."},
                ).status_code,
                302,
            )
            self.assertEqual(
                client.post(
                    f"{investigation_url}/state", data={"state": "paused"}
                ).status_code,
                403,
            )
            self.assertEqual(
                client.post(
                    f"{investigation_url}/report/contents", data={}
                ).status_code,
                403,
            )
            collaborator_report = client.get(f"{investigation_url}/report")
            self.assertEqual(collaborator_report.status_code, 200)
            self.assertIn(b"The case owner controls report inclusion", collaborator_report.data)
            self.assertNotIn(b"Save report contents", collaborator_report.data)
            store = InvestigationStore(instance)
            self.assertEqual(store.active_for_user(bob_id)["id"], investigation["id"])
            bob_note = next(
                event
                for event in store.events_for_user(investigation["id"], bob_id)
                if event["summary"]
                == "Bob confirmed the failure from another VLAN."
            )
            self.assertEqual(bob_note["created_by_username"], "bob")

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "alice", "password": "a different long password"},
            )
            removed = client.post(
                f"{investigation_url}/participants/{bob_id}/remove",
                follow_redirects=True,
            )
            self.assertEqual(removed.status_code, 200)
            self.assertIn(b"Removed the collaborator", removed.data)

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "bob", "password": "another different password"},
            )
            self.assertEqual(client.get(investigation_url).status_code, 404)
            self.assertEqual(store.active_for_user(bob_id), None)
            retained = store.events_for_user(investigation["id"], alice_id)
            self.assertEqual(
                next(event for event in retained if event["id"] == bob_note["id"])[
                    "created_by_username"
                ],
                "bob",
            )

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
            self.assertEqual(
                manifest["case"]["operators"],
                [
                    {
                        "user_id": "test-user",
                        "username": "test-user",
                        "role": "owner",
                    }
                ],
            )
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

            dhcp_offer = {
                "offered_address": "192.0.2.50",
                "server_address": "192.0.2.1",
                "source_address": "192.0.2.1",
                "relay_address": "0.0.0.0",
                "next_server": "",
                "response_time_ms": 42.7,
                "options": [
                    {
                        "code": 1,
                        "name": "Subnet Mask",
                        "value": "255.255.255.0",
                        "hex": "ff ff ff 00",
                    }
                ],
            }
            with (
                patch(
                    "twn_toolkit.dhcp_routes.available_interfaces",
                    return_value=[
                        {"name": "eth0", "mac": "02:00:00:00:00:01"}
                    ],
                ),
                patch(
                    "twn_toolkit.dhcp_routes.discover_offers",
                    return_value=[dhcp_offer],
                ),
            ):
                dhcp_page = client.post(
                    "/tools/dhcp-discover",
                    data={
                        "interface": "eth0",
                        "mac": "02:00:00:00:00:01",
                        "parameters": "1, 3, 6",
                        "timeout": "1",
                    },
                )
            self.assertIn(b"Recorded in the active case", dhcp_page.data)

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
                    "tools.dhcp_discover",
                    "tools.speed_test",
                },
            )
            report = client.get(f"/investigations/{investigation_id}/report")
            for value in (
                b"TCP port scan",
                b"gateway.local",
                b"Primary",
                b"1400 bytes",
                b"42.7 ms",
                b"125.5 Mbps",
            ):
                self.assertIn(value, report.data)
            self.assertEqual(report.data.count(b"Detailed results R-"), 5)

    def test_vendor_exports_and_actions_become_safe_case_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post(
                "/profiles",
                data={
                    "name": "Lab",
                    "host": "https://fortigate.example",
                    "api_key": "profile-secret",
                    "default_vdom": "root",
                },
            )
            client.post("/investigations", data={"title": "Fortinet change review"})
            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            investigation_id = str(investigation["id"])

            with patch(
                "twn_toolkit.fortigate_routes.ExportTask.run",
                return_value="serial,name\nS124,Private Switch\n",
            ):
                export = client.post(
                    "/tasks/export-switches/run",
                    data={"profile": "Lab"},
                )
            self.assertEqual(export.status_code, 200)

            switches = [
                {"switch-id": "switch-a", "name": "Switch A"},
                {"switch-id": "switch-b", "name": "Switch B"},
            ]
            with (
                patch(
                    "twn_toolkit.fortigate_routes.FortiGateClient.get_managed_switches",
                    side_effect=[switches, list(reversed(switches))],
                ),
                patch(
                    "twn_toolkit.fortigate_routes.FortiGateClient.move_managed_switch_after"
                ),
            ):
                apply = client.post(
                    "/fortigate/switch-order/apply",
                    data={
                        "profile": "Lab",
                        "vdom": "root",
                        "switch_id": ["switch-b", "switch-a"],
                        "confirmed": "on",
                    },
                )
            self.assertEqual(apply.status_code, 200)

            events = store.events_for_user(investigation_id, "test-user")
            export_event = next(
                event for event in events if event["tool_id"] == "fortigate.export_switches"
            )
            action_event = next(
                event for event in events if event["tool_id"] == "fortigate.switch_order"
            )
            self.assertEqual(export_event["event_type"], "external.export.completed")
            self.assertEqual(action_event["event_type"], "external.action")
            serialized = json.dumps(events)
            self.assertNotIn("profile-secret", serialized)
            self.assertNotIn("Private Switch", serialized)

            artifacts = store.artifacts_for_user(investigation_id, "test-user")
            export_artifact = next(
                artifact for artifact in artifacts if artifact["event_id"] == export_event["id"]
            )
            self.assertEqual(
                store.datastore.file(export_artifact["relative_path"]).read_text(),
                "serial,name\nS124,Private Switch\n",
            )
            report = client.get(f"/investigations/{investigation_id}/report")
            self.assertIn(b"Export FortiSwitch Data", report.data)
            self.assertIn(b"Applied and verified", report.data)

    def test_wireless_history_retains_collapsed_path_not_raw_vendor_rows(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post(
                "/profiles",
                data={
                    "name": "Lab",
                    "host": "https://fortigate.example",
                    "api_key": "profile-secret",
                    "default_vdom": "root",
                },
            )
            client.post("/investigations", data={"title": "Wireless roaming"})
            result = {
                "mac": "aa:bb:cc:dd:ee:ff",
                "vdom": "root",
                "hours": 24,
                "source": "Local FortiGate",
                "timeline": [
                    {
                        "ap": "Lobby-AP",
                        "first_time": "2026-08-12 10:00:00",
                        "last_time": "2026-08-12 10:02:00",
                        "event_count": 2,
                        "ssid": "Corp",
                        "ip": "192.0.2.20",
                        "details": "Associated",
                        "events": [
                            {
                                "sort_time": datetime.now(timezone.utc),
                                "raw_vendor_secret": "do-not-retain",
                            }
                        ],
                    }
                ],
                "log_row_count": 8,
                "raw_event_count": 2,
                "omitted_unknown_ap_count": 0,
                "live_clients": [],
                "log_error": "",
                "live_error": "",
                "ap_path": ["Lobby-AP"],
            }
            with patch(
                "twn_toolkit.fortigate_routes.wireless_client_history",
                return_value=result,
            ):
                response = client.post(
                    "/fortigate/fortiap/client-history",
                    data={
                        "profile": "Lab",
                        "mac": "aabb.ccdd.eeff",
                        "hours": "24",
                    },
                )
            self.assertIn(b"Recorded in the active case", response.data)

            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            event = next(
                event
                for event in store.events_for_user(investigation["id"], "test-user")
                if event["tool_id"] == "fortigate.wireless_client_history"
            )
            serialized = json.dumps(event)
            self.assertIn("Lobby-AP", serialized)
            self.assertNotIn("do-not-retain", serialized)
            self.assertNotIn("sort_time", serialized)
            report = client.get(f"/investigations/{investigation['id']}/report")
            self.assertIn(b"Lobby-AP", report.data)
            self.assertIn(b"Associated", report.data)

    def test_address_snapshots_and_subnet_calculations_are_deliberate_case_events(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/investigations", data={"title": "Address plan"})

            snapshot = client.post(
                "/tools/whats-my-ip/case-snapshot",
                data={
                    "browser_public": "198.51.100.8",
                    "server_public": "203.0.113.9",
                },
            )
            self.assertTrue(snapshot.get_json()["case_recorded"])
            subnet = client.post(
                "/tools/subnet-excluder",
                data={
                    "supernets": "192.0.2.0/24",
                    "exclusions": "192.0.2.0/25",
                },
            )
            self.assertIn(b"Recorded in the active case", subnet.data)

            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            events = store.events_for_user(investigation["id"], "test-user")
            tools = {event["tool_id"]: event for event in events}
            self.assertEqual(
                tools["tools.whats_my_ip"]["targets"]["browser_public"],
                "198.51.100.8",
            )
            self.assertEqual(
                tools["tools.subnet_excluder"]["details"]["remaining_networks"],
                ["192.0.2.128/25"],
            )
            report = client.get(f"/investigations/{investigation['id']}/report")
            self.assertIn(b"Browser public address", report.data)
            self.assertIn(b"192.0.2.128/25", report.data)

    def test_collected_automation_run_can_be_attached_with_its_portable_zip(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            automation_store = AutomationStore(instance, app.config["SECRET_KEY"])
            automation_id = automation_store.save(
                name="Collect switch state",
                interval_seconds=30,
                trigger_after=1,
                recover_after=1,
                cooldown_seconds=0,
                condition={"type": "manual.trigger", "config": {}},
                actions=[
                    {
                        "type": "ssh.collect",
                        "config": {
                            "hosts": "192.0.2.10",
                            "username": "admin",
                            "password": "profile-secret",
                            "commands": "show clock",
                            "port": 22,
                            "command_timeout": 300,
                            "allow_unknown_hosts": False,
                            "send_ctrl_y": False,
                        },
                    }
                ],
                created_by="test-user",
            )
            run_id = automation_store.record_run(
                automation_id,
                ConditionResult(True, "met", "Manual run", {}),
                [
                    ActionResult(
                        "success",
                        "Collected one host",
                        {
                            "_pipeline": {
                                "stage_name": "Collection",
                                "action_name": "SSH collect",
                            },
                            "hosts": [
                                {
                                    "host": "192.0.2.10",
                                    "host_label": "Core",
                                    "status": "success",
                                    "output": "12:34:56 UTC",
                                }
                            ],
                        },
                    )
                ],
            )
            client.post("/investigations", data={"title": "Automation evidence"})
            response = client.post(f"/automations/runs/{run_id}/case")
            self.assertEqual(response.status_code, 302)

            store = InvestigationStore(instance)
            investigation = store.active_for_user("test-user")
            event = next(
                event
                for event in store.events_for_user(investigation["id"], "test-user")
                if event["tool_id"] == "automation.home"
            )
            self.assertEqual(event["metrics"]["successful_results"], 1)
            self.assertNotIn("profile-secret", json.dumps(event))
            artifact = next(
                artifact
                for artifact in store.artifacts_for_user(investigation["id"], "test-user")
                if artifact["event_id"] == event["id"]
            )
            with zipfile.ZipFile(store.datastore.file(artifact["relative_path"])) as archive:
                host_output = archive.read(
                    next(name for name in archive.namelist() if name.endswith("-Core.txt"))
                )
            self.assertIn(b"12:34:56 UTC", host_output)
            report = client.get(f"/investigations/{investigation['id']}/report")
            self.assertIn(b"Collect switch state", report.data)
            self.assertIn(b"SSH collect", report.data)


if __name__ == "__main__":
    unittest.main()
