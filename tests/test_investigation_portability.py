from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from contextlib import closing
from typing import Callable

from twn_toolkit import create_app
from twn_toolkit.investigation_portability import (
    PORTABLE_CASE_FILENAME,
    PORTABLE_CASE_SCHEMA,
    PortableCaseError,
    load_portable_case_archive,
)
from twn_toolkit.investigations import InvestigationError, InvestigationStore


class InvestigationPortabilityTests(unittest.TestCase):
    def _source_archive(self) -> tuple[bytes, dict[str, object]]:
        source_directory = tempfile.TemporaryDirectory()
        self.addCleanup(source_directory.cleanup)
        app = create_app(source_directory.name)
        app.testing = True
        client = app.test_client()
        client.post("/investigations", data={"title": "Portable branch outage"})
        store = InvestigationStore(source_directory.name)
        investigation = store.active_for_user("test-user")
        store.add_participant(
            investigation["id"],
            "test-user",
            "test-user",
            "remote-operator-id",
            "remote-operator",
        )
        store.add_note(
            investigation["id"],
            "remote-operator-id",
            "remote-operator",
            "Validated the failure from the remote branch.",
        )
        store.remove_participant(
            investigation["id"],
            "test-user",
            "test-user",
            "remote-operator-id",
        )
        artifact = store.add_evidence(
            investigation_id=investigation["id"],
            user_id="test-user",
            username="test-user",
            filename="edge status.txt",
            content_type="text/plain",
            stream=io.BytesIO(b"show system status\n"),
        )
        store.set_report_contents(
            investigation["id"],
            "test-user",
            event_ids=[],
            artifact_ids=[],
        )
        store.set_state(investigation["id"], "test-user", "test-user", "completed")

        response = client.get(
            f"/investigations/{investigation['id']}/portable.twncase"
        )
        self.assertEqual(response.status_code, 200)
        data = bytes(response.data)
        response.close()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            payload = json.loads(archive.read(PORTABLE_CASE_FILENAME))
            self.assertEqual(payload["schema"], PORTABLE_CASE_SCHEMA)
            self.assertGreater(len(payload["events"]), 0)
            self.assertEqual(len(payload["artifacts"]), 1)
            self.assertEqual(
                [item["username"] for item in payload["case"]["operators"]],
                ["test-user", "remote-operator"],
            )
            self.assertEqual(
                archive.read(payload["artifacts"][0]["member"]),
                b"show system status\n",
            )
            self.assertEqual(payload["artifacts"][0]["report_placement"], "excluded")
        return data, {
            "source_id": investigation["id"],
            "artifact_id": artifact["id"],
            "event_origins": {
                item["origin_id"] for item in payload["events"]
            },
        }

    def test_complete_case_round_trip_preserves_source_and_local_access_boundary(
        self,
    ) -> None:
        archive_data, expected = self._source_archive()
        with tempfile.TemporaryDirectory() as target:
            app = create_app(target)
            app.testing = True
            client = app.test_client()
            response = client.post(
                "/investigations/import",
                data={
                    "case_archive": (
                        io.BytesIO(archive_data),
                        "branch-outage.twncase",
                    )
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 302)
            self.assertRegex(response.headers["Location"], r"/investigations/inv_")

            store = InvestigationStore(target)
            cases = store.list_for_user("test-user")
            self.assertEqual(len(cases), 1)
            imported = cases[0]
            self.assertEqual(imported["state"], "completed")
            self.assertTrue(imported["is_imported"])
            self.assertEqual(imported["import_source_case_id"], expected["source_id"])
            self.assertEqual(imported["owner_username"], "test-user")
            self.assertEqual(
                [item["username"] for item in imported["source_operators"]],
                ["test-user", "remote-operator"],
            )
            with self.assertRaises(InvestigationError):
                store.get_for_user(imported["id"], "remote-operator-id")

            events = store.events_for_user(imported["id"], "test-user")
            self.assertEqual(events[-1]["event_type"], "investigation.imported")
            remote_note = next(
                event
                for event in events
                if event["summary"]
                == "Validated the failure from the remote branch."
            )
            self.assertEqual(remote_note["created_by_username"], "remote-operator")
            artifacts = store.artifacts_for_user(imported["id"], "test-user")
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0]["report_placement"], "excluded")
            self.assertEqual(
                store.datastore.file(artifacts[0]["relative_path"]).read_bytes(),
                b"show system status\n",
            )

            detail = client.get(response.headers["Location"])
            self.assertIn(b"Imported", detail.data)
            self.assertIn(b"remote-operator", detail.data)
            self.assertIn(b"original operators remain attributed", detail.data)

            exported = client.get(
                f"/investigations/{imported['id']}/portable.twncase"
            )
            with zipfile.ZipFile(io.BytesIO(exported.data)) as archive:
                payload = json.loads(archive.read(PORTABLE_CASE_FILENAME))
                reexported_data = bytes(exported.data)
            exported.close()
            self.assertEqual(payload["case"]["origin_id"], expected["source_id"])
            self.assertTrue(
                expected["event_origins"].issubset(
                    {item["origin_id"] for item in payload["events"]}
                )
            )

            with tempfile.TemporaryDirectory() as second_target:
                second_app = create_app(second_target)
                second_app.testing = True
                second_response = second_app.test_client().post(
                    "/investigations/import",
                    data={
                        "case_archive": (
                            io.BytesIO(reexported_data),
                            "reexported-branch-outage.twncase",
                        )
                    },
                    content_type="multipart/form-data",
                )
                self.assertEqual(second_response.status_code, 302)
                second_store = InvestigationStore(second_target)
                second_case = second_store.list_for_user("test-user")[0]
                second_events = second_store.events_for_user(
                    second_case["id"], "test-user"
                )
                self.assertEqual(
                    sum(
                        item["event_type"] == "investigation.imported"
                        for item in second_events
                    ),
                    2,
                )
                self.assertEqual(
                    second_events[-1]["created_by_username"], "test-user"
                )

            duplicate = client.post(
                "/investigations/import",
                data={
                    "case_archive": (
                        io.BytesIO(archive_data),
                        "branch-outage.twncase",
                    )
                },
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            self.assertIn(b"already been imported", duplicate.data)
            self.assertEqual(len(store.list_for_user("test-user")), 1)

    def test_import_rejects_tampered_evidence_without_creating_a_case(self) -> None:
        archive_data, _expected = self._source_archive()
        tampered = _rewrite_archive(
            archive_data,
            lambda name, data: b"tampered\n" if name.startswith("evidence/") else data,
        )
        with self.assertRaisesRegex(PortableCaseError, "failed verification"):
            with load_portable_case_archive(io.BytesIO(tampered)):
                pass

        with tempfile.TemporaryDirectory() as target:
            app = create_app(target)
            app.testing = True
            response = app.test_client().post(
                "/investigations/import",
                data={
                    "case_archive": (io.BytesIO(tampered), "tampered.twncase")
                },
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            self.assertIn(b"failed verification", response.data)
            self.assertEqual(InvestigationStore(target).list_for_user("test-user"), [])

    def test_import_rejects_unreferenced_and_unsafe_archive_members(self) -> None:
        archive_data, _expected = self._source_archive()
        with zipfile.ZipFile(io.BytesIO(archive_data)) as source:
            members = {name: source.read(name) for name in source.namelist()}
        for member in ("unexpected.txt", "../escape.txt"):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, data in members.items():
                    archive.writestr(name, data)
                archive.writestr(member, b"nope")
            with self.subTest(member=member):
                with self.assertRaises(PortableCaseError):
                    with load_portable_case_archive(io.BytesIO(output.getvalue())):
                        pass

    def test_import_rejects_unknown_schema(self) -> None:
        archive_data, _expected = self._source_archive()

        def change_schema(name: str, data: bytes) -> bytes:
            if name != PORTABLE_CASE_FILENAME:
                return data
            payload = json.loads(data)
            payload["schema"] = "twn.portable-case.v999"
            return json.dumps(payload).encode()

        incompatible = _rewrite_archive(archive_data, change_schema)
        with self.assertRaisesRegex(PortableCaseError, "schema"):
            with load_portable_case_archive(io.BytesIO(incompatible)):
                pass

    def test_schema_upgrade_adds_portable_case_origin_tables(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = InvestigationStore(instance)
            investigation = store.create(
                owner_user_id="operator-1",
                owner_username="nelson",
                title="Existing case",
            )
            with closing(sqlite3.connect(store.path)) as connection, connection:
                connection.execute("DROP TABLE investigation_artifact_origins")
                connection.execute("DROP TABLE investigation_event_origins")
                connection.execute("DROP TABLE investigation_imports")
                connection.execute(
                    "UPDATE investigation_meta SET value = '2' "
                    "WHERE key = 'schema_version'"
                )

            migrated_store = InvestigationStore(instance)
            migrated = migrated_store.get_for_user(
                investigation["id"], "operator-1"
            )
            self.assertFalse(migrated["is_imported"])
            with closing(sqlite3.connect(migrated_store.path)) as connection:
                version = connection.execute(
                    "SELECT value FROM investigation_meta "
                    "WHERE key = 'schema_version'"
                ).fetchone()[0]
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            self.assertEqual(version, "3")
            self.assertTrue(
                {
                    "investigation_imports",
                    "investigation_event_origins",
                    "investigation_artifact_origins",
                }.issubset(tables)
            )


def _rewrite_archive(
    source_data: bytes, transform: Callable[[str, bytes], bytes]
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(source_data)) as source, zipfile.ZipFile(
        output, "w", zipfile.ZIP_DEFLATED
    ) as destination:
        for name in source.namelist():
            destination.writestr(name, transform(name, source.read(name)))
    return output.getvalue()


if __name__ == "__main__":
    unittest.main()
