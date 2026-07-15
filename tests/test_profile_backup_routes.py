from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from twn_toolkit import create_app
from twn_toolkit.audit import AuditStore


class ProfileBackupRouteTests(unittest.TestCase):
    def test_sensitive_backup_requires_password(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            response = client.post(
                "/settings/backup/export",
                data={"item": ["fortigate_profiles"]},
                follow_redirects=True,
            )

        self.assertIn(b"Enter an encryption password", response.data)

    def test_encrypted_backup_wrong_password_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            Path(instance, "profiles.json").write_text(
                json.dumps(
                    [
                        {
                            "name": "Lab",
                            "host": "https://192.0.2.1",
                            "api_key": "secret-token",
                            "verify_tls": True,
                            "is_default": True,
                            "default_vdom": "root",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            export = client.post(
                "/settings/backup/export",
                data={
                    "item": ["fortigate_profiles"],
                    "backup_password": "correct password",
                    "confirm_backup_password": "correct password",
                },
            )

            response = client.post(
                "/settings/backup/import",
                data={
                    "backup_file": (io.BytesIO(export.data), "backup.json"),
                    "item": ["fortigate_profiles"],
                    "backup_password": "wrong password",
                    "import_mode": "merge",
                },
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            event = AuditStore(instance).recent(1)[0]
            audit_database = Path(instance, "audit.sqlite3").read_bytes()

        self.assertIn(b"password is incorrect", response.data)
        self.assertEqual(event["action"], "backup.import_failed")
        self.assertEqual(event["details"]["outcome"], "failed")
        self.assertTrue(event["details"]["encrypted"])
        self.assertNotIn(b"wrong password", audit_database)
        self.assertNotIn(b"secret-token", audit_database)

    def test_successful_backup_export_and_import_are_audited_without_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            Path(instance, "ping_profiles.json").write_text(
                json.dumps(
                    [
                        {
                            "name": "Private target",
                            "hosts": "sensitive-target.internal",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            export = client.post(
                "/settings/backup/export",
                data={"item": ["ping_profiles"]},
            )
            self.assertEqual(export.status_code, 200)
            response = client.post(
                "/settings/backup/import",
                data={
                    "backup_file": (io.BytesIO(export.data), "backup.json"),
                    "item": ["ping_profiles"],
                    "import_mode": "replace",
                },
                content_type="multipart/form-data",
            )
            events = AuditStore(instance).recent(2)
            audit_database = Path(instance, "audit.sqlite3").read_bytes()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            [event["action"] for event in events],
            ["backup.imported", "backup.exported"],
        )
        imported = events[0]
        self.assertEqual(imported["details"]["import mode"], "replace")
        self.assertEqual(imported["details"]["imported record count"], 1)
        self.assertEqual(
            imported["details"]["selected groups"],
            [
                {
                    "type": "backup item",
                    "name": "Ping profiles",
                    "id": "ping_profiles",
                }
            ],
        )
        exported = events[1]
        self.assertFalse(exported["details"]["encrypted"])
        self.assertFalse(exported["details"]["contains sensitive groups"])
        self.assertNotIn(b"sensitive-target.internal", audit_database)


if __name__ == "__main__":
    unittest.main()
