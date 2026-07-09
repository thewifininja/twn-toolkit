from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from twn_toolkit import create_app


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

        self.assertIn(b"password is incorrect", response.data)


if __name__ == "__main__":
    unittest.main()
