from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.tool_catalog import TOOL_BY_ID


class LocalDatastoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = LocalDatastore(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_folder_upload_list_rename_download_and_delete(self) -> None:
        folder = self.store.create_folder("", "Switch captures")
        path, size = self.store.save_upload(
            "Switch captures", "diagnostics.txt", io.BytesIO(b"switch output")
        )
        self.assertEqual(size, 13)
        self.assertEqual(path.read_bytes(), b"switch output")
        self.assertEqual(os.stat(folder).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(self.store.list("Switch captures")["entries"][0]["name"], "diagnostics.txt")
        renamed = self.store.rename("Switch captures/diagnostics.txt", "core-switch.txt")
        self.assertEqual(self.store.file("Switch captures/core-switch.txt"), renamed)
        self.store.delete("Switch captures/core-switch.txt")
        self.store.delete("Switch captures")
        self.assertEqual(self.store.usage(), {"files": 0, "folders": 0, "bytes": 0})

    def test_paths_symlinks_overwrites_and_nonempty_folder_delete_are_rejected(self) -> None:
        self.store.create_folder("", "safe")
        self.store.save_upload("safe", "one.txt", io.BytesIO(b"one"))
        with self.assertRaises(DatastoreError):
            self.store.list("../")
        with self.assertRaisesRegex(DatastoreError, "already exists"):
            self.store.save_upload("safe", "one.txt", io.BytesIO(b"replacement"))
        with self.assertRaisesRegex(DatastoreError, "must be empty"):
            self.store.delete("safe")
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.store.root / "linked").symlink_to(outside, target_is_directory=True)
        self.assertNotIn("linked", [item["name"] for item in self.store.list()["entries"]])
        with self.assertRaises(DatastoreError):
            self.store.list("linked")

    def test_oversized_upload_is_removed(self) -> None:
        with self.assertRaisesRegex(DatastoreError, "may not exceed"):
            self.store.save_upload("", "large.bin", io.BytesIO(b"12345"), max_bytes=4)
        self.assertFalse((self.store.root / "large.bin").exists())
        self.assertEqual(list(self.store.root.glob(".upload-*")), [])

    def test_bulk_move_and_delete_validate_before_changing_files(self) -> None:
        self.store.create_folder("", "incoming")
        self.store.create_folder("", "archive")
        self.store.save_upload("incoming", "one.txt", io.BytesIO(b"one"))
        self.store.save_upload("incoming", "two.txt", io.BytesIO(b"two"))
        self.assertEqual(
            self.store.move_files(
                ["incoming/one.txt", "incoming/two.txt"], "archive"
            ),
            2,
        )
        self.assertEqual(
            {item["name"] for item in self.store.list("archive")["entries"]},
            {"one.txt", "two.txt"},
        )
        self.store.save_upload("incoming", "one.txt", io.BytesIO(b"collision"))
        with self.assertRaisesRegex(DatastoreError, "already exists"):
            self.store.move_files(["incoming/one.txt"], "archive")
        self.assertTrue(self.store.file("incoming/one.txt").exists())
        self.assertEqual(
            self.store.delete_files(["archive/one.txt", "archive/two.txt"]), 2
        )
        self.assertEqual(self.store.delete_files(["archive"]), 1)

    def test_bulk_folder_move_and_nonempty_delete_safety(self) -> None:
        self.store.create_folder("", "incoming")
        self.store.create_folder("", "archive")
        self.store.create_folder("incoming", "nested")
        self.store.save_upload("incoming/nested", "one.txt", io.BytesIO(b"one"))
        self.assertEqual(self.store.move_files(["incoming/nested"], "archive"), 1)
        self.assertTrue((self.store.root / "archive" / "nested" / "one.txt").is_file())
        with self.assertRaisesRegex(DatastoreError, "not empty"):
            self.store.delete_files(["archive/nested"])
        with self.assertRaisesRegex(DatastoreError, "into itself"):
            self.store.move_files(["archive"], "archive/nested")


class LocalDatastoreRouteTests(unittest.TestCase):
    def test_page_upload_download_and_navigation(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            page = client.get("/local/datastore")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Contained by design", page.data)
            self.assertIn(b"Local Tools", page.data)
            self.assertIn(b"data-datastore-view=\"grid\"", page.data)
            self.assertIn(b"data-datastore-upload", page.data)
            transfers = client.get("/local/file-transfers")
            self.assertEqual(transfers.status_code, 200)
            self.assertIn(b"TFTP service", transfers.data)
            self.assertEqual(client.post("/local/datastore/folders", data={"path": "", "name": "Images"}).status_code, 302)
            response = client.post(
                "/local/datastore/uploads",
                data={"path": "Images", "files": (io.BytesIO(b"hello"), "hello.txt")},
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 302)
            self.assertIn(b"hello.txt", client.get("/local/datastore?path=Images").data)
            download = client.get("/local/datastore/download?path=Images/hello.txt")
            self.assertEqual(download.data, b"hello")
            self.assertIn("attachment", download.headers["Content-Disposition"])
            download.close()

    def test_bulk_move_and_delete_routes(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            client.post("/local/datastore/folders", data={"path": "", "name": "archive"})
            client.post(
                "/local/datastore/uploads",
                data={
                    "path": "",
                    "files": [
                        (io.BytesIO(b"one"), "one.txt"),
                        (io.BytesIO(b"two"), "two.txt"),
                    ],
                },
                content_type="multipart/form-data",
            )
            moved = client.post(
                "/local/datastore/bulk-move",
                data={
                    "path": "",
                    "destination": "archive",
                    "paths_json": json.dumps(["one.txt", "two.txt"]),
                },
            )
            self.assertEqual(moved.status_code, 302)
            store = LocalDatastore(instance)
            self.assertEqual(len(store.list("archive")["entries"]), 2)
            deleted = client.post(
                "/local/datastore/bulk-delete",
                data={
                    "path": "archive",
                    "paths_json": json.dumps(
                        ["archive/one.txt", "archive/two.txt"]
                    ),
                },
            )
            self.assertEqual(deleted.status_code, 302)
            self.assertEqual(store.list("archive")["entries"], [])

    def test_datastore_is_grantable_through_access_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            client.post("/setup", data={"username": "admin", "password": "correct horse battery staple", "confirm_password": "correct horse battery staple"})
            auth = AuthStore(instance)
            profile = auth.save_access_profile(name="Datastore users", tool_ids=["local.datastore"])
            auth.create_user("fileuser", "a different long password", access_profile_ids=[profile["id"]])
            client.post("/logout")
            client.post("/login", data={"username": "fileuser", "password": "a different long password"})
            self.assertEqual(client.get("/local/datastore").status_code, 200)
            self.assertEqual(client.get("/local/file-transfers").status_code, 403)
            self.assertEqual(client.get("/tools/ping").status_code, 403)

    def test_registry_contains_local_datastore(self) -> None:
        tool = TOOL_BY_ID["local.datastore"]
        self.assertEqual(tool.category, "local")
        self.assertTrue(tool.grantable)
        self.assertEqual(TOOL_BY_ID["local.file_transfers"].endpoint, "file_transfers")

    def test_tftp_settings_are_admin_only_and_apply_through_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            with patch("twn_toolkit.datastore_routes.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = ""
                run.return_value.stderr = ""
                response = client.post(
                    "/local/file-transfers/tftp/settings",
                    data={
                        "enabled": "on",
                        "bind_host": "127.0.0.1",
                        "port": "1069",
                        "allow_read": "on",
                        "root_mode": "datastore",
                        "datastore_root": "",
                        "incoming_filename_pattern": "{timestamp}-{client_ip}-{filename}",
                        "allowed_networks": "127.0.0.0/8",
                    },
                )
            self.assertEqual(response.status_code, 302)
            run.assert_called_once()
            self.assertIn("tftp-restart", run.call_args.args[0])

            app.testing = False
            auth = AuthStore(instance)
            admin = auth.create_user("admin", "correct horse battery staple", is_admin=True)
            profile = auth.save_access_profile(name="Files", tool_ids=["local.datastore"])
            auth.create_user("operator", "a different long password", access_profile_ids=[profile["id"]])
            client.post("/login", data={"username": "operator", "password": "a different long password"})
            denied = client.post(
                "/local/file-transfers/tftp/settings",
                data={"bind_host": "127.0.0.1", "port": "1069"},
            )
            self.assertEqual(denied.status_code, 403)


if __name__ == "__main__":
    unittest.main()
