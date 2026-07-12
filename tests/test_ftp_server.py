from __future__ import annotations

import tempfile
import ftplib
import io
import socket
import threading
from pathlib import Path
from unittest.mock import patch
import unittest

from werkzeug.security import check_password_hash

from twn_toolkit import create_app
from twn_toolkit.ftp_server import FTPSettingsStore
from twn_toolkit.ftp_worker import build_handler
from pyftpdlib.servers import FTPServer
from twn_toolkit.ssh_transfer_server import SSHTransferHistoryStore
from twn_toolkit.ssh_transfer_worker import AtomicWriteHandle, TransferContext


class FTPServerTests(unittest.TestCase):
    def test_settings_hash_password_and_validate_passive_range(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = FTPSettingsStore(instance)
            settings = store.save({
                "enabled": True, "bind_host": "127.0.0.1", "port": 2121,
                "passive_start": 31000, "passive_end": 31010,
                "username": "toolkit", "allowed_networks": "127.0.0.1",
            }, "correct horse battery")
            self.assertTrue(check_password_hash(settings["password_hash"], "correct horse battery"))
            self.assertEqual(settings["max_connections"], 50)
            self.assertEqual(settings["max_connections_per_ip"], 5)
            self.assertNotIn("correct horse battery", store.path.read_text())
            with self.assertRaisesRegex(ValueError, "passive"):
                store.save({"passive_start": 32000, "passive_end": 31000})

    def test_temporary_mode_rejects_upload_permission(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            with self.assertRaisesRegex(ValueError, "download-only"):
                FTPSettingsStore(instance).save({
                    "root_mode": "temporary", "allow_write": True,
                })

    def test_file_transfer_page_renders_ftp_controls(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance); app.testing = True
            response = app.test_client().get("/local/file-transfers")
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"FTP service", response.data)
            self.assertIn(b"FTP is plaintext", response.data)

    def test_history_can_clear_only_ftp_records(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            history = SSHTransferHistoryStore(instance)
            common = {"client": "127.0.0.1", "operation": "download", "filename": "a", "status": "success"}
            history.record(protocol="FTP", **common)
            history.record(protocol="SFTP", **common)
            self.assertEqual([item["protocol"] for item in history.recent(protocols={"FTP"})], ["FTP"])
            self.assertEqual(history.clear({"FTP"}), 1)
            self.assertEqual([item["protocol"] for item in history.recent()], ["SFTP"])

    def test_failed_sftp_size_limit_never_commits_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            context = TransferContext(instance, {
                "root_mode": "datastore", "datastore_root": "", "allow_overwrite": True,
                "incoming_filename_pattern": "{filename}",
            }, "127.0.0.1")
            handle = AtomicWriteHandle(context, "oversized.bin")
            with patch("twn_toolkit.ssh_transfer_worker.MAX_UPLOAD_BYTES", 4):
                self.assertEqual(handle.write(0, b"1234"), 0)
                self.assertNotEqual(handle.write(4, b"5"), 0)
                self.assertNotEqual(handle.close(), 0)
            self.assertFalse((Path(instance) / "datastore" / "oversized.bin").exists())

    def test_contained_listener_uploads_and_downloads(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            def free_port() -> int:
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", 0)); return int(probe.getsockname()[1])
            try:
                control, passive = free_port(), free_port()
            except PermissionError as exc:
                self.skipTest(f"Local listeners unavailable in sandbox: {exc}")
            settings = FTPSettingsStore(instance).save({
                "bind_host": "127.0.0.1", "port": control,
                "passive_start": passive, "passive_end": passive,
                "username": "toolkit", "allow_read": True, "allow_write": True,
                "allow_overwrite": True, "incoming_filename_pattern": "{client_ip}-{filename}",
                "allowed_networks": "127.0.0.1",
            }, "correct horse battery")
            try:
                server = FTPServer(("127.0.0.1", control), build_handler(instance, settings))
            except PermissionError as exc:
                self.skipTest(f"Local listeners unavailable in sandbox: {exc}")
            def run_server() -> None:
                try:
                    server.serve_forever(timeout=0.05, blocking=True, handle_exit=False)
                except OSError:
                    pass
            thread = threading.Thread(target=run_server, daemon=True); thread.start()
            try:
                client = ftplib.FTP(); client.connect("127.0.0.1", control, timeout=3)
                client.login("toolkit", "correct horse battery")
                client.storbinary("STOR config.cfg", io.BytesIO(b"configuration"))
                payload = bytearray(); client.retrbinary("RETR 127.0.0.1-config.cfg", payload.extend)
                with patch("twn_toolkit.ftp_worker.MAX_UPLOAD_BYTES", 4):
                    with self.assertRaises(ftplib.Error):
                        client.storbinary("STOR too-big.bin", io.BytesIO(b"12345"))
                client.quit()
                self.assertEqual(bytes(payload), b"configuration")
                self.assertFalse((Path(instance) / "datastore" / "127.0.0.1-too-big.bin").exists())
            finally:
                server.close_all(); thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
