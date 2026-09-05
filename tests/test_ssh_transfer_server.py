from __future__ import annotations

import tempfile
import threading
import time
import socket
import io
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from twn_toolkit.datastore import LocalDatastore
from twn_toolkit.ssh_transfer_server import SSHTransferSettingsStore
from twn_toolkit.ssh_transfer_worker import (
    CLIENT_IDLE_TIMEOUT_SECONDS,
    TransferContext,
    ContainedSFTP,
    AtomicWriteHandle,
    TransferServer,
    _scp_receive,
    _scp_send,
    serve,
)


class Channel:
    def __init__(self, incoming: bytes) -> None:
        self.incoming = bytearray(incoming); self.sent = bytearray(); self.closed = False
    def recv(self, size: int) -> bytes:
        value = bytes(self.incoming[:size]); del self.incoming[:size]; return value
    def sendall(self, value: bytes) -> None: self.sent.extend(value)
    def close(self) -> None: self.closed = True


class SSHTransferServerTests(unittest.TestCase):
    def test_scp_channel_has_idle_timeout_before_handler_starts(self) -> None:
        context = MagicMock()
        context.settings = {"allow_scp": True}
        channel = MagicMock()
        server = TransferServer(context)

        with patch("twn_toolkit.ssh_transfer_worker.threading.Thread") as thread:
            accepted = server.check_channel_exec_request(
                channel, b"scp -f configuration.cfg"
            )

        self.assertTrue(accepted)
        channel.settimeout.assert_called_once_with(CLIENT_IDLE_TIMEOUT_SECONDS)
        thread.return_value.start.assert_called_once_with()

    def test_live_sftp_listener_uploads_and_downloads(self) -> None:
        import paramiko
        with tempfile.TemporaryDirectory() as instance:
            probe = socket.socket()
            try:
                probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]
            except PermissionError:
                self.skipTest("sandbox blocks local TCP listeners")
            finally:
                probe.close()
            SSHTransferSettingsStore(instance).save({
                "enabled": True, "bind_host": "127.0.0.1", "port": port,
                "username": "transfer", "allow_sftp": True, "allow_scp": True,
                "allow_read": True, "allow_write": True, "allow_overwrite": False,
                "root_mode": "datastore", "datastore_root": "",
                "incoming_filename_pattern": "{filename}", "allowed_networks": ["127.0.0.1/32"],
            }, "a long transfer password")
            stop = threading.Event(); ready = threading.Event()
            thread = threading.Thread(
                target=serve, args=(instance, stop, ready.set), daemon=True,
            )
            thread.start()
            self.assertTrue(ready.wait(5), "SSH transfer listener did not become ready")
            client = paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                deadline = time.time() + 5
                while True:
                    try:
                        client.connect("127.0.0.1", port=port, username="transfer", password="a long transfer password", allow_agent=False, look_for_keys=False)
                        break
                    except (OSError, paramiko.SSHException):
                        if time.time() >= deadline: raise
                        time.sleep(0.05)
                sftp = client.open_sftp(); sftp.putfo(io.BytesIO(b"hello"), "hello.txt")
                output = io.BytesIO(); sftp.getfo("hello.txt", output); sftp.close()
                self.assertEqual(output.getvalue(), b"hello")
                # Close the subsystem without sending CLOSE for the open file.
                interrupted = client.open_sftp()
                handle = interrupted.open("interrupted", "w")
                handle.write(b"partial")
                interrupted.close()
                deadline = time.monotonic() + 3
                from twn_toolkit.ssh_transfer_server import SSHTransferHistoryStore
                history = SSHTransferHistoryStore(instance)
                while time.monotonic() < deadline:
                    records = [row for row in history.recent() if row["filename"] == "interrupted"]
                    if records:
                        break
                    time.sleep(0.01)
                self.assertEqual([row["status"] for row in records], ["error"])
                self.assertFalse((Path(instance) / "datastore" / "interrupted").exists())
            finally:
                client.close(); stop.set(); thread.join(3)

    def test_session_cleanup_aborts_only_its_own_unclosed_uploads(self) -> None:
        import os
        import paramiko
        with tempfile.TemporaryDirectory() as instance:
            context = TransferContext(instance, {
                "root_mode": "datastore", "datastore_root": "", "allow_write": True,
                "allow_overwrite": False, "incoming_filename_pattern": "{filename}",
            }, "127.0.0.1")
            first = ContainedSFTP(None, context=context)
            second = ContainedSFTP(None, context=context)
            partial = first.open("partial", os.O_WRONLY | os.O_CREAT, None)
            complete = second.open("complete", os.O_WRONLY | os.O_CREAT, None)
            self.assertEqual(partial.write(0, b"partial"), paramiko.SFTP_OK)
            self.assertEqual(complete.write(0, b"complete"), paramiko.SFTP_OK)
            first.session_ended()
            self.assertEqual(partial.close(), paramiko.SFTP_FAILURE)
            self.assertEqual(complete.close(), paramiko.SFTP_OK)
            self.assertEqual(complete.close(), paramiko.SFTP_OK)
            second.session_ended()
            self.assertFalse((context.root / "partial").exists())
            self.assertEqual((context.root / "complete").read_bytes(), b"complete")
            self.assertEqual(len(context.history.recent()), 2)

    def test_invalid_offset_prevents_prefix_publication(self) -> None:
        import paramiko
        with tempfile.TemporaryDirectory() as instance:
            context = TransferContext(instance, {
                "root_mode": "datastore", "datastore_root": "", "allow_overwrite": True,
                "incoming_filename_pattern": "{filename}",
            }, "127.0.0.1")
            (context.root / "target").write_bytes(b"original")
            handle = AtomicWriteHandle(context, "target")
            self.assertEqual(handle.write(0, b"prefix"), paramiko.SFTP_OK)
            self.assertEqual(handle.write(99, b"invalid"), paramiko.SFTP_BAD_MESSAGE)
            self.assertEqual(handle.close(), paramiko.SFTP_FAILURE)
            self.assertEqual((context.root / "target").read_bytes(), b"original")
            self.assertEqual(context.history.recent()[0]["status"], "error")

    def test_scp_interruption_and_negative_final_status_do_not_publish(self) -> None:
        for data in (b"C0600 5 config.cfg\nhel", b"C0600 5 config.cfg\nhello\x01"):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as instance:
                context = TransferContext(instance, {
                    "root_mode": "datastore", "datastore_root": "", "allow_write": True,
                    "allow_overwrite": True, "incoming_filename_pattern": "{filename}",
                }, "127.0.0.1")
                (context.root / "config.cfg").write_bytes(b"original")
                channel = Channel(data)
                _scp_receive(channel, context, "config.cfg")
                self.assertEqual((context.root / "config.cfg").read_bytes(), b"original")
                self.assertTrue(bytes(channel.sent).startswith(b"\x00\x00\x01"))
                self.assertEqual(context.history.recent()[0]["status"], "error")

    def test_settings_hash_password_and_validate_containment_policy(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = SSHTransferSettingsStore(instance)
            settings = store.save({
                "enabled": True, "bind_host": "127.0.0.1", "port": 2022,
                "username": "transfer", "allow_sftp": True, "allow_scp": True,
                "allow_read": True, "allow_write": True, "allow_overwrite": False,
                "root_mode": "datastore", "datastore_root": "",
                "incoming_filename_pattern": "{timestamp}-{client_ip}-{filename}",
                "allowed_networks": ["192.0.2.0/24"],
            }, "a long transfer password")
            self.assertNotIn("a long transfer password", Path(store.path).read_text())
            self.assertTrue(settings["password_hash"])
            self.assertFalse(settings["allow_legacy_algorithms"])
            settings = store.save({**settings, "allow_legacy_algorithms": True})
            self.assertTrue(settings["allow_legacy_algorithms"])
            with self.assertRaisesRegex(ValueError, "Temporary-file mode"):
                store.save({**settings, "root_mode": "temporary", "allow_write": True})

    def test_scp_upload_is_rewritten_and_downloaded_from_contained_root(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            settings = {
                "root_mode": "datastore", "datastore_root": "", "allow_read": True,
                "allow_write": True, "allow_overwrite": False,
                "incoming_filename_pattern": "{client_ip}-{filename}",
            }
            context = TransferContext(instance, settings, "192.0.2.10")
            upload = Channel(b"C0600 5 config.cfg\nhello\x00")
            _scp_receive(upload, context, "/incoming")
            stored = LocalDatastore(instance).file("192.0.2.10-config.cfg")
            self.assertEqual(stored.read_bytes(), b"hello")
            self.assertEqual(bytes(upload.sent), b"\x00\x00\x00")

            download = Channel(b"\x00\x00\x00")
            _scp_send(download, context, "/192.0.2.10-config.cfg")
            self.assertIn(b"C0600 5 192.0.2.10-config.cfg\nhello\x00", bytes(download.sent))
            self.assertTrue(download.closed)


if __name__ == "__main__": unittest.main()
