from __future__ import annotations

import tempfile
import threading
import time
import socket
import io
import unittest
from pathlib import Path

from twn_toolkit.datastore import LocalDatastore
from twn_toolkit.ssh_transfer_server import SSHTransferSettingsStore
from twn_toolkit.ssh_transfer_worker import TransferContext, _scp_receive, _scp_send, serve


class Channel:
    def __init__(self, incoming: bytes) -> None:
        self.incoming = bytearray(incoming); self.sent = bytearray(); self.closed = False
    def recv(self, size: int) -> bytes:
        value = bytes(self.incoming[:size]); del self.incoming[:size]; return value
    def sendall(self, value: bytes) -> None: self.sent.extend(value)
    def close(self) -> None: self.closed = True


class SSHTransferServerTests(unittest.TestCase):
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
            stop = threading.Event(); thread = threading.Thread(target=serve, args=(instance, stop), daemon=True); thread.start()
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
            finally:
                client.close(); stop.set(); thread.join(3)

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
