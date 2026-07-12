from __future__ import annotations

import io
import socket
import struct
import tempfile
import threading
import time
import unittest

from twn_toolkit.datastore import LocalDatastore
from twn_toolkit.tftp import (
    TFTPHistoryStore,
    TFTPServer,
    TFTPSettingsStore,
    clear_tftp_runtime,
    format_incoming_filename,
)
from datetime import datetime


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class TFTPSettingsTests(unittest.TestCase):
    def test_defaults_are_disabled_and_settings_are_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = TFTPSettingsStore(instance)
            self.assertFalse(store.get()["enabled"])
            saved = store.save(
                {
                    "enabled": True,
                    "bind_host": "127.0.0.1",
                    "port": 1069,
                    "allow_read": True,
                    "allow_write": True,
                    "allow_overwrite": False,
                    "allowed_networks": "127.0.0.1\n10.0.0.0/8",
                }
            )
            self.assertEqual(saved["allowed_networks"], ["127.0.0.1/32", "10.0.0.0/8"])
            self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)

    def test_invalid_bind_network_and_permission_policy_are_rejected(self) -> None:
        base = {
            "enabled": True,
            "bind_host": "127.0.0.1",
            "port": 1069,
            "allow_read": True,
            "allow_write": False,
            "allowed_networks": ["127.0.0.0/8"],
        }
        with self.assertRaisesRegex(ValueError, "bind address"):
            TFTPSettingsStore.validate({**base, "bind_host": "localhost"})
        with self.assertRaisesRegex(ValueError, "Invalid trusted"):
            TFTPSettingsStore.validate({**base, "allowed_networks": ["bad network"]})
        with self.assertRaisesRegex(ValueError, "Enable TFTP reads"):
            TFTPSettingsStore.validate({**base, "allow_read": False})

    def test_incoming_filename_pattern_uses_safe_tokens(self) -> None:
        result = format_incoming_filename(
            "{timestamp}-{client_ip}-{stem}{suffix}",
            "config.cfg",
            "2001:db8::10",
            datetime(2026, 7, 12, 14, 30, 5),
        )
        self.assertEqual(result, "20260712-143005-2001_db8__10-config.cfg")
        base = {
            "enabled": True,
            "bind_host": "127.0.0.1",
            "port": 1069,
            "allow_read": True,
            "allow_write": False,
            "allowed_networks": ["127.0.0.0/8"],
        }
        with self.assertRaisesRegex(ValueError, "pattern tokens"):
            TFTPSettingsStore.validate(
                {**base, "incoming_filename_pattern": "{unknown}-{filename}"}
            )

    def test_temporary_runtime_clear_removes_staged_file(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            runtime = LocalDatastore(instance, "tftp_runtime")
            runtime.save_upload("", "temporary.bin", io.BytesIO(b"temporary"))
            clear_tftp_runtime(instance)
            self.assertEqual(runtime.list()["entries"], [])


class TFTPTransferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.datastore = LocalDatastore(self.temp.name)
        self.datastore.create_folder("", "selected-root")
        self.history = TFTPHistoryStore(self.temp.name)
        try:
            self.port = free_udp_port()
        except PermissionError:
            self.temp.cleanup()
            self.skipTest("UDP sockets are unavailable in the test sandbox")
        self.settings = {
            "enabled": True,
            "bind_host": "127.0.0.1",
            "port": self.port,
            "allow_read": True,
            "allow_write": True,
            "allow_overwrite": False,
            "allowed_networks": ["127.0.0.0/8"],
        }
        self.server = TFTPServer(
            self.datastore, self.history, self.settings, root_prefix="selected-root"
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        deadline = time.time() + 2
        while self.server.socket is None and time.time() < deadline:
            time.sleep(0.01)

    def tearDown(self) -> None:
        self.server.stop()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def test_rrq_download_with_blocksize_negotiation(self) -> None:
        self.datastore.save_upload("selected-root", "config.txt", io.BytesIO(b"abcdefghijklmnop"))
        request = struct.pack("!H", 1) + b"config.txt\0octet\0blksize\0" + b"8\0"
        received = bytearray()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(request, ("127.0.0.1", self.port))
            packet, transfer = client.recvfrom(65535)
            self.assertEqual(struct.unpack("!H", packet[:2])[0], 6)
            client.sendto(struct.pack("!HH", 4, 0), transfer)
            while True:
                packet, source = client.recvfrom(65535)
                opcode, block = struct.unpack("!HH", packet[:4])
                self.assertEqual(opcode, 3)
                payload = packet[4:]
                received.extend(payload)
                client.sendto(struct.pack("!HH", 4, block), source)
                if len(payload) < 8:
                    break
        self.assertEqual(bytes(received), b"abcdefghijklmnop")
        self._wait_for_history()
        self.assertEqual(self.history.recent()[0]["status"], "success")

    def test_wrq_upload_and_existing_name_rejection(self) -> None:
        self._upload("incoming.cfg", b"new configuration")
        self.assertEqual(self.datastore.file("selected-root/incoming.cfg").read_bytes(), b"new configuration")
        opcode, code, message = self._upload("incoming.cfg", b"replacement", expect_error=True)
        self.assertEqual((opcode, code), (5, 6))
        self.assertIn(b"already exists", message)
        self.assertEqual(self.datastore.file("selected-root/incoming.cfg").read_bytes(), b"new configuration")

    def test_wrq_custom_pattern_renames_from_client_ip(self) -> None:
        self.server.settings["incoming_filename_pattern"] = (
            "{timestamp}-{client_ip}-{filename}"
        )
        self._upload("config.cfg", b"switch configuration")
        matches = list(
            (self.datastore.root / "selected-root").glob(
                "*-127.0.0.1-config.cfg"
            )
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].read_bytes(), b"switch configuration")
        self._wait_for_history()
        latest = self.history.recent()[0]
        self.assertEqual(latest["filename"], "config.cfg")
        self.assertTrue(latest["stored_filename"].endswith("-127.0.0.1-config.cfg"))

    def _upload(self, filename: str, payload: bytes, expect_error: bool = False):
        request = struct.pack("!H", 2) + filename.encode() + b"\0octet\0"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(request, ("127.0.0.1", self.port))
            response, transfer = client.recvfrom(65535)
            self.assertEqual(struct.unpack("!HH", response[:4]), (4, 0))
            client.sendto(struct.pack("!HH", 3, 1) + payload, transfer)
            response, _source = client.recvfrom(65535)
        if expect_error:
            return (*struct.unpack("!HH", response[:4]), response[4:-1])
        self.assertEqual(struct.unpack("!HH", response[:4]), (4, 1))
        self._wait_for_history()
        return None

    def _wait_for_history(self) -> None:
        deadline = time.time() + 2
        while not self.history.recent() and time.time() < deadline:
            time.sleep(0.01)


if __name__ == "__main__":
    unittest.main()
