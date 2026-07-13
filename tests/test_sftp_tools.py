from __future__ import annotations

import io
import ftplib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from twn_toolkit import create_app
from twn_toolkit.datastore import LocalDatastore
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.sftp_tools import (
    fetch_sftp_files,
    fetch_ssh_files,
    format_sftp_filename,
    parse_sftp_paths,
    validate_sftp_filename_pattern,
)


class SftpToolTests(unittest.TestCase):
    def test_remote_paths_are_trimmed_deduplicated_and_bounded(self) -> None:
        self.assertEqual(
            parse_sftp_paths(" /var/log/messages\n\n/data/config.cfg\n/var/log/messages "),
            ["/var/log/messages", "/data/config.cfg"],
        )
        with self.assertRaisesRegex(ToolInputError, "at least one"):
            parse_sftp_paths("")

    def test_filename_patterns_use_safe_host_and_path_tokens(self) -> None:
        pattern = validate_sftp_filename_pattern(
            "{timestamp}-{label}-{host}-{stem}{suffix}"
        )
        self.assertEqual(
            format_sftp_filename(
                pattern,
                timestamp="20260712153000",
                host="2001:db8::10",
                label="Core Switch",
                remote_path="/data/config.cfg",
            ),
            "20260712153000-Core-Switch-2001-db8-10-config.cfg",
        )
        with self.assertRaisesRegex(ToolInputError, "pattern tokens"):
            validate_sftp_filename_pattern("{unknown}-{filename}")

    def test_fetch_names_files_by_timestamp_and_host(self) -> None:
        client = MagicMock()
        sftp = client.open_sftp.return_value
        sftp.stat.return_value.st_size = 5
        remote = MagicMock()
        remote.__enter__.return_value = io.BytesIO(b"hello")
        sftp.open.return_value = remote
        with tempfile.TemporaryDirectory() as temporary, patch(
            "paramiko.SSHClient", return_value=client
        ):
            results = fetch_sftp_files(
                hosts=[{"label": "Core Switch", "host": "192.0.2.10"}],
                remote_paths=["/data/config.cfg"],
                username="admin",
                password="secret",
                port=22,
                allow_unknown_hosts=True,
                output_dir=Path(temporary),
                timestamp="20260712153000",
            )
            self.assertEqual(results[0]["status"], "success")
            self.assertEqual(
                results[0]["filename"], "20260712153000-Core-Switch-config.cfg"
            )
            self.assertEqual(
                (Path(temporary) / str(results[0]["filename"])).read_bytes(), b"hello"
            )
        client.connect.assert_called_once_with(
            hostname="192.0.2.10",
            port=22,
            username="admin",
            password="secret",
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10,
        )

    def test_connection_failure_is_reported_for_each_requested_file(self) -> None:
        client = MagicMock()
        client.connect.side_effect = OSError("offline")
        with tempfile.TemporaryDirectory() as temporary, patch(
            "paramiko.SSHClient", return_value=client
        ):
            results = fetch_sftp_files(
                hosts=[{"label": "", "host": "192.0.2.10"}],
                remote_paths=["/one", "/two"],
                username="admin",
                password="secret",
                port=22,
                allow_unknown_hosts=False,
                output_dir=Path(temporary),
            )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(item["status"] == "error" for item in results))
        self.assertTrue(all("Connection failed" in item["error"] for item in results))

    def test_scp_adapter_receives_regular_file_protocol(self) -> None:
        class Channel:
            def __init__(self) -> None:
                self.buffer = bytearray(b"C0644 5 config.cfg\nhello\x00")
                self.sent = []
            def settimeout(self, _value): pass
            def exec_command(self, value): self.command = value
            def sendall(self, value): self.sent.append(value)
            def recv(self, size):
                value = bytes(self.buffer[:size]); del self.buffer[:size]; return value
            def close(self): pass

        channel = Channel()
        transport = MagicMock()
        transport.is_active.return_value = True
        transport.open_session.return_value = channel
        client = MagicMock()
        client.get_transport.return_value = transport
        with tempfile.TemporaryDirectory() as temporary, patch(
            "paramiko.SSHClient", return_value=client
        ):
            results = fetch_ssh_files(
                hosts=[{"label": "Core", "host": "192.0.2.10"}],
                remote_paths=["/config.cfg"], username="admin", password="secret",
                port=22, allow_unknown_hosts=True, output_dir=Path(temporary),
                timestamp="20260712153000", protocol="scp",
            )
            self.assertEqual(results[0]["status"], "success")
            self.assertEqual((Path(temporary) / results[0]["filename"]).read_bytes(), b"hello")
        self.assertEqual(channel.command, "scp -f /config.cfg")
        self.assertEqual(channel.sent, [b"\x00", b"\x00", b"\x00"])

    def test_ftp_adapter_downloads_regular_file(self) -> None:
        ftp = MagicMock()
        ftp.size.return_value = 5
        ftp.retrbinary.side_effect = lambda _command, callback, **_kwargs: callback(b"hello")
        with tempfile.TemporaryDirectory() as temporary, patch(
            "twn_toolkit.sftp_tools.ftplib.FTP", return_value=ftp
        ):
            results = fetch_ssh_files(
                hosts=[{"label": "Legacy Switch", "host": "192.0.2.20"}],
                remote_paths=["/config.cfg"], username="admin", password="secret",
                port=21, allow_unknown_hosts=False, output_dir=Path(temporary),
                timestamp="20260712153000", protocol="ftp",
            )
            self.assertEqual(results[0]["status"], "success")
            self.assertEqual((Path(temporary) / results[0]["filename"]).read_bytes(), b"hello")
        ftp.connect.assert_called_once_with("192.0.2.20", 21, timeout=15)
        ftp.login.assert_called_once_with("admin", "secret")
        ftp.retrbinary.assert_called_once()

    def test_ftp_adapter_streams_when_size_is_unsupported(self) -> None:
        ftp = MagicMock()
        ftp.size.side_effect = ftplib.error_perm("502 SIZE not implemented")
        ftp.retrbinary.side_effect = lambda _command, callback, **_kwargs: callback(b"legacy")
        with tempfile.TemporaryDirectory() as temporary, patch(
            "twn_toolkit.sftp_tools.ftplib.FTP", return_value=ftp
        ):
            results = fetch_ssh_files(
                hosts=[{"label": "", "host": "192.0.2.30"}],
                remote_paths=["/legacy.cfg"], username="admin", password="secret",
                port=21, allow_unknown_hosts=False, output_dir=Path(temporary),
                protocol="ftp",
            )
            self.assertEqual(results[0]["status"], "success")
            self.assertEqual((Path(temporary) / results[0]["filename"]).read_bytes(), b"legacy")


class SftpRouteTests(unittest.TestCase):
    def test_page_is_available_and_datastore_mode_persists_file(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            page = client.get("/tools/multi-transfer")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Fetch and download", page.data)

            def fake_fetch(**kwargs):
                filename = "20260712153000-switch-config.cfg"
                (kwargs["output_dir"] / filename).write_bytes(b"config")
                return [{
                    "host": "192.0.2.10", "host_label": "Switch",
                    "remote_path": "/config.cfg", "status": "success",
                    "filename": filename, "size": 6, "error": "",
                }]

            with patch("twn_toolkit.sftp_routes.fetch_ssh_files", side_effect=fake_fetch):
                response = client.post(
                    "/tools/multi-transfer",
                    data={
                        "hosts": "Switch = 192.0.2.10",
                        "username": "admin",
                        "password": "secret",
                        "port": "22",
                        "remote_paths": "/config.cfg",
                        "output_mode": "datastore",
                        "destination": "",
                    },
                )
            self.assertEqual(response.status_code, 200)
            store = LocalDatastore(instance)
            self.assertEqual(store.file("20260712153000-switch-config.cfg").read_bytes(), b"config")

    def test_download_mode_returns_ephemeral_zip(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()

            def fake_fetch(**kwargs):
                filename = "download.txt"
                (kwargs["output_dir"] / filename).write_bytes(b"hello")
                return [{
                    "host": "192.0.2.10", "host_label": "",
                    "remote_path": "/download.txt", "status": "success",
                    "filename": filename, "size": 5, "error": "",
                }]

            with patch("twn_toolkit.sftp_routes.fetch_ssh_files", side_effect=fake_fetch):
                response = client.post(
                    "/tools/multi-transfer",
                    data={
                        "hosts": "192.0.2.10", "username": "admin",
                        "password": "secret", "port": "22",
                        "remote_paths": "/download.txt", "output_mode": "download",
                        "download_token": "test-download-token",
                    },
                )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, "application/zip")
            self.assertIn(b"PK", response.data[:4])
            results_page = client.get(
                "/tools/multi-transfer?download_result=test-download-token"
            )
            self.assertIn(b"SFTP Results", results_page.data)
            self.assertIn(b"1 of 1 transfer(s) downloaded", results_page.data)
            self.assertIn(b"included in downloaded ZIP", results_page.data)
            self.assertNotIn(b"Open destination", results_page.data)

    def test_download_mode_renders_errors_when_every_transfer_fails(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            app.testing = True
            client = app.test_client()
            failures = [{
                "host": "192.0.2.99", "host_label": "Offline",
                "remote_path": "/missing.cfg", "status": "error",
                "filename": "", "size": 0, "error": "Connection failed: offline",
            }]
            with patch(
                "twn_toolkit.sftp_routes.fetch_ssh_files", return_value=failures
            ):
                response = client.post(
                    "/tools/multi-transfer",
                    data={
                        "protocol": "ftp", "hosts": "Offline = 192.0.2.99",
                        "username": "admin", "password": "secret", "port": "21",
                        "remote_paths": "/missing.cfg", "output_mode": "download",
                    },
                )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, "text/html")
            self.assertIn(b"No files were fetched", response.data)
            self.assertIn(b"Connection failed: offline", response.data)


if __name__ == "__main__":
    unittest.main()
