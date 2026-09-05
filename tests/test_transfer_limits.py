from __future__ import annotations

import io
import json
import socket
import struct
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from twn_toolkit import create_app
from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.ssh_transfer_server import SSHTransferSettingsStore, SSHTransferHistoryStore, SSH_TRANSFER_LIMITS
from twn_toolkit.ssh_transfer_worker import BoundedSFTPServer, ReadHandle, TransferContext, serve
from twn_toolkit.transfer_limits import ChannelActivity, ConnectionAdmission


@contextmanager
def listener(tmp_path, **overrides):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    settings = SSHTransferSettingsStore(str(tmp_path)).save({
        "enabled": True, "port": port, "allow_read": True, "allow_write": True,
        "max_connections": 4, "max_connections_per_ip": 4,
        "authentication_timeout_seconds": 3, "idle_timeout_seconds": 3,
        **overrides,
    }, "a long transfer password")
    stop, ready = threading.Event(), threading.Event()
    worker = threading.Thread(target=serve, args=(str(tmp_path), stop, ready.set), daemon=True)
    worker.start()
    try:
        assert ready.wait(10)
        yield port, settings
    finally:
        stop.set()
        worker.join(7)
        assert not worker.is_alive(), "listener failed to stop"


@contextmanager
def connected(port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port=port, username="toolkit", password="a long transfer password",
                       allow_agent=False, look_for_keys=False, timeout=3, auth_timeout=3)
        yield client
    finally:
        client.close()


def wait_for(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    assert predicate()


def test_old_settings_receive_defaults_and_reject_invalid_limits(tmp_path):
    store = SSHTransferSettingsStore(str(tmp_path))
    saved = store.save({})
    raw = {key: value for key, value in saved.items() if key not in SSH_TRANSFER_LIMITS}
    store.path.write_text(json.dumps(raw))
    assert store.get()["max_connections"] == 32
    for key, (default, minimum, maximum, _label, _description) in SSH_TRANSFER_LIMITS.items():
        for invalid in (minimum - 1, maximum + 1, "1.5", True, None):
            with pytest.raises(ValueError):
                store.save({key: invalid})
        assert store.get()[key] == default
    with pytest.raises(ValueError, match="per client IP"):
        store.save({"max_connections": 1, "max_connections_per_ip": 2})


def test_admission_bounds_total_and_per_ip_and_releases():
    admission = ConnectionAdmission(2, 1)
    one, two, three = object(), object(), object()
    assert admission.acquire(one, "one")
    assert not admission.acquire(two, "one")
    assert admission.acquire(two, "two")
    assert not admission.acquire(three, "three")
    admission.release(one)
    assert admission.acquire(three, "three")


def test_channel_capacity_and_service_claims_are_reusable_after_close():
    activity = ChannelActivity(1)
    channel = MagicMock(closed=False)
    channel.get_id.return_value = 1
    assert activity.admit(1)
    activity.bind(channel)
    assert activity.start_service(channel)
    assert not activity.start_service(channel)
    assert not activity.admit(2)
    channel.closed = True
    assert activity.admit(2)


def test_silent_peer_does_not_block_healthy_client_and_expires(tmp_path):
    with listener(tmp_path, authentication_timeout_seconds=1) as (port, _):
        with socket.create_connection(("127.0.0.1", port), timeout=3) as silent:
            silent.settimeout(3)
            assert silent.recv(1024).startswith(b"SSH-")
            with connected(port) as client:
                with client.open_sftp() as sftp:
                    sftp.putfo(io.BytesIO(b"healthy"), "healthy")
            assert silent.recv(1024) == b""
        assert (tmp_path / "datastore" / "healthy").read_bytes() == b"healthy"


def test_connection_cap_rejects_extra_client_then_recovers(tmp_path):
    with listener(tmp_path, max_connections=1, max_connections_per_ip=1) as (port, _):
        first = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            assert first.recv(1024).startswith(b"SSH-")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as rejected:
                try:
                    assert rejected.recv(1024) == b""
                except ConnectionResetError:
                    pass
        finally:
            first.close()
        # Let the old transport's cleanup release its admission slot.
        time.sleep(0.2)
        with connected(port) as client:
            assert client.get_transport().is_authenticated()


def test_channel_and_handle_limits_return_capacity_on_close(tmp_path):
    with listener(tmp_path, max_channels=1, max_open_handles=1) as (port, _):
        with connected(port) as client:
            sftp = client.open_sftp()
            with pytest.raises(paramiko.ChannelException):
                client.open_sftp()
            upload = sftp.open("one", "w")
            upload.write(b"one")
            with pytest.raises(OSError):
                sftp.open("two", "w")
            with pytest.raises(OSError):
                sftp.listdir(".")
            upload.close()
            sftp.putfo(io.BytesIO(b"two"), "two")
            sftp.close()
            time.sleep(0.1)
            with client.open_sftp() as second:
                assert set(second.listdir(".")) == {"one", "two"}


def test_idle_upload_aborts_while_active_channel_survives(tmp_path):
    with listener(tmp_path, idle_timeout_seconds=1) as (port, _):
        with connected(port) as client:
            idle = client.open_sftp()
            partial = idle.open("partial", "w")
            partial.write(b"partial")
            active = client.open_sftp()
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                active.stat(".")
                time.sleep(0.15)
            assert idle.get_channel().closed
            active.putfo(io.BytesIO(b"complete"), "complete")
            active.close()
            history = SSHTransferHistoryStore(str(tmp_path))
            wait_for(lambda: any(row["filename"] == "partial" for row in history.recent()))
            assert not (tmp_path / "datastore" / "partial").exists()
            assert (tmp_path / "datastore" / "complete").read_bytes() == b"complete"


def test_sftp_commit_failure_is_visible_to_client(tmp_path):
    with listener(tmp_path) as (port, _):
        with connected(port) as client, client.open_sftp() as sftp:
            upload = sftp.open("failed", "w")
            upload.write(b"complete")
            with patch("twn_toolkit.uploads.Upload.commit", side_effect=OSError("injected failure")):
                # SFTPFile.close suppresses server errors. Inspect the wire
                # response through the client's request API instead.
                from paramiko.sftp import CMD_CLOSE
                with pytest.raises(OSError):
                    sftp._request(CMD_CLOSE, upload.handle)
                upload.close()
            assert not (tmp_path / "datastore" / "failed").exists()
            sftp.putfo(io.BytesIO(b"healthy"), "healthy")


def test_download_history_tracks_actual_bytes_and_explicit_completion(tmp_path):
    context = TransferContext(str(tmp_path), {}, "127.0.0.1")
    (context.root / "file").write_bytes(b"complete")
    handle = ReadHandle(context, "file")
    assert context.history.recent() == []
    assert handle.read(0, 3) == b"com"
    handle.abort()
    row = context.history.recent()[0]
    assert row["bytes"] == 3 and row["status"] == "error"
    handle = ReadHandle(context, "file")
    assert handle.read(0, 1000) == b"complete"
    handle.close()
    handle.close()
    rows = context.history.recent()
    assert len(rows) == 2
    assert rows[0]["bytes"] == 8 and rows[0]["status"] == "success"


def test_sftp_packet_ceiling_rejects_length_before_allocating_body():
    server = object.__new__(BoundedSFTPServer)
    server._read_all = MagicMock(return_value=struct.pack(">I", 1024**3))
    with pytest.raises(paramiko.SFTPError):
        server._read_packet()
    server._read_all.assert_called_once_with(4)


def test_shared_upload_policy_is_snapshotted_and_cannot_be_bypassed(tmp_path):
    settings = OperationalSettingsStore(str(tmp_path))
    settings.save({"max_upload_mib": 2})
    store = LocalDatastore(str(tmp_path))
    with store.begin_upload("", "old") as old:
        settings.save({"max_upload_mib": 1})
        old.write(b"x" * (1024**2 + 1))
        old.commit()
    with pytest.raises(DatastoreError):
        store.save_upload("", "new", io.BytesIO(b"x" * (1024**2 + 1)), max_bytes=10 * 1024**2)
    assert store.upload_limit() == 1024**2
    for bad in (0, 65537, "1.5", True):
        with pytest.raises(ValueError):
            settings.save({"max_upload_mib": bad})


def test_settings_ui_persists_limits_and_preserves_omitted_fields(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    client = app.test_client()
    settings = SSHTransferSettingsStore(str(tmp_path))
    existing = settings.save({"max_open_handles": 7})
    form = {
        "bind_host": "127.0.0.1", "port": "2022", "username": "toolkit",
        "allow_sftp": "on", "allow_read": "on", "root_mode": "datastore",
        "allowed_networks": "127.0.0.1", "max_connections": "12", "max_connections_per_ip": "3",
    }
    with patch("twn_toolkit.datastore_routes.subprocess.run") as run:
        run.return_value.returncode = 0
        response = client.post("/local/file-transfers/ssh/settings", data=form)
    assert response.status_code == 302
    assert settings.get()["max_connections"] == 12
    assert settings.get()["max_open_handles"] == existing["max_open_handles"]
    page = client.get("/local/file-transfers")
    assert b'Connection and resource limits' in page.data
    assert b'name="max_connections"' in page.data
    operations = OperationalSettingsStore(str(tmp_path)).get()
    operations["max_upload_mib"] = "3"
    assert client.post("/settings/operations", data=operations).status_code == 302
    assert OperationalSettingsStore(str(tmp_path)).get()["max_upload_mib"] == 3
    assert b'name="max_upload_mib"' in client.get("/settings?section=operations").data


def test_datastore_request_limit_is_request_local_and_live(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    settings = OperationalSettingsStore(str(tmp_path))
    settings.save({"max_upload_mib": 1})
    client = app.test_client()
    observed = []
    @app.before_request
    def observe():
        from flask import request
        observed.append(request.max_content_length)
    client.get("/local/datastore")
    client.post("/local/datastore/uploads", data={"files": (io.BytesIO(b"x"), "one")})
    settings.save({"max_upload_mib": 2048})
    client.post("/local/datastore/uploads", data={"files": (io.BytesIO(b"x"), "two")})
    assert observed == [1024**3 + 1024**2, 2 * 1024**2, 2049 * 1024**2]
    assert app.config["MAX_CONTENT_LENGTH"] == 1024**3 + 1024**2


def test_authentication_deadline_is_not_extended_by_keepalives(tmp_path):
    with listener(tmp_path, authentication_timeout_seconds=1) as (port, _):
        transport = paramiko.Transport(socket.create_connection(("127.0.0.1", port), timeout=3))
        try:
            transport.start_client(timeout=3)
            deadline = time.monotonic() + 2
            while transport.is_active() and time.monotonic() < deadline:
                try:
                    transport.send_ignore()
                except OSError:
                    break
                time.sleep(0.1)
            wait_for(lambda: not transport.is_active())
            assert not (tmp_path / "ssh_transfer_history.sqlite3").exists()
        finally:
            transport.close()


def test_directory_listing_limit_does_not_truncate_or_block_named_download(tmp_path):
    store = LocalDatastore(str(tmp_path))
    for index in range(101):
        (store.root / str(index)).write_bytes(b"file")
    with listener(tmp_path, max_directory_entries=100) as (port, _):
        with connected(port) as client, client.open_sftp() as sftp:
            with pytest.raises(OSError):
                sftp.listdir(".")
            output = io.BytesIO()
            sftp.getfo("0", output)
            assert output.getvalue() == b"file"


def test_shutdown_aborts_open_uploads_and_releases_reservations(tmp_path):
    with listener(tmp_path) as (port, _):
        with connected(port) as client:
            sftp = client.open_sftp()
            upload = sftp.open("interrupted", "w")
            upload.write(b"prefix")
            # Leave the handle open when the transport disconnects.
    assert not (tmp_path / "datastore" / "interrupted").exists()
    assert not list((tmp_path / ".upload-reservations").glob("*/data"))


def test_download_rejects_fifo_without_blocking(tmp_path):
    import os
    context = TransferContext(str(tmp_path), {}, "127.0.0.1")
    os.mkfifo(context.root / "pipe")
    with pytest.raises(OSError, match="regular files"):
        ReadHandle(context, "pipe")


def test_listener_survives_temporary_descriptor_exhaustion(tmp_path):
    import errno
    SSHTransferSettingsStore(str(tmp_path)).save({})
    stop = threading.Event()
    fake = MagicMock()
    def accept():
        if fake.accept.call_count == 1:
            raise OSError(errno.EMFILE, "injected descriptor exhaustion")
        stop.set()
        raise socket.timeout()
    fake.accept.side_effect = accept
    with patch("twn_toolkit.ssh_transfer_worker.socket.socket") as factory, patch("twn_toolkit.ssh_transfer_worker.ensure_ssh_host_key"):
        factory.return_value.__enter__.return_value = fake
        serve(str(tmp_path), stop)
    assert fake.accept.call_count == 2
