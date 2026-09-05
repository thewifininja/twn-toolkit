from __future__ import annotations

import io
import multiprocessing
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.uploads import BUFFER_BYTES, Upload

GIB = 1024**3


@pytest.fixture
def store(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({"datastore_quota_gib": 1, "minimum_free_gib": 0})
    return LocalDatastore(str(tmp_path))


def fill(store, size):
    with (store.root / "baseline").open("wb") as stream:
        stream.truncate(size)


def _hold_upload(instance, connection):
    store = LocalDatastore(instance)
    with store.begin_upload("", "child", expected_bytes=6) as upload:
        upload.write(b"child!")
        upload.flush()
        connection.send("ready")
        connection.recv()


def test_abort_never_publishes_or_exposes_staging(store):
    with store.begin_upload("", "private") as upload:
        upload.write(b"partial")
        upload.flush()
        assert store.list()["entries"] == []
        assert upload.temporary.stat().st_mode & 0o777 == 0o600
    assert not upload.destination.exists()
    assert not upload.directory.exists()
    with pytest.raises(DatastoreError, match="closed"):
        upload.commit()


def test_commit_is_explicit_and_idempotent(store):
    with store.begin_upload("", "complete") as upload:
        upload.write(b"complete")
        assert not upload.destination.exists()
        assert upload.commit() == (upload.destination, 8)
        assert upload.commit() == (upload.destination, 8)
    assert upload.destination.read_bytes() == b"complete"
    assert upload.destination.stat().st_mode & 0o777 == 0o600


def test_expected_length_and_limit_failures_invalidate_upload(store):
    with store.begin_upload("", "short", expected_bytes=5) as upload:
        upload.write(b"a")
        with pytest.raises(DatastoreError, match="declared size"):
            upload.commit()
        assert not upload.destination.exists()
    with store.begin_upload("", "large", max_bytes=4) as upload:
        upload.write(b"four")
        with pytest.raises(DatastoreError, match="may not exceed"):
            upload.write(b"!")
        with pytest.raises(DatastoreError, match="closed"):
            upload.commit()


def test_concurrent_reservations_enforce_quota(store):
    fill(store, GIB - 8)
    with store.begin_upload("", "one", expected_bytes=6) as first:
        with pytest.raises(DatastoreError, match="quota"):
            store.begin_upload("", "two", expected_bytes=4)
        first.abort()
        with store.begin_upload("", "two", expected_bytes=4) as second:
            second.write(b"four")
            second.commit()


def test_shrinking_overwrite_does_not_lend_capacity_before_commit(store):
    fill(store, GIB - 8)
    (store.root / "old").write_bytes(b"12345678")
    with store.begin_upload("", "old", overwrite=True, expected_bytes=1) as replacement:
        replacement.write(b"a")
        with pytest.raises(DatastoreError, match="quota"):
            store.begin_upload("", "other", expected_bytes=1)
        replacement.abort()
    assert (store.root / "old").read_bytes() == b"12345678"
    with store.begin_upload("", "old", overwrite=True, expected_bytes=1) as replacement:
        replacement.write(b"a")
        replacement.commit()
    store.save_upload("", "other", io.BytesIO(b"new"))


def test_competing_destination_and_external_creation_do_not_overwrite(store):
    with store.begin_upload("", "target") as upload:
        with pytest.raises(DatastoreError, match="already writing"):
            store.begin_upload("", "target", overwrite=True)
        upload.write(b"new")
        upload.destination.write_bytes(b"external")
        with pytest.raises(DatastoreError, match="already exists"):
            upload.commit()
        assert upload.destination.read_bytes() == b"external"


def test_overwrite_rejects_destination_changed_during_transfer(store):
    (store.root / "target").write_bytes(b"original")
    with store.begin_upload("", "target", overwrite=True) as upload:
        upload.write(b"new")
        upload.destination.write_bytes(b"external")
        with pytest.raises(DatastoreError, match="changed"):
            upload.commit()
        assert upload.destination.read_bytes() == b"external"


def test_parent_rename_aborts_without_publishing_elsewhere(store):
    folder = store.create_folder("", "folder")
    with store.begin_upload("folder", "target") as upload:
        upload.write(b"new")
        folder.rename(store.root / "moved")
        folder.mkdir()
        with pytest.raises(DatastoreError, match="changed"):
            upload.commit()
    assert not (folder / "target").exists()
    assert not (store.root / "moved" / "target").exists()


def test_commit_rechecks_external_quota_growth(store):
    with store.begin_upload("", "target") as upload:
        upload.write(b"new")
        fill(store, GIB)
        with pytest.raises(DatastoreError, match="quota"):
            upload.commit()
        assert not upload.destination.exists()


def test_disk_reserve_subtracts_only_unwritten_bytes(store):
    with store.begin_upload("", "target", expected_bytes=2 * BUFFER_BYTES) as upload:
        # Exactly enough free bytes for the remaining content. Already-written
        # bytes must not be subtracted again from the current free-space value.
        def disk_usage(_):
            return SimpleNamespace(free=2 * BUFFER_BYTES - upload.temporary.stat().st_size)
        with patch("twn_toolkit.uploads.shutil.disk_usage", side_effect=disk_usage):
            upload.write(b"x" * BUFFER_BYTES)
            upload.write(b"x" * BUFFER_BYTES)
            upload.commit()
        assert upload.destination.stat().st_size == 2 * BUFFER_BYTES


def test_disk_reservations_span_protocol_runtime_roots(store):
    runtime = LocalDatastore(str(store.instance), "ftp_runtime")
    with patch("twn_toolkit.uploads.shutil.disk_usage", return_value=SimpleNamespace(free=8)):
        with store.begin_upload("", "one", expected_bytes=6):
            with pytest.raises(DatastoreError, match="free-disk"):
                runtime.begin_upload("", "two", expected_bytes=4)


def test_external_disk_pressure_aborts_buffered_upload(store):
    with store.begin_upload("", "target") as upload:
        upload.write(b"new")
        with patch("twn_toolkit.uploads.shutil.disk_usage", return_value=SimpleNamespace(free=0)):
            with pytest.raises(DatastoreError, match="free-disk"):
                upload.commit()
        assert not upload.destination.exists()


def test_tiny_packets_do_not_rescan_datastore(store):
    from twn_toolkit.operational import directory_bytes
    with patch("twn_toolkit.uploads.directory_bytes", wraps=directory_bytes) as scan:
        with store.begin_upload("", "target") as upload:
            for _ in range(4096):
                upload.write(b"x" * 512)
            upload.commit()
        assert scan.call_count <= 5
        assert upload.destination.stat().st_size == 2 * 1024**2


def test_separate_process_reservation_and_crash_recovery(store):
    fill(store, GIB - 8)
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(target=_hold_upload, args=(str(store.instance), child))
    process.start()
    child.close()
    try:
        assert parent.poll(10), "upload child did not become ready"
        assert parent.recv() == "ready"
        with pytest.raises(DatastoreError, match="quota"):
            store.begin_upload("", "parent", expected_bytes=4)
        process.terminate()
        process.join(10)
        assert not process.is_alive()
        with store.begin_upload("", "parent", expected_bytes=4) as upload:
            upload.write(b"four")
            upload.commit()
        assert not (store.root / "child").exists()
        assert not list((store.instance / ".upload-reservations").glob("*/data"))
    finally:
        if process.is_alive():
            process.terminate()
            process.join(10)
        parent.close()


def test_unreadable_live_reservation_fails_closed(store):
    with store.begin_upload("", "one") as upload:
        (upload.directory / "record.json").write_text("broken")
        with pytest.raises(DatastoreError, match="registry"):
            store.begin_upload("", "two")


def test_failed_fsync_does_not_publish(store):
    with store.begin_upload("", "target") as upload:
        upload.write(b"new")
        original = os.fsync
        def fsync(descriptor):
            if descriptor == upload.fileno():
                raise OSError("injected fsync failure")
            return original(descriptor)
        with patch("twn_toolkit.uploads.os.fsync", side_effect=fsync):
            with pytest.raises(OSError, match="injected"):
                upload.commit()
        assert not upload.destination.exists()


def test_no_overwrite_publication_is_atomic_against_last_instant_collision(store):
    with store.begin_upload("", "target") as upload:
        upload.write(b"upload")
        original_link = os.link
        def collide(*args, **kwargs):
            upload.destination.write_bytes(b"external")
            return original_link(*args, **kwargs)
        with patch("twn_toolkit.uploads.os.link", side_effect=collide):
            with pytest.raises(DatastoreError, match="already exists"):
                upload.commit()
        assert upload.destination.read_bytes() == b"external"


def test_failed_buffer_write_discards_file_and_reservation(store):
    with store.begin_upload("", "target") as upload:
        with patch.object(upload._file, "write", side_effect=OSError("injected write failure")):
            with pytest.raises(OSError, match="injected"):
                upload.write(b"x" * BUFFER_BYTES)
        assert upload.closed
        assert not upload.directory.exists()
        assert not upload.destination.exists()
    store.save_upload("", "target", io.BytesIO(b"retry"))


def test_cleanup_error_after_publication_does_not_report_failed_commit(store):
    with store.begin_upload("", "target") as upload:
        upload.write(b"complete")
        original_close = upload._file.close
        def close():
            original_close()
            raise OSError("injected close failure")
        with patch.object(upload._file, "close", side_effect=close):
            assert upload.commit() == (upload.destination, 8)
        assert upload.destination.read_bytes() == b"complete"
        assert not upload.directory.exists()
