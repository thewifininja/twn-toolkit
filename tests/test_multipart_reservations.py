import io
import json
import multiprocessing
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from flask import request
from werkzeug.test import EnvironBuilder

from twn_toolkit import create_app
from twn_toolkit.datastore import DatastoreError, LocalDatastore
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.uploads import MultipartSpool


def pending(instance):
    return list((instance / ".upload-reservations").glob("*/data"))


def test_parser_uses_reserved_private_staging_and_promotes_without_copy(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    inode = []
    original = LocalDatastore.save_upload
    def save(store, folder, name, stream, **kwargs):
        assert isinstance(stream, MultipartSpool)
        inode.append(stream.upload.temporary.stat().st_ino)
        assert stream.upload.temporary.parent.parent == tmp_path / ".upload-reservations"
        with patch.object(stream, "read", side_effect=AssertionError("spool must not be copied")):
            return original(store, folder, name, stream, **kwargs)
    with patch.object(LocalDatastore, "save_upload", save):
        response = app.test_client().post("/local/datastore/uploads", data={"files":(io.BytesIO(b"x" * 700000), "file")})
    assert response.status_code == 302
    target = tmp_path / "datastore" / "file"
    assert target.stat().st_ino == inode[0]
    assert target.read_bytes() == b"x" * 700000
    assert not pending(tmp_path)


def test_parser_checks_physical_space_before_store_save(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    with patch("twn_toolkit.uploads.shutil.disk_usage", return_value=SimpleNamespace(free=0)), patch.object(LocalDatastore, "save_upload") as save:
        response = app.test_client().post("/local/datastore/uploads", data={"files":(io.BytesIO(b"x"), "file")})
    assert response.status_code == 507
    save.assert_not_called()
    assert not pending(tmp_path)


def test_file_count_and_size_failures_release_earlier_spools(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    OperationalSettingsStore(str(tmp_path)).save({"max_multipart_files":1, "max_upload_mib":1})
    client = app.test_client()
    response = client.post("/local/datastore/uploads", data={"files":[(io.BytesIO(b"first"),"one"),(io.BytesIO(b"second"),"two")]})
    assert response.status_code == 413
    assert not pending(tmp_path)
    response = client.post("/local/datastore/uploads", data={"files":(io.BytesIO(b"x" * (1024**2 + 1)),"large")})
    assert response.status_code == 413
    assert not pending(tmp_path)


def test_malformed_body_and_handler_failure_release_staging(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    body = b'--boundary\r\nContent-Disposition: form-data; name="files"; filename="bad"\r\n\r\n' + b"x" * 700000
    response = app.test_client().post("/local/datastore/uploads", data=body, content_type="multipart/form-data; boundary=boundary")
    assert response.status_code in {302,400}
    assert not pending(tmp_path)
    with patch.object(LocalDatastore, "save_upload", side_effect=RuntimeError("injected")):
        with pytest.raises(RuntimeError):
            app.test_client().post("/local/datastore/uploads", data={"files":(io.BytesIO(b"x"),"file")})
    assert not pending(tmp_path)


def test_other_multipart_endpoints_use_accounted_streams(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    @app.post("/inspect-spool")
    def inspect():
        stream = request.files["file"].stream
        assert isinstance(stream, MultipartSpool)
        return stream.read()
    response = app.test_client().post("/inspect-spool", data={"file":(io.BytesIO(b"private"),"file")})
    assert response.data == b"private"
    assert not pending(tmp_path)


def test_promotion_rechecks_quota_and_preserves_original(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({"minimum_free_gib":0,"datastore_quota_gib":1})
    store = LocalDatastore(str(tmp_path))
    with (store.root / "original").open("wb") as file:
        file.truncate(1024**3)
    spool = MultipartSpool(store,1024)
    try:
        spool.write(b"new"); spool.seek(0)
        with pytest.raises(DatastoreError,match="quota"):
            store.save_upload("", "new", spool)
        assert (store.root / "original").stat().st_size == 1024**3
    finally:
        spool.close()
    spool = MultipartSpool(store,1024)
    try:
        spool.write(b"replacement"); spool.seek(0)
        store.save_upload("", "original", spool, overwrite=True)
        assert (store.root / "original").read_bytes() == b"replacement"
    finally:
        spool.close()
    assert not pending(tmp_path)


def _abandon(instance, connection):
    spool = MultipartSpool(LocalDatastore(instance), 1024)
    spool.write(b"abandoned"); spool.seek(0)
    connection.send("ready"); connection.recv()


def test_dead_parser_process_spools_are_reclaimed(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({"minimum_free_gib":0})
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    worker = context.Process(target=_abandon, args=(str(tmp_path),child)); worker.start(); child.close()
    try:
        assert parent.poll(10) and parent.recv()=="ready"
        worker.terminate(); worker.join(5)
        store=LocalDatastore(str(tmp_path))
        with store.begin_upload("", "recovered"):
            assert len(pending(tmp_path)) == 1
        assert not pending(tmp_path)
    finally:
        if worker.is_alive(): worker.terminate(); worker.join(5)
        parent.close()


def test_spool_capacity_competes_with_protocol_uploads(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({"minimum_free_gib":0})
    store=LocalDatastore(str(tmp_path))
    with store.begin_upload("", "network", expected_bytes=8):
        with patch("twn_toolkit.uploads.shutil.disk_usage", return_value=SimpleNamespace(free=10)):
            spool=MultipartSpool(store, 1024)
            try:
                with pytest.raises(DatastoreError,match="free-disk"):
                    spool.write(b"four")
            finally: spool.close()


def test_unpromoted_spool_cannot_publish_and_sealed_spool_cannot_be_rewritten(tmp_path):
    store=LocalDatastore(str(tmp_path)); spool=MultipartSpool(store, 1024)
    try:
        spool.write(b"data"); spool.seek(0)
        with pytest.raises(ValueError, match="read-only"): spool.write(b"overwrite")
        with pytest.raises(DatastoreError, match="destination"): spool.upload.commit()
    finally: spool.close()
    assert store.list()["entries"]==[]
    assert not pending(tmp_path)
