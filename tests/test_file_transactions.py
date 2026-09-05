from __future__ import annotations

import multiprocessing
import os

import pytest

from twn_toolkit.auth import AuthStore
from twn_toolkit.file_transactions import file_transaction
from twn_toolkit.profiles import PingProfileStore


def _paused_update(instance, kind, ready, release):
    if kind == "auth":
        store = AuthStore(instance)
        user = store.get_user("admin")
        operation = lambda: store.set_user_theme(user["id"], "light")
    else:
        store = PingProfileStore(instance)
        operation = lambda: store.upsert({"name": "first", "targets": "192.0.2.1"})
    write = store._write

    def paused_write(data):
        ready.set()
        if not release.wait(15):
            raise TimeoutError("Test did not release paused writer.")
        write(data)

    store._write = paused_write
    operation()


def _second_update(instance, kind, started, done):
    started.set()
    if kind == "auth":
        store = AuthStore(instance)
        store.update_password(store.get_user("admin")["id"], "new password value")
    else:
        PingProfileStore(instance).upsert({"name": "second", "targets": "192.0.2.2"})
    done.set()


@pytest.mark.parametrize("kind", ["auth", "profiles"])
def test_concurrent_store_updates_preserve_password_revocation_and_profiles(tmp_path, kind):
    if kind == "auth":
        AuthStore(str(tmp_path)).create_user("admin", "old password value")
    context = multiprocessing.get_context("spawn")
    ready, release, started, done = (context.Event() for _ in range(4))
    first = context.Process(target=_paused_update, args=(str(tmp_path), kind, ready, release))
    second = context.Process(target=_second_update, args=(str(tmp_path), kind, started, done))
    first.start()
    try:
        assert ready.wait(15), "First writer did not reach publication."
        second.start()
        assert started.wait(15), "Second writer did not start."
        # Give the contender time to attempt the update while the first holds
        # an old snapshot. Correct writers must wait for that snapshot to commit.
        blocked = not done.wait(0.5)
        release.set()
        first.join(15)
        second.join(15)
        assert first.exitcode == second.exitcode == 0
        assert blocked, "Another writer committed during an unfinished transaction."
        if kind == "auth":
            store = AuthStore(str(tmp_path))
            assert store.authenticate("admin", "old password value") is None
            user = store.authenticate("admin", "new password value")
            assert user is not None
            assert user["session_version"] == 2
            assert user["theme"] == "light"
        else:
            assert [p["name"] for p in PingProfileStore(str(tmp_path)).all()] == ["first", "second"]
    finally:
        release.set()
        for process in (first, second):
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join(15)


def _hold_file(path, ready):
    with file_transaction(path):
        ready.set()
        # Parent deliberately kills this process to test OS lock cleanup.
        multiprocessing.Event().wait(30)


def _acquire_file(path, done):
    with file_transaction(path):
        done.set()


def test_lock_is_reentrant_and_preserves_a_stable_private_sidecar(tmp_path):
    path = tmp_path / "state.json"
    with file_transaction(path):
        lock = tmp_path / ".state.json.lock"
        inode = lock.stat().st_ino
        assert lock.stat().st_mode & 0o777 == 0o600
        with file_transaction(tmp_path / "." / "state.json"):
            path.write_text("{}")
            replacement = tmp_path / "replacement"
            replacement.write_text('{"new": true}')
            os.replace(replacement, path)
    with pytest.raises(ValueError), file_transaction(path):
        raise ValueError("aborted edit")
    with file_transaction(path):
        assert lock.stat().st_ino == inode


def test_unrelated_files_do_not_block_and_process_death_releases_lock(tmp_path):
    context = multiprocessing.get_context("spawn")
    ready, done = context.Event(), context.Event()
    path = str(tmp_path / "state.json")
    holder = context.Process(target=_hold_file, args=(path, ready))
    holder.start()
    waiter = context.Process(target=_acquire_file, args=(path, done))
    try:
        assert ready.wait(15)
        with file_transaction(tmp_path / "unrelated.json"):
            assert not done.is_set()
        waiter.start()
        holder.terminate()
        holder.join(15)
        assert done.wait(15)
        waiter.join(15)
        assert waiter.exitcode == 0
    finally:
        for process in (holder, waiter):
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join(15)


def _failed_access_import(instance, ready, release):
    from twn_toolkit.configuration_backup_stores import AccessProfilesBackupStore
    from twn_toolkit.profile_backup import import_backup_items

    class FailingStore:
        def all(self):
            return []

        def replace_all(self, records):
            if records:
                ready.set()
                if not release.wait(15):
                    raise TimeoutError("Test did not release import.")
                raise ValueError("Injected import failure")

    selected = [
        {"id": "access", "label": "Access", "supports_replace": True,
         "store": AccessProfilesBackupStore(AuthStore(instance))},
        {"id": "failure", "label": "Failure", "supports_replace": True,
         "store": FailingStore()},
    ]
    try:
        import_backup_items(
            {"access": [{"name": "Imported", "tool_ids": []}],
             "failure": [{"name": "Invalid"}]}, selected, "replace"
        )
    except ValueError as exc:
        assert "Injected import failure" in str(exc)
    else:
        raise AssertionError("Import should fail.")


def test_failed_import_cannot_roll_back_a_concurrent_password_change(tmp_path):
    auth = AuthStore(str(tmp_path))
    auth.create_user("admin", "old password value")
    original = auth.save_access_profile(name="Original", tool_ids=[])
    context = multiprocessing.get_context("spawn")
    ready, release, started, done = (context.Event() for _ in range(4))
    importer = context.Process(target=_failed_access_import, args=(str(tmp_path), ready, release))
    writer = context.Process(target=_second_update, args=(str(tmp_path), "auth", started, done))
    importer.start()
    try:
        assert ready.wait(15)
        writer.start()
        assert started.wait(15)
        blocked = not done.wait(0.5)
        release.set()
        importer.join(15)
        writer.join(15)
        assert importer.exitcode == writer.exitcode == 0
        assert blocked
        assert auth.access_profiles() == [original]
        assert auth.authenticate("admin", "old password value") is None
        assert auth.authenticate("admin", "new password value")["session_version"] == 2
    finally:
        release.set()
        for process in (importer, writer):
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join(15)


def _initial_setup(instance, username, start, results):
    from twn_toolkit.auth import load_or_create_secret_key

    if not start.wait(15):
        raise TimeoutError("Setup did not start.")
    secret = load_or_create_secret_key(instance)
    try:
        AuthStore(instance).create_initial_admin(username, "setup password value")
    except ValueError:
        created = False
    else:
        created = True
    results.put((secret, created))


def test_first_run_creates_one_admin_and_one_complete_session_key(tmp_path):
    context = multiprocessing.get_context("spawn")
    start, results = context.Event(), context.Queue()
    processes = [context.Process(target=_initial_setup, args=(str(tmp_path), f"admin{i}", start, results)) for i in range(4)]
    for process in processes:
        process.start()
    try:
        start.set()
        values = [results.get(timeout=15) for _ in processes]
        for process in processes:
            process.join(15)
            assert process.exitcode == 0
        assert sum(created for _secret, created in values) == 1
        assert len({secret for secret, _created in values}) == 1
        assert len(values[0][0]) >= 48
        assert len(AuthStore(str(tmp_path)).users()) == 1
        assert (tmp_path / "session_secret").stat().st_mode & 0o777 == 0o600
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(15)
        results.close()
        results.join_thread()


def test_threads_share_transactions_without_serializing_unrelated_files(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "counter"
    path.write_text("0")

    def increment():
        for _ in range(20):
            with file_transaction(path):
                value = int(path.read_text())
                path.write_text(str(value + 1))

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(increment) for _ in range(4)]
        for future in futures:
            future.result(timeout=15)
    assert path.read_text() == "80"
