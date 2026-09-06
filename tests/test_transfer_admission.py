import multiprocessing
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.transfer_admission import _try_acquire, transfer_slot
from twn_toolkit.transfer_deadlines import TransferDeadline, TransferPolicy
from twn_toolkit.sftp_tools import fetch_ssh_files


def _compete(instance, barrier, active, peak, lock):
    barrier.wait(15)
    with TransferDeadline(10) as deadline, transfer_slot(instance, 'Same.Host.', deadline):
        with lock:
            active.value += 1
            peak.value = max(peak.value, active.value)
        time.sleep(.15)
        with lock:
            active.value -= 1


@pytest.mark.parametrize('total,per_host,expected', [(2, 4, 2), (4, 1, 1)])
def test_processes_share_total_and_host_ceiling(tmp_path, total, per_host, expected):
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': total, 'transfer_host_connections': per_host})
    ctx = multiprocessing.get_context('spawn')
    barrier = ctx.Barrier(7)
    active, peak = ctx.Value('i', 0), ctx.Value('i', 0)
    lock = ctx.Lock()
    workers = [ctx.Process(target=_compete, args=(str(tmp_path), barrier, active, peak, lock)) for _ in range(6)]
    try:
        for worker in workers:
            worker.start()
        barrier.wait(15)
        for worker in workers:
            worker.join(15)
            assert worker.exitcode == 0
        assert peak.value == expected
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(5)


def _hold(instance, pipe):
    with TransferDeadline(30) as deadline, transfer_slot(instance, 'host', deadline):
        pipe.send('held')
        pipe.recv()


def test_process_death_releases_slot(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': 1})
    ctx = multiprocessing.get_context('spawn')
    parent, child = ctx.Pipe()
    worker = ctx.Process(target=_hold, args=(str(tmp_path), child))
    worker.start()
    child.close()
    try:
        assert parent.poll(10) and parent.recv() == 'held'
        assert _try_acquire(tmp_path, 'different') is None
        worker.terminate()
        worker.join(5)
        descriptor = _try_acquire(tmp_path, 'different')
        assert descriptor is not None
        os.close(descriptor)
    finally:
        if worker.is_alive():
            worker.terminate(); worker.join(5)
        parent.close()


def test_lowered_limit_counts_existing_slots_and_recovers(tmp_path):
    store = OperationalSettingsStore(str(tmp_path))
    store.save({'transfer_connections': 3})
    held = [_try_acquire(tmp_path, str(i)) for i in range(3)]
    try:
        store.save({'transfer_connections': 1})
        assert _try_acquire(tmp_path, 'new') is None
        os.close(held.pop())
        os.close(held.pop())
        assert _try_acquire(tmp_path, 'new') is None
        os.close(held.pop())
        descriptor = _try_acquire(tmp_path, 'new')
        assert descriptor is not None
        os.close(descriptor)
    finally:
        for descriptor in held:
            os.close(descriptor)


def test_host_normalization_and_other_host_progress(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': 2, 'transfer_host_connections': 1})
    held = _try_acquire(tmp_path, 'Example.Test.')
    try:
        assert _try_acquire(tmp_path, 'example.test') is None
        other = _try_acquire(tmp_path, 'other.test')
        assert other is not None
        os.close(other)
    finally:
        os.close(held)


@pytest.mark.parametrize('protocol', ['sftp', 'scp', 'ftp'])
def test_capacity_timeout_opens_no_connection(tmp_path, monkeypatch, protocol):
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': 1})
    held = _try_acquire(tmp_path, 'held')
    def forbidden(**kwargs):
        pytest.fail('connection started without capacity')
    monkeypatch.setattr('twn_toolkit.sftp_tools._fetch_' + protocol + '_host', forbidden)
    try:
        results = fetch_ssh_files(hosts=[{'host': 'waiting'}], remote_paths=['/one', '/two'],
                                  username='user', password='secret', port=22, allow_unknown_hosts=True,
                                  output_dir=tmp_path / 'output', protocol=protocol,
                                  policy=TransferPolicy(deadline_seconds=.1), instance_path=str(tmp_path))
        assert len(results) == 2
        assert all(row['status'] == 'error' and 'no connection was started' in row['error'] for row in results)
    finally:
        os.close(held)


def test_simultaneous_runs_share_one_connection_and_release_after_failure(tmp_path, monkeypatch):
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': 1})
    active = peak = 0
    lock = threading.Lock()
    def fetch(**kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(.05)
        with lock:
            active -= 1
        raise OSError('injected failure')
    monkeypatch.setattr('twn_toolkit.sftp_tools._fetch_sftp_host', fetch)
    def run(i):
        return fetch_ssh_files(hosts=[{'host': str(i)}], remote_paths=['/one'], username='user', password='secret',
                               port=22, allow_unknown_hosts=True, output_dir=tmp_path / str(i),
                               instance_path=str(tmp_path))
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(run, range(4)))
    assert peak == 1
    assert all(row[0]['status'] == 'error' for row in rows)
    with TransferDeadline(1) as deadline, transfer_slot(tmp_path, 'recovered', deadline):
        pass


@pytest.mark.parametrize('key', ['transfer_connections', 'transfer_host_connections'])
def test_admission_settings_validate_and_preserve_custom_values(tmp_path, key):
    store = OperationalSettingsStore(str(tmp_path))
    store.save({key: 2})
    assert store.save({'transfer_workers': 3})[key] == 2
    for invalid in [0, True, '1.5', 1000]:
        with pytest.raises(ValueError):
            store.save({key: invalid})
