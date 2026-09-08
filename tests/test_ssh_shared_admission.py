import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

from twn_toolkit import network_tools as network
from twn_toolkit.operational import OperationalSettingsStore
from twn_toolkit.transfer_admission import _try_acquire


def plans(hosts):
    return [{'host': host, 'label': '', 'command_specs': [{'command': 'show status', 'timeout': 1}]} for host in hosts]


def test_concurrent_runs_share_ten_host_threads(tmp_path, monkeypatch):
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': 32, 'transfer_host_connections': 32})
    lock = threading.Lock(); release = threading.Event(); ten = threading.Event()
    active = peak = 0
    def connected(*args):
        nonlocal active, peak
        with lock:
            active += 1; peak = max(peak, active)
            if active >= 10:
                ten.set()
        try:
            assert release.wait(5)
            return {'host': args[0], 'status': 'success'}
        finally:
            with lock:
                active -= 1
    monkeypatch.setattr(network, '_ssh_host_connection', connected)
    with ThreadPoolExecutor(max_workers=3) as callers:
        futures = [callers.submit(network.run_ssh_host_plans, plans([f'host-{i}-{n}.test' for n in range(8)]),
                                 'user', 'password', instance_path=str(tmp_path)) for i in range(3)]
        try:
            assert ten.wait(5)
            time.sleep(.1)
            assert peak == 10
        finally:
            release.set()
        assert all(len(future.result()) == 8 for future in futures)
    assert active == 0


def test_shared_pool_also_obeys_global_and_normalized_target_limits(tmp_path, monkeypatch):
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': 3, 'transfer_host_connections': 2})
    lock = threading.Lock(); active = {}; peak = {}; total = total_peak = 0
    def connected(*args):
        nonlocal total, total_peak
        host = args[0].lower().rstrip('.')
        with lock:
            active[host] = active.get(host, 0) + 1
            peak[host] = max(peak.get(host, 0), active[host])
            total += 1; total_peak = max(total_peak, total)
            assert active[host] <= 2 and total <= 3
        try:
            time.sleep(.04)
            return {'host': args[0], 'status': 'success'}
        finally:
            with lock:
                active[host] -= 1; total -= 1
    monkeypatch.setattr(network, '_ssh_host_connection', connected)
    with ThreadPoolExecutor(max_workers=3) as callers:
        futures = [callers.submit(network.run_ssh_host_plans, plans(['Same.Host.', 'same.host', 'other.host'] * 3),
                                 'user', 'password', instance_path=str(tmp_path)) for _ in range(3)]
        assert all(all(row['status'] == 'success' for row in future.result()) for future in futures)
    assert total_peak == 3 and peak['same.host'] == 2 and total == 0


def test_transfer_lease_blocks_ssh_before_connection_and_wait_is_bounded(tmp_path, monkeypatch):
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': 2, 'transfer_host_connections': 1})
    lease = _try_acquire(tmp_path, 'Same.Host.')
    assert lease is not None
    monkeypatch.setattr(network, 'SSH_ADMISSION_WAIT_SECONDS', .08)
    monkeypatch.setattr(network, 'open_ssh_client', lambda **kwargs: pytest.fail('SSH connected while target capacity was occupied'))
    try:
        result = network._ssh_host('same.host', 'user', 'password', [{'command': 'show', 'timeout': 1}],
                                   22, False, False, 0, instance_path=str(tmp_path))
        assert result['status'] == 'error' and 'capacity wait' in result['error']
        other = _try_acquire(tmp_path, 'other.host')
        assert other is not None
        os.close(other)
    finally:
        os.close(lease)


@pytest.mark.parametrize('failure', [False, True])
def test_slot_is_held_until_client_close_and_released_on_error(tmp_path, monkeypatch, failure):
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': 1, 'transfer_host_connections': 1})
    client = MagicMock(); closed = []
    def close():
        assert _try_acquire(tmp_path, 'other.host') is None
        closed.append(True)
    client.close.side_effect = close
    monkeypatch.setattr(network, 'open_ssh_client', lambda **kwargs: client)
    monkeypatch.setattr(network, '_read_channel', lambda *args, **kwargs: 'fixture # ')
    if failure:
        client.invoke_shell.side_effect = OSError('fixture transport failure')
    else:
        monkeypatch.setattr(network, '_read_ssh_command', lambda *args, **kwargs: ('done', True))
    result = network._ssh_host('host.test', 'user', 'password', [{'command': 'show', 'timeout': 1}],
                               22, False, False, 0, instance_path=str(tmp_path))
    assert result['status'] == ('error' if failure else 'success')
    assert closed
    lease = _try_acquire(tmp_path, 'other.host')
    assert lease is not None
    os.close(lease)


def test_storage_failure_fails_closed_before_ssh(tmp_path, monkeypatch):
    def fail(*args):
        raise OSError('fixture storage failure')
    monkeypatch.setattr('twn_toolkit.transfer_admission._try_acquire', fail)
    monkeypatch.setattr(network, 'open_ssh_client', lambda **kwargs: pytest.fail('Connected after admission failure'))
    result = network._ssh_host('host.test', 'user', 'password', [{'command': 'show', 'timeout': 1}],
                               22, False, False, 0, instance_path=str(tmp_path))
    assert result['status'] == 'error' and 'capacity' in result['error']


def test_automation_passes_its_runtime_instance_to_ssh(monkeypatch, tmp_path):
    from twn_toolkit.automation_types.actions import _execute_ssh
    from twn_toolkit.automation_types.models import ConditionResult
    captured = []
    monkeypatch.setattr('twn_toolkit.automation_types.actions.run_ssh_host_plans',
                        lambda *args, **kwargs: captured.append(kwargs) or [{'status': 'success'}])
    _execute_ssh({'hosts': 'host.test', 'username': 'user', 'password': 'password', 'commands': 'show status',
                  'port': 22, 'command_timeout': 30, '_instance_path': str(tmp_path)},
                 ConditionResult(True, 'success', 'fixture', {}))
    assert captured[0]['instance_path'] == str(tmp_path)


def _ssh_process_compete(instance, barrier, active, peak, lock):
    from twn_toolkit import network_tools as child_network
    def connected(*args):
        with lock:
            active.value += 1
            peak.value = max(peak.value, active.value)
        time.sleep(.15)
        with lock:
            active.value -= 1
        return {'host': args[0], 'status': 'success'}
    child_network._ssh_host_connection = connected
    barrier.wait(15)
    result = child_network._ssh_host('same.host', 'user', 'password', [{'command': 'show', 'timeout': 1}],
                                     22, False, False, 0, instance_path=instance)
    assert result['status'] == 'success'


def test_ssh_and_transfers_share_target_budget_across_processes(tmp_path):
    import multiprocessing
    from tests.test_transfer_admission import _compete
    OperationalSettingsStore(str(tmp_path)).save({'transfer_connections': 3, 'transfer_host_connections': 1})
    context = multiprocessing.get_context('spawn')
    barrier = context.Barrier(4); active = context.Value('i', 0); peak = context.Value('i', 0); lock = context.Lock()
    children = [context.Process(target=target, args=(str(tmp_path), barrier, active, peak, lock))
                for target in (_compete, _ssh_process_compete, _ssh_process_compete)]
    try:
        for child in children:
            child.start()
        barrier.wait(15)
        for child in children:
            child.join(15)
            assert child.exitcode == 0
        assert peak.value == 1 and active.value == 0
    finally:
        for child in children:
            if child.is_alive():
                child.terminate();child.join(5)


def test_waiting_ssh_admission_observes_increased_live_limit(tmp_path, monkeypatch):
    settings = OperationalSettingsStore(str(tmp_path))
    settings.save({'transfer_connections': 2, 'transfer_host_connections': 1})
    lease = _try_acquire(tmp_path, 'host.test'); denied = threading.Event()
    original = _try_acquire
    def acquire(*args):
        value = original(*args)
        if value is None:
            denied.set()
        return value
    monkeypatch.setattr('twn_toolkit.transfer_admission._try_acquire', acquire)
    monkeypatch.setattr(network, '_ssh_host_connection', lambda *args: {'status': 'success'})
    try:
        with ThreadPoolExecutor(max_workers=1) as caller:
            future = caller.submit(network._ssh_host, 'host.test', 'user', 'password',
                                   [{'command': 'show', 'timeout': 1}], 22, False, False, 0,
                                   instance_path=str(tmp_path))
            assert denied.wait(5)
            settings.save({'transfer_connections': 2, 'transfer_host_connections': 2})
            assert future.result(timeout=5)['status'] == 'success'
    finally:
        os.close(lease)


def test_failed_shared_run_drains_running_tasks_before_releasing_borrow(tmp_path, monkeypatch):
    from twn_toolkit.automation_execution import ssh_worker_pool
    class FixtureFailure(BaseException):
        pass
    entered = threading.Event(); release = threading.Event()
    def connected(*args):
        if args[0] == 'failing.test':
            assert entered.wait(5)
            raise FixtureFailure()
        entered.set()
        assert release.wait(5)
        return {'status': 'success'}
    monkeypatch.setattr(network, '_ssh_host_connection', connected)
    # Keep another borrower alive so shutdown cannot accidentally supply the
    # draining guarantee that the failed caller itself owes its shared pool.
    with ssh_worker_pool(str(tmp_path), 2), ThreadPoolExecutor(max_workers=1) as caller:
        future = caller.submit(network.run_ssh_host_plans, plans(['failing.test', 'running.test']),
                               'user', 'password', instance_path=str(tmp_path))
        try:
            assert entered.wait(5)
            time.sleep(.1)
            assert not future.done()
        finally:
            release.set()
        with pytest.raises(FixtureFailure):
            future.result(timeout=5)


def test_submission_failure_cancels_pending_work_and_drains_started_work(tmp_path, monkeypatch):
    from twn_toolkit.automation_execution import ssh_worker_pool
    entered = threading.Event(); release = threading.Event(); executed = []
    def connected(*args):
        executed.append(args[0]); entered.set()
        assert release.wait(5)
        return {'status': 'success'}
    monkeypatch.setattr(network, '_ssh_host_connection', connected)
    with ssh_worker_pool(str(tmp_path), 1) as pool, ThreadPoolExecutor(max_workers=1) as caller:
        original = pool.submit; submitted = 0
        def submit(*args, **kwargs):
            nonlocal submitted
            submitted += 1
            if submitted == 3:
                raise RuntimeError('fixture submit failure')
            future = original(*args, **kwargs)
            if submitted == 1:
                assert entered.wait(5)
            return future
        monkeypatch.setattr(pool, 'submit', submit)
        future = caller.submit(network.run_ssh_host_plans, plans(['first.test', 'pending.test', 'unsent.test']),
                               'user', 'password', instance_path=str(tmp_path))
        try:
            assert entered.wait(5)
            time.sleep(.1)
            assert not future.done()
        finally:
            release.set()
        with pytest.raises(RuntimeError, match='submit failure'):
            future.result(timeout=5)
    assert executed == ['first.test']
