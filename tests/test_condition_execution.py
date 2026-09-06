import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from twn_toolkit import automation_execution as execution
from twn_toolkit.automation import AutomationEngine
from twn_toolkit.automation_registry import AUTOMATION_REGISTRY
from twn_toolkit.network_tools import scan_tcp_checks
from twn_toolkit.operational import OperationalSettingsStore


def until(predicate):
    end = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < end
        time.sleep(.01)


def test_mixed_condition_batches_share_workers_and_leave_actions_available(tmp_path, monkeypatch):
    OperationalSettingsStore(str(tmp_path)).save({'automation_condition_workers': 2, 'automation_action_workers': 1})
    release = threading.Event()
    lock = threading.Lock()
    active = peak = 0
    def inspect(result):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            assert release.wait(5)
            return result
        finally:
            with lock:
                active -= 1
    monkeypatch.setattr('twn_toolkit.network_tools._scan_tcp_port',
                        lambda target, port, *args: inspect({'host': target['host'], 'port': port, 'status': 'open'}))
    monkeypatch.setattr('twn_toolkit.network_tools._dns_lookup',
                        lambda host, server, *args: inspect({'host': host['host'], 'status': 'success', 'answers': ['192.0.2.1']}))
    monkeypatch.setattr('twn_toolkit.automation_types.condition_types.monitoring._inspect_certificate_target',
                        lambda target, timeout: inspect({'target': target, 'result': None, 'error': 'fixture certificate failure'}))
    monkeypatch.setattr('twn_toolkit.network_tools._ping_host',
                        lambda host, timeout: inspect({'host': host, 'reachable': True, 'latency_ms': 1}))
    capability = lambda: {'accelerated': False, 'engine': 'ping'}
    monkeypatch.setattr('twn_toolkit.network_tools.ping_engine_capability', capability)
    monkeypatch.setattr('twn_toolkit.automation_types.condition_types.network_triggers.ping_engine_capability', capability)
    definitions = [
        ('tcp.reachability', {'targets': 'host.test | 1-20'}),
        ('dns.lookup', {'hosts': '\n'.join(f'host{i}.test' for i in range(20)), 'servers': '192.0.2.53'}),
        ('certificate.health', {'targets': '\n'.join(f'host{i}.test | 443' for i in range(20))}),
        ('ping.multi', {'targets': '\n'.join(f'host{i}.test' for i in range(20)), 'probe_count': 1}),
    ]
    def run(definition):
        kind, config = definition
        engine = AutomationEngine(SimpleNamespace(instance_path=tmp_path))
        return engine.test_condition({'condition': {'type': kind, 'config': config}})
    with ThreadPoolExecutor(max_workers=4) as callers:
        futures = [callers.submit(run, definition) for definition in definitions]
        try:
            until(lambda: active == 2)
            until(lambda: sum(e['users'] for e in execution._pools.values()) == 4)
            assert execution.execute_stage_actions(tmp_path, lambda x: x, [1]) == [1]
            entry = next(iter(execution._pools.values()))
            assert entry['executor']._work_queue.qsize() <= 8
        finally:
            release.set()
        results = [future.result(timeout=5) for future in futures]
    assert peak == 2
    assert not results[0].met and results[2].met
    assert [check['port'] for check in results[0].evidence['checks']] == list(range(1, 21))
    assert not execution._pools


def test_context_restored_on_error_and_manual_scan_is_independent(tmp_path, monkeypatch):
    OperationalSettingsStore(str(tmp_path)).save({'automation_condition_workers': 1})
    with pytest.raises(KeyError):
        with execution.condition_worker_scope(tmp_path):
            AUTOMATION_REGISTRY.evaluate_condition('unknown', {})
    assert execution._condition_instance.get() is None
    monkeypatch.setattr('twn_toolkit.network_tools._scan_tcp_port', lambda host, port, *args: port)
    assert scan_tcp_checks([({'host': 'host'}, 1)], max_workers=1) == [1]
    assert not execution._pools


def test_manual_condition_test_uses_app_instance(tmp_path):
    from flask import Flask
    app = Flask(__name__, instance_path=str(tmp_path))
    with app.app_context(), execution.condition_worker_scope():
        assert execution._condition_instance.get() == str(tmp_path)
    assert execution._condition_instance.get() is None


def test_condition_limit_preserves_per_batch_window_and_reloads_after_drain(tmp_path):
    store = OperationalSettingsStore(str(tmp_path))
    store.save({'automation_condition_workers': 3})
    active = peak = 0
    def check(value):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        time.sleep(.01)
        active -= 1
        return value
    with execution.condition_worker_scope(tmp_path):
        assert execution.condition_worker_map(check, list(range(10)), 1) == list(range(10))
    assert peak == 1
    with execution._borrow(tmp_path, 'condition') as (pool, count):
        assert count == 3
        store.save({'automation_condition_workers': 1})
        with execution._borrow(tmp_path, 'condition') as (same, old_count):
            assert same is pool and old_count == 3
    with execution._borrow(tmp_path, 'condition') as (_, count):
        assert count == 1
    assert not execution._pools


def test_condition_settings_validation(tmp_path):
    store = OperationalSettingsStore(str(tmp_path))
    assert store.get()['automation_condition_workers'] == 20
    store.save({'automation_condition_workers': 3})
    assert store.save({'automation_action_workers': 2})['automation_condition_workers'] == 3
    for invalid in [0, 201, True, '1.5']:
        with pytest.raises(ValueError):
            store.save({'automation_condition_workers': invalid})
