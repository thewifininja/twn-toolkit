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


def test_snmp_polls_share_tcp_capacity_and_close_dispatchers(tmp_path, monkeypatch):
    import asyncio
    from twn_toolkit import snmp_tools

    OperationalSettingsStore(str(tmp_path)).save({'automation_condition_workers': 2})
    release = threading.Event()
    lock = threading.Lock()
    active = peak = closed = created = 0
    loops = []

    class Engine:
        def __init__(self):
            nonlocal active, peak, created
            with lock:
                created += 1
                active += 1
                peak = max(peak, active)
                loops.append(asyncio.get_running_loop())

        def close_dispatcher(self):
            nonlocal active, closed
            with lock:
                active -= 1
                closed += 1

    async def target(host):
        assert release.wait(5)
        return host

    async def get_entry(engine, auth, target, context, entry):
        await asyncio.sleep(.001)
        if target['name'] == 'host1':
            raise RuntimeError('fixture failure')
        return [{'oid': entry['oid'], 'label': entry['label'], 'value': '42'}], ''

    def tcp(host, port, *args):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            assert release.wait(5)
            time.sleep(.001)
            return port
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(snmp_tools, 'SnmpEngine', Engine)
    monkeypatch.setattr(snmp_tools, '_transport_target', target)
    monkeypatch.setattr(snmp_tools, '_authentication', lambda value: value)
    monkeypatch.setattr(snmp_tools, '_get_entry', get_entry)
    monkeypatch.setattr('twn_toolkit.network_tools._scan_tcp_port', tcp)
    hosts = [dict(name=f'host{i}', host=f'host{i}.test', port=161, credential_name='public') for i in range(3)]
    profiles = [dict(name=f'rule{i}', entries=[{'operation': 'get', 'oid': '1.2.3', 'label': 'value'}]) for i in range(2)]

    def snmp():
        with execution.condition_worker_scope(tmp_path):
            return snmp_tools.run_snmp_tests(hosts, {'public': {'name': 'public'}}, profiles, condition_workers=True)

    def scan():
        with execution.condition_worker_scope(tmp_path):
            return scan_tcp_checks([({'host': 'host'}, p) for p in range(6)])

    with ThreadPoolExecutor(max_workers=3) as callers:
        futures = [callers.submit(snmp), callers.submit(snmp), callers.submit(scan)]
        try:
            until(lambda: active == 2)
            until(lambda: sum(e['users'] for e in execution._pools.values()) == 3)
            assert execution.execute_stage_actions(tmp_path, lambda x: x, [1]) == [1]
        finally:
            release.set()
        first, second, ports = [future.result(timeout=5) for future in futures]
    assert peak == 2 and active == 0
    assert created == closed == 12
    assert all(loop.is_closed() for loop in loops)
    expected = [(host['name'], profile['name']) for host in hosts for profile in profiles]
    for results in (first, second):
        assert [(r['host_name'], r['profile_name']) for r in results] == expected
        assert [r['status'] for r in results] == ['success', 'success', 'error', 'error', 'success', 'success']
        assert results[2]['error'] == 'fixture failure'
        assert results[0]['rows'][0]['value'] == '42'
    assert ports == list(range(6))
    assert not execution._pools


def test_snmp_manual_path_and_empty_condition_batch(monkeypatch, tmp_path):
    from twn_toolkit import snmp_tools
    calls = []

    async def original(hosts, credentials, profiles):
        calls.append((hosts, credentials, profiles))
        return ['manual result']

    monkeypatch.setattr(snmp_tools, '_run_snmp_tests', original)
    assert snmp_tools.run_snmp_tests([], {}, []) == ['manual result']
    assert len(calls) == 1
    with execution.condition_worker_scope(tmp_path):
        assert snmp_tools.run_snmp_tests([], {}, [], condition_workers=True) == []
    assert len(calls) == 1
    assert not execution._pools



def test_snmp_engine_evaluation_uses_shared_pool(tmp_path, monkeypatch):
    from twn_toolkit import snmp_tools
    from twn_toolkit.profiles import SNMPCredentialProfileStore, SNMPHostProfileStore, SNMPOidProfileStore

    instance = str(tmp_path)
    monkeypatch.setenv('TWN_TOOLKIT_INSTANCE_PATH', instance)
    OperationalSettingsStore(instance).save({'automation_condition_workers': 1})
    SNMPCredentialProfileStore(instance).upsert({'name': 'Public', 'version': 'v2c', 'community': 'fixture'})
    SNMPHostProfileStore(instance).upsert(dict(name='Switch', host='192.0.2.1', port=161,
                                             credential_name='Public', timeout=1, retries=0))
    SNMPOidProfileStore(instance).upsert({'name': 'Health', 'source': 'CPU = 1.3.6.1.4.1.999.1.0'})
    observed = []

    async def poll(host, credential, profile):
        observed.append(threading.current_thread().name)
        return {'host_name': host['name'], 'profile_name': profile['name'], 'status': 'success',
                'rows': [{'oid': '1.3.6.1.4.1.999.1.0', 'value': '95'}], 'elapsed_ms': 1}

    monkeypatch.setattr(snmp_tools, '_poll_host_profile', poll)
    config = {'host_names': ['Switch'], 'rules': [
        {'id': 'cpu', 'name': 'CPU high', 'oid_profile_name': 'Health',
         'oid': '1.3.6.1.4.1.999.1.0', 'comparison': 'greater_than', 'expected_value': '80'}],
        'host_failure_mode': 'at_least', 'host_failure_count': 1}
    engine = AutomationEngine(SimpleNamespace(instance_path=tmp_path))
    result = engine.test_condition({'condition': {'type': 'snmp.value', 'config': config}})
    assert result.met and result.evidence['matched_hosts'] == 1
    assert len(observed) == 1 and observed[0].startswith('twn-condition')
    assert not execution._pools


def test_snmp_condition_real_udp_timeout_in_worker(tmp_path):
    import socket
    from twn_toolkit.snmp_tools import run_snmp_tests

    OperationalSettingsStore(str(tmp_path)).save({'automation_condition_workers': 2})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent_peer:
        silent_peer.bind(('127.0.0.1', 0))
        host = dict(name='Local', host='127.0.0.1', port=silent_peer.getsockname()[1],
                    credential_name='Public', timeout=.05, retries=0)
        profiles = [dict(name=f'rule{i}', entries=[dict(operation='get', oid='1.3.6.1.2.1.1.3.0',
                                                       label='Uptime')]) for i in range(2)]
        with execution.condition_worker_scope(tmp_path):
            results = run_snmp_tests([host], {'Public': dict(name='Public', version='v2c', community='fixture')},
                                     profiles, condition_workers=True)
        silent_peer.settimeout(2)
        assert silent_peer.recv(65535)
        assert silent_peer.recv(65535)
    assert [result['profile_name'] for result in results] == ['rule0', 'rule1']
    assert all(result['status'] == 'error' and 'timeout' in result['error'].lower() for result in results)
    assert not execution._pools
