import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from twn_toolkit import automation_execution as execution
from twn_toolkit.automation import AutomationEngine
from twn_toolkit.automation_registry import ActionResult, ConditionResult
from twn_toolkit.operational import OperationalSettingsStore


def until(predicate):
    deadline = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < deadline
        time.sleep(.01)


def test_engines_share_threads_and_keep_result_order_and_errors(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({'automation_action_workers': 2})
    release = threading.Event()
    lock = threading.Lock()
    active = peak = 0
    def action(config, trigger):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            assert release.wait(5)
            if config['i'] == 2:
                raise ValueError('injected')
            return ActionResult('success', str(config['i']), {})
        finally:
            with lock:
                active -= 1
    registry = SimpleNamespace(actions={'test': SimpleNamespace(execute=action)})
    stage = {'id': 'stage', 'name': 'Stage', 'actions': [
        {'id': str(i), 'name': str(i), 'type': 'test', 'config': {'i': i}} for i in range(20)]}
    def run():
        engine = AutomationEngine(SimpleNamespace(instance_path=tmp_path), registry)
        return engine._execute_stage(stage, ConditionResult(True, 'met', '', {}), {}, 1)
    with ThreadPoolExecutor(max_workers=4) as callers:
        futures = [callers.submit(run) for _ in range(4)]
        try:
            until(lambda: active == 2)
            until(lambda: sum(entry['users'] for entry in execution._pools.values()) == 4)
            assert peak == 2
            # Only a window per caller may be submitted, not all 80 actions.
            entry = next(iter(execution._pools.values()))
            assert entry['executor']._work_queue.qsize() <= 8
        finally:
            release.set()
        for future in futures:
            results = future.result(timeout=5)
            assert [r.output['_pipeline']['action_id'] for r in results] == [str(i) for i in range(20)]
            assert results[2].status == 'error'
            assert all(r.status == 'success' for i, r in enumerate(results) if i != 2)
    assert peak == 2
    assert not execution._pools


def test_settings_change_applies_after_last_stage_releases_pool(tmp_path):
    store = OperationalSettingsStore(str(tmp_path))
    store.save({'automation_action_workers': 1})
    with execution._borrow(tmp_path) as (pool, count):
        assert count == 1
        store.save({'automation_action_workers': 3})
        with execution._borrow(tmp_path) as (shared, new_count):
            assert shared is pool and new_count == 1
    with execution._borrow(tmp_path) as (replacement, count):
        assert replacement is not pool and count == 3
    assert not execution._pools


def test_blocked_instance_does_not_hold_other_instance(tmp_path):
    entered, release = threading.Event(), threading.Event()
    def block(value):
        entered.set()
        assert release.wait(5)
        return value
    with ThreadPoolExecutor(max_workers=2) as callers:
        first = callers.submit(execution.execute_stage_actions, tmp_path / 'first', block, [1])
        try:
            assert entered.wait(5)
            second = callers.submit(execution.execute_stage_actions, tmp_path / 'second', lambda x: x, [2])
            assert second.result(timeout=2) == [2]
        finally:
            release.set()
        assert first.result(timeout=2) == [1]
    assert not execution._pools


def test_unexpected_failure_drains_submitted_work_and_releases_pool(tmp_path):
    OperationalSettingsStore(str(tmp_path)).save({'automation_action_workers': 1})
    calls = []
    def fail(value):
        calls.append(value)
        raise RuntimeError('injected')
    with pytest.raises(RuntimeError, match='injected'):
        execution.execute_stage_actions(tmp_path, fail, range(100))
    assert calls == [0]
    assert not execution._pools
    assert execution.execute_stage_actions(tmp_path, lambda x: x, [1, 2]) == [1, 2]


def test_action_limit_validation_and_legacy_defaults(tmp_path):
    store = OperationalSettingsStore(str(tmp_path))
    assert store.get()['automation_action_workers'] == 20
    store.save({'automation_action_workers': 3})
    assert store.save({'max_concurrent_automations': 2})['automation_action_workers'] == 3
    for value in [0, 65, True, '1.5']:
        with pytest.raises(ValueError):
            store.save({'automation_action_workers': value})
