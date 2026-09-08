"""Share action, host-check and accelerated-ping pools; discard each when idle."""
from __future__ import annotations

import os
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from .operational import OperationalSettingsStore

_pools = {}
_lock = threading.Lock()
_condition_instance = ContextVar('automation_condition_instance', default=None)


@contextmanager
def _borrow(instance, kind="action", *, worker_limit=None):
    key = (os.getpid(), str(Path(instance).resolve()), kind)
    with _lock:
        entry = _pools.get(key)
        if entry is None:
            workers = worker_limit if worker_limit is not None else OperationalSettingsStore(key[1]).get()[f'automation_{kind}_workers']
            entry = {'executor': ThreadPoolExecutor(max_workers=workers, thread_name_prefix=f'twn-{kind}'),
                     'workers': workers, 'users': 0}
            _pools[key] = entry
        entry['users'] += 1
    try:
        yield entry['executor'], entry['workers']
    finally:
        shutdown = False
        with _lock:
            entry['users'] -= 1
            if not entry['users']:
                del _pools[key]
                shutdown = True
        if shutdown:
            # Callers drain their submitted work before returning the pool.
            entry['executor'].shutdown(wait=True)


@contextmanager
def ssh_worker_pool(instance, workers):
    """Share host workers across concurrent SSH runs on this process/instance."""
    with _borrow(instance, 'ssh', worker_limit=workers) as (executor, _):
        yield executor


@contextmanager
def condition_worker_scope(instance=None):
    if instance is None:
        instance = _condition_instance.get()
    if instance is None:
        from flask import current_app, has_app_context
        instance = current_app.instance_path if has_app_context() else os.environ.get('TWN_TOOLKIT_INSTANCE_PATH')
    token = _condition_instance.set(instance)
    try:
        yield
    finally:
        _condition_instance.reset(token)


def execute_stage_actions(instance, execute, actions):
    if not actions:
        return []
    with _borrow(instance) as (executor, workers):
        return _map_window(executor, workers, execute, actions)


def execute_condition_ping(execute):
    """Admit one intact accelerated-ping round, independently of host workers."""
    instance = _condition_instance.get()
    if not instance:
        return execute()
    with _borrow(instance, "ping") as (executor, _):
        return _map_window(executor, 1, lambda unused: execute(), [None])[0]


def condition_worker_map(execute, items, limit):
    if not items:
        return []
    instance = _condition_instance.get()
    if instance:
        with _borrow(instance, "condition") as (executor, workers):
            return _map_window(executor, min(workers, limit), execute, items)
    # Non-condition callers keep independent per-call concurrency.
    with ThreadPoolExecutor(max_workers=min(limit, len(items))) as executor:
        return _map_window(executor, limit, execute, items)


def _map_window(executor, workers, execute, items):
    results = [None] * len(items)
    pending = {}
    items = iter(enumerate(items))

    def fill():
        while len(pending) < workers:
            item = next(items, None)
            if item is None:
                return
            index, action = item
            pending[executor.submit(execute, action)] = index

    try:
        fill()
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                index = pending.pop(future)
                results[index] = future.result()
            fill()
    finally:
        # Drain running work before releasing its pool; do not start unsent items.
        for future in pending:
            future.cancel()
        wait(pending)
    return results
