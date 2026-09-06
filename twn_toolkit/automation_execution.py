"""Share action threads across overlapping stages; discard pools when idle."""
from __future__ import annotations

import os
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from pathlib import Path

from .operational import OperationalSettingsStore

_pools = {}
_lock = threading.Lock()


@contextmanager
def _borrow(instance):
    key = (os.getpid(), str(Path(instance).resolve()))
    with _lock:
        entry = _pools.get(key)
        if entry is None:
            workers = OperationalSettingsStore(key[1]).get()['automation_action_workers']
            entry = {'executor': ThreadPoolExecutor(max_workers=workers, thread_name_prefix='twn-action'),
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


def execute_stage_actions(instance, execute, actions):
    if not actions:
        return []
    results = [None] * len(actions)
    with _borrow(instance) as (executor, workers):
        pending = {}
        items = iter(enumerate(actions))

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
            # Never release the last pool reference while its work is running.
            # On interruption, do not launch unsent actions or abandon running ones.
            for future in pending:
                future.cancel()
            wait(pending)
    return results
