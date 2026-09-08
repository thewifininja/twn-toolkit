"""Common outgoing capacity, including cancellation-safe asynchronous admission."""
import asyncio
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
import os
import threading
import time
import weakref
from .transfer_admission import _try_acquire as _acquire_slots
from .operational import OperationalSettingsStore

_gates = weakref.WeakKeyDictionary()
_gates_lock = threading.Lock()


class CapacityWaitTimeout(TimeoutError):
    pass


async def try_async(instance, host, timeout=30):
    # Weak values avoid retaining closed event loops through bound semaphores.
    loop = asyncio.get_running_loop()
    with _gates_lock:
        reference = _gates.get(loop)
        gate = reference() if reference else None
        if gate is None:
            gate = asyncio.Semaphore(4)
            _gates[loop] = weakref.ref(gate)
    state = {'descriptor': None, 'abandoned': False}
    lock = threading.Lock()
    def acquire():
        descriptor = _try_acquire(instance, host)
        with lock:
            if state['abandoned']:
                if descriptor is not None:
                    os.close(descriptor)
                return None
            state['descriptor'] = descriptor
        return descriptor
    async def run():
        async with gate:
            return await asyncio.to_thread(acquire)
    try:
        descriptor = await asyncio.wait_for(run(), timeout)
    except BaseException:
        with lock:
            state['abandoned'] = True
            if state['descriptor'] is not None:
                os.close(state['descriptor'])
                state['descriptor'] = None
        raise
    with lock:
        state['descriptor'] = None
    return descriptor


@asynccontextmanager
async def async_slot(instance, host, wait_seconds=None):
    if not instance:
        yield
        return
    if wait_seconds is None:
        wait_seconds = _probe_wait_seconds(instance)
    end = time.monotonic() + wait_seconds
    descriptor = None
    try:
        while descriptor is None:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise CapacityWaitTimeout('Outgoing capacity wait expired; no target operation was started.')
            try:
                descriptor = await try_async(instance, host, remaining)
            except CapacityWaitTimeout:
                raise
            except asyncio.TimeoutError as exc:
                raise CapacityWaitTimeout('Outgoing capacity wait expired; no target operation was started.') from exc
            if descriptor is None:
                await asyncio.sleep(min(.05, remaining))
        if time.monotonic() >= end:
            raise CapacityWaitTimeout('Outgoing capacity wait expired; no target operation was started.')
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)


_instance = ContextVar('outgoing_instance', default=None)


def resolve_instance(instance=None):
    if instance is not None:
        return instance
    if _instance.get() is not None:
        return _instance.get()
    from .automation_execution import _condition_instance
    if _condition_instance.get() is not None:
        return _condition_instance.get()
    from flask import current_app, has_app_context
    if has_app_context():
        return current_app.instance_path
    return os.environ.get('TWN_TOOLKIT_INSTANCE_PATH')


@contextmanager
def outgoing_scope(instance=None):
    token = _instance.set(resolve_instance(instance))
    try:
        yield
    finally:
        _instance.reset(token)


def _capacity_unavailable(exc):
    return CapacityWaitTimeout(
        f'Outgoing capacity could not be checked ({str(exc) if isinstance(exc, ValueError) else type(exc).__name__}); '
        'no target operation was started. Check instance storage and operational settings.'
    )


def _probe_wait_seconds(instance):
    try:
        return OperationalSettingsStore(str(instance)).get()['outgoing_admission_seconds']
    except (OSError, ValueError) as exc:
        raise _capacity_unavailable(exc) from exc


def _try_acquire(instance, host, *, weight=1):
    try:
        return _acquire_slots(instance, host, directory='.outgoing-admission',
                              total_key='outgoing_connections', host_key='outgoing_host_connections', weight=weight)
    except (OSError, ValueError) as exc:
        raise _capacity_unavailable(exc) from exc


class AdmissionDeadline:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def remaining(self):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise CapacityWaitTimeout('Outgoing capacity wait expired; no target operation was started.')
        return remaining


@contextmanager
def outgoing_slot(instance, host, *, deadline=None, wait_seconds=None, weight=1):
    if not instance:
        yield
        return
    if deadline is None:
        if wait_seconds is None:
            wait_seconds = _probe_wait_seconds(instance)
        deadline = AdmissionDeadline(wait_seconds)
    descriptor = None
    try:
        while descriptor is None:
            try:
                remaining = deadline.remaining()
            except TimeoutError as exc:
                raise CapacityWaitTimeout('Outgoing capacity wait expired; no target operation was started.') from exc
            descriptor = _try_acquire(instance, host, weight=weight)
            if descriptor is None:
                time.sleep(min(.05, remaining))
        deadline.remaining()
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
