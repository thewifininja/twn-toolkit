"""Exercise actual child processes without contacting an appliance."""
import subprocess
import sys
import time

import pytest

from twn_toolkit.auth import load_or_create_secret_key
from twn_toolkit.diagnostic_worker import DiagnosticScheduler
from twn_toolkit.preview_binding import PreviewSigner
from twn_toolkit.profiles import ProfileStore
from twn_toolkit.switch_order_jobs import review_context


CHILD = r'''
import runpy, sys, time
from contextlib import contextmanager
from pathlib import Path
from twn_toolkit import switch_order_jobs as operations

phase, instance, job_id = sys.argv[1:]
def stall():
    Path(instance, 'fixture-reached').write_text(phase)
    time.sleep(60)

class Appliance:
    @contextmanager
    def pooled(self):
        yield self
    def get_managed_switches(self, vdom):
        if phase == 'inventory':
            stall()
        return [{'switch-id': 'a'}, {'switch-id': 'b'}]
    def move_managed_switch_after(self, *args):
        stall()
    def get_object(self, *args):
        if phase == 'inventory':
            stall()
        return {'results': [{'name': 'Old'}]}
    def rename_object(self, *args, **kwargs):
        stall()

operations.FortiGateClient.from_profile = lambda _: Appliance()
sys.argv = ['diagnostic', '--instance', instance, '--job', job_id]
runpy.run_module('twn_toolkit.diagnostic_worker', run_name='__main__')
'''


@pytest.mark.parametrize("phase", ["inventory", "move"])
@pytest.mark.parametrize("reason", ["cancel", "deadline", "shutdown", "restart"])
@pytest.mark.parametrize("tool", ["switch_order", "appliance_rename"])
def test_real_child_interruption_preserves_progress_and_never_replays(tmp_path, monkeypatch, phase, reason, tool):
    original = subprocess.Popen

    def launch(command, **kwargs):
        return original([sys.executable, "-c", CHILD, phase, str(tmp_path), command[-1]], **kwargs)

    monkeypatch.setattr("twn_toolkit.diagnostic_worker.subprocess.Popen", launch)
    scheduler = DiagnosticScheduler(tmp_path)
    store = scheduler.store
    profile = {"name": "Lab", "host": "https://fixture.invalid", "api_key": "fixture-secret"}
    ProfileStore(str(tmp_path)).upsert(profile)
    config = dict(profile=profile, mode="apply", vdom="root", username="owner",
                  investigation_id="", original_ids=["a", "b"], desired_ids=["b", "a"])
    signer = PreviewSigner(load_or_create_secret_key(str(tmp_path)), store.instance, "owner")
    config["preview_token"] = signer.issue("switch-order-apply-v1", review_context(config))
    if tool == 'appliance_rename':
        from twn_toolkit.tasks import get_task
        from twn_toolkit.rename_preview import _context, _SCOPE
        task = get_task('rename-aps')
        config.update(task_id=task.id, endpoint=task.endpoint_template, target_revision='',
                      entries=[{'identifier': 'AP1', 'current_name': 'Old', 'new_name': 'New', 'vdom': 'root'}])
        config['preview_token'] = signer.issue(_SCOPE, _context(task, profile, config['endpoint'], config['entries']))
    job_id = store.enqueue(user_id="owner", tool=tool, config=config, request_key="review")
    process = None
    try:
        scheduler.tick()
        process = scheduler.active[job_id]["process"]
        deadline = time.monotonic() + 10
        while not (tmp_path / "fixture-reached").exists():
            assert time.monotonic() < deadline, "child did not reach fixture operation"
            assert process.poll() is None
            time.sleep(0.02)
        saved = store.get(job_id, "owner")["summary"]
        assert saved["attempted_moves"] == int(phase == "move")
        if reason == "cancel":
            store.cancel(job_id, "owner")
        elif reason == "deadline":
            scheduler.active[job_id]["deadline"] = time.monotonic() - 1
        elif reason == "shutdown":
            scheduler.close()
        else:
            process.kill()
            process.wait(timeout=5)
            # Model a dead scheduler: recovery, not its normal tick/close path.
            scheduler.active.clear()
            scheduler = DiagnosticScheduler(tmp_path)

        deadline = time.monotonic() + 10
        while scheduler.active:
            assert time.monotonic() < deadline
            scheduler.tick()
            time.sleep(0.02)
        result = store.get(job_id, "owner")
        expected = "unknown" if phase == "move" or reason in {"shutdown", "restart"} else (
            "cancelled" if reason == "cancel" else "failed")
        assert process.poll() is not None
        assert result["state"] == expected
        assert result["summary"] == saved
        assert store.claim() is None
        assert store.enqueue(user_id="owner", tool=tool, config=config, request_key="review") == job_id
        assert not scheduler.active
    finally:
        scheduler.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
