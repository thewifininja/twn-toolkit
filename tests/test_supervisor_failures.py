import json
import signal
import subprocess
from unittest.mock import MagicMock

import pytest

from twn_toolkit import supervisor_worker as worker


@pytest.mark.parametrize("failure", [subprocess.TimeoutExpired("twn", 30), OSError("restart unavailable")])
def test_restart_failure_does_not_end_supervision(tmp_path, monkeypatch, failure, capsys):
    (tmp_path / "tftp_settings.json").write_text(json.dumps({"enabled": True}))
    (tmp_path / "iperf_servers.sqlite3").touch()
    monkeypatch.setattr("sys.argv", ["supervisor", "--instance", str(tmp_path), "--root", str(tmp_path),
                                    "--pid-file", str(tmp_path / "supervisor.pid"), "--log-file", str(tmp_path / "supervisor.log")])
    handlers = {}
    monkeypatch.setattr(worker.signal, "signal", lambda sig, handler: handlers.update({sig: handler}))
    monkeypatch.setattr(worker, "acquire_singleton_lock", lambda *a: MagicMock())
    monkeypatch.setattr(worker, "record_lock_owner", lambda *a: None)
    monkeypatch.setattr(worker, "_pid_running", lambda *a: False)
    monkeypatch.setattr(worker, "process_marker_ready", lambda *a: False)
    restore = MagicMock(return_value=0)
    monkeypatch.setattr(worker, "_restore_iperf_listeners", restore)
    calls = []
    def restart(args, **kwargs):
        calls.append(args[-1])
        if args[-1] == "automation-restart":
            raise failure
        return subprocess.CompletedProcess(args, 0)
    monkeypatch.setattr(worker.subprocess, "run", restart)
    monkeypatch.setattr(worker.time, "sleep", lambda _: handlers[signal.SIGTERM]())
    worker.main()
    assert calls == ["automation-restart", "tftp-restart"]
    restore.assert_called_once()
    assert type(failure).__name__ in capsys.readouterr().out


@pytest.mark.parametrize("outcome", [subprocess.CompletedProcess([], 7), OSError("unavailable")])
def test_failed_attempt_has_monotonic_cooldown(tmp_path, monkeypatch, outcome, capsys):
    now = [100.0]
    monkeypatch.setattr(worker.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(worker, "_pid_running", lambda *a: False)
    restart = MagicMock(side_effect=outcome) if isinstance(outcome, Exception) else MagicMock(return_value=outcome)
    monkeypatch.setattr(worker.subprocess, "run", restart)
    retries = {}
    worker.supervise_once(tmp_path, tmp_path, retries)
    assert retries["twn-automation.pid"] == 130
    now[0] = 129
    worker.supervise_once(tmp_path, tmp_path, retries)
    assert restart.call_count == 1
    now[0] = 130
    worker.supervise_once(tmp_path, tmp_path, retries)
    assert restart.call_count == 2
    assert "Could not" in capsys.readouterr().out


def test_bad_settings_and_health_probe_do_not_block_other_services(tmp_path, monkeypatch, capsys):
    (tmp_path / "tftp_settings.json").write_text("[]")
    (tmp_path / "ftp_settings.json").write_text('{"enabled": true}')
    monkeypatch.setattr(worker, "_pid_running", MagicMock(side_effect=OSError("probe failed")))
    monkeypatch.setattr(worker, "process_marker_ready", lambda *a: False)
    restart = MagicMock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(worker.subprocess, "run", restart)
    retries = {}
    worker.supervise_once(tmp_path, tmp_path, retries)
    assert restart.call_args.args[0][-1] == "ftp-restart"
    assert "twn-automation.pid" in retries and "twn-tftp.pid" in retries
    output = capsys.readouterr().out
    assert "probe failed" in output and "boolean enabled" in output


def test_iperf_failure_is_contained_and_backed_off(tmp_path, monkeypatch):
    (tmp_path / "iperf_servers.sqlite3").touch()
    monkeypatch.setattr(worker, "_pid_running", lambda *a: True)
    monkeypatch.setattr(worker, "_heartbeat_fresh", lambda *a: True)
    restore = MagicMock(side_effect=OSError("iperf unavailable"))
    monkeypatch.setattr(worker, "_restore_iperf_listeners", restore)
    retries = {}
    worker.supervise_once(tmp_path, tmp_path, retries)
    worker.supervise_once(tmp_path, tmp_path, retries)
    assert restore.call_count == 1


def test_shutdown_stops_admission_of_further_restarts(tmp_path, monkeypatch):
    (tmp_path / "tftp_settings.json").write_text('{"enabled": true}')
    stopped = []
    monkeypatch.setattr(worker, "_pid_running", lambda *a: False)
    def restart(*args, **kwargs):
        stopped.append(True)
        return subprocess.CompletedProcess([], 0)
    run = MagicMock(side_effect=restart)
    monkeypatch.setattr(worker.subprocess, "run", run)
    worker.supervise_once(tmp_path, tmp_path, {}, stopping=lambda: bool(stopped))
    assert run.call_count == 1


@pytest.mark.parametrize("payload", [[], {"updated_at": None}, {"updated_at": "nan"}, {"updated_at": "inf"}, {"updated_at": 999999999999}])
def test_malformed_or_future_heartbeat_is_unhealthy(tmp_path, payload):
    path = tmp_path / "heartbeat.json"
    path.write_text(json.dumps(payload))
    assert not worker._heartbeat_fresh(path, 20)
    worker._remove_own_heartbeat(path)


def test_heartbeat_write_failure_is_reported_without_ending_recovery(tmp_path, capsys):
    path = tmp_path / "directory"
    path.mkdir()
    worker._write_heartbeat(path)
    assert "Could not write supervisor heartbeat" in capsys.readouterr().out
