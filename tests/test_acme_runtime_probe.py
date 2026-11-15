import os
import stat

import pytest

from twn_toolkit import acme_dns
from twn_toolkit.acme_dns import AcmeDnsManager


@pytest.fixture(autouse=True)
def empty_probe_cache():
    acme_dns._RUNTIME_PROBES.clear()
    yield
    acme_dns._RUNTIME_PROBES.clear()


def _certbot(tmp_path, body):
    """Write a stand-in executable that records each launch."""
    script = tmp_path / "certbot"
    launches = tmp_path / "launches"
    script.write_text(f"#!/bin/sh\necho launched >> '{launches}'\n{body}\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script, launches


def _launch_count(launches):
    return len(launches.read_text().splitlines()) if launches.exists() else 0


def test_version_is_probed_once_per_executable(tmp_path):
    script, launches = _certbot(tmp_path, "echo 'certbot 9.9.9'")
    manager = AcmeDnsManager(str(tmp_path / "instance"), certbot_path=str(script))

    first = manager.runtime()
    for _ in range(5):
        assert manager.runtime() == first
    # A second manager, as each web request path may construct, shares the answer.
    assert AcmeDnsManager(str(tmp_path / "instance"), certbot_path=str(script)).runtime() == first

    assert first == {"available": True, "path": str(script), "version": "certbot 9.9.9"}
    assert _launch_count(launches) == 1


def test_callers_cannot_alter_the_remembered_result(tmp_path):
    script, _ = _certbot(tmp_path, "echo 'certbot 9.9.9'")
    manager = AcmeDnsManager(str(tmp_path / "instance"), certbot_path=str(script))
    manager.runtime()["version"] = "changed by caller"
    assert manager.runtime()["version"] == "certbot 9.9.9"


def test_replaced_executable_is_probed_again(tmp_path):
    script, launches = _certbot(tmp_path, "echo 'certbot 9.9.9'")
    manager = AcmeDnsManager(str(tmp_path / "instance"), certbot_path=str(script))
    assert manager.runtime()["version"] == "certbot 9.9.9"

    script, _ = _certbot(tmp_path, "echo 'certbot 10.0.0 upgraded'")
    assert manager.runtime()["version"] == "certbot 10.0.0 upgraded"
    assert _launch_count(launches) == 2
    assert len(acme_dns._RUNTIME_PROBES) == 1


def test_failed_probe_is_retried_after_a_short_interval(tmp_path, monkeypatch):
    script, launches = _certbot(tmp_path, "echo broken >&2; exit 3")
    manager = AcmeDnsManager(str(tmp_path / "instance"), certbot_path=str(script))

    assert manager.runtime()["available"] is False
    assert manager.runtime()["available"] is False
    assert _launch_count(launches) == 1

    monkeypatch.setattr(acme_dns, "_RUNTIME_PROBE_FAILURE_SECONDS", 0.0)
    acme_dns._RUNTIME_PROBES.clear()
    assert manager.runtime()["available"] is False
    assert manager.runtime()["available"] is False
    assert _launch_count(launches) == 3


def test_missing_executable_reports_unavailable_without_remembering(tmp_path):
    missing = tmp_path / "absent-certbot"
    manager = AcmeDnsManager(str(tmp_path / "instance"), certbot_path=str(missing))
    # Unchanged legacy answer: a configured path that cannot start has no version.
    assert manager.runtime() == {"available": True, "path": str(missing), "version": ""}
    assert acme_dns._RUNTIME_PROBES == {}
    assert AcmeDnsManager(str(tmp_path / "instance"), certbot_path="").runtime()["available"] is False
