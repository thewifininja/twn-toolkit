from __future__ import annotations

import json
import stat
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from twn_toolkit import create_app
from twn_toolkit.audit import AuditStore
from twn_toolkit.automation_registry import AUTOMATION_REGISTRY, ConditionResult
from twn_toolkit.time_settings import TimeSettingsStore


def test_time_settings_follow_host_by_default_and_persist_private_override(tmp_path):
    store = TimeSettingsStore(tmp_path)
    fixed = datetime(2026, 8, 2, 12, 34, 56, tzinfo=timezone.utc)

    with patch(
        "twn_toolkit.time_settings.local_timezone_name",
        return_value="America/Chicago",
    ):
        default = store.snapshot(now=fixed)

    assert default["timezone"] == ""
    assert default["resolved_timezone"] == "America/Chicago"
    assert default["source"] == "Host timezone"
    assert default["current_display"] == "Aug 2, 2026 7:34:56 AM CDT"
    assert default["utc_offset"] == "UTC-05:00"

    assert store.save("America/New_York") == {"timezone": "America/New_York"}
    assert store.resolved_timezone() == "America/New_York"
    winter = store.snapshot(
        now=datetime(2026, 1, 2, 12, 34, 56, tzinfo=timezone.utc)
    )
    assert winter["current_display"] == "Jan 2, 2026 7:34:56 AM EST"
    assert winter["utc_offset"] == "UTC-05:00"
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert json.loads(store.path.read_text(encoding="utf-8")) == {
        "timezone": "America/New_York"
    }


def test_time_settings_reject_unknown_iana_timezone(tmp_path):
    store = TimeSettingsStore(tmp_path)

    with pytest.raises(ValueError, match="Unknown IANA timezone"):
        store.save("Eastern-ish")

    assert not store.path.exists()


def test_time_settings_fall_back_safely_when_saved_file_is_malformed(tmp_path):
    store = TimeSettingsStore(tmp_path)
    store.path.write_text("[]", encoding="utf-8")

    with patch(
        "twn_toolkit.time_settings.local_timezone_name",
        return_value="America/Denver",
    ):
        assert store.get() == {"timezone": ""}
        assert store.resolved_timezone() == "America/Denver"


def test_system_settings_save_timezone_without_restart(tmp_path):
    app = create_app(str(tmp_path))
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.post(
        "/settings/timezone",
        data={"timezone": "America/Los_Angeles"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(
        "/settings?section=system#toolkit-timezone"
    )
    assert TimeSettingsStore(tmp_path).get() == {
        "timezone": "America/Los_Angeles"
    }
    event = AuditStore(str(tmp_path)).recent(1)[0]
    assert event["action"] == "settings.timezone_updated"
    assert event["summary"] == "Updated the toolkit timezone."

    page = client.get("/settings?section=system")
    assert page.status_code == 200
    assert b"Time and localization" in page.data
    assert b'list="toolkit-timezone-choices" value="America/Los_Angeles"' in page.data
    assert b"No restart is required" in page.data

    schedules = client.get("/automations/schedules")
    assert b'name="schedule_timezone"' in schedules.data
    assert b'value="America/Los_Angeles"' in schedules.data
    actions = client.get("/automations/actions")
    assert b'"timestamp":"{{timestamp.local}}"' in actions.data
    assert b'"timezone":"{{toolkit.timezone}}"' in actions.data
    assert actions.data.count(b"{{toolkit.version}}") >= 3
    assert b"Time: {{timestamp.display}}" in actions.data

    invalid = client.post(
        "/settings/timezone",
        data={"timezone": "Not/A-Timezone"},
        follow_redirects=True,
    )
    assert b"Unknown IANA timezone" in invalid.data
    assert TimeSettingsStore(tmp_path).get()["timezone"] == "America/Los_Angeles"


def test_webhook_time_variables_keep_utc_and_add_configured_local_time(tmp_path):
    TimeSettingsStore(tmp_path).save("America/New_York")
    fixed = datetime(2026, 8, 2, 12, 34, 56, tzinfo=timezone.utc)
    trigger = ConditionResult(
        True,
        "started",
        "Toolkit started",
        {
            "startup": {
                "reason": "Toolkit service started",
                "mode": "toolkit_start",
                "occurred_at": fixed.timestamp(),
            }
        },
    )
    delivered = {
        "status": 204,
        "reason": "No Content",
        "elapsed_ms": 2.0,
        "resolved_addresses": ["192.0.2.40"],
        "body": "",
        "truncated": False,
        "redirect": "",
    }
    body_template = json.dumps(
        {
            "legacy": "{{timestamp}}",
            "utc": "{{timestamp.utc}}",
            "local": "{{timestamp.local}}",
            "display": "{{timestamp.display}}",
            "timezone": "{{toolkit.timezone}}",
            "startup_legacy": "{{startup.occurred_at}}",
            "startup_local": "{{startup.occurred_at_local}}",
            "startup_display": "{{startup.occurred_at_display}}",
        }
    )
    with patch(
        "twn_toolkit.automation_types.actions._utc_now", return_value=fixed
    ), patch(
        "twn_toolkit.automation_types.actions.send_api_request",
        return_value=delivered,
    ) as sender:
        result = AUTOMATION_REGISTRY.actions["webhook.send"].execute(
            {
                "_instance_path": str(tmp_path),
                "endpoints": "https://hooks.example.com/startup",
                "method": "POST",
                "headers": "",
                "body_format": "json",
                "body": body_template,
                "timeout": 5,
                "verify_tls": True,
                "expected_statuses": "200-299",
            },
            trigger,
        )

    body = json.loads(sender.call_args.kwargs["body"])
    assert body["legacy"] == "2026-08-02T12:34:56Z"
    assert body["utc"] == body["legacy"]
    assert body["local"] == "2026-08-02T08:34:56-04:00"
    assert body["display"] == "Aug 2, 2026 8:34:56 AM EDT"
    assert body["timezone"] == "America/New_York"
    assert body["startup_legacy"] == body["legacy"]
    assert body["startup_local"] == body["local"]
    assert body["startup_display"] == body["display"]
    assert result.status == "success"
