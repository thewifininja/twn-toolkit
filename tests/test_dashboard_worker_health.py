from __future__ import annotations

import json
import os
import time

import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore


@pytest.mark.parametrize("status,message", [
    ("missing", "Scheduler is not running"),
    ("stale", "Scheduler is not reporting"),
    ("malformed", "Scheduler is not reporting"),
    ("stopping", "Scheduler is stopping"),
    ("running", "No reported errors"),
])
@pytest.mark.parametrize("admin", [True, False])
def test_dashboard_reports_scheduler_health_without_exposing_it_to_nonadmins(
    tmp_path, status, message, admin
):
    app = create_app(str(tmp_path))
    auth = AuthStore(str(tmp_path))
    auth.create_user("admin", "TemporaryReviewPassword123!", is_admin=True)
    if not admin:
        auth.create_user("operator", "TemporaryReviewPassword123!", is_admin=False)
    if status != "missing":
        (tmp_path / "twn-automation.pid").write_text(str(os.getpid()))
        payload = {
            "updated_at": time.time() - (60 if status == "stale" else 0),
            "state": status,
        }
        (tmp_path / "automation-heartbeat.json").write_text(
            "not json" if status == "malformed" else json.dumps(payload)
        )
    try:
        client = app.test_client()
        client.post("/login", data={
            "username": "admin" if admin else "operator",
            "password": "TemporaryReviewPassword123!",
        })
        response = client.get("/")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Everything looks clear" not in html
        if admin:
            assert message in html
            if status != "running":
                assert "1 item needs attention" in html
                assert "Review scheduler status" in html
            else:
                assert "No queued or failed jobs" in html
        else:
            assert "Scheduler is" not in html
            assert "Review scheduler status" not in html
            assert "No reported errors" in html
    finally:
        app.extensions["remote_session_manager"].close()
