"""Actual API browser-fixture protocol, with no server binding or external requests."""
from contextlib import ExitStack
import json
from pathlib import Path
import runpy
from unittest.mock import Mock, patch

import pytest

from twn_toolkit.api_request_receipts import ApiRequestReceiptStore

FIXTURE = Path(__file__).parent / "fixtures" / "api_request_continuity_app.py"
BOUNDARIES = ("subprocess.Popen", "requests.request", "requests.sessions.Session.request", "socket.create_connection", "socket.getaddrinfo")


@pytest.fixture
def browser_fixture(tmp_path, monkeypatch):
    instance = tmp_path / "instance"
    instance.mkdir()
    server, factory = Mock(), Mock()
    factory.return_value = server
    with monkeypatch.context() as setup:
        setup.setattr("sys.argv", [str(FIXTURE), "--port", "5135"])
        setup.setattr("tempfile.mkdtemp", lambda **kwargs: str(instance))
        setup.setattr("werkzeug.serving.make_server", factory)
        state = runpy.run_path(str(FIXTURE))
    factory.assert_called_once()
    server.serve_forever.assert_called_once_with()
    server.server_close.assert_called_once_with()
    # runpy's finalizer closed its patch stack. Reinstall every boundary before
    # any test-client request; only the explicit fixture sender may execute.
    with ExitStack() as stack:
        mocks = [stack.enter_context(patch(target, side_effect=AssertionError("No external fixture boundary: " + target))) for target in BOUNDARIES]
        sender = stack.enter_context(patch("twn_toolkit.api_request_routes.send_api_request", side_effect=state["synthetic_sender"]))
        yield state, state["app"].test_client(), instance, sender
        for mock in mocks:
            mock.assert_not_called()
    assert all(count == 0 for count in state["counts"]["blocked_calls"].values())
    state["app"].extensions["remote_session_manager"].close()


def compose(client):
    response = client.get("/tools/api-request/admission")
    assert response.status_code == 200
    return {"admission_token": response.json["token"], "method": "POST", "url": "https://fixture.test/write", "headers": "Authorization: SyntheticHeader", "body": "SyntheticBody", "timeout": "1", "verify_tls": "on", "write_consent": "yes"}


@pytest.mark.parametrize("mode,status,mimetype,dispatched,state_name", [
    ("normal", 200, "application/json", True, "confirmed"),
    ("forbidden", 403, "text/html", False, "issued"),
    ("html_after", 200, "text/html", True, "confirmed"),
    ("json500_after", 500, "application/json", True, "confirmed"),
    ("wrong_token", 200, "application/json", True, "confirmed"),
    ("sender_timeout", 200, "application/json", True, "unconfirmed"),
    ("unexpected", 200, "application/json", True, "unconfirmed"),
])
def test_actual_fixture_response_and_retained_truth(browser_fixture, mode, status, mimetype, dispatched, state_name):
    state, client, instance, sender = browser_fixture
    state["control_path"].write_text(json.dumps({"response": mode, "delay": 0}))
    values = compose(client)
    response = client.post("/tools/api-request", data=values, headers={"Accept": "application/json"})
    assert response.status_code == status and response.mimetype == mimetype
    assert state["counts"]["posts"] == 1
    assert state["counts"]["responses"] == [{"status": status, "mimetype": mimetype, "mode": mode, "dispatched": dispatched}]
    assert sender.call_count == state["counts"]["synthetic_sender_calls"] == int(dispatched)
    receipt = ApiRequestReceiptStore(instance).get("test-user", values["admission_token"])
    assert receipt["state"] == state_name
    if mode == "normal":
        assert response.json["admission_token"] == values["admission_token"]
        assert response.json["result"]["body"] == "<script>synthetic text</script>"
    elif mode == "wrong_token":
        assert response.json["admission_token"] == "f" * 64
        assert ApiRequestReceiptStore(instance).get("test-user", "f" * 64) is None
    elif mode == "html_after":
        assert b"lost acknowledgment" in response.data
    elif mode == "json500_after":
        assert "acknowledgment unavailable" in response.json["error"]
    elif mode in {"sender_timeout", "unexpected"}:
        assert response.json["result"] is None
        assert "may already have executed" in response.json["error"]
        assert "private exception marker" not in response.get_data(as_text=True)
    assert json.loads((instance / "counts.json").read_text())["responses"] == state["counts"]["responses"]
    if dispatched:
        # Refresh or a lost/faulted acknowledgment must not create another send.
        retry = client.post("/tools/api-request", data=values, headers={"Accept": "application/json"})
        assert retry.status_code == 409 and retry.json["dispatched"] is False
        assert sender.call_count == state["counts"]["synthetic_sender_calls"] == 1
        page = client.get("/tools/api-request", query_string={"receipt": values["admission_token"]})
        assert page.status_code == 200 and b"contents were not saved" in page.data
        assert b"<script>synthetic text</script>" not in page.data
        assert sender.call_count == 1


def test_fixture_blocks_nonallowlisted_destination_method_and_route(browser_fixture):
    state, client, instance, sender = browser_fixture
    values = compose(client)
    assert client.post("/tools/api-request", data={**values, "url": "https://outside.example/write"}).status_code == 403
    assert client.post("/tools/api-request", data={**values, "url": "https://fixture.test/write?extra=1"}).status_code == 403
    invalid_method = client.post("/tools/api-request", data={**values, "method": "TRACE"}, headers={"Accept": "application/json"})
    assert invalid_method.status_code == 400 and invalid_method.json["dispatched"] is False
    assert client.post("/tools/ntp-test", data={}).status_code == 403
    assert client.get("/admin").status_code == 403
    assert sender.call_count == state["counts"]["synthetic_sender_calls"] == 0
    assert ApiRequestReceiptStore(instance).get("test-user", values["admission_token"])["state"] == "issued"


def test_native_fixture_post_redirect_refresh_and_repeat_are_safe(browser_fixture):
    state, client, instance, sender = browser_fixture
    values = compose(client)
    response = client.post("/tools/api-request", data=values)
    assert response.status_code == 303
    assert response.headers["Cache-Control"].startswith("no-store")
    for _ in range(2):
        page = client.get(response.location)
        assert page.status_code == 200
        assert b"HTTP 200" in page.data
        assert b"SyntheticHeader" not in page.data and b"SyntheticBody" not in page.data
    repeat = client.post("/tools/api-request", data=values)
    assert repeat.status_code == 409
    assert sender.call_count == state["counts"]["synthetic_sender_calls"] == 1
    # Native303 receipt redirects also record the real admitted dispatch.
    assert state["counts"]["responses"][0] == {"status": 303, "mimetype": "text/html", "mode": "normal", "dispatched": True}
