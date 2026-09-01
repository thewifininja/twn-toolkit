from __future__ import annotations

import json
import stat
import time
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

import pytest

from twn_toolkit.app import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.distributed_agents import (
    DistributedEnrollmentWindow,
    DistributedSettingsStore,
)
from twn_toolkit.distributed_transport import (
    EnrollmentClient,
    EnrollmentClosedError,
    EnrollmentServer,
    EnrollmentTransportError,
)
from twn_toolkit.distributed_worker import _agent_tick


def test_loopback_enrollment_requires_approval_and_delivers_credentials(tmp_path):
    mainframe = tmp_path / "mainframe"
    agent = tmp_path / "agent"
    server = EnrollmentServer(mainframe, "127.0.0.1", 0)
    server.enrollment_window.open(5)
    server.start()
    try:
        client = EnrollmentClient(agent, f"https://127.0.0.1:{server.port}")
        pending = client.begin("Test Agent")
        assert len(pending["pairing_code"]) == 6
        assert "token" not in pending
        assert client.poll() == {"state": "pending"}

        # Closing enrollment affects only new identities, not an in-flight approval.
        server.enrollment_window.close()

        enrollment = server.agent_store.list("pending")[0]
        pairing = server.pairing_store.active_for_agent(enrollment["id"])
        assert pairing["pairing_code"] == pending["pairing_code"]
        server.agent_store.set_state(enrollment["id"], "approved")

        assert client.poll() == {"state": "approved"}
        assert client.certificate_path.exists()
        assert client.ca_path.exists()
        assert stat.S_IMODE(client.certificate_path.stat().st_mode) == 0o600
        assert not client.pending_path.exists()
        heartbeat = client.heartbeat(
            [{"id": "system.identity", "version": "1"}],
            toolkit_version="1.2.3",
            platform="TestOS 1",
            hostname="test-agent",
        )
        assert heartbeat["agent_id"] == enrollment["id"]
        connected = server.agent_store.get(enrollment["id"])
        assert connected["online"] is True
        assert connected["capabilities"] == [
            {"id": "system.identity", "version": "1"}
        ]
        assert connected["toolkit_version"] == "1.2.3"
        assert connected["platform"] == "TestOS 1"
        assert connected["hostname"] == "test-agent"

        with ThreadPoolExecutor(max_workers=1) as executor:
            waiting = executor.submit(
                client.heartbeat,
                [{"id": "system.identity", "version": "1"}],
                wait_seconds=2,
            )
            time.sleep(0.15)
            queued = server.job_store.enqueue(
                agent_id=enrollment["id"],
                requester_id="test-user",
                capability_id="system.identity",
                capability_version="1",
            )
            delivered = waiting.result(timeout=2)
        assert [job["id"] for job in delivered["jobs"]] == [queued["id"]]

        tunnel = server.job_store.enqueue(
            agent_id=enrollment["id"], requester_id="interactive-user",
            capability_id="system.http.tunnel", capability_version="1",
            inputs={"method": "GET", "path": "/"},
        )
        interactive = client.interactive(wait_seconds=0)
        assert [item["id"] for item in interactive["requests"]] == [tunnel["id"]]
        client.interactive(
            [{"id": tunnel["id"], "state": "succeeded", "output": {"status": 200}, "error": ""}],
            wait_seconds=0,
        )
        assert server.job_store.get(tunnel["id"])["state"] == "succeeded"

        server.agent_store.set_state(enrollment["id"], "revoked")
        with pytest.raises(EnrollmentTransportError):
            client.heartbeat([{"id": "system.identity", "version": "1"}])
    finally:
        server.stop()


def test_wrong_pairing_token_cannot_poll_enrollment(tmp_path):
    server = EnrollmentServer(tmp_path / "mainframe", "127.0.0.1", 0)
    server.enrollment_window.open(5)
    server.start()
    try:
        client = EnrollmentClient(
            tmp_path / "agent", f"https://127.0.0.1:{server.port}"
        )
        client.begin("Test Agent")
        pending = json.loads(client.pending_path.read_text())
        pending["token"] = "wrong"
        client.pending_path.write_text(json.dumps(pending))
        with pytest.raises(EnrollmentTransportError):
            client.poll()
    finally:
        server.stop()


def test_client_uses_fallback_for_enrollment_and_authenticated_traffic(tmp_path):
    mainframe = tmp_path / "mainframe"
    server = EnrollmentServer(mainframe, "127.0.0.1", 0)
    server.enrollment_window.open(5)
    server.start()
    fallback_url = f"https://127.0.0.1:{server.port}"
    try:
        client = EnrollmentClient(
            tmp_path / "agent",
            "https://127.0.0.1:1",
            fallback_url,
        )
        pending = client.begin("Fallback Agent")
        assert pending["mainframe_url"] == fallback_url
        enrollment = server.agent_store.list("pending")[0]
        server.agent_store.set_state(enrollment["id"], "approved")
        assert client.poll() == {"state": "approved"}
        assert client.heartbeat([], hostname="fallback-agent")["agent_id"] == enrollment["id"]
        assert client.mainframe_url == fallback_url
    finally:
        server.stop()


def test_browser_flow_requests_compares_approves_and_installs(tmp_path):
    mainframe_path = tmp_path / "mainframe"
    agent_path = tmp_path / "agent"
    server = EnrollmentServer(mainframe_path, "127.0.0.1", 0)
    server.enrollment_window.open(5)
    server.start()
    try:
        DistributedSettingsStore(mainframe_path).save(
            {
                "role": "mainframe",
                "mainframe_listen_interfaces": ["127.0.0.1"],
                "mainframe_port": server.port,
                "agent_mainframe_url": "",
            }
        )
        DistributedSettingsStore(agent_path).save(
            {
                "role": "agent",
                "mainframe_listen_interfaces": ["127.0.0.1"],
                "mainframe_port": 5051,
                "agent_mainframe_url": f"https://127.0.0.1:{server.port}",
            }
        )
        mainframe_app = create_app(str(mainframe_path))
        mainframe_app.config.update(TESTING=False)
        mainframe_auth = AuthStore(str(mainframe_path))
        administrator = mainframe_auth.create_user(
            "mainframe-admin", "correct horse battery staple", is_admin=True
        )
        agent_app = create_app(str(agent_path))
        agent_app.config.update(TESTING=True)
        mainframe_web = mainframe_app.test_client()
        agent_web = agent_app.test_client()
        assert mainframe_web.post(
            "/login",
            data={
                "username": "mainframe-admin",
                "password": "correct horse battery staple",
            },
        ).status_code == 302

        assert agent_web.post("/mainframe/enroll").status_code == 302
        agent_page = agent_web.get("/mainframe")
        enrollment = server.agent_store.list("pending")[0]
        pairing = server.pairing_store.active_for_agent(enrollment["id"])
        assert pairing["pairing_code"].encode() in agent_page.data

        mainframe_page = mainframe_web.get("/mainframe")
        assert pairing["pairing_code"].encode() in mainframe_page.data
        assert mainframe_web.post(
            f"/settings/agents/{enrollment['id']}/approve",
            data={"pairing_code_confirmed": "on"},
        ).status_code == 302

        assert agent_web.post("/mainframe/enroll/poll").status_code == 302
        credentials = EnrollmentClient(
            agent_path, f"https://127.0.0.1:{server.port}"
        )
        assert credentials.enrolled()
        worker_status = _agent_tick(
            agent_path,
            {"agent_mainframe_url": f"https://127.0.0.1:{server.port}"},
        )
        assert worker_status["state"] == "approved"
        refreshed_mainframe = mainframe_web.get("/mainframe")
        assert b"Online" in refreshed_mainframe.data
        assert b"system.identity@1" in refreshed_mainframe.data

        selected = mainframe_web.post(
            "/execution-context",
            data={"context_id": enrollment["id"], "next": "/tools/multi-ssh"},
        )
        assert selected.status_code == 302
        assert selected.headers["Location"].endswith(
            f"/agents/{enrollment['id']}/ui/tools/multi-ssh"
        )
        assert mainframe_auth.execution_context(administrator["id"]) == enrollment["id"]
        with ThreadPoolExecutor(max_workers=1) as executor:
            selected_request = executor.submit(
                mainframe_web.get, selected.headers["Location"]
            )
            time.sleep(0.1)
            for _ in range(8):
                _agent_tick(
                    agent_path,
                    {"agent_mainframe_url": f"https://127.0.0.1:{server.port}"},
                )
                if selected_request.done():
                    break
            selected_page = selected_request.result(timeout=40)
        tunnel_jobs = mainframe_app.extensions["distributed_job_store"].recent(
            requester_id=administrator["id"]
        )
        assert selected_page.status_code == 200, [
            (item["capability_id"], item["state"], item["error"])
            for item in tunnel_jobs
        ]
        assert b'data-execution-context-select' in selected_page.data
        assert b"Bulk SSH" in selected_page.data
        assert f'/agents/{enrollment["id"]}/ui/static/styles.css'.encode() in selected_page.data
        local_navigation = mainframe_web.get("/", headers={"Accept": "text/html"})
        assert local_navigation.status_code == 302
        assert local_navigation.headers["Location"].endswith(
            f"/agents/{enrollment['id']}/ui/"
        )

        remote_dns = mainframe_web.post(
            f"/agents/{enrollment['id']}/tools/dns-response",
            data={
                "hosts": "Example = example.com",
                "servers": "Cloudflare = 1.1.1.1",
                "record_type": "A",
                "timeout": "3",
            },
        )
        assert remote_dns.status_code == 302
        assert f"/agents/{enrollment['id']}/tools/dns-response?job=" in remote_dns.headers["Location"]
        dns_result = {
            "host": "example.com",
            "host_label": "Example",
            "server": "1.1.1.1",
            "server_label": "Cloudflare",
            "record_type": "A",
            "status": "success",
            "answers": ["192.0.2.10"],
            "response_ms": 12.3,
        }
        with patch(
            "twn_toolkit.distributed_capabilities.dns_lookup_matrix",
            return_value=[dns_result],
        ):
            _agent_tick(
                agent_path,
                {"agent_mainframe_url": f"https://127.0.0.1:{server.port}"},
            )
            _agent_tick(
                agent_path,
                {"agent_mainframe_url": f"https://127.0.0.1:{server.port}"},
            )
        dns_page = mainframe_web.get(remote_dns.headers["Location"])
        assert b"Remote network tool" in dns_page.data
        assert b"192.0.2.10" in dns_page.data
        assert b"12.3 ms" in dns_page.data

        assert mainframe_web.post("/mainframe/system-identity").status_code == 302
        jobs = mainframe_app.extensions["distributed_job_store"].recent(
            requester_id=administrator["id"]
        )
        assert jobs[0]["state"] == "queued"
        _agent_tick(
            agent_path,
            {"agent_mainframe_url": f"https://127.0.0.1:{server.port}"},
        )
        _agent_tick(
            agent_path,
            {"agent_mainframe_url": f"https://127.0.0.1:{server.port}"},
        )
        completed = mainframe_app.extensions["distributed_job_store"].get(jobs[0]["id"])
        assert completed["state"] == "succeeded"
        assert completed["output"]["toolkit"]["hostname"]
        assert completed["output"]["toolkit"]["version"]
    finally:
        server.stop()


def test_enrollment_attempts_are_bounded_per_source(tmp_path):
    server = EnrollmentServer(tmp_path / "mainframe", "127.0.0.1", 0)
    server.enrollment_window.open(5)
    identity = EnrollmentClient(tmp_path / "agent", "https://unused").identity_store.load_or_create()
    payload = {
        "protocol": 1,
        "name": "Retrying Agent",
        "public_key": identity["public_key"],
        "fingerprint": identity["fingerprint"],
    }
    for _ in range(5):
        server.begin_enrollment(payload, "192.0.2.30")
    with pytest.raises(ValueError, match="Too many"):
        server.begin_enrollment(payload, "192.0.2.30")
    server.httpd.server_close()
    restarted = EnrollmentServer(tmp_path / "mainframe", "127.0.0.1", 0)
    try:
        with pytest.raises(ValueError, match="Too many"):
            restarted.begin_enrollment(payload, "192.0.2.30")
    finally:
        restarted.httpd.server_close()


def test_new_enrollment_is_closed_by_default_and_window_expires(tmp_path):
    server = EnrollmentServer(tmp_path / "mainframe", "127.0.0.1", 0)
    identity = EnrollmentClient(
        tmp_path / "agent", "https://unused"
    ).identity_store.load_or_create()
    payload = {
        "protocol": 1,
        "name": "Fresh Agent",
        "public_key": identity["public_key"],
        "fingerprint": identity["fingerprint"],
    }
    try:
        with pytest.raises(EnrollmentClosedError, match="closed"):
            server.begin_enrollment(payload, "192.0.2.31")
        status = server.enrollment_window.open(1)
        assert status["open"] is True
        assert server.begin_enrollment(payload, "192.0.2.31")["session_id"]
        with patch("twn_toolkit.distributed_agents.time.time", return_value=status["open_until"] + 1):
            assert DistributedEnrollmentWindow(tmp_path / "mainframe").status()["open"] is False
            with pytest.raises(EnrollmentClosedError, match="closed"):
                server.begin_enrollment(payload, "192.0.2.32")
    finally:
        server.httpd.server_close()
