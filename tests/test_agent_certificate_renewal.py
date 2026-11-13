from datetime import timedelta
from unittest.mock import patch

import pytest
from cryptography import x509

from twn_toolkit.distributed_transport import EnrollmentClient, EnrollmentServer, EnrollmentTransportError


def enroll(server, client):
    server.enrollment_window.open(5)
    client.begin("Renewal test")
    agent = server.agent_store.list("pending")[0]
    server.agent_store.set_state(agent["id"], "approved")
    issue = server.pki_store.issue_agent_certificate
    with patch.object(server.pki_store, "issue_agent_certificate",
                      side_effect=lambda **kwargs: issue(**kwargs, valid_days=1)):
        client.poll()
    return agent


def test_live_renewal_preserves_identity_and_mso_and_only_renews_when_due(tmp_path):
    server = EnrollmentServer(tmp_path / "hub", "127.0.0.1", 0)
    server.start()
    try:
        client = EnrollmentClient(tmp_path / "agent", f"https://127.0.0.1:{server.port}")
        agent = enroll(server, client)
        identity = client.identity_store.path.read_bytes()
        mso = client.instance_path / "mso.sqlite3"
        mso.write_bytes(b"existing MSO data")
        old = x509.load_pem_x509_certificate(client.certificate_path.read_bytes())
        result = client.heartbeat([])
        renewed = x509.load_pem_x509_certificate(client.certificate_path.read_bytes())
        assert "client_certificate" in result
        assert renewed.not_valid_after_utc > old.not_valid_after_utc + timedelta(days=28)
        assert renewed.public_key() == old.public_key()
        assert client.identity_store.path.read_bytes() == identity
        assert mso.read_bytes() == b"existing MSO data"
        assert result["agent_id"] == agent["id"]
        certificate = client.certificate_path.read_bytes()
        assert "client_certificate" not in client.heartbeat([])
        assert client.certificate_path.read_bytes() == certificate
    finally:
        server.stop()


def test_revoked_agent_cannot_renew(tmp_path):
    server = EnrollmentServer(tmp_path / "hub", "127.0.0.1", 0)
    server.start()
    try:
        client = EnrollmentClient(tmp_path / "agent", f"https://127.0.0.1:{server.port}")
        agent = enroll(server, client)
        certificate = client.certificate_path.read_bytes()
        server.agent_store.set_state(agent["id"], "revoked")
        with pytest.raises(EnrollmentTransportError, match="not approved"):
            client.heartbeat([])
        assert client.certificate_path.read_bytes() == certificate
    finally:
        server.stop()


def test_enrollment_reports_server_rejection(tmp_path):
    server = EnrollmentServer(tmp_path / "hub", "127.0.0.1", 0)
    server.start()
    try:
        client = EnrollmentClient(tmp_path / "agent", f"https://127.0.0.1:{server.port}")
        enroll(server, client)
        with pytest.raises(EnrollmentTransportError, match="already approved"):
            client.begin("Same identity")
    finally:
        server.stop()


def test_invalid_renewal_preserves_existing_certificate(tmp_path):
    server = EnrollmentServer(tmp_path / "hub", "127.0.0.1", 0)
    server.start()
    try:
        client = EnrollmentClient(tmp_path / "agent", f"https://127.0.0.1:{server.port}")
        enroll(server, client)
        certificate = client.certificate_path.read_bytes()
        with pytest.raises(EnrollmentTransportError, match="invalid renewed"):
            client._install_renewed_certificate(server.pki_store.ca_certificate_pem())
        assert client.certificate_path.read_bytes() == certificate
    finally:
        server.stop()


def test_reenrollment_preserves_mso_ids_and_deduplicates_pending_retry(tmp_path):
    from twn_toolkit.distributed_agents import DistributedSettingsStore
    from twn_toolkit.mso import MsoStore

    main_path, agent_path = tmp_path / "hub", tmp_path / "agent"
    for path, role in ((main_path, "mainframe"), (agent_path, "agent")):
        settings = DistributedSettingsStore(path)
        settings.save({**settings.get(), "role": role,
                       "agent_mainframe_url": "https://mainframe.example:5051"})
    main, local = MsoStore(main_path), MsoStore(agent_path)
    created = local.save({"name": "WAN", "targets": [{"host": "192.0.2.1", "label": ""}],
                          "interval": 2, "timeout": 1, "health_thresholds": {}}, enabled=True)
    server = EnrollmentServer(main_path, "127.0.0.1", 0)
    server.start()
    try:
        client = EnrollmentClient(agent_path, f"https://127.0.0.1:{server.port}")
        agent = enroll(server, client)
        # Deliver a proposal but lose its acknowledgement before recovery.
        pending = local.request()
        client.mso_exchange(pending)
        before = local.path.read_bytes()
        identity = client.identity_store.path.read_bytes()
        server.agent_store.set_state(agent["id"], "revoked")
        server.agent_store.remove_revoked(agent["id"])
        client.reset_credentials()
        assert local.path.read_bytes() == before
        recovered = enroll(server, client)
        assert recovered["id"] == agent["id"]
        assert client.identity_store.path.read_bytes() == identity
        assert local.request() == pending
        local.receive(client.mso_exchange(pending), pending)
        request = local.request()
        local.receive(client.mso_exchange(request), request)
        assert len(main.profiles(metadata=True)) == 1
        assert len(local.profiles(metadata=True)) == 1
        assert main.profiles(metadata=True)[0]["mso"]["id"] == created["mso"]["id"]
        assert local.profiles(metadata=True)[0]["mso"]["id"] == created["mso"]["id"]
        assert local.profiles(metadata=True)[0]["mso"]["state"] == "Synced"
    finally:
        server.stop()


def test_expired_agent_gets_recovery_instructions_without_modifying_data(tmp_path):
    from datetime import datetime, timezone
    server = EnrollmentServer(tmp_path / "hub", "127.0.0.1", 0)
    server.start()
    try:
        client = EnrollmentClient(tmp_path / "agent", f"https://127.0.0.1:{server.port}")
        enroll(server, client)
        before = client.certificate_path.read_bytes()
        future = datetime.now(timezone.utc) + timedelta(days=2)
        with patch("twn_toolkit.distributed_transport.datetime") as clock:
            clock.now.return_value = future
            with pytest.raises(EnrollmentTransportError, match="Reset local enrollment"):
                client.heartbeat([])
        assert client.certificate_path.read_bytes() == before
    finally:
        server.stop()
