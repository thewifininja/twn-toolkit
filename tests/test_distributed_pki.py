from __future__ import annotations

import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID

from twn_toolkit.distributed_pki import DistributedPkiStore, PairingSessionStore


def test_mainframe_pki_is_stable_private_and_covers_listener_addresses(tmp_path):
    store = DistributedPkiStore(tmp_path)
    first = store.ensure_mainframe_identity(
        ["192.0.2.10", "0.0.0.0"], dns_names=["mainframe.example.test"]
    )
    second = store.ensure_mainframe_identity(
        ["192.0.2.10", "0.0.0.0"], dns_names=["mainframe.example.test"]
    )

    assert first == second
    assert os.stat(store.ca_key_path).st_mode & 0o777 == 0o600
    assert os.stat(store.server_key_path).st_mode & 0o777 == 0o600
    certificate = x509.load_pem_x509_certificate(store.server_cert_path.read_bytes())
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "192.0.2.10" in [str(value) for value in san.get_values_for_type(x509.IPAddress)]
    assert "mainframe.example.test" in san.get_values_for_type(x509.DNSName)


def test_agent_certificate_is_ca_signed_client_auth_and_contains_no_private_key(tmp_path):
    store = DistributedPkiStore(tmp_path)
    store.ensure_mainframe_identity(["127.0.0.1"])
    agent_key = Ed25519PrivateKey.generate()
    public_key = agent_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    pem = store.issue_agent_certificate(
        agent_id="agent_0123456789abcdef", public_key=public_key.hex()
    )

    certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
    usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in usage
    assert certificate.issuer == x509.load_pem_x509_certificate(
        store.ca_cert_path.read_bytes()
    ).subject
    assert "PRIVATE" not in pem


def test_pairing_session_code_binds_both_identities_and_token_is_not_persisted(tmp_path):
    store = PairingSessionStore(tmp_path)
    session = store.create(
        agent_id="agent_a",
        agent_public_key=bytes(range(32)).hex(),
        mainframe_public_key=bytes(reversed(range(32))).hex(),
    )

    authenticated = store.authenticate(session["id"], session["token"])
    assert authenticated["pairing_code"] == session["pairing_code"]
    assert len(session["pairing_code"]) == 6
    assert session["token"] not in store.path.read_bytes().decode("latin-1")
    with pytest.raises(ValueError, match="invalid"):
        store.authenticate(session["id"], "wrong token")


def test_pairing_session_can_only_be_consumed_once(tmp_path):
    store = PairingSessionStore(tmp_path)
    session = store.create(
        agent_id="agent_a",
        agent_public_key=bytes(range(32)).hex(),
        mainframe_public_key=bytes(reversed(range(32))).hex(),
    )

    assert store.consume(session["id"], session["token"])["consumed_at"]
    with pytest.raises(ValueError, match="consumed"):
        store.consume(session["id"], session["token"])
