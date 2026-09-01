from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .distributed_agents import pairing_code


PAIRING_LIFETIME_SECONDS = 10 * 60
CLIENT_CERTIFICATE_DAYS = 30


class DistributedPkiStore:
    """Toolkit-managed CA, listener certificate, and bounded client issuance."""

    def __init__(self, instance_path: str | Path) -> None:
        self.root = Path(instance_path) / "distributed_pki"
        self.ca_key_path = self.root / "ca-key.pem"
        self.ca_cert_path = self.root / "ca-cert.pem"
        self.server_key_path = self.root / "server-key.pem"
        self.server_cert_path = self.root / "server-cert.pem"

    def ensure_mainframe_identity(
        self, listen_interfaces: list[str], *, dns_names: list[str] | None = None
    ) -> dict[str, str]:
        addresses = _addresses(listen_interfaces)
        names = _dns_names(dns_names or [])
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        ca_key, ca_cert = self._load_or_create_ca()
        if not self._server_certificate_covers(addresses, names, ca_cert):
            self._write_server_identity(ca_key, ca_cert, addresses, names)
        return self.status()

    def status(self) -> dict[str, str]:
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        server_cert = x509.load_pem_x509_certificate(self.server_cert_path.read_bytes())
        return {
            "ca_fingerprint": ca_cert.fingerprint(hashes.SHA256()).hex(),
            "server_fingerprint": server_cert.fingerprint(hashes.SHA256()).hex(),
            "server_expires_at": server_cert.not_valid_after_utc.isoformat(timespec="seconds"),
        }

    def issue_agent_certificate(
        self, *, agent_id: str, public_key: str, valid_days: int = CLIENT_CERTIFICATE_DAYS
    ) -> str:
        if not agent_id.startswith("agent_") or len(agent_id) > 80:
            raise ValueError("Invalid agent identity.")
        if not 1 <= int(valid_days) <= 90:
            raise ValueError("Agent certificate lifetime must be between 1 and 90 days.")
        try:
            public_bytes = bytes.fromhex(public_key)
            agent_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        except (ValueError, TypeError) as exc:
            raise ValueError("Agent public key must be a 32-byte Ed25519 key.") from exc
        if len(public_bytes) != 32:
            raise ValueError("Agent public key must be a 32-byte Ed25519 key.")
        ca_key, ca_cert = self._load_ca()
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
            .issuer_name(ca_cert.subject)
            .public_key(agent_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=2))
            .not_valid_after(now + timedelta(days=int(valid_days)))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(agent_public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def ca_certificate_pem(self) -> str:
        return self.ca_cert_path.read_text(encoding="ascii")

    def _load_or_create_ca(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        if self.ca_key_path.exists() or self.ca_cert_path.exists():
            key, certificate = self._load_ca()
            try:
                certificate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                )
                certificate.extensions.get_extension_for_class(
                    x509.AuthorityKeyIdentifier
                )
            except x509.ExtensionNotFound:
                certificate = self._build_ca_certificate(key)
                _public_write(
                    self.ca_cert_path,
                    certificate.public_bytes(serialization.Encoding.PEM),
                )
            return key, certificate
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = self._build_ca_certificate(key)
        _private_write(
            self.ca_key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        _public_write(
            self.ca_cert_path, certificate.public_bytes(serialization.Encoding.PEM)
        )
        return key, certificate

    def _build_ca_certificate(self, key: rsa.RSAPrivateKey) -> x509.Certificate:
        now = datetime.now(timezone.utc)
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "TWN Toolkit Mainframe CA")]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return certificate

    def _load_ca(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        if self.ca_key_path.stat().st_mode & 0o077:
            raise RuntimeError("Distributed CA private key permissions are too broad.")
        key = serialization.load_pem_private_key(
            self.ca_key_path.read_bytes(), password=None
        )
        certificate = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        if not isinstance(key, rsa.RSAPrivateKey):
            raise RuntimeError("Distributed CA key is not an RSA private key.")
        if certificate.public_key().public_numbers() != key.public_key().public_numbers():
            raise RuntimeError("Distributed CA certificate and private key do not match.")
        return key, certificate

    def _server_certificate_covers(
        self,
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
        names: list[str],
        ca_cert: x509.Certificate,
    ) -> bool:
        if not self.server_key_path.exists() or not self.server_cert_path.exists():
            return False
        try:
            if self.server_key_path.stat().st_mode & 0o077:
                return False
            certificate = x509.load_pem_x509_certificate(self.server_cert_path.read_bytes())
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            cert_addresses = set(san.get_values_for_type(x509.IPAddress))
            cert_names = set(san.get_values_for_type(x509.DNSName))
            certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            return (
                certificate.issuer == ca_cert.subject
                and certificate.not_valid_after_utc > datetime.now(timezone.utc) + timedelta(days=7)
                and set(addresses).issubset(cert_addresses)
                and set(names).issubset(cert_names)
            )
        except (OSError, ValueError, x509.ExtensionNotFound):
            return False

    def _write_server_identity(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
        names: list[str],
    ) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject_name = next((name for name in names if len(name) <= 64), "twn-mainframe")
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=2))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName(
                    [*(x509.IPAddress(value) for value in addresses), *(x509.DNSName(value) for value in names)]
                ),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        _private_write(
            self.server_key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        _public_write(
            self.server_cert_path, certificate.public_bytes(serialization.Encoding.PEM)
        )


class PairingSessionStore:
    """Short-lived bootstrap sessions authenticated by an unexported bearer token."""

    def __init__(self, instance_path: str | Path) -> None:
        instance = Path(instance_path)
        instance.mkdir(parents=True, exist_ok=True)
        self.path = instance / "distributed_agents.sqlite3"
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS distributed_pairing_sessions (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    pairing_code TEXT NOT NULL,
                    transcript_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                )
                """
            )

    def create(
        self, *, agent_id: str, agent_public_key: str, mainframe_public_key: str
    ) -> dict[str, Any]:
        agent_key = _canonical_key(agent_public_key, "agent")
        mainframe_key = _canonical_key(mainframe_public_key, "mainframe")
        nonce = secrets.token_hex(32)
        token = secrets.token_urlsafe(32)
        transcript = json.dumps(
            _pairing_transcript(agent_id, agent_key, mainframe_key, nonce),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        now = time.time()
        session_id = f"pair_{secrets.token_hex(16)}"
        item = {
            "id": session_id,
            "agent_id": agent_id,
            "token": token,
            "pairing_code": pairing_code(transcript),
            "transcript_hash": hashlib.sha256(transcript).hexdigest(),
            "created_at": now,
            "expires_at": now + PAIRING_LIFETIME_SECONDS,
            "transcript": _pairing_transcript(
                agent_id, agent_key, mainframe_key, nonce
            ),
        }
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO distributed_pairing_sessions
                    (id, agent_id, token_hash, pairing_code, transcript_hash,
                     created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["id"],
                    agent_id,
                    _token_hash(token),
                    item["pairing_code"],
                    item["transcript_hash"],
                    item["created_at"],
                    item["expires_at"],
                ),
            )
        return item

    def active_for_agent(self, agent_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, agent_id, pairing_code, transcript_hash, created_at,
                       expires_at, consumed_at
                FROM distributed_pairing_sessions
                WHERE agent_id = ? AND consumed_at IS NULL AND expires_at > ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (agent_id, time.time()),
            ).fetchone()
        return dict(row) if row else None

    def authenticate(self, session_id: str, token: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM distributed_pairing_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        if not row or not secrets.compare_digest(str(row["token_hash"]), _token_hash(token)):
            raise ValueError("Pairing session credentials are invalid.")
        if row["consumed_at"] is not None:
            raise ValueError("Pairing session has already been consumed.")
        if float(row["expires_at"]) <= time.time():
            raise ValueError("Pairing session has expired.")
        return {key: row[key] for key in row.keys() if key != "token_hash"}

    def consume(self, session_id: str, token: str) -> dict[str, Any]:
        item = self.authenticate(session_id, token)
        consumed_at = time.time()
        with self._connect() as connection:
            connection.execute(
                "UPDATE distributed_pairing_sessions SET consumed_at = ? WHERE id = ?",
                (consumed_at, session_id),
            )
        return {**item, "consumed_at": consumed_at}

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection


def _addresses(values: list[str]) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    addresses = []
    for value in values:
        address = ipaddress.ip_address(value)
        if address.is_unspecified:
            continue
        if address not in addresses:
            addresses.append(address)
    for loopback in (ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")):
        if loopback not in addresses:
            addresses.append(loopback)
    return addresses


def _dns_names(values: list[str]) -> list[str]:
    names = ["localhost"]
    for raw_value in values:
        value = str(raw_value).strip().lower()
        if not value or len(value) > 253 or "." not in value:
            raise ValueError(f"Invalid mainframe certificate name: {value or 'empty'}")
        if value not in names:
            names.append(value)
    return names


def _canonical_key(value: str, label: str) -> str:
    try:
        decoded = bytes.fromhex(str(value))
    except ValueError as exc:
        raise ValueError(f"Invalid {label} public key.") from exc
    if len(decoded) != 32:
        raise ValueError(f"Invalid {label} public key.")
    return decoded.hex()


def canonical_pairing_transcript(payload: dict[str, Any]) -> bytes:
    transcript = _pairing_transcript(
        str(payload.get("agent_id", "")),
        _canonical_key(str(payload.get("agent_public_key", "")), "agent"),
        _canonical_key(str(payload.get("mainframe_public_key", "")), "mainframe"),
        str(payload.get("nonce", "")),
    )
    if len(transcript["nonce"]) != 64:
        raise ValueError("Invalid pairing nonce.")
    try:
        bytes.fromhex(transcript["nonce"])
    except ValueError as exc:
        raise ValueError("Invalid pairing nonce.") from exc
    return json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode("ascii")


def _pairing_transcript(
    agent_id: str, agent_public_key: str, mainframe_public_key: str, nonce: str
) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "agent_public_key": agent_public_key,
        "mainframe_public_key": mainframe_public_key,
        "nonce": nonce,
        "protocol": 1,
    }


def _token_hash(token: str) -> str:
    return hashlib.sha256(b"twn-enrollment-token-v1\0" + str(token).encode("utf-8")).hexdigest()


def _private_write(path: Path, content: bytes) -> None:
    _atomic_write(path, content, 0o600)


def _public_write(path: Path, content: bytes) -> None:
    _atomic_write(path, content, 0o644)


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    fd, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
