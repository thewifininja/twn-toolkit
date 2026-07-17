from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

import requests
from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from requests.adapters import HTTPAdapter

from .certificate_tools import HOSTNAME_PATTERN


MAX_CA_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 2 * 1024 * 1024
MAX_DNS_NAMES = 20
VALID_KEY_SIZES = {2048, 3072, 4096}


class CertificateAutomationError(RuntimeError):
    pass


class CertificateStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class EnrollmentResult:
    status: str
    request_id: str
    ca_name: str = ""
    message: str = ""
    certificate_pem: bytes = b""
    chain_pem: bytes = b""
    backend: str = ""


class CertificateAutomationStore:
    """Encrypted local state for PKI profiles and managed certificates."""

    def __init__(self, instance_path: str, secret_key: str) -> None:
        self.path = Path(instance_path) / "certificate_automation.sqlite3"
        encryption_key = base64.urlsafe_b64encode(
            hashlib.sha256(secret_key.encode("utf-8")).digest()
        )
        self._cipher = Fernet(encryption_key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS pki_credentials (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    username TEXT NOT NULL,
                    password_encrypted TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pki_servers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    provider TEXT NOT NULL,
                    enrollment_url TEXT NOT NULL,
                    credential_id TEXT,
                    ca_bundle_pem TEXT NOT NULL DEFAULT '',
                    retrieval_strategy TEXT NOT NULL DEFAULT 'same_endpoint',
                    timeout REAL NOT NULL DEFAULT 15,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (credential_id) REFERENCES pki_credentials(id) ON DELETE SET NULL
                );
                CREATE TABLE IF NOT EXISTS pki_templates (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    server_id TEXT NOT NULL,
                    template_identifier TEXT NOT NULL,
                    key_size INTEGER NOT NULL DEFAULT 2048,
                    renewal_days INTEGER NOT NULL DEFAULT 30,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (server_id) REFERENCES pki_servers(id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS managed_certificates (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    server_id TEXT NOT NULL,
                    template_id TEXT NOT NULL,
                    common_name TEXT NOT NULL,
                    dns_names_json TEXT NOT NULL,
                    current_version_id TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (server_id) REFERENCES pki_servers(id) ON DELETE RESTRICT,
                    FOREIGN KEY (template_id) REFERENCES pki_templates(id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS certificate_versions (
                    id TEXT PRIMARY KEY,
                    managed_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_id TEXT NOT NULL DEFAULT '',
                    ca_name TEXT NOT NULL DEFAULT '',
                    backend TEXT NOT NULL DEFAULT '',
                    message TEXT NOT NULL DEFAULT '',
                    private_key_encrypted TEXT NOT NULL,
                    certificate_pem TEXT NOT NULL DEFAULT '',
                    chain_pem TEXT NOT NULL DEFAULT '',
                    serial_number TEXT NOT NULL DEFAULT '',
                    fingerprint_sha256 TEXT NOT NULL DEFAULT '',
                    not_before TEXT NOT NULL DEFAULT '',
                    not_after TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    FOREIGN KEY (managed_id) REFERENCES managed_certificates(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS certificate_versions_managed
                    ON certificate_versions(managed_id, created_at DESC);
                """
            )
        os.chmod(self.path, 0o600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def _new_id() -> str:
        return secrets.token_hex(12)

    def _encrypt(self, value: bytes | str) -> str:
        payload = value.encode("utf-8") if isinstance(value, str) else value
        return self._cipher.encrypt(payload).decode("ascii")

    def _decrypt(self, value: str) -> bytes:
        try:
            return self._cipher.decrypt(value.encode("ascii"))
        except InvalidToken as exc:
            raise CertificateStoreError(
                "Could not decrypt saved certificate credentials or keys."
            ) from exc

    def credential_profiles(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, name, username, updated_at FROM pki_credentials ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [dict(row) | {"has_password": True} for row in rows]

    def credential_profile(
        self, credential_id: str, *, include_password: bool = False
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM pki_credentials WHERE id = ?", (credential_id,)
            ).fetchone()
        if not row:
            return None
        profile = dict(row)
        encrypted = profile.pop("password_encrypted")
        profile["has_password"] = bool(encrypted)
        if include_password:
            profile["password"] = self._decrypt(encrypted).decode("utf-8")
        return profile

    def save_credential(
        self, *, credential_id: str, name: str, username: str, password: str
    ) -> dict[str, Any]:
        now = time.time()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT password_encrypted, created_at FROM pki_credentials WHERE id = ?",
                (credential_id,),
            ).fetchone()
            if not password and not existing:
                raise ValueError("Enter a password for the new credential profile.")
            encrypted = self._encrypt(password) if password else existing["password_encrypted"]
            created_at = float(existing["created_at"]) if existing else now
            credential_id = credential_id or self._new_id()
            try:
                connection.execute(
                    """
                    INSERT INTO pki_credentials
                        (id, name, username, password_encrypted, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name, username = excluded.username,
                        password_encrypted = excluded.password_encrypted,
                        updated_at = excluded.updated_at
                    """,
                    (credential_id, name, username, encrypted, created_at, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A credential profile already uses that name.") from exc
        return self.credential_profile(credential_id) or {}

    def delete_credential(self, credential_id: str) -> bool:
        with self._connect() as connection:
            result = connection.execute(
                "DELETE FROM pki_credentials WHERE id = ?", (credential_id,)
            )
        return bool(result.rowcount)

    def server_profiles(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT s.*, c.name AS credential_name
                FROM pki_servers s LEFT JOIN pki_credentials c ON c.id = s.credential_id
                ORDER BY s.name COLLATE NOCASE
                """
            ).fetchall()
        return [dict(row) | {"has_ca_bundle": bool(row["ca_bundle_pem"])} for row in rows]

    def server_profile(self, server_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT s.*, c.name AS credential_name
                FROM pki_servers s LEFT JOIN pki_credentials c ON c.id = s.credential_id
                WHERE s.id = ?
                """,
                (server_id,),
            ).fetchone()
        return dict(row) | {"has_ca_bundle": bool(row["ca_bundle_pem"])} if row else None

    def save_server(self, values: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        server_id = str(values.get("id", "")) or self._new_id()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT created_at, ca_bundle_pem FROM pki_servers WHERE id = ?", (server_id,)
            ).fetchone()
            ca_bundle = str(values.get("ca_bundle_pem", ""))
            if values.get("remove_ca_bundle"):
                ca_bundle = ""
            elif values.get("keep_ca_bundle") and existing:
                ca_bundle = str(existing["ca_bundle_pem"])
            try:
                connection.execute(
                    """
                    INSERT INTO pki_servers
                        (id, name, provider, enrollment_url, credential_id, ca_bundle_pem,
                         retrieval_strategy, timeout, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name, provider = excluded.provider,
                        enrollment_url = excluded.enrollment_url,
                        credential_id = excluded.credential_id,
                        ca_bundle_pem = excluded.ca_bundle_pem,
                        retrieval_strategy = excluded.retrieval_strategy,
                        timeout = excluded.timeout, updated_at = excluded.updated_at
                    """,
                    (
                        server_id,
                        values["name"],
                        values["provider"],
                        values["enrollment_url"],
                        values.get("credential_id") or None,
                        ca_bundle,
                        values["retrieval_strategy"],
                        values["timeout"],
                        float(existing["created_at"]) if existing else now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A PKI server profile already uses that name.") from exc
        return self.server_profile(server_id) or {}

    def delete_server(self, server_id: str) -> bool:
        try:
            with self._connect() as connection:
                result = connection.execute("DELETE FROM pki_servers WHERE id = ?", (server_id,))
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "This PKI server is still used by a template or managed certificate."
            ) from exc
        return bool(result.rowcount)

    def template_profiles(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT t.*, s.name AS server_name
                FROM pki_templates t JOIN pki_servers s ON s.id = t.server_id
                ORDER BY t.name COLLATE NOCASE
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def template_profile(self, template_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT t.*, s.name AS server_name
                FROM pki_templates t JOIN pki_servers s ON s.id = t.server_id
                WHERE t.id = ?
                """,
                (template_id,),
            ).fetchone()
        return dict(row) if row else None

    def save_template(self, values: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        template_id = str(values.get("id", "")) or self._new_id()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT created_at FROM pki_templates WHERE id = ?", (template_id,)
            ).fetchone()
            try:
                connection.execute(
                    """
                    INSERT INTO pki_templates
                        (id, name, server_id, template_identifier, key_size,
                         renewal_days, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name, server_id = excluded.server_id,
                        template_identifier = excluded.template_identifier,
                        key_size = excluded.key_size, renewal_days = excluded.renewal_days,
                        updated_at = excluded.updated_at
                    """,
                    (
                        template_id,
                        values["name"],
                        values["server_id"],
                        values["template_identifier"],
                        values["key_size"],
                        values["renewal_days"],
                        float(existing["created_at"]) if existing else now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                message = (
                    "A certificate template profile already uses that name."
                    if "name" in str(exc).lower()
                    else "Select a valid PKI server profile."
                )
                raise ValueError(message) from exc
        return self.template_profile(template_id) or {}

    def delete_template(self, template_id: str) -> bool:
        try:
            with self._connect() as connection:
                result = connection.execute(
                    "DELETE FROM pki_templates WHERE id = ?", (template_id,)
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("This template is still used by a managed certificate.") from exc
        return bool(result.rowcount)

    def managed_certificates(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT m.*, t.name AS template_name, s.name AS server_name,
                       v.status, v.request_id, v.not_before, v.not_after,
                       v.fingerprint_sha256, v.serial_number, v.message,
                       (SELECT COUNT(*) FROM certificate_versions cv WHERE cv.managed_id = m.id)
                           AS version_count
                FROM managed_certificates m
                JOIN pki_templates t ON t.id = m.template_id
                JOIN pki_servers s ON s.id = m.server_id
                LEFT JOIN certificate_versions v ON v.id = m.current_version_id
                ORDER BY m.name COLLATE NOCASE
                """
            ).fetchall()
        return [self._managed_row(row) for row in rows]

    def managed_certificate(self, managed_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT m.*, t.name AS template_name, t.template_identifier,
                       t.key_size, t.renewal_days, s.name AS server_name,
                       v.status, v.request_id, v.not_before, v.not_after,
                       v.fingerprint_sha256, v.serial_number, v.message,
                       v.ca_name, v.backend,
                       (SELECT COUNT(*) FROM certificate_versions cv WHERE cv.managed_id = m.id)
                           AS version_count
                FROM managed_certificates m
                JOIN pki_templates t ON t.id = m.template_id
                JOIN pki_servers s ON s.id = m.server_id
                LEFT JOIN certificate_versions v ON v.id = m.current_version_id
                WHERE m.id = ?
                """,
                (managed_id,),
            ).fetchone()
            if not row:
                return None
            versions = connection.execute(
                """
                SELECT id, status, request_id, ca_name, backend, message,
                       serial_number, fingerprint_sha256, not_before, not_after, created_at,
                       certificate_pem != '' AS has_certificate
                FROM certificate_versions WHERE managed_id = ? ORDER BY created_at DESC
                """,
                (managed_id,),
            ).fetchall()
        result = self._managed_row(row)
        result["versions"] = [
            dict(version)
            | {
                "created_at_display": datetime.fromtimestamp(
                    float(version["created_at"]), timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
            }
            for version in versions
        ]
        return result

    @staticmethod
    def _managed_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["dns_names"] = json.loads(result.pop("dns_names_json"))
        not_after = result.get("not_after")
        result["days_remaining"] = None
        if not_after:
            expires = datetime.fromisoformat(str(not_after))
            result["days_remaining"] = (expires - datetime.now(timezone.utc)).days
        return result

    def save_enrollment(
        self,
        *,
        managed_id: str,
        name: str,
        server_id: str,
        template_id: str,
        common_name: str,
        dns_names: list[str],
        private_key_pem: bytes,
        result: EnrollmentResult,
    ) -> dict[str, Any]:
        now = time.time()
        managed_id = managed_id or self._new_id()
        version_id = self._new_id()
        certificate_details = _stored_certificate_details(result.certificate_pem)
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT created_at FROM managed_certificates WHERE id = ?", (managed_id,)
            ).fetchone()
            try:
                connection.execute(
                    """
                    INSERT INTO managed_certificates
                        (id, name, server_id, template_id, common_name, dns_names_json,
                         current_version_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name, server_id = excluded.server_id,
                        template_id = excluded.template_id, common_name = excluded.common_name,
                        dns_names_json = excluded.dns_names_json,
                        current_version_id = excluded.current_version_id,
                        updated_at = excluded.updated_at
                    """,
                    (
                        managed_id,
                        name,
                        server_id,
                        template_id,
                        common_name,
                        json.dumps(dns_names),
                        version_id,
                        float(existing["created_at"]) if existing else now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO certificate_versions
                        (id, managed_id, status, request_id, ca_name, backend, message,
                         private_key_encrypted, certificate_pem, chain_pem, serial_number,
                         fingerprint_sha256, not_before, not_after, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        version_id,
                        managed_id,
                        result.status,
                        result.request_id,
                        result.ca_name,
                        result.backend,
                        result.message,
                        self._encrypt(private_key_pem),
                        result.certificate_pem.decode("ascii") if result.certificate_pem else "",
                        result.chain_pem.decode("ascii") if result.chain_pem else "",
                        certificate_details["serial_number"],
                        certificate_details["fingerprint_sha256"],
                        certificate_details["not_before"],
                        certificate_details["not_after"],
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A managed certificate already uses that name.") from exc
        return self.managed_certificate(managed_id) or {}

    def version_material(self, managed_id: str, version_id: str = "") -> dict[str, Any] | None:
        with self._connect() as connection:
            if version_id:
                row = connection.execute(
                    "SELECT * FROM certificate_versions WHERE id = ? AND managed_id = ?",
                    (version_id, managed_id),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT v.* FROM certificate_versions v
                    JOIN managed_certificates m ON m.current_version_id = v.id
                    WHERE m.id = ?
                    """,
                    (managed_id,),
                ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["private_key_pem"] = self._decrypt(result.pop("private_key_encrypted"))
        result["certificate_pem"] = result["certificate_pem"].encode("ascii")
        result["chain_pem"] = result["chain_pem"].encode("ascii")
        return result

    def complete_pending_version(
        self, managed_id: str, version_id: str, result: EnrollmentResult
    ) -> dict[str, Any]:
        if result.status != "issued" or not result.certificate_pem:
            raise ValueError("Only an issued certificate can complete a pending request.")
        details = _stored_certificate_details(result.certificate_pem)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM certificate_versions WHERE id = ? AND managed_id = ?",
                (version_id, managed_id),
            ).fetchone()
            if not row or row["status"] != "pending":
                raise ValueError("The pending certificate request was not found.")
            connection.execute(
                """
                UPDATE certificate_versions SET
                    status = 'issued', ca_name = ?, backend = ?, message = ?,
                    certificate_pem = ?, chain_pem = ?, serial_number = ?,
                    fingerprint_sha256 = ?, not_before = ?, not_after = ?
                WHERE id = ? AND managed_id = ?
                """,
                (
                    result.ca_name,
                    result.backend,
                    result.message,
                    result.certificate_pem.decode("ascii"),
                    result.chain_pem.decode("ascii"),
                    details["serial_number"],
                    details["fingerprint_sha256"],
                    details["not_before"],
                    details["not_after"],
                    version_id,
                    managed_id,
                ),
            )
            connection.execute(
                "UPDATE managed_certificates SET current_version_id = ?, updated_at = ? WHERE id = ?",
                (version_id, time.time(), managed_id),
            )
        return self.managed_certificate(managed_id) or {}

    def delete_managed_certificate(self, managed_id: str) -> bool:
        with self._connect() as connection:
            result = connection.execute(
                "DELETE FROM managed_certificates WHERE id = ?", (managed_id,)
            )
        return bool(result.rowcount)

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()


def validate_enrollment_url(value: str) -> str:
    candidate = value.strip().rstrip("/")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Enter an HTTPS AD CS Web Enrollment URL without credentials or query text.")
    path = parsed.path.rstrip("/")
    if not path:
        path = "/certsrv"
    if not path.lower().endswith("/certsrv"):
        raise ValueError("The AD CS Web Enrollment URL must end in /certsrv.")
    return urlunsplit(("https", parsed.netloc, path, "", ""))


def validate_ca_bundle(content: bytes) -> str:
    if not content:
        return ""
    if len(content) > MAX_CA_BUNDLE_BYTES:
        raise ValueError("The CA bundle must be 2 MiB or smaller.")
    certificates = []
    marker = b"-----END CERTIFICATE-----"
    for part in content.split(marker):
        if b"-----BEGIN CERTIFICATE-----" not in part:
            continue
        pem = part[part.index(b"-----BEGIN CERTIFICATE-----") :] + marker + b"\n"
        try:
            certificates.append(x509.load_pem_x509_certificate(pem))
        except ValueError as exc:
            raise ValueError("The uploaded CA bundle contains an invalid PEM certificate.") from exc
    if not certificates:
        raise ValueError("Upload a PEM-encoded CA certificate bundle.")
    return b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certificates).decode(
        "ascii"
    )


def validate_template_identifier(value: str) -> str:
    identifier = value.strip()
    if not identifier or len(identifier) > 255 or not re.fullmatch(r"[A-Za-z0-9_. -]+", identifier):
        raise ValueError(
            "Enter a certificate template name or OID using letters, numbers, spaces, "
            "dots, underscores, or hyphens."
        )
    return identifier


def normalize_certificate_identity(
    common_name: str, dns_names: list[str] | str
) -> tuple[str, list[str]]:
    common_name = common_name.strip().rstrip(".").lower()
    if not common_name or len(common_name) > 64 or not _valid_dns_name(common_name):
        raise ValueError("Enter a valid DNS Common Name of 64 characters or fewer.")
    if isinstance(dns_names, str):
        values = re.split(r"[\s,]+", dns_names)
    else:
        values = dns_names
    normalized: list[str] = []
    for value in values:
        name = value.strip().rstrip(".").lower()
        if not name:
            continue
        if not _valid_dns_name(name):
            raise ValueError(f"Invalid DNS Subject Alternative Name: {value}")
        if name not in normalized:
            normalized.append(name)
    if common_name in normalized:
        normalized.remove(common_name)
    normalized.insert(0, common_name)
    if len(normalized) > MAX_DNS_NAMES:
        raise ValueError(f"Enter no more than {MAX_DNS_NAMES} DNS names.")
    return common_name, normalized


def _valid_dns_name(value: str) -> bool:
    if value.startswith("*."):
        value = value[2:]
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return bool(HOSTNAME_PATTERN.fullmatch(ascii_value))


def load_or_generate_private_key(
    *, key_size: int, existing_key: bytes = b"", password: str = ""
) -> rsa.RSAPrivateKey:
    if key_size not in VALID_KEY_SIZES:
        raise ValueError("Select a 2048, 3072, or 4096-bit RSA key.")
    if not existing_key:
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if len(existing_key) > MAX_PRIVATE_KEY_BYTES:
        raise ValueError("The private key must be 2 MiB or smaller.")
    try:
        key = serialization.load_pem_private_key(
            existing_key, password=password.encode("utf-8") if password else None
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("The private key or its passphrase is invalid.") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("The first release supports RSA private keys only.")
    if key.key_size not in VALID_KEY_SIZES:
        raise ValueError("The RSA private key must be 2048, 3072, or 4096 bits.")
    return key


def build_certificate_request(
    common_name: str, dns_names: list[str], private_key: rsa.RSAPrivateKey
) -> tuple[bytes, bytes]:
    common_name, dns_names = normalize_certificate_identity(common_name, dns_names)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(private_key, hashes.SHA256())
    )
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key_pem, csr.public_bytes(serialization.Encoding.PEM)


def validate_issued_certificate(
    certificate_pem: bytes,
    private_key_pem: bytes,
    common_name: str,
    dns_names: list[str],
) -> x509.Certificate:
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise CertificateAutomationError("The issued certificate or saved private key is invalid.") from exc
    cert_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if cert_public != key_public:
        raise CertificateAutomationError("The issued certificate does not match the private key.")
    try:
        issued_names = {
            name.lower()
            for name in certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        }
    except x509.ExtensionNotFound as exc:
        raise CertificateAutomationError(
            "The issued certificate has no DNS Subject Alternative Names."
        ) from exc
    missing = sorted(set(name.lower() for name in dns_names) - issued_names)
    if missing:
        raise CertificateAutomationError(
            "The issued certificate is missing requested DNS names: " + ", ".join(missing)
        )
    try:
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateAutomationError(
            "The issued certificate has no Extended Key Usage extension."
        ) from exc
    if ExtendedKeyUsageOID.SERVER_AUTH not in usages:
        raise CertificateAutomationError("The issued certificate does not permit TLS server authentication.")
    if certificate.not_valid_after_utc <= datetime.now(timezone.utc):
        raise CertificateAutomationError("The issued certificate is already expired.")
    return certificate


def _stored_certificate_details(certificate_pem: bytes) -> dict[str, str]:
    if not certificate_pem:
        return {key: "" for key in ("serial_number", "fingerprint_sha256", "not_before", "not_after")}
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    return {
        "serial_number": format(certificate.serial_number, "X"),
        "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(":"),
        "not_before": certificate.not_valid_before_utc.isoformat(timespec="seconds"),
        "not_after": certificate.not_valid_after_utc.isoformat(timespec="seconds"),
    }


class _DirectAddressAdapter(HTTPAdapter):
    def __init__(self, hostname: str, *args: Any, **kwargs: Any) -> None:
        self.hostname = hostname
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **kwargs: Any) -> None:
        kwargs["server_hostname"] = self.hostname
        kwargs["assert_hostname"] = self.hostname
        super().init_poolmanager(connections, maxsize, block=block, **kwargs)


class AdcsWebEnrollmentProvider:
    provider_id = "adcs_web_enrollment"

    def __init__(
        self,
        profile: dict[str, Any],
        username: str,
        password: str,
        *,
        session: requests.Session | None = None,
    ) -> None:
        self.profile = profile
        self.username = username
        self.password = password
        self.base_url = validate_enrollment_url(str(profile["enrollment_url"]))
        self.timeout = float(profile.get("timeout", 15))
        self.session = session or self._authenticated_session()

    def _authenticated_session(self) -> requests.Session:
        try:
            from requests_ntlm import HttpNtlmAuth
        except ImportError as exc:
            raise CertificateAutomationError(
                "AD CS enrollment requires the requests-ntlm runtime dependency."
            ) from exc
        session = requests.Session()
        session.auth = HttpNtlmAuth(self.username, self.password)
        session.headers.update({"User-Agent": "TWN-Toolkit-Certificate-Automation/1"})
        return session

    @contextmanager
    def _verify_value(self) -> Iterator[bool | str]:
        ca_bundle = str(self.profile.get("ca_bundle_pem", ""))
        if not ca_bundle:
            yield True
            return
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", prefix="twn-pki-ca-", suffix=".pem", delete=False
        )
        try:
            handle.write(ca_bundle)
            handle.close()
            os.chmod(handle.name, 0o600)
            yield handle.name
        finally:
            try:
                os.unlink(handle.name)
            except FileNotFoundError:
                pass

    def test_connection(self) -> int:
        with self._verify_value() as verify:
            try:
                response = self.session.get(
                    self.base_url + "/", timeout=self.timeout, verify=verify, allow_redirects=False
                )
            except requests.RequestException as exc:
                raise CertificateAutomationError(_request_error(exc)) from exc
        if response.status_code == 401:
            raise CertificateAutomationError("The PKI server rejected the enrollment credentials.")
        if response.status_code >= 500:
            raise CertificateAutomationError(
                f"The PKI server returned HTTP {response.status_code}."
            )
        return response.status_code

    def enroll(
        self,
        csr_pem: bytes,
        template_identifier: str,
        private_key_pem: bytes,
        common_name: str,
        dns_names: list[str],
    ) -> EnrollmentResult:
        with self._verify_value() as verify:
            try:
                response = self.session.post(
                    self.base_url + "/certfnsh.asp",
                    data={
                        "Mode": "newreq",
                        "CertRequest": csr_pem.decode("ascii"),
                        "CertAttrib": f"CertificateTemplate:{template_identifier}",
                        "FriendlyType": "Saved-Request Certificate",
                        "TargetStoreFlags": "0",
                        "SaveCert": "yes",
                    },
                    timeout=self.timeout,
                    verify=verify,
                    allow_redirects=False,
                )
            except requests.RequestException as exc:
                raise CertificateAutomationError(_request_error(exc)) from exc
            if response.status_code == 401:
                raise CertificateAutomationError("The PKI server rejected the enrollment credentials.")
            if response.status_code >= 400:
                raise CertificateAutomationError(
                    f"The PKI server returned HTTP {response.status_code} while submitting the request."
                )
            status, request_id, ca_name, message = parse_adcs_response(response.text)
            if status != "issued":
                return EnrollmentResult(status, request_id, ca_name, message)
            certificate_pem, chain_pem, backend = self._retrieve_issued(
                request_id, private_key_pem, verify
            )
        validate_issued_certificate(
            certificate_pem, private_key_pem, common_name, dns_names
        )
        return EnrollmentResult(
            "issued", request_id, ca_name, message, certificate_pem, chain_pem, backend
        )

    def retrieve(
        self,
        request_id: str,
        private_key_pem: bytes,
        common_name: str,
        dns_names: list[str],
        *,
        ca_name: str = "",
    ) -> EnrollmentResult:
        if not request_id.isdigit():
            raise CertificateAutomationError("The pending request has no valid AD CS request ID.")
        with self._verify_value() as verify:
            certificate_pem, chain_pem, backend = self._retrieve_issued(
                request_id, private_key_pem, verify
            )
        validate_issued_certificate(
            certificate_pem, private_key_pem, common_name, dns_names
        )
        return EnrollmentResult(
            "issued",
            request_id,
            ca_name,
            "Pending request is now issued.",
            certificate_pem,
            chain_pem,
            backend,
        )

    def _retrieve_issued(
        self, request_id: str, private_key_pem: bytes, verify: bool | str
    ) -> tuple[bytes, bytes, str]:
        attempts: list[tuple[str, str]] = [(self.base_url, "")]
        if self.profile.get("retrieval_strategy") == "resolved_ipv4":
            host = urlsplit(self.base_url).hostname or ""
            try:
                addresses = sorted(
                    {
                        result[4][0]
                        for result in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
                    }
                )
            except OSError as exc:
                raise CertificateAutomationError(
                    f"Could not resolve PKI server backends for {host}."
                ) from exc
            attempts.extend((self.base_url, address) for address in addresses)

        last_error = ""
        for base_url, address in attempts:
            try:
                certificate_der = self._download(
                    base_url, f"/certnew.cer?ReqID={request_id}&Enc=bin", verify, address
                )
                certificate = x509.load_der_x509_certificate(certificate_der)
                certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
                if not _certificate_matches_key(certificate, private_key_pem):
                    last_error = "A backend returned a certificate for a different key."
                    continue
                chain_der = self._download(
                    base_url, f"/certnew.p7b?ReqID={request_id}&Enc=bin", verify, address
                )
                chain_pem = _extract_chain(chain_der, certificate)
                return certificate_pem, chain_pem, address or urlsplit(base_url).hostname or ""
            except (CertificateAutomationError, ValueError) as exc:
                last_error = str(exc)
        raise CertificateAutomationError(
            last_error or "The issued certificate could not be retrieved from the PKI server."
        )

    def _download(
        self, base_url: str, path: str, verify: bool | str, address: str = ""
    ) -> bytes:
        session = self.session
        url = base_url + path
        headers: dict[str, str] = {}
        if address:
            parsed = urlsplit(base_url)
            hostname = parsed.hostname or ""
            port = parsed.port or 443
            netloc = f"{address}:{port}" if port != 443 else address
            url = urlunsplit((parsed.scheme, netloc, parsed.path, "", "")) + path
            session = self._authenticated_session()
            session.mount(f"https://{netloc}", _DirectAddressAdapter(hostname))
            headers["Host"] = parsed.netloc
        try:
            response = session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=verify,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise CertificateAutomationError(_request_error(exc)) from exc
        if response.status_code == 401:
            raise CertificateAutomationError("The PKI server rejected the enrollment credentials.")
        if response.status_code >= 400:
            request_id = request_id_from_path(path)
            raise CertificateAutomationError(
                f"A PKI backend returned HTTP {response.status_code} "
                f"while retrieving request {request_id}."
            )
        return response.content


def request_id_from_path(path: str) -> str:
    match = re.search(r"ReqID=([0-9]+)", path, re.IGNORECASE)
    return match.group(1) if match else ""


def parse_adcs_response(html: str) -> tuple[str, str, str, str]:
    request_match = re.search(r"certnew\.cer\?ReqID=([0-9]+)", html, re.IGNORECASE)
    if not request_match:
        request_match = re.search(r"\bReqID[=: ]+([0-9]+)", html, re.IGNORECASE)
    request_id = request_match.group(1) if request_match else ""
    ca_match = re.search(r"--&nbsp;\s*([^&<]+?)\s*&nbsp;", html, re.IGNORECASE)
    ca_name = re.sub(r"\s+", " ", ca_match.group(1)).strip() if ca_match else ""
    plain = re.sub(r"<[^>]+>", " ", html)
    plain = re.sub(r"&(?:nbsp|#160);", " ", plain, flags=re.IGNORECASE)
    plain = re.sub(r"\s+", " ", plain).strip()
    if re.search(r"Certificate\s+Issued", html, re.IGNORECASE):
        if not request_id:
            raise CertificateAutomationError(
                "AD CS reported issuance but did not return a recognizable request ID."
            )
        return "issued", request_id, ca_name, "Certificate issued."
    if re.search(r"pending|taken under submission", plain, re.IGNORECASE):
        return "pending", request_id, ca_name, _bounded_adcs_message(plain, "Request is pending approval.")
    if re.search(r"denied|rejected", plain, re.IGNORECASE):
        return "denied", request_id, ca_name, _bounded_adcs_message(plain, "The CA denied the request.")
    raise CertificateAutomationError(
        _bounded_adcs_message(plain, "The CA did not return a recognizable issuance disposition.")
    )


def _bounded_adcs_message(plain: str, fallback: str) -> str:
    for pattern in (
        r"(?:Error|Denied|Disposition|LastStatus)\s*[:=-]?\s*([^.;]{1,300}[.;]?)",
        r"(The disposition message is[^.]{1,300}\.)",
    ):
        match = re.search(pattern, plain, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:400]
    return fallback


def _certificate_matches_key(certificate: x509.Certificate, private_key_pem: bytes) -> bool:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    return certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _extract_chain(content: bytes, leaf: x509.Certificate) -> bytes:
    try:
        certificates = pkcs7.load_der_pkcs7_certificates(content)
    except ValueError:
        try:
            certificates = pkcs7.load_pem_pkcs7_certificates(content)
        except ValueError as exc:
            raise CertificateAutomationError(
                "The PKI server returned an invalid PKCS#7 certificate chain."
            ) from exc
    leaf_fingerprint = leaf.fingerprint(hashes.SHA256())
    remaining = [
        certificate
        for certificate in certificates
        if certificate.fingerprint(hashes.SHA256()) != leaf_fingerprint
    ]
    if not remaining:
        raise CertificateAutomationError("The PKI server returned no issuing CA certificates.")
    chain: list[x509.Certificate] = []
    issuer = leaf.issuer
    while remaining:
        match = next((certificate for certificate in remaining if certificate.subject == issuer), None)
        if not match:
            chain.extend(remaining)
            break
        chain.append(match)
        remaining.remove(match)
        if match.subject == match.issuer:
            chain.extend(remaining)
            break
        issuer = match.issuer
    return b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain)


def _request_error(exc: requests.RequestException) -> str:
    if isinstance(exc, requests.exceptions.SSLError):
        detail = str(exc).casefold()
        if "certificate has expired" in detail or "certificate expired" in detail:
            return "The PKI server's HTTPS certificate has expired."
        if "hostname mismatch" in detail or "not valid for" in detail:
            return "The PKI server's HTTPS certificate does not match its hostname."
        return "TLS validation of the PKI server failed. Check its certificate and configured CA bundle."
    if isinstance(exc, requests.exceptions.Timeout):
        return "The PKI server did not respond before the configured timeout."
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "The toolkit could not connect to the PKI server."
    return "The PKI request failed."
