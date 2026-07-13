from __future__ import annotations

import ipaddress
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def tls_paths(instance_path: str | Path) -> tuple[Path, Path, Path]:
    directory = Path(instance_path) / "tls"
    return directory / "cert.pem", directory / "key.pem", directory / "enabled"


def default_certificate_names() -> tuple[list[str], list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    names = {"localhost", socket.gethostname(), socket.getfqdn()}
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = {
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::1"),
    }
    for name in tuple(names):
        if not name:
            continue
        try:
            for result in socket.getaddrinfo(name, None):
                addresses.add(ipaddress.ip_address(result[4][0].split("%", 1)[0]))
        except (OSError, ValueError):
            pass
    return sorted(name for name in names if name), sorted(addresses, key=str)


def generate_self_signed_certificate(
    instance_path: str | Path,
    *,
    extra_names: list[str] | None = None,
    valid_days: int = 825,
) -> tuple[Path, Path]:
    cert_path, key_path, enabled_path = tls_paths(instance_path)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(cert_path.parent, 0o700)
    names, addresses = default_certificate_names()
    for value in extra_names or []:
        value = value.strip()
        if not value:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            if len(value) > 253 or any(not part for part in value.split(".")):
                raise ValueError(f"Invalid certificate hostname: {value}")
            names.append(value)
        else:
            addresses.append(address)
    names = sorted(set(names))
    addresses = sorted(set(addresses), key=str)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    # X.509 Common Name attributes are limited to 64 characters. Hostnames can
    # legally be longer and still belong in Subject Alternative Name, which is
    # what modern TLS clients validate. Prefer the stable local name for the
    # legacy subject and retain every discovered/requested name in SAN below.
    subject_name = (
        "localhost"
        if "localhost" in names
        else next((name for name in names if len(name) <= 64), "localhost")
    )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName(
                [*(x509.DNSName(name) for name in names), *(x509.IPAddress(address) for address in addresses)]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)
    enabled_path.touch(mode=0o600, exist_ok=True)
    return cert_path, key_path


def regenerate_self_signed_certificate(
    instance_path: str | Path, *, extra_names: list[str] | None = None
) -> tuple[Path, Path]:
    cert_path, key_path, _enabled_path = tls_paths(instance_path)
    validate_certificate_pair(cert_path, key_path)
    previous_cert = cert_path.read_bytes()
    previous_key = key_path.read_bytes()
    try:
        return generate_self_signed_certificate(
            instance_path, extra_names=extra_names
        )
    except Exception:
        cert_path.write_bytes(previous_cert)
        key_path.write_bytes(previous_key)
        os.chmod(cert_path, 0o644)
        os.chmod(key_path, 0o600)
        raise


def validate_certificate_pair(cert_path: str | Path, key_path: str | Path) -> x509.Certificate:
    cert_path = Path(cert_path)
    key_path = Path(key_path)
    if key_path.stat().st_mode & 0o077:
        raise ValueError("TLS private key permissions are too broad; expected mode 600.")
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    cert_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_public != key_public:
        raise ValueError("TLS certificate and private key do not match.")
    if certificate.not_valid_after_utc <= datetime.now(timezone.utc):
        raise ValueError("TLS certificate has expired.")
    return certificate


def certificate_status(instance_path: str | Path, preferred_fqdn: str = "") -> dict[str, object]:
    cert_path, key_path, enabled_path = tls_paths(instance_path)
    status: dict[str, object] = {
        "enabled": enabled_path.exists(),
        "present": cert_path.exists() and key_path.exists(),
        "valid": False,
        "preferred_fqdn": preferred_fqdn,
        "fqdn_covered": not preferred_fqdn,
        "dns_names": [],
        "expires_at": "",
        "error": "",
    }
    if not status["present"]:
        return status
    try:
        certificate = validate_certificate_pair(cert_path, key_path)
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except (OSError, ValueError, TypeError, x509.ExtensionNotFound) as exc:
        status["error"] = str(exc)
        return status
    status.update(
        valid=True,
        dns_names=names,
        fqdn_covered=not preferred_fqdn or preferred_fqdn.lower() in {name.lower() for name in names},
        expires_at=certificate.not_valid_after_utc.isoformat(timespec="seconds"),
    )
    return status
