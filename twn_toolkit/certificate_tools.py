from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID


HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


class CertificateInspectionError(RuntimeError):
    pass


def normalize_certificate_target(value: str, port_value: str | int = 443) -> tuple[str, int]:
    target = value.strip()
    if not target:
        raise ValueError("Enter a hostname or IP address.")

    try:
        form_port = int(port_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Port must be a whole number from 1 to 65535.") from exc

    if "://" in target:
        parsed = urlsplit(target)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("Enter an HTTPS URL, hostname, or IP address.")
        if parsed.username or parsed.password:
            raise ValueError("Target URLs cannot contain credentials.")
        host = parsed.hostname
        try:
            port = parsed.port or form_port
        except ValueError as exc:
            raise ValueError("Enter a valid HTTPS port.") from exc
    else:
        try:
            parsed = urlsplit(f"//{target}")
            host = parsed.hostname or target
            port = parsed.port or form_port
        except ValueError as exc:
            raise ValueError("Enter a valid hostname and port.") from exc

    host = host.rstrip(".")
    try:
        normalized_host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            normalized_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Enter a valid hostname or IP address.") from exc
        if not HOSTNAME_PATTERN.fullmatch(normalized_host):
            raise ValueError("Enter a valid hostname or IP address.")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be a whole number from 1 to 65535.")
    return normalized_host, port


def inspect_certificate_chain(host: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    if not 0.2 <= timeout <= 30:
        raise ValueError("Timeout must be between 0.2 and 30 seconds.")

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=2) as executor:
        chain_future = executor.submit(_retrieve_presented_chain, host, port, timeout)
        trust_future = executor.submit(_validate_with_system_trust, host, port, timeout)
        try:
            chain_der, tls_details = chain_future.result()
        except (OSError, ssl.SSLError) as exc:
            raise CertificateInspectionError(_connection_error(host, port, exc)) from exc
        trust_result = trust_future.result()
    if not chain_der:
        raise CertificateInspectionError("The server completed TLS but did not provide a certificate.")

    certificates = [x509.load_der_x509_certificate(raw) for raw in chain_der]
    hostname_result = check_certificate_hostname(certificates[0], host)
    now = datetime.now(timezone.utc)
    summaries = [summarize_certificate(cert, index, now) for index, cert in enumerate(certificates)]
    order_checks = [
        {
            "child": index + 1,
            "issuer": index + 2,
            "matches": certificates[index].issuer == certificates[index + 1].subject,
        }
        for index in range(len(certificates) - 1)
    ]
    chain_order_valid = all(item["matches"] for item in order_checks)
    last_is_self_issued = certificates[-1].issuer == certificates[-1].subject
    likely_missing_intermediate = (
        not chain_order_valid
        or (
            not trust_result["valid"]
            and len(certificates) == 1
            and not last_is_self_issued
            and _looks_like_missing_issuer(str(trust_result.get("error", "")))
        )
    )

    return {
        "host": host,
        "port": port,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        "tls": tls_details,
        "certificates": summaries,
        "presented_count": len(summaries),
        "chain_order_valid": chain_order_valid,
        "order_checks": order_checks,
        "server_sent_self_issued_root": last_is_self_issued,
        "likely_missing_intermediate": likely_missing_intermediate,
        "hostname": hostname_result,
        "trust": trust_result,
        "overall_valid": bool(
            trust_result["valid"]
            and hostname_result["valid"]
            and summaries[0]["time_valid"]
            and chain_order_valid
        ),
    }


def _retrieve_presented_chain(
    host: str, port: int, timeout: float
) -> tuple[list[bytes], dict[str, Any]]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            cipher = tls_socket.cipher()
            chain_getter = getattr(tls_socket, "get_unverified_chain", None)
            if chain_getter is None:
                chain_getter = getattr(tls_socket._sslobj, "get_unverified_chain", None)
            chain = chain_getter() if chain_getter else []
            if not chain:
                leaf = tls_socket.getpeercert(binary_form=True)
                chain = [leaf] if leaf else []
            return [_certificate_to_der(item) for item in chain], {
                "version": tls_socket.version() or "Unknown",
                "cipher": cipher[0] if cipher else "Unknown",
                "cipher_protocol": cipher[1] if cipher else "",
                "cipher_bits": cipher[2] if cipher else None,
                "alpn": tls_socket.selected_alpn_protocol(),
            }


def _certificate_to_der(certificate: Any) -> bytes:
    if isinstance(certificate, bytes):
        if certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
            return x509.load_pem_x509_certificate(certificate).public_bytes(
                serialization.Encoding.DER
            )
        return certificate
    if hasattr(certificate, "public_bytes"):
        encoded = certificate.public_bytes()
        if isinstance(encoded, str):
            encoded = encoded.encode("ascii")
        if encoded.startswith(b"-----BEGIN CERTIFICATE-----"):
            return x509.load_pem_x509_certificate(encoded).public_bytes(
                serialization.Encoding.DER
            )
        return encoded
    raise CertificateInspectionError("The TLS runtime returned an unreadable certificate chain.")


def _validate_with_system_trust(host: str, port: int, timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host):
                return {"valid": True, "error": ""}
    except ssl.SSLCertVerificationError as exc:
        return {
            "valid": False,
            "error": exc.verify_message or str(exc),
            "verify_code": exc.verify_code,
        }
    except (OSError, ssl.SSLError) as exc:
        return {"valid": False, "error": str(exc)}


def summarize_certificate(
    certificate: x509.Certificate, index: int, now: datetime | None = None
) -> dict[str, Any]:
    current_time = now or datetime.now(timezone.utc)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    san_dns: list[str] = []
    san_ip: list[str] = []
    san_uri: list[str] = []
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_dns = san.get_values_for_type(x509.DNSName)
        san_ip = [str(item) for item in san.get_values_for_type(x509.IPAddress)]
        san_uri = san.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        pass

    is_ca = False
    try:
        is_ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        pass

    aia_issuers: list[str] = []
    ocsp_urls: list[str] = []
    try:
        aia = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        for description in aia:
            if description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                aia_issuers.append(str(description.access_location.value))
            elif description.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(str(description.access_location.value))
    except x509.ExtensionNotFound:
        pass

    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    try:
        signature_hash = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm:
        signature_hash = None
    if index == 0:
        role = "Leaf"
    elif certificate.subject == certificate.issuer:
        role = "Self-issued root / CA"
    elif is_ca:
        role = "Intermediate CA"
    else:
        role = "Additional certificate"
    return {
        "position": index + 1,
        "role": role,
        "subject": certificate.subject.rfc4514_string(),
        "common_name": common_names[0].value if common_names else "",
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": format(certificate.serial_number, "X"),
        "not_before": not_before,
        "not_after": not_after,
        "time_valid": not_before <= current_time <= not_after,
        "not_yet_valid": current_time < not_before,
        "expired": current_time > not_after,
        "days_remaining": (not_after - current_time).days,
        "is_ca": is_ca,
        "is_self_issued": certificate.subject == certificate.issuer,
        "san_dns": san_dns,
        "san_ip": san_ip,
        "san_uri": san_uri,
        "public_key": _public_key_description(certificate.public_key()),
        "signature_algorithm": getattr(
            certificate.signature_algorithm_oid,
            "_name",
            certificate.signature_algorithm_oid.dotted_string,
        ),
        "signature_hash": signature_hash.name if signature_hash else "Unknown",
        "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(":").upper(),
        "aia_issuers": aia_issuers,
        "ocsp_urls": ocsp_urls,
    }


def check_certificate_hostname(certificate: x509.Certificate, host: str) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None

    if address is not None:
        candidates = san.get_values_for_type(x509.IPAddress) if san else []
        valid = address in candidates
        return {
            "valid": valid,
            "source": "IP Subject Alternative Name",
            "matched": str(address) if valid else "",
            "error": "" if valid else f"No IP Subject Alternative Name matches {host}.",
        }

    dns_names = san.get_values_for_type(x509.DNSName) if san else []
    source = "DNS Subject Alternative Name"
    if not dns_names:
        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        dns_names = [common_names[0].value] if common_names else []
        source = "Common Name fallback"
    matched = next((name for name in dns_names if _dns_name_matches(name, host)), "")
    return {
        "valid": bool(matched),
        "source": source,
        "matched": matched,
        "error": "" if matched else f"No certificate name matches {host}.",
    }


def _dns_name_matches(pattern: str, host: str) -> bool:
    normalized_pattern = pattern.rstrip(".").lower()
    normalized_host = host.rstrip(".").lower()
    if "*" not in normalized_pattern:
        return normalized_pattern == normalized_host
    pattern_labels = normalized_pattern.split(".")
    host_labels = normalized_host.split(".")
    return (
        len(pattern_labels) == len(host_labels)
        and pattern_labels[0] == "*"
        and pattern_labels[1:] == host_labels[1:]
    )


def _public_key_description(key: Any) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size} bits"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name} ({key.key_size} bits)"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA {key.key_size} bits"
    return type(key).__name__


def _looks_like_missing_issuer(message: str) -> bool:
    lowered = message.lower()
    return any(
        phrase in lowered
        for phrase in (
            "unable to get local issuer",
            "unable to verify the first certificate",
            "issuer certificate",
        )
    )


def _connection_error(host: str, port: int, error: BaseException) -> str:
    if isinstance(error, socket.timeout):
        return f"Timed out connecting to {host}:{port}."
    if isinstance(error, socket.gaierror):
        return f"Could not resolve {host}: {error}."
    return f"Could not inspect TLS at {host}:{port}: {error}."
