from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from twn_toolkit.certificate_tools import (
    check_certificate_hostname,
    inspect_certificate_chain,
    normalize_certificate_target,
    summarize_certificate,
)


class CertificateToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.now = datetime.now(timezone.utc)
        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ca = _certificate(
            subject_name="Toolkit Test CA",
            issuer_name="Toolkit Test CA",
            subject_key=cls.ca_key,
            issuer_key=cls.ca_key,
            now=cls.now,
            is_ca=True,
        )
        cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.leaf = _certificate(
            subject_name="portal.example.com",
            issuer_name="Toolkit Test CA",
            subject_key=cls.leaf_key,
            issuer_key=cls.ca_key,
            now=cls.now,
            is_ca=False,
            dns_names=["portal.example.com", "*.guest.example.com"],
        )

    def test_normalizes_hostname_url_and_port(self) -> None:
        self.assertEqual(
            normalize_certificate_target("https://portal.example.com:8443/login", "443"),
            ("portal.example.com", 8443),
        )
        self.assertEqual(
            normalize_certificate_target("192.0.2.10", "443"),
            ("192.0.2.10", 443),
        )
        with self.assertRaises(ValueError):
            normalize_certificate_target("http://portal.example.com", "443")

    def test_matches_san_and_single_label_wildcard(self) -> None:
        self.assertTrue(check_certificate_hostname(self.leaf, "portal.example.com")["valid"])
        wildcard = check_certificate_hostname(self.leaf, "wifi.guest.example.com")
        self.assertTrue(wildcard["valid"])
        self.assertEqual(wildcard["matched"], "*.guest.example.com")
        self.assertFalse(
            check_certificate_hostname(self.leaf, "deep.wifi.guest.example.com")["valid"]
        )

    def test_summarizes_certificate_validity_and_key(self) -> None:
        summary = summarize_certificate(self.leaf, 0, self.now)
        self.assertEqual(summary["role"], "Leaf")
        self.assertTrue(summary["time_valid"])
        self.assertEqual(summary["public_key"], "RSA 2048 bits")
        self.assertIn("portal.example.com", summary["san_dns"])

    def test_inspection_preserves_server_chain_and_checks_order(self) -> None:
        chain = [
            self.leaf.public_bytes(serialization.Encoding.DER),
            self.ca.public_bytes(serialization.Encoding.DER),
        ]
        tls = {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_protocol": "TLSv1.3",
            "cipher_bits": 256,
            "alpn": "h2",
        }
        with (
            patch(
                "twn_toolkit.certificate_tools._retrieve_presented_chain",
                return_value=(chain, tls),
            ),
            patch(
                "twn_toolkit.certificate_tools._validate_with_system_trust",
                return_value={"valid": True, "error": ""},
            ),
        ):
            result = inspect_certificate_chain("portal.example.com", 443, 3)

        self.assertEqual(result["presented_count"], 2)
        self.assertTrue(result["chain_order_valid"])
        self.assertTrue(result["hostname"]["valid"])
        self.assertTrue(result["overall_valid"])
        self.assertEqual(result["certificates"][1]["role"], "Self-issued root / CA")


def _certificate(
    *,
    subject_name: str,
    issuer_name: str,
    subject_key,
    issuer_key,
    now: datetime,
    is_ca: bool,
    dns_names: list[str] | None = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
