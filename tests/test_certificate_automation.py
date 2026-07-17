from __future__ import annotations

import io
import sqlite3
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from twn_toolkit import create_app
from twn_toolkit.certificate_automation import (
    AdcsWebEnrollmentProvider,
    CertificateAutomationError,
    CertificateAutomationStore,
    EnrollmentResult,
    build_certificate_request,
    load_or_generate_private_key,
    normalize_certificate_identity,
    parse_adcs_response,
    validate_ca_bundle,
    validate_enrollment_url,
    validate_issued_certificate,
    validate_template_identifier,
)
from twn_toolkit.profile_backup import build_backup_catalog


def _ca_and_leaf(
    private_key: rsa.RSAPrivateKey, dns_names: list[str]
) -> tuple[bytes, bytes, x509.Certificate]:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])]))
        .issuer_name(ca.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    chain = pkcs7.serialize_certificates([leaf, ca], serialization.Encoding.DER)
    return leaf.public_bytes(serialization.Encoding.PEM), chain, ca


class _Response:
    def __init__(
        self, *, status_code: int = 200, text: str = "", content: bytes = b""
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.content = content


class _Session:
    def __init__(self, post_response: _Response, get_responses: list[_Response]) -> None:
        self.post_response = post_response
        self.get_responses = list(get_responses)
        self.posts: list[tuple[str, dict[str, object]]] = []
        self.gets: list[tuple[str, dict[str, object]]] = []
        self.mounts: list[tuple[str, object]] = []

    def post(self, url: str, **kwargs: object) -> _Response:
        self.posts.append((url, kwargs))
        return self.post_response

    def get(self, url: str, **kwargs: object) -> _Response:
        self.gets.append((url, kwargs))
        return self.get_responses.pop(0)

    def mount(self, prefix: str, adapter: object) -> None:
        self.mounts.append((prefix, adapter))


class CertificateAutomationCoreTests(unittest.TestCase):
    def test_enrollment_url_requires_https_certsrv_and_no_credentials(self) -> None:
        self.assertEqual(
            validate_enrollment_url("https://pki.example.test"),
            "https://pki.example.test/certsrv",
        )
        self.assertEqual(
            validate_enrollment_url("https://pki.example.test/certsrv/"),
            "https://pki.example.test/certsrv",
        )
        for value in (
            "http://pki.example.test/certsrv",
            "https://user:pass@pki.example.test/certsrv",
            "https://pki.example.test/other",
            "https://pki.example.test/certsrv?x=1",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_enrollment_url(value)

    def test_identity_normalization_adds_cn_deduplicates_and_rejects_bad_names(self) -> None:
        common_name, names = normalize_certificate_identity(
            "Radius.Example.Test.", "radius\nRADIUS.EXAMPLE.TEST,secondary.example.test"
        )
        self.assertEqual(common_name, "radius.example.test")
        self.assertEqual(
            names, ["radius.example.test", "radius", "secondary.example.test"]
        )
        with self.assertRaises(ValueError):
            normalize_certificate_identity("bad name", "bad name")

    def test_template_identifier_accepts_name_or_oid(self) -> None:
        self.assertEqual(validate_template_identifier("Internal Web Server"), "Internal Web Server")
        self.assertEqual(validate_template_identifier("1.3.6.1.4.1.311.21.8.1"), "1.3.6.1.4.1.311.21.8.1")
        with self.assertRaises(ValueError):
            validate_template_identifier("bad:value")

    def test_key_and_csr_contain_requested_server_identity(self) -> None:
        key = load_or_generate_private_key(key_size=2048)
        key_pem, csr_pem = build_certificate_request(
            "radius.example.test", ["radius.example.test", "radius"], key
        )
        saved_key = serialization.load_pem_private_key(key_pem, password=None)
        csr = x509.load_pem_x509_csr(csr_pem)
        self.assertEqual(saved_key.key_size, 2048)
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            .value.get_values_for_type(x509.DNSName),
            ["radius.example.test", "radius"],
        )
        self.assertIn(
            ExtendedKeyUsageOID.SERVER_AUTH,
            csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
        )

    def test_password_protected_existing_key_is_normalized(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        encrypted = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"correct"),
        )
        loaded = load_or_generate_private_key(
            key_size=2048, existing_key=encrypted, password="correct"
        )
        self.assertEqual(loaded.key_size, 3072)
        with self.assertRaisesRegex(ValueError, "passphrase"):
            load_or_generate_private_key(
                key_size=2048, existing_key=encrypted, password="wrong"
            )

    def test_ca_bundle_is_normalized_and_invalid_upload_is_rejected(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _leaf, _chain, ca = _ca_and_leaf(key, ["radius.example.test"])
        pem = ca.public_bytes(serialization.Encoding.PEM)
        self.assertEqual(validate_ca_bundle(pem), pem.decode("ascii"))
        with self.assertRaises(ValueError):
            validate_ca_bundle(b"not a certificate")

    def test_issued_certificate_must_match_key_names_and_server_eku(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        leaf_pem, _chain, _ca = _ca_and_leaf(
            key, ["radius.example.test", "radius"]
        )
        certificate = validate_issued_certificate(
            leaf_pem, key_pem, "radius.example.test", ["radius.example.test", "radius"]
        )
        self.assertGreater(certificate.not_valid_after_utc, datetime.now(timezone.utc))
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with self.assertRaisesRegex(CertificateAutomationError, "does not match"):
            validate_issued_certificate(
                leaf_pem, other_pem, "radius.example.test", ["radius.example.test"]
            )
        with self.assertRaisesRegex(CertificateAutomationError, "missing requested"):
            validate_issued_certificate(
                leaf_pem, key_pem, "radius.example.test", ["missing.example.test"]
            )

    def test_adcs_response_parser_handles_issued_pending_denied_and_unknown(self) -> None:
        issued = (
            '<html>Certificate Issued <a href="certnew.cer?ReqID=42&Enc=bin">x</a>'
            "<!--&nbsp; Example CA &nbsp;--></html>"
        )
        self.assertEqual(parse_adcs_response(issued)[:3], ("issued", "42", "Example CA"))
        self.assertEqual(parse_adcs_response("Request pending ReqID=43")[0:2], ("pending", "43"))
        self.assertEqual(parse_adcs_response("The request was denied ReqID=44")[0:2], ("denied", "44"))
        with self.assertRaises(CertificateAutomationError):
            parse_adcs_response("Welcome to certificate services")

    def test_provider_submits_csr_and_downloads_matching_certificate_and_chain(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem, csr_pem = build_certificate_request(
            "radius.example.test", ["radius.example.test"], key
        )
        leaf_pem, chain_der, _ca = _ca_and_leaf(key, ["radius.example.test"])
        leaf_der = x509.load_pem_x509_certificate(leaf_pem).public_bytes(
            serialization.Encoding.DER
        )
        html = 'Certificate Issued <a href="certnew.cer?ReqID=77&Enc=bin">download</a>'
        session = _Session(
            _Response(text=html),
            [_Response(content=leaf_der), _Response(content=chain_der)],
        )
        provider = AdcsWebEnrollmentProvider(
            {
                "enrollment_url": "https://pki.example.test/certsrv",
                "timeout": 10,
                "retrieval_strategy": "same_endpoint",
                "ca_bundle_pem": "",
            },
            "user@example.test",
            "secret",
            session=session,  # type: ignore[arg-type]
        )
        result = provider.enroll(
            csr_pem,
            "InternalWebServer",
            key_pem,
            "radius.example.test",
            ["radius.example.test"],
        )
        self.assertEqual(result.status, "issued")
        self.assertEqual(result.request_id, "77")
        self.assertEqual(result.certificate_pem, leaf_pem)
        chain_certificate = x509.load_pem_x509_certificate(result.chain_pem)
        self.assertEqual(
            chain_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Test Issuing CA",
        )
        submitted = session.posts[0][1]["data"]
        self.assertEqual(submitted["CertAttrib"], "CertificateTemplate:InternalWebServer")
        self.assertNotIn("secret", str(session.posts))

    def test_resolved_backend_retrieval_preserves_tls_hostname_and_matches_key(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem, csr_pem = build_certificate_request(
            "radius.example.test", ["radius.example.test"], key
        )
        leaf_pem, chain_der, _ca = _ca_and_leaf(key, ["radius.example.test"])
        leaf_der = x509.load_pem_x509_certificate(leaf_pem).public_bytes(
            serialization.Encoding.DER
        )
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_leaf, _wrong_chain, _wrong_ca = _ca_and_leaf(
            wrong_key, ["other.example.test"]
        )
        wrong_der = x509.load_pem_x509_certificate(wrong_leaf).public_bytes(
            serialization.Encoding.DER
        )
        initial = _Session(
            _Response(
                text='Certificate Issued <a href="certnew.cer?ReqID=88&Enc=bin">x</a>'
            ),
            [_Response(content=wrong_der)],
        )
        backend = _Session(
            _Response(), [_Response(content=leaf_der), _Response(content=chain_der)]
        )
        provider = AdcsWebEnrollmentProvider(
            {
                "enrollment_url": "https://pki.example.test/certsrv",
                "timeout": 10,
                "retrieval_strategy": "resolved_ipv4",
                "ca_bundle_pem": "",
            },
            "user",
            "password",
            session=initial,  # type: ignore[arg-type]
        )
        with (
            patch(
                "twn_toolkit.certificate_automation.socket.getaddrinfo",
                return_value=[
                    (2, 1, 6, "", ("192.0.2.20", 443)),
                    (2, 1, 6, "", ("192.0.2.20", 443)),
                ],
            ),
            patch.object(provider, "_authenticated_session", return_value=backend),
        ):
            result = provider.enroll(
                csr_pem,
                "Template",
                key_pem,
                "radius.example.test",
                ["radius.example.test"],
            )
        self.assertEqual(result.backend, "192.0.2.20")
        self.assertEqual(len(backend.mounts), 2)
        self.assertEqual(backend.gets[0][1]["headers"], {"Host": "pki.example.test"})
        self.assertTrue(backend.gets[0][0].startswith("https://192.0.2.20/certsrv/"))


class CertificateAutomationStoreTests(unittest.TestCase):
    def test_profiles_and_key_material_are_encrypted_and_versioned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = CertificateAutomationStore(directory, "test-secret-key")
            credential = store.save_credential(
                credential_id="",
                name="Enrollment",
                username="user@example.test",
                password="sensitive-password",
            )
            server = store.save_server(
                {
                    "name": "AD CS",
                    "provider": "adcs_web_enrollment",
                    "enrollment_url": "https://pki.example.test/certsrv",
                    "credential_id": credential["id"],
                    "ca_bundle_pem": "",
                    "retrieval_strategy": "same_endpoint",
                    "timeout": 15,
                }
            )
            template = store.save_template(
                {
                    "name": "RADIUS",
                    "server_id": server["id"],
                    "template_identifier": "InternalWebServer",
                    "key_size": 2048,
                    "renewal_days": 30,
                }
            )
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            leaf_pem, chain_der, ca = _ca_and_leaf(key, ["radius.example.test"])
            chain_pem = ca.public_bytes(serialization.Encoding.PEM)
            first = store.save_enrollment(
                managed_id="",
                name="District RADIUS",
                server_id=server["id"],
                template_id=template["id"],
                common_name="radius.example.test",
                dns_names=["radius.example.test"],
                private_key_pem=key_pem,
                result=EnrollmentResult(
                    "issued", "10", certificate_pem=leaf_pem, chain_pem=chain_pem
                ),
            )
            store.save_enrollment(
                managed_id=first["id"],
                name="District RADIUS",
                server_id=server["id"],
                template_id=template["id"],
                common_name="radius.example.test",
                dns_names=["radius.example.test"],
                private_key_pem=key_pem,
                result=EnrollmentResult(
                    "issued", "11", certificate_pem=leaf_pem, chain_pem=chain_pem
                ),
            )
            managed = store.managed_certificate(first["id"])
            self.assertEqual(managed["version_count"], 2)
            self.assertEqual(managed["request_id"], "11")
            material = store.version_material(first["id"])
            self.assertEqual(material["private_key_pem"], key_pem)
            database = Path(directory, "certificate_automation.sqlite3").read_bytes()
            self.assertNotIn(b"sensitive-password", database)
            self.assertNotIn(b"BEGIN PRIVATE KEY", database)
            self.assertEqual(Path(directory, "certificate_automation.sqlite3").stat().st_mode & 0o777, 0o600)

    def test_pending_version_can_be_completed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = CertificateAutomationStore(directory, "secret")
            server = store.save_server(
                {
                    "name": "AD CS",
                    "provider": "adcs_web_enrollment",
                    "enrollment_url": "https://pki.example.test/certsrv",
                    "credential_id": "",
                    "ca_bundle_pem": "",
                    "retrieval_strategy": "same_endpoint",
                    "timeout": 15,
                }
            )
            template = store.save_template(
                {
                    "name": "RADIUS",
                    "server_id": server["id"],
                    "template_identifier": "Template",
                    "key_size": 2048,
                    "renewal_days": 30,
                }
            )
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            pending = store.save_enrollment(
                managed_id="",
                name="Pending",
                server_id=server["id"],
                template_id=template["id"],
                common_name="radius.example.test",
                dns_names=["radius.example.test"],
                private_key_pem=key_pem,
                result=EnrollmentResult("pending", "55", message="Awaiting approval"),
            )
            material = store.version_material(pending["id"])
            leaf, _chain, ca = _ca_and_leaf(key, ["radius.example.test"])
            completed = store.complete_pending_version(
                pending["id"],
                material["id"],
                EnrollmentResult(
                    "issued",
                    "55",
                    certificate_pem=leaf,
                    chain_pem=ca.public_bytes(serialization.Encoding.PEM),
                ),
            )
            self.assertEqual(completed["status"], "issued")
            self.assertTrue(completed["fingerprint_sha256"])


class CertificateAutomationRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = create_app(self.directory.name)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_page_and_profile_workflow_do_not_render_saved_password(self) -> None:
        response = self.client.get("/tools/certificate-automation")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Certificate Automation", response.data)
        response = self.client.post(
            "/tools/certificate-automation/credentials",
            data={
                "name": "Enrollment",
                "username": "user@example.test",
                "password": "never-render-this",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Enrollment", response.data)
        self.assertNotIn(b"never-render-this", response.data)

    def test_profile_enrollment_and_download_archive(self) -> None:
        store = CertificateAutomationStore(
            self.directory.name, str(self.app.config["SECRET_KEY"])
        )
        server = store.save_server(
            {
                "name": "AD CS",
                "provider": "adcs_web_enrollment",
                "enrollment_url": "https://pki.example.test/certsrv",
                "credential_id": "",
                "ca_bundle_pem": "",
                "retrieval_strategy": "same_endpoint",
                "timeout": 15,
            }
        )
        template = store.save_template(
            {
                "name": "RADIUS",
                "server_id": server["id"],
                "template_identifier": "InternalWebServer",
                "key_size": 2048,
                "renewal_days": 30,
            }
        )

        class FakeProvider:
            def enroll(
                self,
                csr_pem: bytes,
                template_identifier: str,
                key_pem: bytes,
                common_name: str,
                dns_names: list[str],
            ) -> EnrollmentResult:
                key = serialization.load_pem_private_key(key_pem, password=None)
                leaf, _chain, ca = _ca_and_leaf(key, dns_names)
                return EnrollmentResult(
                    "issued",
                    "101",
                    "Test CA",
                    "Certificate issued.",
                    leaf,
                    ca.public_bytes(serialization.Encoding.PEM),
                    "pki.example.test",
                )

        with patch(
            "twn_toolkit.certificate_automation_routes._provider",
            return_value=FakeProvider(),
        ):
            response = self.client.post(
                "/tools/certificate-automation/enroll",
                data={
                    "name": "District RADIUS",
                    "template_id": template["id"],
                    "common_name": "radius.example.test",
                    "dns_names": "radius.example.test\nradius",
                    "key_source": "generate",
                    "username": "one-time-user",
                    "password": "one-time-password",
                },
            )
        self.assertEqual(response.status_code, 302)
        managed = store.managed_certificates()[0]
        download = self.client.get(
            f"/tools/certificate-automation/managed/{managed['id']}/download"
        )
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.mimetype, "application/zip")
        with zipfile.ZipFile(io.BytesIO(download.data)) as archive:
            names = set(archive.namelist())
            self.assertIn("District-RADIUS.key", names)
            self.assertIn("District-RADIUS.pem", names)
            self.assertIn("District-RADIUS-chain.pem", names)
            self.assertIn("District-RADIUS-fullchain.pem", names)
            self.assertIn("District-RADIUS-bundle.pem", names)

    def test_invalid_server_url_is_rejected_without_saving(self) -> None:
        response = self.client.post(
            "/tools/certificate-automation/servers",
            data={"name": "Bad", "enrollment_url": "http://pki.example.test/certsrv"},
            follow_redirects=True,
        )
        self.assertIn(b"HTTPS AD CS", response.data)
        store = CertificateAutomationStore(
            self.directory.name, str(self.app.config["SECRET_KEY"])
        )
        self.assertEqual(store.server_profiles(), [])

    def test_reset_data_removes_certificate_database_and_backups_exclude_keys(self) -> None:
        store = CertificateAutomationStore(
            self.directory.name, str(self.app.config["SECRET_KEY"])
        )
        store.save_credential(
            credential_id="",
            name="Enrollment",
            username="user@example.test",
            password="secret",
        )
        catalog_ids = {item["id"] for item in build_backup_catalog(self.directory.name)}
        self.assertFalse(any("certificate" in item_id or "pki" in item_id for item_id in catalog_ids))
        result = self.app.test_cli_runner().invoke(args=["reset-data", "--yes"])
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(store.path.exists())


if __name__ == "__main__":
    unittest.main()
