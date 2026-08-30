from __future__ import annotations

import os
import sys
import tempfile
import threading
import textwrap
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from twn_toolkit import acme_dns_hook, create_app
from twn_toolkit.acme_dns import (
    AcmeDnsError,
    AcmeDnsManager,
    LETS_ENCRYPT_STAGING_DIRECTORY,
    _read_json,
    _write_json,
    acme_txt_record,
    normalize_acme_request,
)
from twn_toolkit.acme_dns_hook import run_hook


def _certificate_material(domains: list[str]) -> dict[str, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(value) for value in domains]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return {
        "cert.pem": cert_pem,
        "chain.pem": cert_pem,
        "fullchain.pem": cert_pem + cert_pem,
        "privkey.pem": key_pem,
    }


class AcmeDnsCoreTests(unittest.TestCase):
    def test_failed_attempts_can_be_deleted_but_issued_jobs_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = AcmeDnsManager(directory, certbot_path="/usr/bin/true")

            def create_job(job_id: str, status: str) -> Path:
                job_path = manager.jobs_root / job_id
                (job_path / "challenges").mkdir(parents=True, mode=0o700)
                _write_json(
                    job_path / "request.json",
                    {
                        "id": job_id,
                        "name": "Public RADIUS",
                        "email": "admin@example.org",
                        "domains": ["radius.example.org"],
                        "environment": "staging",
                        "key_type": "ecdsa",
                        "cert_name": f"twn-acme-{job_id}",
                        "created_at": time.time(),
                    },
                )
                _write_json(
                    job_path / "status.json",
                    {
                        "status": status,
                        "message": "Test request stopped.",
                        "updated_at": time.time(),
                    },
                )
                return job_path

            failed_id = "1" * 24
            failed_path = create_job(failed_id, "failed")
            deleted = manager.delete_failed(failed_id)
            self.assertEqual(deleted["status"], "failed")
            self.assertFalse(failed_path.exists())

            issued_id = "2" * 24
            issued_path = create_job(issued_id, "issued")
            with self.assertRaisesRegex(
                AcmeDnsError, "Only failed or cancelled ACME attempts"
            ):
                manager.delete_failed(issued_id)
            self.assertTrue(issued_path.exists())

    def test_request_normalization_supports_wildcards_and_rejects_bad_input(self) -> None:
        values = normalize_acme_request(
            "Guest Portal",
            "Admin@Example.ORG",
            "*.Guest.Example.org.\nguest.example.org,*.guest.example.org",
            environment="staging",
            key_type="ecdsa",
        )
        self.assertEqual(values["email"], "admin@example.org")
        self.assertEqual(
            values["domains"], ["*.guest.example.org", "guest.example.org"]
        )
        with self.assertRaisesRegex(ValueError, "Invalid DNS name"):
            normalize_acme_request(
                "Bad",
                "admin@example.org",
                "www.*.example.org",
                environment="production",
                key_type="rsa",
            )
        with self.assertRaisesRegex(ValueError, "valid email"):
            normalize_acme_request(
                "Bad",
                "not-an-address",
                "example.org",
                environment="production",
                key_type="rsa",
            )

    def test_challenge_record_strips_wildcard(self) -> None:
        self.assertEqual(
            acme_txt_record("*.guest.example.org"),
            "_acme-challenge.guest.example.org",
        )

    def test_certbot_command_uses_noninteractive_hooks_and_private_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = AcmeDnsManager(directory, certbot_path="/opt/certbot/bin/certbot")
            job_id = "a" * 24
            job_path = manager.jobs_root / job_id
            job_path.mkdir(mode=0o700)
            request_data = {
                "id": job_id,
                "name": "Guest",
                "email": "admin@example.org",
                "domains": ["guest.example.org", "*.guest.example.org"],
                "environment": "staging",
                "key_type": "ecdsa",
                "cert_name": f"twn-acme-{job_id}",
            }
            command = manager._command(request_data)
            self.assertEqual(command[0:3], ["/opt/certbot/bin/certbot", "certonly", "--manual"])
            self.assertIn("--non-interactive", command)
            self.assertIn("--manual-auth-hook", command)
            self.assertNotIn(
                "-m twn_toolkit.acme_dns",
                " ".join(command),
            )
            self.assertTrue(
                any("acme_dns_hook.py auth" in argument for argument in command)
            )
            self.assertEqual(
                command[command.index("--server") + 1],
                LETS_ENCRYPT_STAGING_DIRECTORY,
            )
            self.assertEqual(command.count("--domain"), 2)
            self.assertEqual(
                command[command.index("--config-dir") + 1],
                str(manager.config_root),
            )

    def test_auth_hook_publishes_challenge_and_waits_for_continue_signal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            job_path = Path(directory) / ("b" * 24)
            (job_path / "challenges").mkdir(parents=True, mode=0o700)
            _write_json(job_path / "status.json", {"status": "running"})
            (job_path / "process.pid").write_text(str(os.getpid()), encoding="ascii")
            result: list[int] = []
            environment = {
                "CERTBOT_IDENTIFIER": "*.guest.example.org",
                "CERTBOT_VALIDATION": "validation-token",
                "CERTBOT_REMAINING_CHALLENGES": "1",
            }

            def invoke() -> None:
                with patch.dict(os.environ, environment, clear=False):
                    result.append(run_hook("auth", str(job_path)))

            original_merge_status = acme_dns_hook._merge_status

            def delayed_merge_status(path: Path, **updates: object) -> None:
                if updates.get("status") == "awaiting_dns":
                    time.sleep(0.1)
                original_merge_status(path, **updates)

            thread = threading.Thread(target=invoke)
            challenge_path = job_path / "challenge.json"
            with patch.object(
                acme_dns_hook,
                "_merge_status",
                side_effect=delayed_merge_status,
            ):
                thread.start()
                try:
                    challenge: dict[str, object] = {}
                    observed_status: dict[str, object] = {}
                    for _ in range(100):
                        challenge = _read_json(challenge_path)
                        observed_status = _read_json(job_path / "status.json")
                        if challenge and observed_status.get("status") == "awaiting_dns":
                            break
                        time.sleep(0.02)
                    else:
                        self.fail(
                            "The ACME hook did not publish a complete awaiting-DNS "
                            "state within two seconds."
                        )
                    self.assertEqual(
                        challenge["record_name"],
                        "_acme-challenge.guest.example.org",
                    )
                    self.assertEqual(challenge["record_value"], "validation-token")
                    (job_path / f"continue-{challenge['id']}").touch(mode=0o600)
                    thread.join(timeout=3)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(result, [0])
                    self.assertEqual(
                        _read_json(job_path / "status.json")["status"],
                        "validating",
                    )
                finally:
                    if thread.is_alive():
                        (job_path / "cancel").touch(mode=0o600)
                        thread.join(timeout=3)

    def test_dns_check_distinguishes_cached_system_answer_from_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = AcmeDnsManager(directory, certbot_path="/usr/bin/true")
            job = {
                "challenge": {
                    "id": "challenge-1",
                    "record_name": "_acme-challenge.gate.example.org",
                    "record_value": "production-token",
                }
            }
            system_result = {
                "responded": True,
                "values": ["staging-token"],
                "error": "",
                "canonical_name": "_acme-challenge.gate.example.org",
            }
            authority_result = {
                "available": True,
                "zone": "example.org",
                "nameservers": ["ns1.example.net", "ns2.example.net"],
                "total": 2,
                "checked": 2,
                "matched": 2,
                "ready": True,
                "values": ["production-token"],
                "error": "",
            }
            resolver = SimpleNamespace(
                nameservers=["10.103.254.1"], cache=None
            )
            with (
                patch.object(manager, "job", return_value=job),
                patch(
                    "twn_toolkit.acme_dns.dns.resolver.Resolver",
                    return_value=resolver,
                ),
                patch(
                    "twn_toolkit.acme_dns._resolver_txt_check",
                    return_value=system_result,
                ),
                patch(
                    "twn_toolkit.acme_dns._authoritative_txt_check",
                    return_value=authority_result,
                ),
            ):
                result = manager.check_dns("a" * 24, "challenge-1")

            self.assertTrue(result["found"])
            self.assertEqual(result["source"], "authoritative")
            self.assertTrue(result["cache_disagreement"])
            self.assertFalse(result["system"]["found"])
            self.assertEqual(result["system"]["resolvers"], ["10.103.254.1"])
            self.assertTrue(result["authoritative"]["ready"])

    def test_dns_check_waits_when_authoritative_servers_disagree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = AcmeDnsManager(directory, certbot_path="/usr/bin/true")
            job = {
                "challenge": {
                    "id": "challenge-2",
                    "record_name": "_acme-challenge.gate.example.org",
                    "record_value": "production-token",
                }
            }
            resolver = SimpleNamespace(
                nameservers=["10.103.254.1"], cache=None
            )
            with (
                patch.object(manager, "job", return_value=job),
                patch(
                    "twn_toolkit.acme_dns.dns.resolver.Resolver",
                    return_value=resolver,
                ),
                patch(
                    "twn_toolkit.acme_dns._resolver_txt_check",
                    return_value={
                        "responded": True,
                        "values": ["production-token"],
                        "error": "",
                        "canonical_name": "_acme-challenge.gate.example.org",
                    },
                ),
                patch(
                    "twn_toolkit.acme_dns._authoritative_txt_check",
                    return_value={
                        "available": True,
                        "zone": "example.org",
                        "nameservers": [
                            "ns1.example.net",
                            "ns2.example.net",
                        ],
                        "total": 2,
                        "checked": 2,
                        "matched": 1,
                        "ready": False,
                        "values": [
                            "production-token",
                            "staging-token",
                        ],
                        "error": "",
                    },
                ),
            ):
                result = manager.check_dns("a" * 24, "challenge-2")

            self.assertFalse(result["found"])
            self.assertEqual(result["source"], "authoritative")
            self.assertTrue(result["cache_disagreement"])

    def test_artifact_collection_validates_names_and_sets_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = AcmeDnsManager(directory, certbot_path="/usr/bin/true")
            job_id = "c" * 24
            cert_name = f"twn-acme-{job_id}"
            job_path = manager.jobs_root / job_id
            job_path.mkdir(mode=0o700)
            _write_json(
                job_path / "request.json",
                {
                    "id": job_id,
                    "name": "Guest",
                    "email": "admin@example.org",
                    "domains": ["guest.example.org"],
                    "environment": "staging",
                    "key_type": "ecdsa",
                    "cert_name": cert_name,
                    "created_at": time.time(),
                },
            )
            live = manager.config_root / "live" / cert_name
            live.mkdir(parents=True)
            for filename, content in _certificate_material(["guest.example.org"]).items():
                (live / filename).write_bytes(content)

            manager._collect_artifacts(job_id)

            artifacts = job_path / "artifacts"
            self.assertEqual(artifacts.stat().st_mode & 0o777, 0o700)
            self.assertEqual((artifacts / "privkey.pem").stat().st_mode & 0o777, 0o600)
            self.assertEqual((artifacts / "cert.pem").stat().st_mode & 0o777, 0o644)
            self.assertTrue(_read_json(job_path / "certificate.json")["fingerprint_sha256"])

    def test_download_archive_marks_key_entries_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = AcmeDnsManager(directory, certbot_path="/usr/bin/true")
            job_id = "d" * 24
            job_path = manager.jobs_root / job_id
            artifacts = job_path / "artifacts"
            artifacts.mkdir(parents=True, mode=0o700)
            _write_json(
                job_path / "request.json",
                {
                    "id": job_id,
                    "name": "Public RADIUS",
                    "email": "admin@example.org",
                    "domains": ["radius.example.org"],
                    "environment": "production",
                    "key_type": "ecdsa",
                    "cert_name": f"twn-acme-{job_id}",
                    "created_at": time.time(),
                },
            )
            _write_json(
                job_path / "status.json",
                {"status": "issued", "message": "ready", "updated_at": time.time()},
            )
            _write_json(
                job_path / "certificate.json",
                {"not_after": "2030-01-01T00:00:00+00:00"},
            )
            for filename, content in _certificate_material(["radius.example.org"]).items():
                (artifacts / filename).write_bytes(content)

            with zipfile.ZipFile(manager.download_archive(job_id)) as archive:
                key_info = archive.getinfo("Public-RADIUS.key")
                cert_info = archive.getinfo("Public-RADIUS.pem")
                self.assertEqual((key_info.external_attr >> 16) & 0o777, 0o600)
                self.assertEqual((cert_info.external_attr >> 16) & 0o777, 0o644)
                self.assertIn("Public-RADIUS-bundle.pem", archive.namelist())

    def test_background_certbot_process_waits_for_dns_and_collects_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seed = base / "seed"
            seed.mkdir()
            for filename, content in _certificate_material(["radius.example.org"]).items():
                (seed / filename).write_bytes(content)
            fake_certbot = base / "fake-certbot"
            fake_certbot.write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    import os
                    import shutil
                    import subprocess
                    import sys
                    from pathlib import Path

                    if "--version" in sys.argv:
                        print("certbot fake")
                        raise SystemExit(0)

                    def option(name):
                        return sys.argv[sys.argv.index(name) + 1]

                    domains = [
                        sys.argv[index + 1]
                        for index, value in enumerate(sys.argv)
                        if value == "--domain"
                    ]
                    environment = dict(os.environ)
                    environment.update(
                        CERTBOT_IDENTIFIER=domains[0],
                        CERTBOT_VALIDATION="fake-validation-token",
                        CERTBOT_REMAINING_CHALLENGES="0",
                    )
                    result = subprocess.run(
                        option("--manual-auth-hook"),
                        shell=True,
                        env=environment,
                        check=False,
                    )
                    if result.returncode:
                        raise SystemExit(result.returncode)
                    live = Path(option("--config-dir")) / "live" / option("--cert-name")
                    live.mkdir(parents=True)
                    seed = Path({str(seed)!r})
                    for filename in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"):
                        shutil.copyfile(seed / filename, live / filename)
                    subprocess.run(
                        option("--manual-cleanup-hook"),
                        shell=True,
                        env=environment,
                        check=False,
                    )
                    """
                ),
                encoding="utf-8",
            )
            os.chmod(fake_certbot, 0o700)
            manager = AcmeDnsManager(directory, certbot_path=str(fake_certbot))
            job = manager.start(
                {
                    "name": "Public RADIUS",
                    "email": "admin@example.org",
                    "domains": ["radius.example.org"],
                    "environment": "staging",
                    "key_type": "ecdsa",
                }
            )
            for _ in range(200):
                job = manager.job(job["id"]) or {}
                if job.get("status") == "awaiting_dns":
                    break
                time.sleep(0.02)
            self.assertEqual(job["status"], "awaiting_dns")
            self.assertEqual(job["challenge"]["record_value"], "fake-validation-token")
            manager.continue_challenge(job["id"], job["challenge"]["id"])
            for _ in range(300):
                job = manager.job(job["id"]) or {}
                if job.get("status") in {"issued", "failed"}:
                    break
                time.sleep(0.02)
            self.assertEqual(job["status"], "issued", job.get("message"))
            self.assertTrue(job["download_ready"])
            self.assertNotIn(
                "RuntimeWarning",
                (manager.jobs_root / job["id"] / "certbot.log").read_text(
                    encoding="utf-8"
                ),
            )
            self.assertEqual(
                (manager.jobs_root / job["id"] / "artifacts" / "privkey.pem").stat().st_mode
                & 0o777,
                0o600,
            )


class AcmeDnsRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = create_app(self.directory.name)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_page_renders_guided_acme_workflow(self) -> None:
        response = self.client.get("/tools/certificate-automation")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ACME / Let", response.data)
        self.assertIn(b"compare the toolkit resolver", response.data)
        self.assertIn(b"Start with staging", response.data)
        self.assertIn(b"renewals require repeating", response.data)
        self.assertIn(b"authoritative nameservers", response.data)
        self.assertIn(b'main class="shell certificate-shell"', response.data)
        self.assertIn(b'aria-label="Certificate authority"', response.data)
        self.assertIn(b'id="acme-issuance"', response.data)
        self.assertNotIn(b'id="request-certificate"', response.data)

    def test_adcs_tab_only_renders_internal_pki_workspace(self) -> None:
        response = self.client.get("/tools/certificate-automation?section=adcs")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="request-certificate"', response.data)
        self.assertIn(b'id="managed-certificates"', response.data)
        self.assertIn(b'id="pki-profiles"', response.data)
        self.assertNotIn(b'id="acme-issuance"', response.data)

    def test_legacy_certificate_link_selects_adcs_tab(self) -> None:
        response = self.client.get(
            "/tools/certificate-automation?certificate=missing"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="request-certificate"', response.data)
        self.assertNotIn(b'id="acme-issuance"', response.data)

    def test_certificate_inspector_uses_full_width_shell(self) -> None:
        response = self.client.get("/tools/certificate-inspector")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'main class="shell certificate-shell"', response.data)

    def test_acme_start_requires_terms_and_redirects_to_new_job(self) -> None:
        response = self.client.post(
            "/tools/certificate-automation/acme",
            data={
                "name": "Public RADIUS",
                "email": "admin@example.org",
                "domains": "radius.example.org",
                "environment": "staging",
                "key_type": "ecdsa",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Subscriber Agreement", response.data)

        job_id = "e" * 24
        with patch(
            "twn_toolkit.certificate_automation_routes.AcmeDnsManager.start",
            return_value={"id": job_id},
        ):
            response = self.client.post(
                "/tools/certificate-automation/acme",
                data={
                    "name": "Public RADIUS",
                    "email": "admin@example.org",
                    "domains": "radius.example.org",
                    "environment": "staging",
                    "key_type": "ecdsa",
                    "agree_terms": "1",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"acme={job_id}".encode(), response.headers["Location"].encode())
        self.assertIn(b"section=acme", response.headers["Location"].encode())

    def test_status_endpoint_exposes_workflow_without_internal_paths_or_pid(self) -> None:
        manager = AcmeDnsManager(self.directory.name, certbot_path="/usr/bin/true")
        job_id = "f" * 24
        job_path = manager.jobs_root / job_id
        (job_path / "challenges").mkdir(parents=True, mode=0o700)
        _write_json(
            job_path / "request.json",
            {
                "id": job_id,
                "name": "Public RADIUS",
                "email": "admin@example.org",
                "domains": ["radius.example.org"],
                "environment": "staging",
                "key_type": "ecdsa",
                "cert_name": f"twn-acme-{job_id}",
                "created_at": time.time(),
            },
        )
        _write_json(
            job_path / "status.json",
            {
                "status": "failed",
                "message": "Test request stopped.",
                "process_id": 12345,
                "updated_at": time.time(),
            },
        )
        response = self.client.get(
            f"/tools/certificate-automation/acme/{job_id}/status"
        )
        self.assertEqual(response.status_code, 200)
        public_job = response.get_json()["job"]
        self.assertEqual(public_job["name"], "Public RADIUS")
        self.assertNotIn("cert_name", public_job)
        self.assertNotIn("process_id", public_job)
        self.assertIn("/status", public_job["status_url"])

    def test_failed_request_can_be_deleted_from_history(self) -> None:
        manager = AcmeDnsManager(self.directory.name, certbot_path="/usr/bin/true")
        job_id = "3" * 24
        job_path = manager.jobs_root / job_id
        (job_path / "challenges").mkdir(parents=True, mode=0o700)
        _write_json(
            job_path / "request.json",
            {
                "id": job_id,
                "name": "Failed Public RADIUS",
                "email": "admin@example.org",
                "domains": ["radius.example.org"],
                "environment": "staging",
                "key_type": "ecdsa",
                "cert_name": f"twn-acme-{job_id}",
                "created_at": time.time(),
            },
        )
        _write_json(
            job_path / "status.json",
            {
                "status": "failed",
                "message": "Test request stopped.",
                "updated_at": time.time(),
            },
        )

        page = self.client.get("/tools/certificate-automation?section=acme")
        self.assertIn(
            f"/tools/certificate-automation/acme/{job_id}/delete".encode(),
            page.data,
        )
        response = self.client.post(
            f"/tools/certificate-automation/acme/{job_id}/delete",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Deleted failed ACME request Failed Public RADIUS", response.data)
        self.assertFalse(job_path.exists())

    def test_reset_data_removes_certbot_account_and_artifacts(self) -> None:
        acme_root = Path(self.directory.name) / "acme_dns"
        marker = acme_root / "certbot-config" / "accounts" / "marker"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("account data", encoding="utf-8")
        result = self.app.test_cli_runner().invoke(args=["reset-data", "--yes"])
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(acme_root.exists())


if __name__ == "__main__":
    unittest.main()
