from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .certificate_automation import MAX_DNS_NAMES, _valid_dns_name


LETS_ENCRYPT_PRODUCTION_DIRECTORY = (
    "https://acme-v02.api.letsencrypt.org/directory"
)
LETS_ENCRYPT_STAGING_DIRECTORY = (
    "https://acme-staging-v02.api.letsencrypt.org/directory"
)
ACTIVE_STATUSES = {
    "starting",
    "running",
    "awaiting_dns",
    "validating",
    "cancel_requested",
    "collecting",
}
TERMINAL_STATUSES = {"issued", "failed", "cancelled", "interrupted"}
JOB_ID_PATTERN = re.compile(r"^[a-f0-9]{24}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_LOG_MESSAGE = 2400


class AcmeDnsError(RuntimeError):
    pass


def normalize_acme_request(
    name: str,
    email: str,
    domains: list[str] | str,
    *,
    environment: str,
    key_type: str,
) -> dict[str, Any]:
    display_name = name.strip()
    if not display_name or len(display_name) > 100:
        raise ValueError("Enter a request name of 100 characters or fewer.")

    normalized_email = email.strip().lower()
    if (
        not normalized_email
        or len(normalized_email) > 254
        or not EMAIL_PATTERN.fullmatch(normalized_email)
    ):
        raise ValueError("Enter a valid email address for Let's Encrypt notices.")

    values = re.split(r"[\s,]+", domains) if isinstance(domains, str) else domains
    normalized_domains: list[str] = []
    for value in values:
        domain = value.strip().rstrip(".").lower()
        if not domain:
            continue
        if domain.count("*") > 1 or ("*" in domain and not domain.startswith("*.")):
            raise ValueError(f"Invalid DNS name: {value}")
        base_domain = domain[2:] if domain.startswith("*.") else domain
        try:
            ascii_domain = base_domain.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"Invalid DNS name: {value}") from exc
        if not _valid_dns_name(ascii_domain):
            raise ValueError(f"Invalid DNS name: {value}")
        normalized = f"*.{ascii_domain}" if domain.startswith("*.") else ascii_domain
        if normalized not in normalized_domains:
            normalized_domains.append(normalized)
    if not normalized_domains:
        raise ValueError("Enter at least one DNS name.")
    if len(normalized_domains) > MAX_DNS_NAMES:
        raise ValueError(f"Enter no more than {MAX_DNS_NAMES} DNS names.")

    if environment not in {"staging", "production"}:
        raise ValueError("Select the Let's Encrypt staging or production environment.")
    if key_type not in {"ecdsa", "rsa"}:
        raise ValueError("Select an ECDSA or RSA certificate key.")

    return {
        "name": display_name,
        "email": normalized_email,
        "domains": normalized_domains,
        "environment": environment,
        "key_type": key_type,
    }


def acme_txt_record(identifier: str) -> str:
    domain = identifier.strip().rstrip(".").lower()
    if domain.startswith("*."):
        domain = domain[2:]
    if not _valid_dns_name(domain):
        raise ValueError("Certbot supplied an invalid DNS challenge identifier.")
    return f"_acme-challenge.{domain}"


def _txt_values(answers: Any) -> list[str]:
    values: list[str] = []
    for answer in answers:
        strings = getattr(answer, "strings", ())
        if strings:
            value = b"".join(strings).decode("utf-8", errors="replace")
        else:
            value = str(answer).strip('"')
        if value not in values:
            values.append(value)
    return values


def _resolver_txt_check(
    record_name: str, resolver: dns.resolver.Resolver, *, lifetime: float
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "responded": False,
        "values": [],
        "error": "",
        "canonical_name": record_name,
        "ttl": None,
    }
    try:
        answers = resolver.resolve(
            record_name, "TXT", lifetime=lifetime, search=False
        )
    except dns.resolver.NXDOMAIN:
        result.update(responded=True, error="NXDOMAIN")
    except dns.resolver.NoAnswer:
        result.update(responded=True, error="No TXT answer")
    except (dns.exception.DNSException, OSError) as exc:
        result["error"] = str(exc) or "The TXT record could not be resolved."
    else:
        result.update(
            responded=True,
            values=_txt_values(answers),
            canonical_name=str(
                getattr(answers, "canonical_name", record_name)
            ).rstrip("."),
            ttl=int(answers.rrset.ttl) if getattr(answers, "rrset", None) else None,
        )
    return result


def _public_nameserver_addresses(
    hostname: str, resolver: dns.resolver.Resolver
) -> list[str]:
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(
                hostname, record_type, lifetime=2.5, search=False
            )
        except (dns.exception.DNSException, OSError):
            continue
        for answer in answers:
            value = str(answer).strip()
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_global and value not in addresses:
                addresses.append(value)
    return addresses


def _authoritative_txt_check(
    record_name: str,
    expected: str,
    *,
    discovery_resolver: dns.resolver.Resolver,
    canonical_name: str = "",
) -> dict[str, Any]:
    query_name = canonical_name or record_name
    result: dict[str, Any] = {
        "available": False,
        "zone": "",
        "nameservers": [],
        "total": 0,
        "checked": 0,
        "matched": 0,
        "ready": False,
        "values": [],
        "error": "",
    }
    try:
        zone = dns.resolver.zone_for_name(
            query_name, resolver=discovery_resolver, lifetime=3
        )
        ns_answers = discovery_resolver.resolve(
            zone, "NS", lifetime=3, search=False
        )
        nameservers = list(
            dict.fromkeys(
                str(getattr(answer, "target", answer)).rstrip(".")
                for answer in ns_answers
            )
        )[:4]
    except (dns.exception.DNSException, OSError) as exc:
        result["error"] = (
            str(exc) or "Authoritative nameservers could not be discovered."
        )
        return result

    result.update(
        available=bool(nameservers),
        zone=str(zone).rstrip("."),
        nameservers=nameservers,
        total=len(nameservers),
    )
    server_errors: list[str] = []
    for nameserver in nameservers:
        addresses = _public_nameserver_addresses(
            nameserver, discovery_resolver
        )
        if not addresses:
            server_errors.append(
                f"{nameserver} has no reachable public address"
            )
            continue
        server_result: dict[str, Any] | None = None
        for address in addresses[:2]:
            direct_resolver = dns.resolver.Resolver(configure=False)
            direct_resolver.nameservers = [address]
            direct_resolver.cache = None
            direct_resolver.timeout = 1.5
            direct_resolver.lifetime = 2.5
            candidate = _resolver_txt_check(
                query_name, direct_resolver, lifetime=2.5
            )
            if candidate["responded"]:
                server_result = candidate
                break
        if server_result is None:
            server_errors.append(f"{nameserver} did not answer directly")
            continue
        result["checked"] += 1
        for value in server_result["values"]:
            if value not in result["values"]:
                result["values"].append(value)
        if expected in server_result["values"]:
            result["matched"] += 1

    result["ready"] = bool(result["total"]) and (
        result["checked"] == result["total"]
        and result["matched"] == result["total"]
    )
    if server_errors:
        result["error"] = "; ".join(server_errors)
    return result


class AcmeDnsManager:
    """Coordinates Certbot manual DNS challenges through filesystem job state."""

    def __init__(self, instance_path: str, *, certbot_path: str | None = None) -> None:
        self.root = Path(instance_path) / "acme_dns"
        self.jobs_root = self.root / "jobs"
        self.config_root = self.root / "certbot-config"
        self.work_root = self.root / "certbot-work"
        self.logs_root = self.root / "certbot-logs"
        for path in (
            self.root,
            self.jobs_root,
            self.config_root,
            self.work_root,
            self.logs_root,
        ):
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o700)
        self.certbot_path = certbot_path if certbot_path is not None else _find_certbot()

    def runtime(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "available": bool(self.certbot_path),
            "path": self.certbot_path or "",
            "version": "",
        }
        if not self.certbot_path:
            return result
        try:
            completed = subprocess.run(
                [self.certbot_path, "--version"],
                capture_output=True,
                check=False,
                text=True,
                timeout=3,
            )
        except (OSError, subprocess.SubprocessError):
            return result
        output = (completed.stdout or completed.stderr).strip()
        result["version"] = output[:100]
        result["available"] = completed.returncode == 0
        return result

    def start(self, values: dict[str, Any]) -> dict[str, Any]:
        if not self.certbot_path:
            raise AcmeDnsError(
                "Certbot is not installed in the toolkit runtime. Install the toolkit "
                "dependencies, then restart the service."
            )
        job_id = secrets.token_hex(12)
        self._acquire_lock(job_id)
        job_path = self._job_path(job_id)
        try:
            job_path.mkdir(mode=0o700)
            (job_path / "challenges").mkdir(mode=0o700)
            now = time.time()
            request_data = {
                "id": job_id,
                **values,
                "cert_name": f"twn-acme-{job_id}",
                "created_at": now,
            }
            _write_json(job_path / "request.json", request_data)
            self._write_status(
                job_id,
                status="starting",
                message="Starting Certbot and requesting DNS challenges…",
                updated_at=now,
            )
            worker = threading.Thread(
                target=self._run,
                args=(job_id,),
                name=f"twn-acme-{job_id[:8]}",
                daemon=True,
            )
            worker.start()
        except Exception:
            shutil.rmtree(job_path, ignore_errors=True)
            self._release_lock(job_id)
            raise
        return self.job(job_id) or {}

    def jobs(self) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        for path in self.jobs_root.iterdir():
            if not path.is_dir() or not JOB_ID_PATTERN.fullmatch(path.name):
                continue
            job = self.job(path.name)
            if job:
                jobs.append(job)
        return sorted(jobs, key=lambda item: item.get("created_at", 0), reverse=True)

    def job(self, job_id: str) -> dict[str, Any] | None:
        job_path = self._job_path(job_id)
        request_data = _read_json(job_path / "request.json")
        status_data = _read_json(job_path / "status.json")
        if not request_data or not status_data:
            return None
        status = str(status_data.get("status", "interrupted"))
        process_id = _read_process_id(job_path) or int(
            status_data.get("process_id", 0) or 0
        )
        status_data["process_id"] = process_id
        if status in ACTIVE_STATUSES and not _process_alive(
            process_id
        ):
            status_age = time.time() - float(status_data.get("updated_at", 0))
            if process_id == 0 and status_age <= 5:
                pass
            elif status == "collecting" and status_age <= 30:
                pass
            elif self._artifacts_available(request_data):
                try:
                    self._collect_artifacts(job_id)
                except AcmeDnsError as exc:
                    self._write_status(
                        job_id,
                        status="failed",
                        message=str(exc),
                        completed_at=time.time(),
                    )
                else:
                    self._write_status(
                        job_id,
                        status="issued",
                        message="Certificate issued and stored by the toolkit.",
                        completed_at=time.time(),
                    )
            elif (job_path / "cancel").exists():
                self._write_status(
                    job_id,
                    status="cancelled",
                    message="The ACME request was cancelled.",
                    completed_at=time.time(),
                )
            elif status != "starting" or (
                time.time() - float(status_data.get("updated_at", 0)) > 30
            ):
                self._write_status(
                    job_id,
                    status="interrupted",
                    message=(
                        "The Certbot process stopped before the certificate was issued. "
                        "Start a new request."
                    ),
                    completed_at=time.time(),
                )
            status_data = _read_json(job_path / "status.json")
            if status_data.get("status") in TERMINAL_STATUSES:
                self._release_lock(job_id)

        challenge = _read_json(job_path / "challenge.json")
        certificate = _read_json(job_path / "certificate.json")
        challenges = [
            data
            for data in (
                _read_json(path)
                for path in sorted((job_path / "challenges").glob("*.json"))
            )
            if data
        ]
        return {
            **request_data,
            **status_data,
            "challenge": challenge or None,
            "challenges": challenges,
            "certificate": certificate or None,
            "download_ready": bool(certificate),
            "active": str(status_data.get("status")) in ACTIVE_STATUSES,
            "cancellable": str(status_data.get("status"))
            in {"starting", "running", "awaiting_dns", "validating"},
            "created_at_display": _display_time(float(request_data["created_at"])),
            "updated_at_display": _display_time(
                float(status_data.get("updated_at", request_data["created_at"]))
            ),
        }

    def check_dns(self, job_id: str, challenge_id: str) -> dict[str, Any]:
        job = self.job(job_id)
        if not job:
            raise AcmeDnsError("ACME request not found.")
        challenge = job.get("challenge")
        if not challenge or challenge.get("id") != challenge_id:
            raise AcmeDnsError("That DNS challenge is no longer active.")
        record_name = str(challenge["record_name"])
        expected = str(challenge["record_value"])
        system_resolver = dns.resolver.Resolver(configure=True)
        system_resolver.cache = None
        system = _resolver_txt_check(
            record_name, system_resolver, lifetime=5
        )
        system.update(
            found=expected in system["values"],
            resolvers=[
                str(nameserver)
                for nameserver in system_resolver.nameservers
            ],
        )
        authoritative = _authoritative_txt_check(
            record_name,
            expected,
            discovery_resolver=system_resolver,
            canonical_name=str(system.get("canonical_name", "")),
        )
        if authoritative["checked"]:
            found = bool(authoritative["ready"])
            source = "authoritative"
        else:
            found = bool(system["found"])
            source = "system"
        return {
            "found": found,
            "source": source,
            "record_name": record_name,
            "values": system["values"],
            "error": system["error"],
            "system": system,
            "authoritative": authoritative,
            "cache_disagreement": bool(authoritative["checked"])
            and bool(system["found"]) != bool(authoritative["ready"]),
            "checked_at": time.time(),
        }

    def continue_challenge(self, job_id: str, challenge_id: str) -> dict[str, Any]:
        job = self.job(job_id)
        if not job:
            raise AcmeDnsError("ACME request not found.")
        challenge = job.get("challenge")
        if (
            job.get("status") != "awaiting_dns"
            or not challenge
            or challenge.get("id") != challenge_id
        ):
            raise AcmeDnsError("That DNS challenge is no longer waiting.")
        signal_path = self._job_path(job_id) / f"continue-{challenge_id}"
        signal_path.touch(mode=0o600, exist_ok=False)
        self._write_status(
            job_id,
            status="validating",
            message=(
                "Certbot is validating this record. Keep every challenge TXT value "
                "in DNS until issuance completes."
            ),
        )
        return self.job(job_id) or {}

    def cancel(self, job_id: str) -> dict[str, Any]:
        job = self.job(job_id)
        if not job:
            raise AcmeDnsError("ACME request not found.")
        if not job.get("cancellable"):
            raise AcmeDnsError("This ACME request is no longer running.")
        (self._job_path(job_id) / "cancel").touch(mode=0o600, exist_ok=True)
        self._write_status(
            job_id,
            status="cancel_requested",
            message="Cancellation requested. Certbot is stopping…",
        )
        process_id = int(job.get("process_id", 0) or 0)
        if process_id > 1 and _process_matches_job(process_id, job_id):
            try:
                os.kill(process_id, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        return self.job(job_id) or {}

    def delete_failed(self, job_id: str) -> dict[str, Any]:
        job = self.job(job_id)
        if not job:
            raise AcmeDnsError("ACME request not found.")
        if job.get("status") not in {"failed", "cancelled", "interrupted"}:
            raise AcmeDnsError("Only failed or cancelled ACME attempts can be deleted.")
        shutil.rmtree(self._job_path(job_id))
        self._release_lock(job_id)
        return job

    def download_archive(self, job_id: str) -> io.BytesIO:
        job = self.job(job_id)
        if not job or not job.get("download_ready"):
            raise AcmeDnsError("Issued certificate material not found.")
        artifacts = self._job_path(job_id) / "artifacts"
        prefix = _safe_filename(str(job["name"]))
        try:
            files = {
                f"{prefix}.key": (artifacts / "privkey.pem").read_bytes(),
                f"{prefix}.pem": (artifacts / "cert.pem").read_bytes(),
                f"{prefix}-chain.pem": (artifacts / "chain.pem").read_bytes(),
                f"{prefix}-fullchain.pem": (artifacts / "fullchain.pem").read_bytes(),
            }
        except OSError as exc:
            raise AcmeDnsError("Issued certificate material not found.") from exc
        files[f"{prefix}-bundle.pem"] = (
            files[f"{prefix}.key"] + files[f"{prefix}-fullchain.pem"]
        )
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for filename, content in files.items():
                mode = (
                    0o600
                    if filename.endswith(".key")
                    or filename.endswith("-bundle.pem")
                    else 0o644
                )
                info = zipfile.ZipInfo(filename)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = mode << 16
                archive.writestr(info, content)
            readme = (
                "Let's Encrypt certificate material generated by TWN Toolkit.\n\n"
                "Private key and combined bundle files should remain mode 0600. Certificate\n"
                "and chain files may be mode 0644. The archive itself contains unencrypted\n"
                "private-key material; transfer it securely and delete unneeded copies.\n\n"
                "Files:\n"
                f"- {prefix}.key: private key\n"
                f"- {prefix}.pem: leaf certificate\n"
                f"- {prefix}-chain.pem: issuing chain\n"
                f"- {prefix}-fullchain.pem: leaf plus issuing chain\n"
                f"- {prefix}-bundle.pem: private key plus full chain\n"
            )
            archive.writestr("README.txt", readme)
        output.seek(0)
        return output

    def clear(self) -> None:
        for job in self.jobs():
            if not job.get("active"):
                continue
            try:
                (self._job_path(str(job["id"])) / "cancel").touch(
                    mode=0o600, exist_ok=True
                )
                process_id = int(job.get("process_id", 0) or 0)
                if process_id > 1 and _process_matches_job(
                    process_id, str(job["id"])
                ):
                    os.kill(process_id, signal.SIGTERM)
            except (OSError, AcmeDnsError):
                pass
        if self.root.exists():
            shutil.rmtree(self.root)

    def _job_path(self, job_id: str) -> Path:
        if not JOB_ID_PATTERN.fullmatch(job_id):
            raise AcmeDnsError("ACME request not found.")
        return self.jobs_root / job_id

    def _write_status(self, job_id: str, **updates: Any) -> None:
        path = self._job_path(job_id) / "status.json"
        status = _read_json(path)
        status.update(updates)
        status["updated_at"] = float(updates.get("updated_at", time.time()))
        _write_json(path, status)

    def _run(self, job_id: str) -> None:
        request_data = _read_json(self._job_path(job_id) / "request.json")
        log_path = self._job_path(job_id) / "certbot.log"
        try:
            command = self._command(request_data)
            with log_path.open("wb") as log:
                os.chmod(log_path, 0o600)
                self._write_status(
                    job_id,
                    status="running",
                    message="Certbot is requesting the first DNS challenge…",
                )
                process = subprocess.Popen(
                    command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                _write_process_id(self._job_path(job_id), process.pid)
                return_code = process.wait()
                self._write_status(
                    job_id,
                    status="collecting",
                    message="Certbot finished. Validating and protecting the result…",
                )
            cancelled = (self._job_path(job_id) / "cancel").exists()
            if cancelled:
                self._write_status(
                    job_id,
                    status="cancelled",
                    message="The ACME request was cancelled.",
                    completed_at=time.time(),
                )
            elif return_code:
                self._write_status(
                    job_id,
                    status="failed",
                    message=self._failure_message(log_path),
                    return_code=return_code,
                    completed_at=time.time(),
                )
            else:
                self._collect_artifacts(job_id)
                self._write_status(
                    job_id,
                    status="issued",
                    message="Certificate issued and stored by the toolkit.",
                    return_code=0,
                    completed_at=time.time(),
                )
        except Exception as exc:
            self._write_status(
                job_id,
                status="failed",
                message=f"The Certbot workflow failed: {exc}",
                completed_at=time.time(),
            )
        finally:
            self._release_lock(job_id)

    def _command(self, request_data: dict[str, Any]) -> list[str]:
        if not self.certbot_path:
            raise AcmeDnsError("Certbot is not installed.")
        job_path = self._job_path(str(request_data["id"]))
        python = shlex.quote(sys.executable)
        hook_script = shlex.quote(
            str(Path(__file__).resolve().with_name("acme_dns_hook.py"))
        )
        job_argument = shlex.quote(str(job_path))
        auth_hook = f"{python} {hook_script} auth {job_argument}"
        cleanup_hook = f"{python} {hook_script} cleanup {job_argument}"
        directory_url = (
            LETS_ENCRYPT_STAGING_DIRECTORY
            if request_data["environment"] == "staging"
            else LETS_ENCRYPT_PRODUCTION_DIRECTORY
        )
        command = [
            self.certbot_path,
            "certonly",
            "--manual",
            "--preferred-challenges",
            "dns",
            "--manual-auth-hook",
            auth_hook,
            "--manual-cleanup-hook",
            cleanup_hook,
            "--non-interactive",
            "--agree-tos",
            "--email",
            str(request_data["email"]),
            "--server",
            directory_url,
            "--cert-name",
            str(request_data["cert_name"]),
            "--config-dir",
            str(self.config_root),
            "--work-dir",
            str(self.work_root),
            "--logs-dir",
            str(self.logs_root),
            "--key-type",
            str(request_data["key_type"]),
        ]
        if request_data["key_type"] == "ecdsa":
            command.extend(["--elliptic-curve", "secp256r1"])
        else:
            command.extend(["--rsa-key-size", "2048"])
        for domain in request_data["domains"]:
            command.extend(["--domain", str(domain)])
        return command

    def _artifacts_available(self, request_data: dict[str, Any]) -> bool:
        live = self.config_root / "live" / str(request_data["cert_name"])
        return all(
            (live / filename).is_file()
            for filename in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem")
        )

    def _collect_artifacts(self, job_id: str) -> None:
        request_data = _read_json(self._job_path(job_id) / "request.json")
        live = self.config_root / "live" / str(request_data["cert_name"])
        try:
            material = {
                filename: (live / filename).read_bytes()
                for filename in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem")
            }
            certificate = x509.load_pem_x509_certificate(material["cert.pem"])
            private_key = serialization.load_pem_private_key(
                material["privkey.pem"], password=None
            )
        except (OSError, TypeError, ValueError) as exc:
            raise AcmeDnsError(
                "Certbot completed, but the issued certificate files could not be read."
            ) from exc
        certificate_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if certificate_public != private_public:
            raise AcmeDnsError("The issued certificate does not match its private key.")
        if certificate.not_valid_after_utc <= datetime.now(timezone.utc):
            raise AcmeDnsError("Certbot returned an already expired certificate.")
        try:
            issued_names = {
                value.lower()
                for value in certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            }
        except x509.ExtensionNotFound as exc:
            raise AcmeDnsError(
                "The issued certificate has no DNS Subject Alternative Names."
            ) from exc
        missing = sorted(set(request_data["domains"]) - issued_names)
        if missing:
            raise AcmeDnsError(
                "The issued certificate is missing requested names: " + ", ".join(missing)
            )

        artifacts = self._job_path(job_id) / "artifacts"
        artifacts.mkdir(mode=0o700, exist_ok=True)
        for filename, content in material.items():
            target = artifacts / filename
            target.write_bytes(content)
            os.chmod(target, 0o600 if filename == "privkey.pem" else 0o644)
        details = {
            "serial_number": format(certificate.serial_number, "X"),
            "fingerprint_sha256": certificate.fingerprint(
                hashes.SHA256()
            ).hex(":"),
            "not_before": certificate.not_valid_before_utc.isoformat(timespec="seconds"),
            "not_after": certificate.not_valid_after_utc.isoformat(timespec="seconds"),
            "issuer": certificate.issuer.rfc4514_string(),
        }
        _write_json(self._job_path(job_id) / "certificate.json", details)

    @staticmethod
    def _failure_message(log_path: Path) -> str:
        try:
            output = log_path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            output = ""
        if not output:
            return "Certbot did not issue a certificate. Review DNS and try a new request."
        tail = output[-MAX_LOG_MESSAGE:]
        return "Certbot did not issue a certificate. Its final output was:\n" + tail

    def _acquire_lock(self, job_id: str) -> None:
        lock_path = self.root / "active.lock"
        descriptor = -1
        for attempt in range(2):
            try:
                descriptor = os.open(
                    lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                break
            except FileExistsError as exc:
                active_id = ""
                try:
                    active_id = lock_path.read_text(encoding="ascii").strip()
                except OSError:
                    pass
                if (
                    attempt == 0
                    and JOB_ID_PATTERN.fullmatch(active_id)
                    and not (self.job(active_id) or {}).get("active")
                ):
                    self._release_lock(active_id)
                    continue
                message = "Another ACME request is already running."
                if JOB_ID_PATTERN.fullmatch(active_id):
                    message += " Finish or cancel it before starting another."
                raise AcmeDnsError(message) from exc
        if descriptor < 0:
            raise AcmeDnsError("The ACME request lock could not be created.")
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(job_id)

    def _release_lock(self, job_id: str) -> None:
        lock_path = self.root / "active.lock"
        try:
            if lock_path.read_text(encoding="ascii").strip() == job_id:
                lock_path.unlink()
        except FileNotFoundError:
            pass


def _find_certbot() -> str:
    found = shutil.which("certbot")
    if found:
        return found
    alongside_python = Path(sys.executable).resolve().parent / "certbot"
    return str(alongside_python) if alongside_python.is_file() else ""


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_process_id(job_path: Path, process_id: int) -> None:
    path = job_path / "process.pid"
    temporary = job_path / f".process.pid.{secrets.token_hex(4)}.tmp"
    temporary.write_text(str(process_id), encoding="ascii")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _read_process_id(job_path: Path) -> int:
    try:
        return int((job_path / "process.pid").read_text(encoding="ascii").strip())
    except (FileNotFoundError, OSError, ValueError):
        return 0


def _process_alive(process_id: int) -> bool:
    if process_id <= 1:
        return False
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_matches_job(process_id: int, job_id: str) -> bool:
    token = f"twn-acme-{job_id}"
    proc_command = Path(f"/proc/{process_id}/cmdline")
    try:
        if proc_command.is_file():
            return token.encode("ascii") in proc_command.read_bytes()
    except OSError:
        return False
    try:
        completed = subprocess.run(
            ["ps", "-p", str(process_id), "-o", "command="],
            capture_output=True,
            check=False,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0 and token in completed.stdout


def _display_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-.") or "certificate"
