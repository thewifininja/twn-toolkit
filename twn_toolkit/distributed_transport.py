from __future__ import annotations

import io
import json
import os
import ssl
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .distributed_agents import (
    DistributedAgentStore,
    DistributedEnrollmentWindow,
    DistributedIdentityStore,
    split_mainframe_certificate_hosts,
)
from .distributed_pki import (
    DistributedPkiStore,
    PairingSessionStore,
    canonical_pairing_transcript,
)
from .distributed_agents import pairing_code
from .distributed_job_epochs import DistributedJobStore


PROTOCOL_VERSION = 1
MAX_ENROLLMENT_REQUEST_BYTES = 32 * 1024
MAX_AGENT_RPC_BYTES = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 10
MAX_LONG_POLL_SECONDS = 25
ENROLLMENT_ATTEMPT_WINDOW_SECONDS = 60
MAX_ENROLLMENT_ATTEMPTS_PER_WINDOW = 5
MAX_LISTENER_CONNECTIONS = 32
LISTENER_HANDSHAKE_TIMEOUT_SECONDS = 5
LISTENER_READ_TIMEOUT_SECONDS = 10
LISTENER_WRITE_TIMEOUT_SECONDS = 10


class EnrollmentTransportError(RuntimeError):
    pass


class EnrollmentClosedError(ValueError):
    pass


class EnrollmentServer:
    """Bounded HTTPS bootstrap server. Normal agent RPC will require mTLS."""

    def __init__(
        self,
        instance_path: str | Path,
        host: str,
        port: int,
        advertised_hosts: list[str] | None = None,
    ) -> None:
        self.instance_path = Path(instance_path)
        self.host = host
        self.port = int(port)
        self.identity_store = DistributedIdentityStore(self.instance_path)
        self.agent_store = DistributedAgentStore(self.instance_path)
        self.enrollment_window = DistributedEnrollmentWindow(self.instance_path)
        self.pairing_store = PairingSessionStore(self.instance_path)
        self.pki_store = DistributedPkiStore(self.instance_path)
        self.job_store = DistributedJobStore(self.instance_path)
        self._attempt_lock = threading.Lock()
        self._attempts_path = self.instance_path / "distributed_enrollment_attempts.sqlite3"
        with sqlite3.connect(self._attempts_path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS enrollment_attempts "
                "(address TEXT NOT NULL, attempted_at REAL NOT NULL)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS enrollment_attempts_address_time "
                "ON enrollment_attempts(address, attempted_at)"
            )
        os.chmod(self._attempts_path, 0o600)
        addresses, dns_names = split_mainframe_certificate_hosts(
            [host], advertised_hosts or []
        )
        self.pki_store.ensure_mainframe_identity(addresses, dns_names=dns_names)
        handler = _handler_for(self)
        server_class = _IPv6ThreadingHTTPServer if ":" in host else _BoundedThreadingHTTPServer
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            str(self.pki_store.server_cert_path), str(self.pki_store.server_key_path)
        )
        context.load_verify_locations(cafile=str(self.pki_store.ca_cert_path))
        context.verify_mode = ssl.CERT_OPTIONAL
        # Accept plain TCP first so a silent TLS peer cannot stall the accept
        # loop before the bounded worker admission check.
        self.httpd = server_class((host, self.port), handler, tls_context=context)
        self.httpd.daemon_threads = True
        self.httpd.timeout = 1
        self.port = int(self.httpd.server_address[1])
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self.httpd.serve_forever,
            name="twn-enrollment-listener",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def begin_enrollment(self, payload: dict[str, Any], address: str) -> dict[str, Any]:
        if not self.enrollment_window.status()["open"]:
            raise EnrollmentClosedError(
                "New agent enrollment is closed on this Mainframe."
            )
        self._record_attempt(address)
        if int(payload.get("protocol", 0)) != PROTOCOL_VERSION:
            raise ValueError("Unsupported enrollment protocol version.")
        agent = self.agent_store.request_enrollment(
            public_key=str(payload.get("public_key", "")),
            fingerprint=str(payload.get("fingerprint", "")),
            name=str(payload.get("name", "")),
            address=address,
        )
        mainframe_identity = self.identity_store.load_or_create()
        session = self.pairing_store.create(
            agent_id=agent["id"],
            agent_public_key=agent["public_key"],
            mainframe_public_key=mainframe_identity["public_key"],
        )
        return {
            "protocol": PROTOCOL_VERSION,
            "session_id": session["id"],
            "token": session["token"],
            "pairing_code": session["pairing_code"],
            "expires_at": session["expires_at"],
            "transcript": session["transcript"],
        }

    def _record_attempt(self, address: str) -> None:
        now = time.time()
        cutoff = now - ENROLLMENT_ATTEMPT_WINDOW_SECONDS
        with self._attempt_lock:
            with sqlite3.connect(self._attempts_path) as connection:
                connection.execute(
                    "DELETE FROM enrollment_attempts WHERE attempted_at <= ?", (cutoff,)
                )
                count = connection.execute(
                    "SELECT COUNT(*) FROM enrollment_attempts "
                    "WHERE address = ? AND attempted_at > ?",
                    (address, cutoff),
                ).fetchone()[0]
                if int(count) >= MAX_ENROLLMENT_ATTEMPTS_PER_WINDOW:
                    raise ValueError("Too many enrollment requests; wait before trying again.")
                connection.execute(
                    "INSERT INTO enrollment_attempts(address, attempted_at) VALUES (?, ?)",
                    (address, now),
                )

    def enrollment_status(self, session_id: str, token: str) -> dict[str, Any]:
        pairing = self.pairing_store.authenticate(session_id, token)
        agent = self.agent_store.get(str(pairing["agent_id"]))
        if not agent:
            raise ValueError("Agent enrollment does not exist.")
        response: dict[str, Any] = {
            "protocol": PROTOCOL_VERSION,
            "state": agent["state"],
        }
        if agent["state"] == "approved":
            response.update(
                certificate=self.pki_store.issue_agent_certificate(
                    agent_id=agent["id"], public_key=agent["public_key"]
                ),
                ca_certificate=self.pki_store.ca_certificate_pem(),
            )
            self.pairing_store.consume(session_id, token)
        return response

    def heartbeat(
        self, certificate_der: bytes | None, payload: dict[str, Any], address: str
    ) -> dict[str, Any]:
        agent_id = self._approved_certificate_agent(certificate_der)
        if int(payload.get("protocol", 0)) != PROTOCOL_VERSION:
            raise ValueError("Unsupported agent protocol version.")
        agent = self.agent_store.record_heartbeat(
            agent_id,
            capabilities=payload.get("capabilities", []),
            address=address,
            protocol_version=int(payload.get("protocol", 0)),
            toolkit_version=str(payload.get("toolkit_version", "")),
            platform=str(payload.get("platform", "")),
            hostname=str(payload.get("hostname", "")),
        )
        activation_id = str(payload.get("activation_id", ""))
        self.job_store.activate_agent(agent_id, activation_id)
        results = payload.get("results", [])
        if not isinstance(results, list) or len(results) > 16:
            raise ValueError("Agent job results must be a bounded list.")
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("Agent job result must be an object.")
            self.job_store.complete(
                str(result.get("id", "")),
                agent_id=agent_id,
                state=str(result.get("state", "")),
                output=result.get("output") or {},
                error=str(result.get("error", "")),
            )
        try:
            wait_seconds = float(payload.get("wait_seconds", 0) or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("Agent wait time must be a number.") from exc
        wait_seconds = max(0.0, min(wait_seconds, MAX_LONG_POLL_SECONDS))
        deadline = time.monotonic() + wait_seconds
        excluded_capability = "system.http.tunnel" if wait_seconds > 0 else ""
        jobs = self.job_store.claim(
            agent_id,
            exclude_capability_id=excluded_capability,
            activation_id=activation_id,
        )
        while not jobs and time.monotonic() < deadline:
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
            jobs = self.job_store.claim(
                agent_id,
            exclude_capability_id=excluded_capability,
            activation_id=activation_id,
            )
        return {
            "protocol": PROTOCOL_VERSION,
            "state": "approved",
            "agent_id": agent["id"],
            "server_time": time.time(),
            "jobs": jobs,
        }

    def interactive(
        self, certificate_der: bytes | None, payload: dict[str, Any]
    ) -> dict[str, Any]:
        agent_id = self._approved_certificate_agent(certificate_der)
        if int(payload.get("protocol", 0)) != PROTOCOL_VERSION:
            raise ValueError("Unsupported agent protocol version.")
        activation_id = str(payload.get("activation_id", ""))
        self.job_store.activate_agent(agent_id, activation_id)
        results = payload.get("results", [])
        if not isinstance(results, list) or len(results) > 8:
            raise ValueError("Interactive results must be a bounded list.")
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("Interactive result must be an object.")
            self.job_store.complete(
                str(result.get("id", "")), agent_id=agent_id,
                state=str(result.get("state", "")),
                output=result.get("output") or {}, error=str(result.get("error", "")),
            )
        wait_seconds = max(0.0, min(float(payload.get("wait_seconds", 0) or 0), MAX_LONG_POLL_SECONDS))
        deadline = time.monotonic() + wait_seconds
        jobs = self.job_store.claim(
            agent_id, limit=1, capability_id="system.http.tunnel",
            activation_id=activation_id,
        )
        while not jobs and time.monotonic() < deadline:
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            jobs = self.job_store.claim(
            agent_id, limit=1, capability_id="system.http.tunnel",
            activation_id=activation_id,
        )
        return {"protocol": PROTOCOL_VERSION, "state": "approved", "requests": jobs}

    def _approved_certificate_agent(self, certificate_der: bytes | None) -> str:
        if not certificate_der:
            raise ValueError("A Mainframe-issued client certificate is required.")
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
            names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            agent_id = names[0].value if len(names) == 1 else ""
            public_key = certificate.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ).hex()
        except (ValueError, TypeError) as exc:
            raise ValueError("Client certificate identity is invalid.") from exc
        agent = self.agent_store.get(agent_id)
        if not agent or agent["state"] != "approved" or agent["public_key"] != public_key:
            raise ValueError("Client certificate identity is not approved.")
        return agent_id


class EnrollmentClient:
    """Agent-side bootstrap client with no manually exchanged credential."""

    def __init__(
        self,
        instance_path: str | Path,
        mainframe_url: str,
        fallback_url: str = "",
    ) -> None:
        self.instance_path = Path(instance_path)
        self.mainframe_url = mainframe_url.rstrip("/")
        self.mainframe_urls = [self.mainframe_url]
        normalized_fallback = fallback_url.rstrip("/")
        if normalized_fallback and normalized_fallback not in self.mainframe_urls:
            self.mainframe_urls.append(normalized_fallback)
        self.identity_store = DistributedIdentityStore(self.instance_path)
        self.credentials_root = self.instance_path / "distributed_agent_credentials"
        self.pending_path = self.credentials_root / "pending.json"
        self.certificate_path = self.credentials_root / "client-cert.pem"
        self.ca_path = self.credentials_root / "mainframe-ca.pem"

    def begin(self, name: str) -> dict[str, Any]:
        identity = self.identity_store.load_or_create()
        response = self._request(
            "POST",
            "/v1/enrollment",
            {
                "protocol": PROTOCOL_VERSION,
                "name": name,
                "public_key": identity["public_key"],
                "fingerprint": identity["fingerprint"],
            },
        )
        transcript = dict(response.get("transcript") or {})
        if (
            transcript.get("agent_id") != f"agent_{identity['fingerprint'][:32]}"
            or transcript.get("agent_public_key") != identity["public_key"]
        ):
            raise EnrollmentTransportError("Mainframe returned a mismatched pairing identity.")
        expected_code = pairing_code(canonical_pairing_transcript(transcript))
        if expected_code != response.get("pairing_code"):
            raise EnrollmentTransportError("Mainframe returned an invalid pairing transcript.")
        pending = {
            "session_id": str(response["session_id"]),
            "token": str(response["token"]),
            "pairing_code": expected_code,
            "expires_at": float(response["expires_at"]),
            "mainframe_url": self.mainframe_url,
        }
        self._private_json(self.pending_path, pending)
        return {key: value for key, value in pending.items() if key != "token"}

    def poll(self) -> dict[str, Any]:
        try:
            pending = json.loads(self.pending_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EnrollmentTransportError("No pending Mainframe enrollment exists.") from exc
        pending_url = str(pending.get("mainframe_url", "")).rstrip("/")
        if pending_url and pending_url in self.mainframe_urls:
            self.mainframe_urls.remove(pending_url)
            self.mainframe_urls.insert(0, pending_url)
        response = self._request(
            "GET",
            f"/v1/enrollment/{pending['session_id']}",
            authorization=f"Bearer {pending['token']}",
        )
        state = str(response.get("state", ""))
        if state == "approved":
            certificate = str(response.get("certificate", ""))
            ca_certificate = str(response.get("ca_certificate", ""))
            if "BEGIN CERTIFICATE" not in certificate or "BEGIN CERTIFICATE" not in ca_certificate:
                raise EnrollmentTransportError("Mainframe returned incomplete credentials.")
            self.credentials_root.mkdir(parents=True, exist_ok=True)
            os.chmod(self.credentials_root, 0o700)
            _private_write(self.certificate_path, certificate.encode("ascii"))
            _private_write(self.ca_path, ca_certificate.encode("ascii"))
            self.pending_path.unlink(missing_ok=True)
        return {"state": state}

    def pending(self) -> dict[str, Any] | None:
        try:
            payload = json.loads(self.pending_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return {
            key: payload[key]
            for key in ("session_id", "pairing_code", "expires_at", "mainframe_url")
            if key in payload
        }

    def enrolled(self) -> bool:
        return self.certificate_path.exists() and self.ca_path.exists()

    def heartbeat(
        self,
        capabilities: list[dict[str, str]],
        *,
        toolkit_version: str = "",
        platform: str = "",
        hostname: str = "",
        activation_id: str = "",
        results: list[dict[str, Any]] | None = None,
        wait_seconds: float = 0,
    ) -> dict[str, Any]:
        if not self.enrolled():
            raise EnrollmentTransportError("This agent has not completed enrollment.")
        return self._request(
            "POST",
            "/v1/heartbeat",
            {
                "protocol": PROTOCOL_VERSION,
                "capabilities": capabilities,
                "toolkit_version": toolkit_version,
                "platform": platform,
                "hostname": hostname,
                "activation_id": activation_id,
                "results": results or [],
                "wait_seconds": max(0.0, min(float(wait_seconds), MAX_LONG_POLL_SECONDS)),
            },
            authenticated=True,
            request_timeout=max(
                REQUEST_TIMEOUT_SECONDS,
                max(0.0, min(float(wait_seconds), MAX_LONG_POLL_SECONDS)) + 5,
            ),
        )

    def interactive(
        self, results: list[dict[str, Any]] | None = None, *,
        wait_seconds: float = 20, activation_id: str = ""
    ) -> dict[str, Any]:
        if not self.enrolled():
            raise EnrollmentTransportError("This agent has not completed enrollment.")
        wait_seconds = max(0.0, min(float(wait_seconds), MAX_LONG_POLL_SECONDS))
        return self._request(
            "POST", "/v1/interactive",
            {
                "protocol": PROTOCOL_VERSION,
                "activation_id": activation_id,
                "results": results or [],
                "wait_seconds": wait_seconds,
            },
            authenticated=True,
            request_timeout=max(REQUEST_TIMEOUT_SECONDS, wait_seconds + 5),
        )

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        authorization: str = "",
        authenticated: bool = False,
        request_timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        if authenticated:
            context = ssl.create_default_context(cafile=str(self.ca_path))
            context.load_cert_chain(
                certfile=str(self.certificate_path), keyfile=str(self.identity_store.path)
            )
        else:
            context = ssl.create_default_context()
            # First contact cannot validate a private CA. The pairing-code comparison
            # authenticates both device identities; approved credentials pin the CA.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        last_error: OSError | urllib.error.URLError | None = None
        for mainframe_url in self.mainframe_urls:
            request = urllib.request.Request(
                mainframe_url + path,
                data=data,
                method=method,
                headers={
                    "Accept": "application/json",
                    **({"Content-Type": "application/json"} if data is not None else {}),
                    **({"Authorization": authorization} if authorization else {}),
                },
            )
            try:
                with urllib.request.urlopen(
                    request, context=context, timeout=request_timeout
                ) as response:
                    maximum = MAX_AGENT_RPC_BYTES if authenticated else MAX_ENROLLMENT_REQUEST_BYTES
                    body = response.read(maximum + 1)
                self.mainframe_url = mainframe_url
                if self.mainframe_urls[0] != mainframe_url:
                    self.mainframe_urls.remove(mainframe_url)
                    self.mainframe_urls.insert(0, mainframe_url)
                break
            except urllib.error.HTTPError as exc:
                raise EnrollmentTransportError(
                    f"Mainframe enrollment request failed: {exc}"
                ) from exc
            except (OSError, urllib.error.URLError) as exc:
                last_error = exc
        else:
            raise EnrollmentTransportError(
                f"Mainframe enrollment request failed: {last_error}"
            ) from last_error
        if len(body) > maximum:
            raise EnrollmentTransportError("Mainframe enrollment response was too large.")
        try:
            result = json.loads(body)
        except json.JSONDecodeError as exc:
            raise EnrollmentTransportError("Mainframe returned invalid JSON.") from exc
        if not isinstance(result, dict):
            raise EnrollmentTransportError("Mainframe returned an invalid response.")
        return result

    def _private_json(self, path: Path, payload: dict[str, Any]) -> None:
        _private_write(path, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    def __init__(
        self, *args: Any, tls_context: ssl.SSLContext, **kwargs: Any
    ) -> None:
        self._tls_context = tls_context
        self._connection_slots = threading.BoundedSemaphore(MAX_LISTENER_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        connection = request
        try:
            connection = self._tls_context.wrap_socket(
                request, server_side=True, do_handshake_on_connect=False
            )
            connection.settimeout(LISTENER_HANDSHAKE_TIMEOUT_SECONDS)
            connection.do_handshake()
            self.finish_request(connection, client_address)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            # TLS failures, timeouts, and disconnects are normal peer failures.
            pass
        except Exception:
            self.handle_error(connection, client_address)
        finally:
            try:
                self.shutdown_request(connection)
            finally:
                self._connection_slots.release()


class _IPv6ThreadingHTTPServer(_BoundedThreadingHTTPServer):
    import socket

    address_family = socket.AF_INET6


class _DeadlineSocketReader(io.RawIOBase):
    """Give buffered HTTP parsing one absolute budget for headers and body."""

    def __init__(self, connection: ssl.SSLSocket, timeout: float) -> None:
        super().__init__()
        self.connection = connection
        self.deadline = time.monotonic() + timeout

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP request read deadline exceeded.")
        self.connection.settimeout(remaining)
        return self.connection.recv_into(buffer)


def _handler_for(enrollment_server: EnrollmentServer) -> type[BaseHTTPRequestHandler]:
    class EnrollmentHandler(BaseHTTPRequestHandler):
        server_version = "TWNEnrollment/1"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.rfile.close()
            self.rfile = io.BufferedReader(
                _DeadlineSocketReader(self.connection, LISTENER_READ_TIMEOUT_SECONDS)
            )

        def do_POST(self) -> None:
            if self.path not in {"/v1/enrollment", "/v1/heartbeat", "/v1/interactive"}:
                self._json(404, {"error": "Not found."})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(400, {"error": "Invalid content length."})
                return
            maximum = (
                MAX_AGENT_RPC_BYTES
                if self.path in {"/v1/heartbeat", "/v1/interactive"}
                else MAX_ENROLLMENT_REQUEST_BYTES
            )
            if not 0 < length <= maximum:
                self._json(413, {"error": "Enrollment request is too large or empty."})
                return
            try:
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("Enrollment payload must be an object.")
                if self.path == "/v1/enrollment":
                    result = enrollment_server.begin_enrollment(
                        payload, str(self.client_address[0])
                    )
                elif self.path == "/v1/heartbeat":
                    result = enrollment_server.heartbeat(
                        self.connection.getpeercert(binary_form=True),
                        payload,
                        str(self.client_address[0]),
                    )
                else:
                    result = enrollment_server.interactive(
                        self.connection.getpeercert(binary_form=True), payload
                    )
            except EnrollmentClosedError as exc:
                self._json(403, {"error": str(exc)})
                return
            except (json.JSONDecodeError, ValueError) as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(201 if self.path == "/v1/enrollment" else 200, result)

        def do_GET(self) -> None:
            prefix = "/v1/enrollment/"
            if not self.path.startswith(prefix) or "/" in self.path[len(prefix) :]:
                self._json(404, {"error": "Not found."})
                return
            authorization = self.headers.get("Authorization", "")
            token = authorization[7:] if authorization.startswith("Bearer ") else ""
            try:
                result = enrollment_server.enrollment_status(
                    self.path[len(prefix) :], token
                )
            except ValueError as exc:
                self._json(403, {"error": str(exc)})
                return
            self._json(200, result)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            # Server-side long polling does not consume the request-read budget.
            # Bound response writes independently after the result is ready.
            self.connection.settimeout(LISTENER_WRITE_TIMEOUT_SECONDS)
            content = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(content)

    return EnrollmentHandler


def _private_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{threading.get_ident()}"
    try:
        with temporary.open("wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
