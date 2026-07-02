from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .network_tools import ToolInputError


MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024


def eapol_test_available() -> bool:
    return shutil.which("eapol_test") is not None


def radius_eap_authenticate(
    servers: list[dict[str, Any]],
    credentials: dict[str, Any],
    protocol: str,
    *,
    timeout: float,
    ca_certificate: bytes,
    client_certificate: bytes = b"",
    private_key: bytes = b"",
    private_key_password: str = "",
    anonymous_identity: str = "anonymous",
    server_domain: str = "",
) -> list[dict[str, Any]]:
    protocol = protocol.lower()
    if protocol not in {"peap-mschapv2", "eap-tls"}:
        raise ToolInputError("Select PEAP with MSCHAPv2 or EAP-TLS.")
    if not eapol_test_available():
        raise ToolInputError(
            "EAP testing requires the eapol_test executable from wpa_supplicant/eapoltest."
        )
    if not 1 <= timeout <= 30:
        raise ToolInputError("EAP timeout must be between 1 and 30 seconds.")
    if not ca_certificate:
        raise ToolInputError("Upload the CA certificate used to validate the RADIUS server.")
    _validate_upload(ca_certificate, "CA certificate")
    if protocol == "eap-tls":
        if not client_certificate or not private_key:
            raise ToolInputError("EAP-TLS requires a client certificate and matching private key.")
        _validate_upload(client_certificate, "Client certificate")
        _validate_upload(private_key, "Private key")

    workers = min(5, len(servers))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _radius_eap_one,
                server,
                credentials,
                protocol,
                timeout,
                ca_certificate,
                client_certificate,
                private_key,
                private_key_password,
                anonymous_identity,
                server_domain,
            ): index
            for index, server in enumerate(servers)
        }
        indexed = [(futures[future], future.result()) for future in as_completed(futures)]
    return [result for _index, result in sorted(indexed)]


def _radius_eap_one(
    server: dict[str, Any],
    credentials: dict[str, Any],
    protocol: str,
    timeout: float,
    ca_certificate: bytes,
    client_certificate: bytes,
    private_key: bytes,
    private_key_password: str,
    anonymous_identity: str,
    server_domain: str,
) -> dict[str, Any]:
    started = time.monotonic()
    secrets = [server["secret"], credentials.get("password", ""), private_key_password]
    try:
        address = socket.getaddrinfo(
            server["host"], server["port"], socket.AF_UNSPEC, socket.SOCK_DGRAM
        )[0][4][0]
        with tempfile.TemporaryDirectory(prefix="twn-eap-") as directory:
            root = Path(directory)
            ca_path = _write_private_file(root / "ca-cert", ca_certificate)
            values = [
                "network={",
                "    key_mgmt=IEEE8021X",
                "    eapol_flags=0",
                f'    identity="{_config_value(credentials["username"])}"',
                f'    ca_cert="{_config_value(str(ca_path))}"',
            ]
            if server_domain.strip():
                values.append(
                    f'    domain_suffix_match="{_config_value(server_domain.strip())}"'
                )
            if protocol == "peap-mschapv2":
                values.extend(
                    [
                        "    eap=PEAP",
                        f'    anonymous_identity="{_config_value(anonymous_identity or "anonymous")}"',
                        f'    password="{_config_value(credentials["password"])}"',
                        '    phase1="peapver=0"',
                        '    phase2="auth=MSCHAPV2"',
                    ]
                )
            else:
                cert_path = _write_private_file(root / "client-cert", client_certificate)
                key_path = _write_private_file(root / "private-key", private_key)
                values.extend(
                    [
                        "    eap=TLS",
                        f'    client_cert="{_config_value(str(cert_path))}"',
                        f'    private_key="{_config_value(str(key_path))}"',
                    ]
                )
                if private_key_password:
                    values.append(
                        f'    private_key_passwd="{_config_value(private_key_password)}"'
                    )
            values.append("}")
            config_path = root / "eapol-test.conf"
            config_path.write_text("\n".join(values) + "\n", encoding="utf-8")
            os.chmod(config_path, 0o600)
            command = [
                shutil.which("eapol_test") or "eapol_test",
                "-c",
                str(config_path),
                "-a",
                address,
                "-p",
                str(server["port"]),
                "-s",
                server["secret"],
                "-t",
                str(max(1, int(timeout))),
            ]
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout + 5,
                check=False,
            )
        output = _redact_output(completed.stdout or "", secrets)
        success = completed.returncode == 0 and "SUCCESS" in output
        status = "Access-Accept" if success else "Access-Reject"
        error = "" if success else _failure_summary(output, completed.returncode)
        return _result(server, status, started, output, error)
    except subprocess.TimeoutExpired:
        return _result(server, "error", started, "", "EAP exchange exceeded its timeout.")
    except Exception as exc:
        return _result(server, "error", started, "", f"{type(exc).__name__}: {exc}")


def _write_private_file(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    os.chmod(path, 0o600)
    return path


def _validate_upload(content: bytes, label: str) -> None:
    if len(content) > MAX_CERTIFICATE_BYTES:
        raise ToolInputError(f"{label} must be 2 MiB or smaller.")


def _config_value(value: str) -> str:
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ToolInputError("EAP identity and certificate settings cannot contain line breaks.")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _redact_output(output: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            output = output.replace(secret, "[redacted]")
    output = re.sub(r"(?i)(password|private_key_passwd)=\\?\"?[^\s\"]+", r"\1=[redacted]", output)
    safe_lines = []
    for line in output.splitlines():
        if re.search(r"(?i)\b(password|private_key_passwd)\b.*hexdump", line):
            continue
        # eapol_test can print credentials and derived key material as byte dumps.
        if re.search(r"(?:^|\s)(?:[0-9a-fA-F]{2}\s+){4,}", line):
            continue
        safe_lines.append(line)
    return "\n".join(safe_lines)[-30000:]


def _failure_summary(output: str, returncode: int) -> str:
    for line in reversed(output.splitlines()):
        if any(word in line.upper() for word in ("FAIL", "ERROR", "REJECT")):
            return line[:500]
    return f"EAP authentication failed (eapol_test exit code {returncode})."


def _result(
    server: dict[str, Any],
    status: str,
    started: float,
    transcript: str,
    error: str,
) -> dict[str, Any]:
    return {
        "server_name": server["name"],
        "server": server["host"],
        "port": server["port"],
        "status": status,
        "response_ms": round((time.monotonic() - started) * 1000, 1),
        "attributes": [],
        "transcript": transcript,
        "error": error,
    }
