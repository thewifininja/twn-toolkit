from __future__ import annotations

import ipaddress
import json
import platform
import re
import selectors
import socket
import subprocess
import os
import sys
from pathlib import Path
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import requests

from .network_tools import ToolInputError, validate_hosts


SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
MAX_API_RESPONSE = 1024 * 1024


def test_path_mtu(
    host: str,
    *,
    family: str = "auto",
    minimum: int = 576,
    maximum: int = 1500,
    timeout: float = 1.0,
) -> dict[str, Any]:
    host = host.strip()
    validate_hosts(host, limit=1)
    if family not in {"auto", "ipv4", "ipv6"}:
        raise ToolInputError("Address family must be Auto, IPv4, or IPv6.")
    if not 0.2 <= timeout <= 5:
        raise ToolInputError("Probe timeout must be between 0.2 and 5 seconds.")
    requested = {"auto": socket.AF_UNSPEC, "ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}[family]
    try:
        answers = socket.getaddrinfo(host, None, requested, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise ToolInputError(f"Could not resolve '{host}': {exc}") from exc
    if not answers:
        raise ToolInputError(f"Could not resolve '{host}'.")
    resolved_family = answers[0][0]
    address = answers[0][4][0]
    floor = 1280 if resolved_family == socket.AF_INET6 else 576
    ceiling = 65535
    if not floor <= minimum <= maximum <= ceiling:
        raise ToolInputError(f"MTU range must be between {floor} and {ceiling} bytes.")

    overhead = 48 if resolved_family == socket.AF_INET6 else 28
    probes = []
    low, high = minimum, maximum
    best = None
    while low <= high:
        mtu = (low + high) // 2
        payload = mtu - overhead
        success, detail = _mtu_probe(address, resolved_family, payload, timeout)
        probes.append({"mtu": mtu, "payload": payload, "success": success, "detail": detail})
        if success:
            best = mtu
            low = mtu + 1
        else:
            high = mtu - 1
    return {
        "host": host,
        "address": address,
        "family": "IPv6" if resolved_family == socket.AF_INET6 else "IPv4",
        "mtu": best,
        "minimum": minimum,
        "maximum": maximum,
        "overhead": overhead,
        "probes": probes,
        "conclusive": best is not None,
    }


def _mtu_probe(address: str, family: int, payload: int, timeout: float) -> tuple[bool, str]:
    system = platform.system()
    executable = "ping6" if family == socket.AF_INET6 and system == "Darwin" else "ping"
    if system == "Darwin":
        command = [executable, "-n", "-c", "1", "-W", str(max(1, int(timeout * 1000)))]
        if family == socket.AF_INET:
            command.append("-D")
    else:
        command = [executable, "-n", "-c", "1", "-W", str(max(1, int(timeout)))]
        if family == socket.AF_INET:
            command.extend(["-M", "do"])
        elif family == socket.AF_INET6:
            command.append("-6")
    command.extend(["-s", str(payload), address])
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (completed.stdout or "").strip()
    detail = output.splitlines()[-1] if output else f"ping exited {completed.returncode}"
    return completed.returncode == 0, detail


def parse_http_headers(value: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line_number, raw in enumerate(value.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if ":" not in line:
            raise ToolInputError(f"Header line {line_number} must use Name: Value.")
        name, header_value = line.split(":", 1)
        name = name.strip()
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name):
            raise ToolInputError(f"Header line {line_number} has an invalid name.")
        if "\r" in header_value or "\n" in header_value:
            raise ToolInputError("Header values cannot contain line breaks.")
        headers[name] = header_value.strip()
    return headers


API_DEADLINE_ERROR = (
    "API request deadline exceeded; no complete response was confirmed. "
    "The remote operation may have executed; reconcile its state before retrying."
)


def send_api_request(
    method: str, url: str, *, headers: dict[str, str] | None = None,
    body: str = "", timeout: float = 10, verify_tls: bool = True,
) -> dict[str, Any]:
    """Run one request in a killable child; the budget includes process startup."""
    _validate_api_request(method, url, timeout)
    started = time.monotonic()
    payload = json.dumps({
        "parent": os.getpid(), "deadline": started + timeout,
        "request": {"method": method, "url": url, "headers": headers,
                    "body": body, "timeout": timeout, "verify_tls": verify_tls},
    }).encode()
    process = None
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "twn_toolkit.api_request_worker"],
            cwd=str(Path(__file__).resolve().parent.parent),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        output, _ = process.communicate(payload, timeout=max(0, started + timeout - time.monotonic()))
        if process.returncode == 124 or time.monotonic() >= started + timeout:
            raise ToolInputError(API_DEADLINE_ERROR)
        if process.returncode != 0:
            raise ToolInputError("API request process exited without a confirmed response; reconcile any remote operation before retrying.")
        message = json.loads(output)
        if "error" in message:
            raise ToolInputError(message["error"])
        result = message["result"]
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        return result
    except subprocess.TimeoutExpired as exc:
        raise ToolInputError(API_DEADLINE_ERROR) from exc
    except ToolInputError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ToolInputError("API request failed without a confirmed response; reconcile any remote operation before retrying.") from exc
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.communicate()


def _validate_api_request(method, url, timeout):
    if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ToolInputError("Select a supported HTTP method.")
    try:
        parsed = urlsplit(url.strip())
        _ = parsed.port
    except ValueError as exc:
        raise ToolInputError("Enter a valid HTTP or HTTPS URL and port.") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise ToolInputError("Enter an HTTP or HTTPS URL without embedded credentials.")
    if not 0.2 <= timeout <= 30:
        raise ToolInputError("Timeout must be between 0.2 and 30 seconds.")
    return parsed


def _send_api_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = 10,
    verify_tls: bool = True,
) -> dict[str, Any]:
    parsed = _validate_api_request(method, url, timeout)
    method = method.upper()
    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise ToolInputError(f"Could not resolve API destination: {exc}") from exc
    if any(ipaddress.ip_address(address).is_unspecified or ipaddress.ip_address(address).is_multicast for address in addresses):
        raise ToolInputError("The API destination resolved to an unusable address.")

    started = time.monotonic()
    deadline = started + timeout
    response = None
    try:
        response = requests.request(
            method,
            url,
            headers=headers or {},
            data=body.encode("utf-8") if body else None,
            timeout=(timeout, timeout),
            verify=verify_tls,
            allow_redirects=False,
            stream=True,
        )
        chunks = []
        received = 0
        truncated = False
        for chunk in response.iter_content(65536):
            if time.monotonic() >= deadline:
                raise ToolInputError("API response exceeded the configured deadline.")
            if not chunk:
                continue
            remaining = MAX_API_RESPONSE - received
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                truncated = True
                break
            chunks.append(chunk)
            received += len(chunk)
        if time.monotonic() >= deadline:
            raise ToolInputError("API response exceeded the configured deadline.")
        raw = b"".join(chunks)
    except requests.RequestException as exc:
        raise ToolInputError(f"API request failed: {exc}") from exc
    finally:
        if response is not None:
            response.close()
    elapsed_ms = round((time.monotonic() - started) * 1000, 2)
    content_type = response.headers.get("Content-Type", "")
    text = raw.decode(response.encoding or "utf-8", errors="replace")
    if "json" in content_type.lower():
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            pass
    return {
        "status": response.status_code,
        "reason": response.reason,
        "elapsed_ms": elapsed_ms,
        "url": url,
        "resolved_addresses": sorted(addresses),
        "request_headers": _redact_headers(headers or {}),
        "response_headers": _redact_headers(dict(response.headers)),
        "body": text,
        "bytes": len(raw),
        "truncated": truncated,
        "redirect": response.headers.get("Location", ""),
    }


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: "[redacted]" if name.lower() in SENSITIVE_HEADERS else value
        for name, value in headers.items()
    }


def receive_syslog(
    protocol: str,
    bind_address: str,
    port: int,
    *,
    duration: float = 10,
    max_messages: int = 100,
) -> list[dict[str, Any]]:
    protocol = protocol.lower()
    if protocol not in {"udp", "tcp"}:
        raise ToolInputError("Syslog protocol must be UDP or TCP.")
    if not 1 <= port <= 65535:
        raise ToolInputError("Syslog port must be between 1 and 65535.")
    if not 1 <= duration <= 30:
        raise ToolInputError("Listen duration must be between 1 and 30 seconds.")
    if not 1 <= max_messages <= 500:
        raise ToolInputError("Maximum messages must be between 1 and 500.")
    try:
        address = ipaddress.ip_address(bind_address)
    except ValueError as exc:
        raise ToolInputError("Bind address must be a local IPv4 or IPv6 address.") from exc
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    listener = socket.socket(family, kind)
    selector = selectors.DefaultSelector()
    messages: list[dict[str, Any]] = []
    buffers: dict[socket.socket, bytes] = {}
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_address, port))
        listener.setblocking(False)
        if protocol == "tcp":
            listener.listen(20)
        selector.register(listener, selectors.EVENT_READ, "listener")
        deadline = time.monotonic() + duration
        while len(messages) < max_messages and time.monotonic() < deadline:
            for key, _mask in selector.select(max(0, deadline - time.monotonic())):
                sock = key.fileobj
                if protocol == "udp":
                    data, peer = listener.recvfrom(65535)
                    messages.append(_syslog_message(data, peer))
                elif key.data == "listener":
                    connection, peer = listener.accept()
                    connection.setblocking(False)
                    buffers[connection] = b""
                    selector.register(connection, selectors.EVENT_READ, peer)
                else:
                    data = sock.recv(65535)
                    if not data:
                        pending = buffers.pop(sock, b"")
                        if pending:
                            messages.append(_syslog_message(pending, key.data))
                        selector.unregister(sock)
                        sock.close()
                        continue
                    buffer = buffers.get(sock, b"") + data
                    lines = buffer.split(b"\n")
                    buffers[sock] = lines.pop()
                    for line in lines:
                        if line.rstrip(b"\r"):
                            messages.append(_syslog_message(line.rstrip(b"\r"), key.data))
                            if len(messages) >= max_messages:
                                break
        return messages
    except PermissionError as exc:
        raise ToolInputError("Permission denied opening the syslog port; use port 1024 or higher, or grant bind privileges.") from exc
    except OSError as exc:
        raise ToolInputError(f"Could not run syslog receiver: {exc}") from exc
    finally:
        for connection in list(buffers):
            connection.close()
        selector.close()
        listener.close()


def send_syslog(
    protocol: str,
    host: str,
    port: int,
    *,
    facility: int = 16,
    severity: int = 6,
    hostname: str = "-",
    app_name: str = "twn-toolkit",
    message: str,
    timeout: float = 3,
) -> dict[str, Any]:
    protocol = protocol.lower()
    if protocol not in {"udp", "tcp"}:
        raise ToolInputError("Syslog protocol must be UDP or TCP.")
    validate_hosts(host.strip(), limit=1)
    if not 1 <= port <= 65535:
        raise ToolInputError("Syslog port must be between 1 and 65535.")
    if not 0 <= facility <= 23:
        raise ToolInputError("Syslog facility must be between 0 and 23.")
    if not 0 <= severity <= 7:
        raise ToolInputError("Syslog severity must be between 0 and 7.")
    if not 0.2 <= timeout <= 10:
        raise ToolInputError("Send timeout must be between 0.2 and 10 seconds.")
    if not message or len(message.encode("utf-8")) > 8192:
        raise ToolInputError("Syslog message must be between 1 and 8,192 UTF-8 bytes.")
    hostname = _syslog_token(hostname, "Host name", 255)
    app_name = _syslog_token(app_name, "Application name", 48)
    priority = facility * 8 + severity
    timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    wire_message = f"<{priority}>1 {timestamp} {hostname} {app_name} - - - {message}"
    payload = wire_message.encode("utf-8")
    try:
        answers = socket.getaddrinfo(
            host.strip(),
            port,
            type=socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM,
        )
        if not answers:
            raise ToolInputError(f"Could not resolve syslog destination '{host}'.")
        family, kind, proto, _canonical, address = answers[0]
        with socket.socket(family, kind, proto) as client:
            client.settimeout(timeout)
            if protocol == "udp":
                sent = client.sendto(payload, address)
            else:
                client.connect(address)
                client.sendall(payload + b"\n")
                sent = len(payload) + 1
    except socket.gaierror as exc:
        raise ToolInputError(f"Could not resolve syslog destination: {exc}") from exc
    except OSError as exc:
        raise ToolInputError(f"Could not send syslog message: {exc}") from exc
    return {
        "protocol": protocol.upper(),
        "host": host.strip(),
        "address": str(address[0]),
        "port": port,
        "priority": priority,
        "facility": facility,
        "severity": severity,
        "bytes": sent,
        "wire_message": wire_message,
    }


def _syslog_token(value: str, label: str, maximum: int) -> str:
    value = value.strip() or "-"
    if len(value) > maximum or not re.fullmatch(r"[\x21-\x7e]+", value):
        raise ToolInputError(
            f"{label} must be {maximum} or fewer printable ASCII characters without spaces."
        )
    return value


def _syslog_message(data: bytes, peer: tuple[Any, ...]) -> dict[str, Any]:
    text = data.decode("utf-8", errors="replace")
    priority = None
    match = re.match(r"^<(\d{1,3})>", text)
    if match and int(match.group(1)) <= 191:
        priority = int(match.group(1))
    return {
        "received_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "source": str(peer[0]),
        "source_port": int(peer[1]),
        "priority": priority,
        "facility": priority // 8 if priority is not None else None,
        "severity": priority % 8 if priority is not None else None,
        "message": text,
        "bytes": len(data),
    }
