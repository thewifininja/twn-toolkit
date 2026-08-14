from __future__ import annotations

import base64
from collections.abc import Mapping
import errno
import hashlib
import hmac
import os
from pathlib import Path
import platform
import re
import stat
import tempfile
import threading
import time
from typing import Any


LEGACY_SSH_RSA_ENVIRONMENT_VARIABLE = "TWN_ALLOW_LEGACY_SSH_RSA"
SSH_BANNER_TIMEOUT_SECONDS = 15
SSH_BANNER_ATTEMPTS = 2
SSH_BANNER_RETRY_DELAY_SECONDS = 0.25
_KNOWN_HOSTS_EDIT_LOCK = threading.Lock()
_KNOWN_HOSTS_LINE = re.compile(r"^(\s*)(\S+)([ \t]+.*?)(\r?\n)?$")


class SSHKnownHostsError(ValueError):
    pass


def disabled_ssh_algorithms(
    *, allow_legacy_algorithms: bool = False
) -> dict[str, list[str]] | None:
    """Return the shared SSH policy, allowing a scoped legacy exception."""
    environment_override = os.environ.get(
        LEGACY_SSH_RSA_ENVIRONMENT_VARIABLE, ""
    ).strip().lower() in {"1", "true", "yes", "on"}
    if allow_legacy_algorithms or environment_override:
        return None
    return {
        "keys": ["ssh-rsa"],
        "pubkeys": ["ssh-rsa"],
    }


def open_ssh_client(
    *,
    hostname: str,
    port: int,
    username: str,
    password: str,
    allow_unknown_hosts: bool,
    allow_legacy_algorithms: bool = False,
    connect_timeout: float = 10,
    auth_timeout: float = 10,
) -> Any:
    """Open an SSH client with one bounded retry for a missing server banner."""
    import paramiko

    for attempt in range(SSH_BANNER_ATTEMPTS):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
            if allow_unknown_hosts
            else paramiko.RejectPolicy()
        )
        try:
            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                allow_agent=False,
                look_for_keys=False,
                timeout=connect_timeout,
                auth_timeout=auth_timeout,
                banner_timeout=SSH_BANNER_TIMEOUT_SECONDS,
                disabled_algorithms=disabled_ssh_algorithms(
                    allow_legacy_algorithms=allow_legacy_algorithms
                ),
            )
            return client
        except Exception as exc:
            close_ssh_client(client)
            if attempt + 1 >= SSH_BANNER_ATTEMPTS or not _is_banner_failure(exc):
                raise
            time.sleep(SSH_BANNER_RETRY_DELAY_SECONDS)
    raise RuntimeError("SSH connection attempts were exhausted.")


def close_ssh_client(client: Any | None) -> None:
    """Close Paramiko's socket even when a failed transport is inactive."""
    if client is None:
        return
    transport = None
    try:
        transport = client.get_transport()
    except Exception:
        pass
    connection = getattr(transport, "sock", None)
    try:
        client.close()
    except Exception:
        pass
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _is_banner_failure(exc: BaseException) -> bool:
    return "error reading ssh protocol banner" in str(exc).lower()


def format_ssh_connection_error(exc: Exception) -> str:
    """Add actionable guidance to known SSH connection failures."""
    mismatch = ssh_host_key_mismatch(exc)
    if mismatch:
        return (
            f"SSH host identity changed for {mismatch['hostname']}. The "
            f"presented {mismatch['presented_key_type']} key does not match "
            f"the saved {mismatch['expected_key_type']} key. Verify the "
            "device before forgetting the saved key."
        )
    message = f"{type(exc).__name__}: {exc}"
    normalized = message.lower()
    if "incompatiblepeer" in normalized or "no acceptable" in normalized:
        return f"{message}. This device may require legacy SSH compatibility."
    if platform.system() == "Darwin" and errno.EHOSTUNREACH in _nested_errnos(exc):
        return (
            f"{message}. macOS may be blocking local-network access for this "
            "background toolkit process. Test the target from the toolkit TCP "
            "Port Scanner and review Local Network Privacy; a successful "
            "Terminal connection does not test the same privacy context."
        )
    return message


def ssh_host_key_mismatch(exc: Exception) -> dict[str, str] | None:
    """Return safe, readable details for Paramiko host-identity failures."""
    if type(exc).__name__ != "BadHostKeyException":
        return None
    presented = getattr(exc, "key", None)
    expected = getattr(exc, "expected_key", None)
    hostname = str(getattr(exc, "hostname", "")).strip()
    if not hostname or presented is None or expected is None:
        return None
    try:
        return {
            "hostname": hostname,
            "presented_key_type": str(presented.get_name()),
            "presented_fingerprint": ssh_key_fingerprint(presented),
            "expected_key_type": str(expected.get_name()),
            "expected_fingerprint": ssh_key_fingerprint(expected),
        }
    except Exception:
        return None


def ssh_key_fingerprint(key: Any) -> str:
    """Return the familiar OpenSSH SHA-256 fingerprint for a public key."""
    digest = hashlib.sha256(bytes(key.asbytes())).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def forget_ssh_known_host(
    hostname: str,
    port: int,
    expected_fingerprint: str,
    *,
    known_hosts_path: Path | None = None,
) -> dict[str, Any]:
    """Remove one verified host identity from the user's OpenSSH trust file."""
    clean_host = str(hostname).strip()
    try:
        clean_port = int(port)
    except (TypeError, ValueError) as exc:
        raise SSHKnownHostsError("Enter a valid SSH port.") from exc
    if (
        not clean_host
        or len(clean_host) > 255
        or any(character.isspace() for character in clean_host)
        or any(character in clean_host for character in (",", "\x00"))
    ):
        raise SSHKnownHostsError("Enter a valid SSH host name or IP address.")
    if not 1 <= clean_port <= 65535:
        raise SSHKnownHostsError("SSH port must be between 1 and 65535.")
    clean_fingerprint = str(expected_fingerprint).strip()
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", clean_fingerprint):
        raise SSHKnownHostsError("The expected SSH fingerprint is invalid.")

    configured_path = known_hosts_path or Path.home() / ".ssh" / "known_hosts"
    try:
        target = configured_path.expanduser().resolve(strict=True)
    except FileNotFoundError as exc:
        raise SSHKnownHostsError("No saved system SSH key exists for this host.") from exc
    if not target.is_file():
        raise SSHKnownHostsError("The system SSH known-hosts path is not a file.")

    identity = clean_host if clean_port == 22 else f"[{clean_host}]:{clean_port}"
    with _KNOWN_HOSTS_EDIT_LOCK:
        try:
            original = target.read_bytes()
        except OSError as exc:
            raise SSHKnownHostsError("The saved SSH key could not be read.") from exc
        lines = original.decode("utf-8", errors="surrogateescape").splitlines()
        matching = [
            parsed
            for line in lines
            if (parsed := _known_hosts_line(line, identity)) is not None
        ]
        if not matching:
            raise SSHKnownHostsError("No saved system SSH key exists for this host.")
        if clean_fingerprint not in {
            str(item[1]) for item in matching if item[1]
        }:
            raise SSHKnownHostsError(
                "The saved SSH key changed after these results were generated. Run Bulk SSH again before removing it."
            )

        rewritten: list[str] = []
        removed_entries = 0
        for line in lines:
            parsed = _known_hosts_line(line, identity)
            if parsed is None:
                rewritten.append(line)
                continue
            retained_hosts = parsed[0]
            removed_entries += 1
            if retained_hosts:
                match = _KNOWN_HOSTS_LINE.match(line)
                if match:
                    rewritten.append(
                        f"{match.group(1)}{','.join(retained_hosts)}{match.group(3)}"
                    )

        trailing_newline = original.endswith((b"\n", b"\r"))
        updated_text = "\n".join(rewritten)
        if rewritten and trailing_newline:
            updated_text += "\n"
        _atomic_known_hosts_write(
            target, updated_text.encode("utf-8", errors="surrogateescape")
        )

    return {
        "hostname": clean_host,
        "port": clean_port,
        "identity": identity,
        "removed_entries": removed_entries,
    }


def _known_hosts_line(line: str, identity: str) -> tuple[list[str], str] | None:
    match = _KNOWN_HOSTS_LINE.match(line)
    if not match or match.group(2).startswith(("#", "@")):
        return None
    hosts = match.group(2).split(",")
    matching_hosts = [host for host in hosts if _known_host_matches(host, identity)]
    if not matching_hosts:
        return None
    fields = match.group(3).strip().split()
    fingerprint = ""
    if len(fields) >= 2:
        try:
            key_blob = base64.b64decode(fields[1].encode("ascii"), validate=True)
            fingerprint = "SHA256:" + base64.b64encode(
                hashlib.sha256(key_blob).digest()
            ).decode("ascii").rstrip("=")
        except (UnicodeEncodeError, ValueError):
            fingerprint = ""
    retained = [host for host in hosts if host not in matching_hosts]
    return retained, fingerprint


def _known_host_matches(saved_host: str, identity: str) -> bool:
    if hmac.compare_digest(saved_host, identity):
        return True
    if not saved_host.startswith("|1|"):
        return False
    parts = saved_host.split("|")
    if len(parts) != 4:
        return False
    try:
        salt = base64.b64decode(parts[2].encode("ascii"), validate=True)
        expected = base64.b64decode(parts[3].encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError):
        return False
    actual = hmac.new(salt, identity.encode("utf-8"), hashlib.sha1).digest()
    return hmac.compare_digest(actual, expected)


def _atomic_known_hosts_write(target: Path, content: bytes) -> None:
    existing = target.stat()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.twn-", dir=str(target.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, stat.S_IMODE(existing.st_mode))
        if hasattr(os, "chown"):
            os.chown(temporary, existing.st_uid, existing.st_gid)
        os.replace(temporary, target)
    except OSError as exc:
        raise SSHKnownHostsError("The saved SSH key could not be updated.") from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _nested_errnos(exc: BaseException) -> set[int]:
    """Collect errno values hidden by wrappers such as Paramiko."""
    found: set[int] = set()
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        value = getattr(current, "errno", None)
        if isinstance(value, int):
            found.add(value)
        wrapped = getattr(current, "errors", None)
        if isinstance(wrapped, Mapping):
            pending.extend(
                item for item in wrapped.values() if isinstance(item, BaseException)
            )
        for item in (current.__cause__, current.__context__):
            if isinstance(item, BaseException):
                pending.append(item)
    return found
