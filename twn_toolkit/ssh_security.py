from __future__ import annotations

from collections.abc import Mapping
import errno
import os
import platform
import time
from typing import Any


LEGACY_SSH_RSA_ENVIRONMENT_VARIABLE = "TWN_ALLOW_LEGACY_SSH_RSA"
SSH_BANNER_TIMEOUT_SECONDS = 15
SSH_BANNER_ATTEMPTS = 2
SSH_BANNER_RETRY_DELAY_SECONDS = 0.25


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
