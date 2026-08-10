from __future__ import annotations

from collections.abc import Mapping
import errno
import os
import platform


LEGACY_SSH_RSA_ENVIRONMENT_VARIABLE = "TWN_ALLOW_LEGACY_SSH_RSA"


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
