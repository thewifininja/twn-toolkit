from __future__ import annotations

import os


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
    """Add actionable guidance to SSH algorithm-negotiation failures."""
    message = f"{type(exc).__name__}: {exc}"
    normalized = message.lower()
    if "incompatiblepeer" in normalized or "no acceptable" in normalized:
        return f"{message}. This device may require legacy SSH compatibility."
    return message
