from __future__ import annotations

import os


LEGACY_SSH_RSA_ENVIRONMENT_VARIABLE = "TWN_ALLOW_LEGACY_SSH_RSA"


def disabled_ssh_algorithms() -> dict[str, list[str]] | None:
    """Disable SHA-1 RSA negotiation unless an operator explicitly opts in."""
    allow_legacy = os.environ.get(
        LEGACY_SSH_RSA_ENVIRONMENT_VARIABLE, ""
    ).strip().lower() in {"1", "true", "yes", "on"}
    if allow_legacy:
        return None
    return {
        "keys": ["ssh-rsa"],
        "pubkeys": ["ssh-rsa"],
    }
