"""Disabled EAP test compatibility API; no external supplicant is invoked."""
from __future__ import annotations

from typing import Any

from .network_tools import ToolInputError

EAP_DISABLED_REASON = (
    "EAP testing is temporarily disabled because the external test program exposes "
    "the RADIUS shared secret in process arguments. PAP and CHAP remain available."
)


def eapol_test_available() -> bool:
    """The toolkit capability stays unavailable even if the executable exists."""
    return False


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
    # No runtime flag or installed binary can enable the unsafe argv path.
    raise ToolInputError(EAP_DISABLED_REASON)
