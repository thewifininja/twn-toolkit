"""Public dependency choices, excluding secrets and internal saved-list metadata."""
from __future__ import annotations

from typing import Any

from .mso_secrets import redact
from .profiles import (
    RadiusProfileStore,
    SNMPCredentialProfileStore,
    SNMPHostProfileStore,
    SNMPOidProfileStore,
)

FIELDS = {
    "snmp": {
        "credentials": ("name", "version"),
        "hosts": ("name", "host", "port", "credential_name"),
        "oids": ("name", "count"),
    },
    "radius": {
        "servers": ("name", "host", "port"),
        "credentials": ("name", "username"),
        "attributes": ("name", "count"),
    },
}


def choice(tool: str, kind: str, profile: dict[str, Any]) -> dict[str, Any]:
    """Project only the agreed display fields; never serialize a whole profile."""
    public = redact(profile)
    if tool == "snmp" and kind == "oids" and "count" not in public:
        # Built-in collections predate persisted count metadata.
        from .network_tools import ToolInputError
        from .snmp_tools import parse_oid_profile

        try:
            public["count"] = len(parse_oid_profile(str(profile.get("source", ""))))
        except (ToolInputError, ValueError):
            public["count"] = 0
    return {field: public[field] for field in FIELDS[tool][kind] if field in public}


def save_acknowledgment(tool: str, kind: str, profile: dict[str, Any]) -> dict[str, Any]:
    """Preserve existing save-control metadata, with its shared secret redaction."""
    public = choice(tool, kind, profile)
    if "mso" in profile:
        public["mso"] = redact(profile["mso"])
    return public


def choices(instance: str, tool: str) -> dict[str, list[dict[str, Any]]]:
    if tool == "snmp":
        stores = {
            "credentials": SNMPCredentialProfileStore(instance),
            "hosts": SNMPHostProfileStore(instance),
            "oids": SNMPOidProfileStore(instance),
        }
    elif tool == "radius":
        stores = {kind: RadiusProfileStore(instance, kind) for kind in FIELDS[tool]}
    else:
        raise ValueError("Unknown network profile tool.")
    return {
        kind: [choice(tool, kind, profile) for profile in store.all()]
        for kind, store in stores.items()
    }
