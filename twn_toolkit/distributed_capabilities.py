from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .network_tools import (
    ToolInputError,
    dns_lookup_matrix,
    parse_dns_hosts,
    parse_dns_servers,
)
from .system_identity import collect_system_identity
from .distributed_http import dispatch_http_request


CapabilityHandler = Callable[[Path, dict[str, Any]], dict[str, Any]]


def advertised_capabilities() -> list[dict[str, str]]:
    return [
        {"id": capability_id, "version": version}
        for capability_id, version in _CAPABILITIES
    ]


def execute_capability(
    instance_path: str | Path,
    capability_id: str,
    capability_version: str,
    inputs: object,
) -> dict[str, Any]:
    handler = _CAPABILITIES.get((str(capability_id), str(capability_version)))
    if handler is None:
        raise ValueError("Agent does not support the requested capability version.")
    if not isinstance(inputs, dict):
        raise ValueError("Remote tool inputs must be an object.")
    return handler(Path(instance_path), inputs)


def _system_identity(instance: Path, _inputs: dict[str, Any]) -> dict[str, Any]:
    return collect_system_identity(instance)


def _dns_lookup(_instance: Path, inputs: dict[str, Any]) -> dict[str, Any]:
    hosts_text = _bounded_text(inputs.get("hosts", ""), 8192, "DNS query names")
    servers_text = _bounded_text(inputs.get("servers", ""), 2048, "DNS servers")
    record_type = _bounded_text(inputs.get("record_type", "A"), 16, "Record type")
    try:
        timeout = float(inputs.get("timeout", 3))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("DNS timeout must be a number.") from exc
    hosts = parse_dns_hosts(hosts_text, limit=25)
    servers = parse_dns_servers(servers_text, limit=8)
    results = dns_lookup_matrix(hosts, servers, record_type, timeout)
    successful = [item for item in results if item.get("status") == "success"]
    return {
        "form": {
            "hosts": hosts_text,
            "servers": servers_text,
            "record_type": record_type.upper(),
            "timeout": str(inputs.get("timeout", "3")),
        },
        "summary": {
            "queries": len(results),
            "successful": len(successful),
            "failed": len(results) - len(successful),
            "average_ms": (
                round(
                    sum(float(item["response_ms"]) for item in successful)
                    / len(successful),
                    1,
                )
                if successful
                else None
            ),
        },
        "results": results,
    }


def _bounded_text(value: object, limit: int, label: str) -> str:
    text = str(value).strip()
    if not text:
        raise ToolInputError(f"{label} cannot be empty.")
    if len(text.encode("utf-8")) > limit:
        raise ToolInputError(f"{label} exceeds the remote tool limit.")
    return text


_CAPABILITIES: dict[tuple[str, str], CapabilityHandler] = {
    ("system.http.tunnel", "1"): dispatch_http_request,
    ("system.identity", "1"): _system_identity,
    ("tools.dns.lookup", "1"): _dns_lookup,
}
