from __future__ import annotations

import base64
import threading
from pathlib import Path
from typing import Any


# The base64 representation plus job metadata must remain below the 256 KiB
# durable-control envelope. Leave room for the delegated user, route, and headers.
MAX_TUNNEL_BODY_BYTES = 160 * 1024
_clients: dict[tuple[str, str], Any] = {}
_client_locks: dict[tuple[str, str], threading.Lock] = {}
_clients_lock = threading.Lock()


def dispatch_http_request(instance: Path, inputs: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one Mainframe-authenticated request inside the agent web app."""
    method = str(inputs.get("method", "GET")).upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("The tunneled HTTP method is not supported.")
    path = str(inputs.get("path", "/"))
    if not path.startswith("/") or "\x00" in path or len(path) > 8192:
        raise ValueError("The tunneled HTTP path is invalid.")
    prefix = str(inputs.get("prefix", ""))
    if not prefix.startswith("/agents/") or not prefix.endswith("/ui"):
        raise ValueError("The tunneled HTTP prefix is invalid.")
    user = inputs.get("user")
    if not isinstance(user, dict) or not str(user.get("id", "")):
        raise ValueError("A delegated Mainframe user is required.")
    try:
        body = base64.b64decode(str(inputs.get("body", "")), validate=True)
    except ValueError as exc:
        raise ValueError("The tunneled HTTP body is invalid.") from exc
    if len(body) > MAX_TUNNEL_BODY_BYTES:
        raise ValueError("The tunneled HTTP body is too large.")

    from .app import create_app

    key = (str(instance.resolve()), str(user["id"]))
    with _clients_lock:
        client = _clients.get(key)
        if client is None:
            app = create_app(str(instance))
            app.config["DISTRIBUTED_AGENT_DISPATCH"] = True
            client = app.test_client()
            _clients[key] = client
            _client_locks[key] = threading.Lock()
    headers = {
        str(name): str(value)
        for name, value in (inputs.get("headers") or {}).items()
        if str(name).lower() in {"accept", "content-type", "content-length", "range"}
    }
    request_options = {
        "method": method,
        "data": body,
        "headers": headers,
        "environ_overrides": {
            "SCRIPT_NAME": prefix,
            "twn.delegated_user": {
                "id": str(user["id"]),
                "username": str(user.get("username", "Mainframe administrator")),
                "is_admin": bool(user.get("is_admin", False)),
            },
            "twn.delegated_fabric": inputs.get("fabric", {}),
            "REMOTE_ADDR": "127.0.0.1",
        },
        "follow_redirects": False,
    }
    interactive_terminal = (
        path.startswith("/tools/remote-terminal/sessions/")
        and any(path.split("?", 1)[0].endswith(f"/{suffix}") for suffix in ("output", "input", "resize"))
    )
    if interactive_terminal:
        response = client.application.test_client().open(path, **request_options)
    else:
        with _client_locks[key]:
            response = client.open(path, **request_options)
    response_body = response.get_data()
    if len(response_body) > MAX_TUNNEL_BODY_BYTES:
        raise ValueError("The tunneled HTTP response is too large.")
    returned_headers = []
    for name, value in response.headers.items():
        if name.lower() in {
            "content-type", "content-disposition", "location", "cache-control",
            "etag", "last-modified",
        }:
            returned_headers.append([name, value])
    return {
        "status": response.status_code,
        "headers": returned_headers,
        "body": base64.b64encode(response_body).decode("ascii"),
    }
