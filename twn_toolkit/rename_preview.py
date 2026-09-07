"""Bind a FortiGate rename confirmation to the context actually reviewed."""
from __future__ import annotations

import hmac
import json
from urllib.parse import urlsplit

from flask import current_app, g
from itsdangerous import BadData, URLSafeTimedSerializer

RENAME_PREVIEW_MAX_AGE_SECONDS = 15 * 60


def _serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt="fortigate-rename-preview-v1")


def _binding(task, profile, endpoint, entries):
    context = {
        "instance": current_app.instance_path,
        "actor": (getattr(g, "current_user", None) or {}).get("id", ""),
        "task": task.id,
        "profile": profile,
        "endpoint": endpoint,
        "entries": entries,
    }
    # Only a keyed digest is carried in the token, never profile credentials.
    encoded = json.dumps(context, sort_keys=True, separators=(",", ":")).encode()
    return hmac.digest(_serializer().secret_key, encoded, "sha256").hex()


def issue_rename_preview(task, profile, endpoint, entries):
    return _serializer().dumps(_binding(task, profile, endpoint, entries))


def valid_rename_preview(token, task, profile, endpoint, entries):
    try:
        binding = _serializer().loads(token, max_age=RENAME_PREVIEW_MAX_AGE_SECONDS)
    except BadData:
        return False
    return isinstance(binding, str) and hmac.compare_digest(
        binding, _binding(task, profile, endpoint, entries)
    )


def rename_target(profile):
    """Display the target origin without any URL credentials, path or query."""
    try:
        parsed = urlsplit(profile["host"])
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        return f"{parsed.scheme}://{host}" + (f":{parsed.port}" if parsed.port else "")
    except (TypeError, ValueError):
        return "Configured profile target"
