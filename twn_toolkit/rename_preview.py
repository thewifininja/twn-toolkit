"""Bind a FortiGate rename confirmation to the context actually reviewed."""
from __future__ import annotations

from urllib.parse import urlsplit

from .preview_binding import PREVIEW_MAX_AGE_SECONDS, issue_bound_preview, valid_bound_preview

RENAME_PREVIEW_MAX_AGE_SECONDS = PREVIEW_MAX_AGE_SECONDS
_SCOPE = "fortigate-rename-preview-v1"


def _context(task, profile, endpoint, entries, target_revision=""):
    context = {"task": task.id, "profile": profile, "endpoint": endpoint, "entries": entries}
    if target_revision:
        context["target_revision"] = target_revision
    return context


def issue_rename_preview(task, profile, endpoint, entries, *, target_revision=""):
    return issue_bound_preview(_SCOPE, _context(task, profile, endpoint, entries, target_revision))


def valid_rename_preview(token, task, profile, endpoint, entries, *, target_revision=""):
    return valid_bound_preview(token, _SCOPE, _context(task, profile, endpoint, entries, target_revision),
                               max_age=RENAME_PREVIEW_MAX_AGE_SECONDS)


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
