"""Validation for caller-supplied post-action redirect targets."""

from __future__ import annotations

from urllib.parse import urlsplit


def local_redirect_target(candidate: object, default: str) -> str:
    """Return ``candidate`` only when a browser will keep it on this origin.

    Checking for a leading ``//`` is not sufficient. Browsers discard tabs and
    line breaks while parsing a ``Location`` and treat a backslash as a slash,
    so ``/<TAB>/host`` and ``/\\host`` both resolve to another origin.
    """
    if not isinstance(candidate, str):
        return default
    if not candidate.startswith("/") or candidate.startswith("//"):
        return default
    if "\\" in candidate or any(
        ord(character) < 32 or ord(character) == 127 for character in candidate
    ):
        return default
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return default
    if parsed.scheme or parsed.netloc:
        return default
    return candidate
