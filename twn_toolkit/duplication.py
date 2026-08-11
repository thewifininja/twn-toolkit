from __future__ import annotations

import re
from collections.abc import Iterable


_COPY_SUFFIX_RE = re.compile(r"^(?P<stem>.+?) copy(?: (?P<number>[1-9][0-9]*))?$", re.IGNORECASE)


def duplicate_name(
    source_name: str,
    existing_names: Iterable[str],
    *,
    max_length: int = 100,
) -> str:
    """Return a stable, case-insensitively unique name for a copied record."""

    source = " ".join(str(source_name).strip().split()) or "Untitled"
    match = _COPY_SUFFIX_RE.fullmatch(source)
    stem = match.group("stem") if match else source
    existing = {str(name).strip().casefold() for name in existing_names}

    number = 1
    while True:
        suffix = " copy" if number == 1 else f" copy {number}"
        candidate = f"{stem[: max(1, max_length - len(suffix))].rstrip()}{suffix}"
        if candidate.casefold() not in existing:
            return candidate
        number += 1
