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

    return DuplicateNameIndex(existing_names).reserve(source_name, max_length=max_length)


class DuplicateNameIndex:
    """Reserve copy names against one snapshot during a batch mutation."""

    def __init__(self, existing_names: Iterable[str]) -> None:
        self._existing = {str(name).strip().casefold() for name in existing_names}
        self._next: dict[tuple[str, int], int] = {}

    def reserve(self, source_name: str, *, max_length: int = 100) -> str:
        source = " ".join(str(source_name).strip().split()) or "Untitled"
        match = _COPY_SUFFIX_RE.fullmatch(source)
        stem = match.group("stem") if match else source

        key = (stem.casefold(), max_length)
        number = self._next.get(key, 1)
        while True:
            suffix = " copy" if number == 1 else f" copy {number}"
            candidate = f"{stem[: max(1, max_length - len(suffix))].rstrip()}{suffix}"
            if candidate.casefold() not in self._existing:
                self._existing.add(candidate.casefold())
                self._next[key] = number + 1
                return candidate
            number += 1
