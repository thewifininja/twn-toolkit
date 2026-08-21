from __future__ import annotations

from pathlib import Path

from .datastore import LocalDatastore, format_bytes


CLASSIC_PCAP_SUFFIXES = {".cap", ".pcap"}


def datastore_packet_captures(
    store: LocalDatastore, *, max_bytes: int
) -> list[dict[str, object]]:
    """List classic PCAP files throughout a datastore with bounded-use metadata."""
    captures: list[dict[str, object]] = []
    for folder in store.folders():
        for entry in store.list(str(folder["path"]))["entries"]:
            if entry["is_dir"]:
                continue
            if Path(str(entry["name"])).suffix.casefold() not in CLASSIC_PCAP_SUFFIXES:
                continue
            captures.append(
                {
                    **entry,
                    "size_display": format_bytes(int(entry["size"])),
                    "within_limit": int(entry["size"]) <= max_bytes,
                }
            )
    return sorted(captures, key=lambda item: str(item["path"]).casefold())
