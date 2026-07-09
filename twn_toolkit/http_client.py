from __future__ import annotations


DEFAULT_HTTP_TIMEOUT_SECONDS = 20
DEFAULT_CONNECT_TIMEOUT_SECONDS = 3


def split_request_timeout(
    timeout: int | float,
    *,
    connect_timeout: int | float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
) -> tuple[float, float]:
    """Return a requests-compatible (connect, read) timeout tuple."""

    read_timeout = max(float(timeout), 1.0)
    return min(float(connect_timeout), read_timeout), read_timeout


def format_seconds(seconds: float) -> str:
    if seconds.is_integer():
        return f"{int(seconds)} seconds"
    return f"{seconds:g} seconds"
