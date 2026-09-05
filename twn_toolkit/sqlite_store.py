"""Lifecycle helpers for SQLite-backed toolkit stores.

Store construction is the schema boundary.  A normal store connection only
applies connection-local safety settings and executes application data queries.
Schema creation and compatibility migrations run under both the stable
cross-process file lock and SQLite's write transaction so web and worker
processes cannot inspect and alter an older database concurrently.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from .file_transactions import file_transaction


@contextmanager
def sqlite_store_connection(
    path: str | Path,
    *,
    timeout_seconds: float = 10.0,
) -> Iterator[sqlite3.Connection]:
    """Open one writable store connection without performing schema work."""
    database = Path(path)
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        database, timeout=max(0.0, float(timeout_seconds))
    )
    connection.row_factory = sqlite3.Row
    try:
        timeout_milliseconds = max(0, int(float(timeout_seconds) * 1000))
        connection.execute(f"PRAGMA busy_timeout = {timeout_milliseconds}")
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def bootstrap_sqlite_store(
    path: str | Path,
    initializer: Callable[[sqlite3.Connection], None],
    *,
    timeout_seconds: float = 10.0,
) -> None:
    """Run a store's schema initialization once under process and DB locks.

    ``initializer`` may create tables and indexes, make compatible alterations,
    and migrate rows.  It must not commit: this function commits the whole
    schema transition only after the initializer returns successfully.
    """
    database = Path(path)
    with file_transaction(database):
        with sqlite_store_connection(
            database,
            timeout_seconds=timeout_seconds,
        ) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            initializer(connection)
