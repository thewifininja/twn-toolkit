from __future__ import annotations

import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class AuditStore:
    def __init__(self, instance_path: str) -> None:
        self.path = Path(instance_path) / "audit.sqlite3"
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY, recorded_at REAL NOT NULL, user_id TEXT NOT NULL,
                    username TEXT NOT NULL, remote_ip TEXT NOT NULL, method TEXT NOT NULL,
                    endpoint TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS audit_events_recent ON audit_events(recorded_at DESC);
            """)

    def record(self, **values: Any) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?)", (
                secrets.token_hex(12), time.time(), str(values.get("user_id", "")),
                str(values.get("username", ""))[:128], str(values.get("remote_ip", ""))[:128],
                str(values.get("method", ""))[:12], str(values.get("endpoint", ""))[:160],
                str(values.get("path", ""))[:500], int(values.get("status_code", 0)),
            ))
            connection.execute("DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY recorded_at DESC LIMIT 10000)")

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM audit_events ORDER BY recorded_at DESC LIMIT ?", (limit,))]

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10); connection.row_factory = sqlite3.Row
        try: yield connection; connection.commit()
        except Exception: connection.rollback(); raise
        finally:
            connection.close()
            if self.path.exists(): os.chmod(self.path, 0o600)
