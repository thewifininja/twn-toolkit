from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from typing import Any, Iterator

from .network_tools import ToolInputError


ACTIVE_STATUSES = {"queued", "running", "stopping"}


class LLDPSessionStore:
    """Durable ownership and state for bounded LLDP egress workers."""

    def __init__(self, instance_path: str | Path) -> None:
        self.instance_path = Path(instance_path).resolve()
        self.path = self.instance_path / "lldp_sessions.sqlite3"
        with self._connect():
            pass

    def create(
        self,
        *,
        interface: str,
        persona: dict[str, Any],
        frame_hex: str,
        shutdown_frame_hex: str,
        created_by: str,
        created_by_username: str,
        investigation_id: str = "",
    ) -> str:
        self._reconcile_workers()
        session_id = os.urandom(12).hex()
        now = time.time()
        duration_seconds = int(persona["duration_minutes"]) * 60
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                """
                SELECT id FROM lldp_sessions
                WHERE interface = ? AND status IN ('queued', 'running', 'stopping')
                LIMIT 1
                """,
                (interface,),
            ).fetchone()
            if active:
                raise ToolInputError(
                    f"An LLDP Lab transmission is already active on {interface}."
                )
            connection.execute(
                """
                INSERT INTO lldp_sessions (
                    id, status, interface, persona_name, persona_json,
                    frame_hex, shutdown_frame_hex, interval_seconds,
                    duration_seconds, created_by, created_by_username,
                    investigation_id, created_at, updated_at
                ) VALUES (?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    interface,
                    str(persona["name"]),
                    json.dumps(persona, separators=(",", ":")),
                    frame_hex,
                    shutdown_frame_hex,
                    int(persona["interval_seconds"]),
                    duration_seconds,
                    created_by,
                    created_by_username,
                    investigation_id,
                    now,
                    now,
                ),
            )
        return session_id

    def launch(self, session_id: str) -> None:
        command = [
            sys.executable,
            "-m",
            "twn_toolkit.lldp_worker",
            "--instance",
            str(self.instance_path),
            "--session-id",
            session_id,
        ]
        try:
            process = subprocess.Popen(
                command,
                cwd=str(Path(__file__).resolve().parent.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            self.finish(session_id, status="error", error=f"Worker launch failed: {exc}")
            raise ToolInputError(f"Could not launch the LLDP worker: {exc}") from exc
        with self._connect() as connection:
            connection.execute(
                "UPDATE lldp_sessions SET worker_pid = ?, updated_at = ? WHERE id = ?",
                (process.pid, time.time(), session_id),
            )

    def begin(self, session_id: str) -> dict[str, Any]:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE lldp_sessions
                SET status = 'running', worker_pid = ?, started_at = ?, updated_at = ?
                WHERE id = ? AND status = 'queued'
                """,
                (os.getpid(), now, now, session_id),
            )
        session = self.get(session_id, reconcile=False)
        if not session or session["status"] != "running":
            raise ToolInputError("LLDP Lab session is not available to run.")
        return session

    def get(self, session_id: str, *, reconcile: bool = True) -> dict[str, Any] | None:
        if reconcile:
            self._reconcile_workers()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM lldp_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        return self._from_row(row) if row else None

    def recent(self, *, user_id: str, limit: int = 20) -> list[dict[str, Any]]:
        self._reconcile_workers()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM lldp_sessions
                WHERE created_by = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (user_id, max(1, min(limit, 100))),
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def request_stop(self, session_id: str, *, user_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE lldp_sessions
                SET stop_requested = 1, status = 'stopping', updated_at = ?
                WHERE id = ? AND created_by = ? AND status IN ('queued', 'running')
                """,
                (time.time(), session_id, user_id),
            )
        if not cursor.rowcount:
            raise ToolInputError("That LLDP Lab session is no longer running.")
        return self.get(session_id, reconcile=False) or {}

    def stop_requested(self, session_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT stop_requested FROM lldp_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        return bool(row and row["stop_requested"])

    def progress(self, session_id: str, *, frames_sent: int) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE lldp_sessions
                SET frames_sent = ?, updated_at = ?
                WHERE id = ? AND status IN ('running', 'stopping')
                """,
                (frames_sent, time.time(), session_id),
            )

    def finish(self, session_id: str, *, status: str, error: str = "") -> None:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE lldp_sessions
                SET status = ?, finished_at = ?, error = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, now, str(error)[:2000], now, session_id),
            )

    def _reconcile_workers(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, worker_pid, updated_at FROM lldp_sessions
                WHERE status IN ('queued', 'running', 'stopping')
                """
            ).fetchall()
            now = time.time()
            for row in rows:
                if row["worker_pid"] is None:
                    if now - float(row["updated_at"]) <= 20:
                        continue
                    connection.execute(
                        """
                        UPDATE lldp_sessions SET status = 'error', finished_at = ?,
                            updated_at = ?, error = 'The LLDP worker did not start.'
                        WHERE id = ? AND status = 'queued'
                        """,
                        (now, now, row["id"]),
                    )
                    continue
                try:
                    os.kill(int(row["worker_pid"]), 0)
                except (OSError, ValueError):
                    connection.execute(
                        """
                        UPDATE lldp_sessions SET status = 'error', finished_at = ?,
                            updated_at = ?, error = CASE WHEN error = ''
                                THEN 'The LLDP worker exited unexpectedly.' ELSE error END
                        WHERE id = ? AND status IN ('queued', 'running', 'stopping')
                        """,
                        (now, now, row["id"]),
                    )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS lldp_sessions (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    persona_name TEXT NOT NULL,
                    persona_json TEXT NOT NULL,
                    frame_hex TEXT NOT NULL,
                    shutdown_frame_hex TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL,
                    duration_seconds INTEGER NOT NULL,
                    worker_pid INTEGER,
                    stop_requested INTEGER NOT NULL DEFAULT 0,
                    frames_sent INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_by_username TEXT NOT NULL DEFAULT '',
                    investigation_id TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    started_at REAL,
                    finished_at REAL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS lldp_sessions_recent
                    ON lldp_sessions(created_at DESC);
                CREATE INDEX IF NOT EXISTS lldp_sessions_active
                    ON lldp_sessions(interface, status);
                """
            )
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
            if self.path.exists():
                os.chmod(self.path, 0o600)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        try:
            item["persona"] = json.loads(item.pop("persona_json"))
        except (json.JSONDecodeError, TypeError):
            item["persona"] = {}
        item["active"] = item["status"] in ACTIVE_STATUSES
        if item.get("started_at") and item["active"]:
            item["elapsed_seconds"] = max(0, int(time.time() - item["started_at"]))
        elif item.get("started_at") and item.get("finished_at"):
            item["elapsed_seconds"] = max(
                0, int(item["finished_at"] - item["started_at"])
            )
        else:
            item["elapsed_seconds"] = 0
        return item
