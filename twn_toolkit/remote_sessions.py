from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .investigations import InvestigationError, InvestigationStore
from .serial_console import SerialConsoleError, open_serial_channel, serial_settings
from .ssh_security import close_ssh_client, format_ssh_connection_error, open_ssh_client
from .telnet_client import open_telnet_channel


REMOTE_SESSION_LIMIT_PER_USER = 12
REMOTE_SESSION_OUTPUT_LIMIT_BYTES = 100 * 1024 * 1024
REMOTE_SESSION_LIVE_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024
REMOTE_SESSION_INPUT_LIMIT_BYTES = 16 * 1024
REMOTE_SESSION_OUTPUT_PAGE_LIMIT = 500
REMOTE_SESSION_OUTPUT_PAGE_BYTES = 512 * 1024
REMOTE_SESSION_CHECKPOINT_LIMIT_BYTES = 8 * 1024 * 1024
REMOTE_SESSION_CHECKPOINT_VERSION = 1
REMOTE_SESSION_IDLE_SECONDS = 8 * 60 * 60
REMOTE_SESSION_RETENTION_SECONDS = 7 * 24 * 60 * 60
ACTIVE_REMOTE_SESSION_STATES = frozenset({"connecting", "running"})

_ANSI_ESCAPE = re.compile(
    r"(?:\x1B[@-_][0-?]*[ -/]*[@-~]|\x1B\][^\x07]*(?:\x07|\x1B\\))"
)


class RemoteSessionError(ValueError):
    pass


class RemoteSessionStore:
    """Durable transcripts and rolling live delivery for browser-managed shells."""

    def __init__(self, instance_path: str) -> None:
        self.instance_path = Path(instance_path)
        self.instance_path.mkdir(parents=True, exist_ok=True)
        self.path = self.instance_path / "remote_sessions.sqlite3"
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS remote_sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    title TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    remote_username TEXT NOT NULL,
                    telnet_username_available INTEGER NOT NULL DEFAULT 0,
                    telnet_password_available INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL,
                    record_transcript INTEGER NOT NULL DEFAULT 0,
                    investigation_id TEXT NOT NULL DEFAULT '',
                    investigation_attached_at REAL,
                    allow_unknown_hosts INTEGER NOT NULL DEFAULT 0,
                    allow_legacy_algorithms INTEGER NOT NULL DEFAULT 0,
                    console_device_id TEXT NOT NULL DEFAULT '',
                    console_device_path TEXT NOT NULL DEFAULT '',
                    console_device_label TEXT NOT NULL DEFAULT '',
                    console_baud_rate INTEGER NOT NULL DEFAULT 9600,
                    console_data_bits INTEGER NOT NULL DEFAULT 8,
                    console_parity TEXT NOT NULL DEFAULT 'none',
                    console_stop_bits TEXT NOT NULL DEFAULT '1',
                    console_flow_control TEXT NOT NULL DEFAULT 'none',
                    terminal_columns INTEGER NOT NULL DEFAULT 120,
                    terminal_rows INTEGER NOT NULL DEFAULT 32,
                    output_bytes INTEGER NOT NULL DEFAULT 0,
                    output_truncated INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    termination TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    connected_at REAL,
                    last_activity_at REAL NOT NULL,
                    completed_at REAL,
                    evidence_finalized_at REAL
                );
                CREATE INDEX IF NOT EXISTS remote_sessions_user_active
                    ON remote_sessions(user_id, state, created_at);
                CREATE INDEX IF NOT EXISTS remote_sessions_case_active
                    ON remote_sessions(investigation_id, state, created_at);
                CREATE TABLE IF NOT EXISTS remote_session_output (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    output TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES remote_sessions(id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS remote_session_output_cursor
                    ON remote_session_output(session_id, id);
                CREATE TABLE IF NOT EXISTS remote_session_live_output (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    output TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES remote_sessions(id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS remote_session_live_output_cursor
                    ON remote_session_live_output(session_id, id);
                CREATE TABLE IF NOT EXISTS remote_session_store_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS remote_session_checkpoints (
                    session_id TEXT PRIMARY KEY,
                    output_cursor INTEGER NOT NULL,
                    snapshot TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES remote_sessions(id)
                        ON DELETE CASCADE
                );
                """
            )
            # Web workers initialize this store independently. Keep every
            # inspect-and-alter migration under one writer lock so two fresh
            # workers cannot race on a newly introduced session column.
            connection.execute("BEGIN IMMEDIATE")
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(remote_sessions)")
            }
            migrations = {
                "owner_pid": "INTEGER NOT NULL DEFAULT 0",
                "control_path": "TEXT NOT NULL DEFAULT ''",
                "source_host_id": "TEXT NOT NULL DEFAULT ''",
                "investigation_attached_at": "REAL",
                "telnet_username_available": "INTEGER NOT NULL DEFAULT 0",
                "telnet_password_available": "INTEGER NOT NULL DEFAULT 0",
                "console_device_id": "TEXT NOT NULL DEFAULT ''",
                "console_device_path": "TEXT NOT NULL DEFAULT ''",
                "console_device_label": "TEXT NOT NULL DEFAULT ''",
                "console_baud_rate": "INTEGER NOT NULL DEFAULT 9600",
                "console_data_bits": "INTEGER NOT NULL DEFAULT 8",
                "console_parity": "TEXT NOT NULL DEFAULT 'none'",
                "console_stop_bits": "TEXT NOT NULL DEFAULT '1'",
                "console_flow_control": "TEXT NOT NULL DEFAULT 'none'",
                "terminal_columns": "INTEGER NOT NULL DEFAULT 120",
                "terminal_rows": "INTEGER NOT NULL DEFAULT 32",
                "live_output_bytes": "INTEGER NOT NULL DEFAULT 0",
                "live_output_floor_cursor": "INTEGER NOT NULL DEFAULT 0",
            }
            for name, definition in migrations.items():
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE remote_sessions ADD COLUMN {name} {definition}"
                    )
            live_migration = connection.execute(
                """
                SELECT 1 FROM remote_session_store_metadata
                WHERE key = 'live_output_v1'
                """
            ).fetchone()
            if not live_migration:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO remote_session_live_output(
                        id, session_id, output, created_at
                    )
                    SELECT id, session_id, output, created_at
                    FROM remote_session_output
                    """
                )
                connection.execute(
                    """
                    UPDATE remote_sessions
                    SET live_output_bytes = COALESCE((
                        SELECT SUM(length(CAST(output AS BLOB)))
                        FROM remote_session_live_output
                        WHERE remote_session_live_output.session_id = remote_sessions.id
                    ), 0)
                    """
                )
                connection.execute(
                    """
                    INSERT INTO remote_session_store_metadata(key, value)
                    VALUES ('live_output_v1', 'complete')
                    """
                )
            connection.execute(
                """
                DELETE FROM remote_sessions
                WHERE completed_at IS NOT NULL AND completed_at < ?
                """,
                (time.time() - REMOTE_SESSION_RETENTION_SECONDS,),
            )

    def interrupt_session(self, session_id: str) -> dict[str, Any] | None:
        """Mark a shell whose owning worker no longer exists as interrupted."""
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE remote_sessions
                SET state = 'interrupted', termination = 'toolkit_restart',
                    completed_at = ?, last_activity_at = ?
                WHERE id = ? AND state IN ('connecting', 'running')
                """,
                (now, now, session_id),
            )
        return self.get_session(session_id)

    def active_sessions(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM remote_sessions
                WHERE state IN ('connecting', 'running')
                ORDER BY created_at
                """
            ).fetchall()
        return [self._session(row) for row in rows]

    def create_session(
        self,
        *,
        user_id: str,
        username: str,
        title: str,
        host: str,
        port: int,
        remote_username: str,
        record_transcript: bool,
        telnet_username_available: bool = False,
        telnet_password_available: bool = False,
        investigation_id: str = "",
        allow_unknown_hosts: bool = False,
        allow_legacy_algorithms: bool = False,
        source_host_id: str = "",
        owner_pid: int = 0,
        control_path: str = "",
        protocol: str = "ssh",
        console_device_id: str = "",
        console_device_path: str = "",
        console_device_label: str = "",
        console_baud_rate: int = 9600,
        console_data_bits: int = 8,
        console_parity: str = "none",
        console_stop_bits: str = "1",
        console_flow_control: str = "none",
        terminal_columns: int = 120,
        terminal_rows: int = 32,
    ) -> dict[str, Any]:
        clean_protocol = str(protocol).strip().lower()
        if clean_protocol not in {"ssh", "telnet", "console"}:
            raise RemoteSessionError("Choose SSH, Telnet, or Console.")
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active_count = connection.execute(
                """
                SELECT COUNT(*) FROM remote_sessions
                WHERE user_id = ? AND state IN ('connecting', 'running')
                """,
                (user_id,),
            ).fetchone()[0]
            if int(active_count) >= REMOTE_SESSION_LIMIT_PER_USER:
                raise RemoteSessionError(
                    f"Stop one of your remote sessions before starting another. "
                    f"Each operator can keep up to {REMOTE_SESSION_LIMIT_PER_USER}."
                )
            if clean_protocol == "console":
                if not console_device_id:
                    raise RemoteSessionError("Choose a local console device.")
                in_use = connection.execute(
                    """
                    SELECT title FROM remote_sessions
                    WHERE protocol = 'console' AND console_device_id = ?
                      AND state IN ('connecting', 'running')
                    LIMIT 1
                    """,
                    (console_device_id,),
                ).fetchone()
                if in_use:
                    raise RemoteSessionError(
                        "That console device is already in use by another active session."
                    )
            session_id = secrets.token_hex(12)
            connection.execute(
                """
                INSERT INTO remote_sessions (
                    id, user_id, username, title, protocol, host, port,
                    remote_username, telnet_username_available,
                    telnet_password_available, state, record_transcript, investigation_id,
                    investigation_attached_at,
                    allow_unknown_hosts, allow_legacy_algorithms, created_at,
                    last_activity_at, owner_pid, control_path, source_host_id,
                    console_device_id, console_device_path, console_device_label,
                    console_baud_rate, console_data_bits, console_parity,
                    console_stop_bits, console_flow_control, terminal_columns,
                    terminal_rows
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'connecting', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    user_id,
                    username,
                    title,
                    clean_protocol,
                    host,
                    port,
                    remote_username,
                    int(telnet_username_available),
                    int(telnet_password_available),
                    int(record_transcript),
                    investigation_id,
                    now if investigation_id else None,
                    int(allow_unknown_hosts),
                    int(allow_legacy_algorithms),
                    now,
                    now,
                    owner_pid,
                    control_path,
                    source_host_id,
                    console_device_id if clean_protocol == "console" else "",
                    console_device_path if clean_protocol == "console" else "",
                    console_device_label if clean_protocol == "console" else "",
                    int(console_baud_rate),
                    int(console_data_bits),
                    str(console_parity),
                    str(console_stop_bits),
                    str(console_flow_control),
                    int(terminal_columns),
                    int(terminal_rows),
                ),
            )
        session = self.get_session(session_id, user_id=user_id)
        if session is None:  # pragma: no cover
            raise RuntimeError("Remote session could not be created.")
        return session

    def get_session(
        self, session_id: str, *, user_id: str = ""
    ) -> dict[str, Any] | None:
        query = "SELECT * FROM remote_sessions WHERE id = ?"
        values: tuple[Any, ...] = (session_id,)
        if user_id:
            query += " AND user_id = ?"
            values += (user_id,)
        with self._connect() as connection:
            row = connection.execute(query, values).fetchone()
        return self._session(row) if row else None

    def sessions_for_user(
        self, user_id: str, *, include_finished: bool = False
    ) -> list[dict[str, Any]]:
        states = (
            "('connecting', 'running', 'stopped', 'error', 'interrupted')"
            if include_finished
            else "('connecting', 'running')"
        )
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM remote_sessions
                WHERE user_id = ? AND state IN {states}
                ORDER BY created_at DESC
                LIMIT 24
                """,
                (user_id,),
            ).fetchall()
        return [self._session(row) for row in rows]

    def sessions_for_investigation(
        self, investigation_id: str, *, user_id: str
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM remote_sessions
                WHERE investigation_id = ? AND user_id = ?
                  AND state IN ('connecting', 'running')
                ORDER BY created_at
                """,
                (investigation_id, user_id),
            ).fetchall()
        return [self._session(row) for row in rows]

    def sessions_needing_evidence_finalization(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM remote_sessions
                WHERE investigation_id != ''
                  AND state NOT IN ('connecting', 'running')
                  AND evidence_finalized_at IS NULL
                ORDER BY completed_at
                """
            ).fetchall()
        return [self._session(row) for row in rows]

    def mark_connected(self, session_id: str) -> dict[str, Any] | None:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE remote_sessions
                SET state = 'running', connected_at = ?, last_activity_at = ?
                WHERE id = ? AND state = 'connecting'
                """,
                (now, now, session_id),
            )
        return self.get_session(session_id)

    def touch(self, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE remote_sessions SET last_activity_at = ? WHERE id = ?",
                (time.time(), session_id),
            )

    def update_terminal_geometry(
        self,
        session_id: str,
        *,
        user_id: str,
        columns: int,
        rows: int,
    ) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE remote_sessions
                SET terminal_columns = ?, terminal_rows = ?
                WHERE id = ? AND user_id = ?
                """,
                (int(columns), int(rows), session_id, user_id),
            )
        session = self.get_session(session_id, user_id=user_id)
        if not session:  # pragma: no cover - ownership is checked by the manager
            raise RemoteSessionError("Remote session not found.")
        return session

    def append_output(self, session_id: str, output: str) -> int:
        if not output:
            return 0
        encoded = output.encode("utf-8", errors="replace")
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT output_bytes, live_output_bytes, live_output_floor_cursor, state
                FROM remote_sessions WHERE id = ?
                """,
                (session_id,),
            ).fetchone()
            if not row:
                return 0
            live = encoded.decode("utf-8", errors="replace")
            live_cursor = int(
                connection.execute(
                    """
                    INSERT INTO remote_session_live_output(session_id, output, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (session_id, live, now),
                ).lastrowid
            )
            remaining = REMOTE_SESSION_OUTPUT_LIMIT_BYTES - int(row["output_bytes"])
            retained = encoded[: max(0, remaining)]
            while retained:
                try:
                    clean = retained.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    retained = retained[:-1]
            else:
                clean = ""
            if clean:
                connection.execute(
                    """
                    INSERT INTO remote_session_output(session_id, output, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (session_id, clean, now),
                )
            kept = len(retained)
            connection.execute(
                """
                UPDATE remote_sessions
                SET output_bytes = output_bytes + ?,
                    output_truncated = MAX(output_truncated, ?),
                    live_output_bytes = live_output_bytes + ?,
                    last_activity_at = ?
                WHERE id = ?
                """,
                (kept, int(kept < len(encoded)), len(encoded), now, session_id),
            )
            live_bytes = int(row["live_output_bytes"]) + len(encoded)
            if live_bytes > REMOTE_SESSION_LIVE_OUTPUT_LIMIT_BYTES:
                excess = live_bytes - REMOTE_SESSION_LIVE_OUTPUT_LIMIT_BYTES
                reclaimed = 0
                floor_cursor = int(row["live_output_floor_cursor"])
                oldest = connection.execute(
                    """
                    SELECT id, length(CAST(output AS BLOB)) AS byte_count
                    FROM remote_session_live_output
                    WHERE session_id = ? AND id < ?
                    ORDER BY id
                    """,
                    (session_id, live_cursor),
                ).fetchall()
                for old in oldest:
                    reclaimed += int(old["byte_count"])
                    floor_cursor = int(old["id"])
                    if reclaimed >= excess:
                        break
                if reclaimed:
                    connection.execute(
                        """
                        DELETE FROM remote_session_live_output
                        WHERE session_id = ? AND id <= ?
                        """,
                        (session_id, floor_cursor),
                    )
                    connection.execute(
                        """
                        UPDATE remote_sessions
                        SET live_output_bytes = MAX(0, live_output_bytes - ?),
                            live_output_floor_cursor = MAX(live_output_floor_cursor, ?)
                        WHERE id = ?
                        """,
                        (reclaimed, floor_cursor, session_id),
                    )
        return kept

    def save_checkpoint(
        self,
        session_id: str,
        *,
        user_id: str,
        output_cursor: int,
        snapshot: dict[str, Any],
    ) -> bool:
        """Retain an owner-scoped browser terminal state at a durable output cursor."""
        if (
            not isinstance(snapshot, dict)
            or snapshot.get("version") != REMOTE_SESSION_CHECKPOINT_VERSION
        ):
            raise RemoteSessionError("Terminal checkpoint format is not supported.")
        columns = snapshot.get("columns")
        rows = snapshot.get("rows")
        history = snapshot.get("history")
        screen = snapshot.get("screen")
        if (
            not isinstance(columns, int)
            or isinstance(columns, bool)
            or not 40 <= columns <= 300
            or not isinstance(rows, int)
            or isinstance(rows, bool)
            or not 10 <= rows <= 120
            or not isinstance(history, list)
            or len(history) > 12000
            or not isinstance(screen, list)
            or not screen
            or len(screen) > rows
        ):
            raise RemoteSessionError("Terminal checkpoint state is invalid.")
        try:
            encoded = json.dumps(
                snapshot,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise RemoteSessionError("Terminal checkpoint is not valid JSON.") from exc
        if len(encoded.encode("utf-8")) > REMOTE_SESSION_CHECKPOINT_LIMIT_BYTES:
            raise RemoteSessionError("Terminal checkpoint is too large.")

        cursor = int(output_cursor)
        if cursor <= 0:
            raise RemoteSessionError("Terminal checkpoint cursor is invalid.")
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            owned = connection.execute(
                "SELECT 1 FROM remote_sessions WHERE id = ? AND user_id = ?",
                (session_id, user_id),
            ).fetchone()
            if not owned:
                return False
            cursor_range = connection.execute(
                """
                SELECT live_output_floor_cursor,
                       (SELECT MAX(id) FROM remote_session_live_output
                        WHERE session_id = remote_sessions.id) AS latest_cursor
                FROM remote_sessions
                WHERE id = ? AND user_id = ?
                """,
                (session_id, user_id),
            ).fetchone()
            floor_cursor = int(cursor_range["live_output_floor_cursor"] or 0)
            latest_cursor = int(cursor_range["latest_cursor"] or 0)
            if cursor < floor_cursor or cursor > latest_cursor:
                raise RemoteSessionError("Terminal checkpoint cursor is unavailable.")
            existing = connection.execute(
                """
                SELECT output_cursor FROM remote_session_checkpoints
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if existing and int(existing["output_cursor"]) >= cursor:
                return False
            connection.execute(
                """
                INSERT INTO remote_session_checkpoints(
                    session_id, output_cursor, snapshot, created_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    output_cursor = excluded.output_cursor,
                    snapshot = excluded.snapshot,
                    created_at = excluded.created_at
                """,
                (session_id, cursor, encoded, now),
            )
        return True

    def output_page(
        self,
        session_id: str,
        *,
        user_id: str,
        after_id: int = 0,
        include_checkpoint: bool = False,
    ) -> dict[str, Any] | None:
        session = self.get_session(session_id, user_id=user_id)
        if not session:
            return None
        checkpoint: dict[str, Any] | None = None
        cursor = max(0, after_id)
        floor_cursor = 0
        history_gap = False
        with self._connect() as connection:
            live_state = connection.execute(
                """
                SELECT live_output_floor_cursor
                FROM remote_sessions WHERE id = ? AND user_id = ?
                """,
                (session_id, user_id),
            ).fetchone()
            if not live_state:
                return None
            floor_cursor = int(live_state["live_output_floor_cursor"] or 0)
            history_gap = cursor < floor_cursor
            if (include_checkpoint and cursor == 0) or history_gap:
                checkpoint_row = connection.execute(
                    """
                    SELECT output_cursor, snapshot, created_at
                    FROM remote_session_checkpoints
                    WHERE session_id = ?
                    """,
                    (session_id,),
                ).fetchone()
                if (
                    checkpoint_row
                    and int(checkpoint_row["output_cursor"]) >= floor_cursor
                ):
                    try:
                        snapshot = json.loads(str(checkpoint_row["snapshot"]))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        snapshot = None
                    if isinstance(snapshot, dict):
                        cursor = int(checkpoint_row["output_cursor"])
                        checkpoint = {
                            "cursor": cursor,
                            "snapshot": snapshot,
                            "created_at": float(checkpoint_row["created_at"]),
                        }
                        history_gap = False
            if history_gap:
                cursor = floor_cursor
            rows = connection.execute(
                """
                SELECT id, output, created_at FROM remote_session_live_output
                WHERE session_id = ? AND id > ? ORDER BY id
                LIMIT ?
                """,
                (session_id, cursor, REMOTE_SESSION_OUTPUT_PAGE_LIMIT + 1),
            ).fetchall()
        chunks = []
        page_bytes = 0
        for row in rows:
            if len(chunks) >= REMOTE_SESSION_OUTPUT_PAGE_LIMIT:
                break
            chunk = dict(row)
            chunk_bytes = len(str(chunk["output"]).encode("utf-8"))
            if chunks and page_bytes + chunk_bytes > REMOTE_SESSION_OUTPUT_PAGE_BYTES:
                break
            chunks.append(chunk)
            page_bytes += chunk_bytes
        return {
            "session": session,
            "chunks": chunks,
            "next_cursor": int(chunks[-1]["id"]) if chunks else cursor,
            "has_more": len(chunks) < len(rows),
            "checkpoint": checkpoint,
            "history_gap": history_gap,
            "floor_cursor": floor_cursor,
        }

    def transcript(self, session_id: str) -> str:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT output FROM remote_session_output
                WHERE session_id = ? ORDER BY id
                """,
                (session_id,),
            ).fetchall()
        return sanitize_terminal_text("".join(str(row["output"]) for row in rows))

    def delete_session(
        self, session_id: str, *, user_id: str
    ) -> dict[str, Any] | None:
        session = self.get_session(session_id, user_id=user_id)
        if not session:
            return None
        if session["state"] in ACTIVE_REMOTE_SESSION_STATES:
            raise RemoteSessionError(
                "Stop the remote session before deleting its retained history."
            )
        if session.get("investigation_id") and not session.get(
            "evidence_finalized_at"
        ):
            raise RemoteSessionError(
                "Case evidence is still being finalized for this session. Try again shortly."
            )
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM remote_sessions WHERE id = ? AND user_id = ?",
                (session_id, user_id),
            )
        return session

    def finish(
        self,
        session_id: str,
        *,
        state: str,
        termination: str,
        error: str = "",
    ) -> dict[str, Any] | None:
        if state not in {"stopped", "error", "interrupted"}:
            raise RemoteSessionError("Invalid completed remote-session state.")
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE remote_sessions
                SET state = ?, termination = ?, last_error = ?,
                    completed_at = COALESCE(completed_at, ?), last_activity_at = ?
                WHERE id = ? AND state IN ('connecting', 'running')
                """,
                (state, termination, error[:2000], now, now, session_id),
            )
        return self.get_session(session_id)

    def rename_session(
        self, session_id: str, *, user_id: str, title: str
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE remote_sessions SET title = ? WHERE id = ? AND user_id = ?",
                (title, session_id, user_id),
            )
        return self.get_session(session_id, user_id=user_id)

    def attach_investigation(
        self, session_id: str, *, user_id: str, investigation_id: str
    ) -> dict[str, Any]:
        session = self.get_session(session_id, user_id=user_id)
        if not session:
            raise RemoteSessionError("Remote session not found.")
        existing_id = str(session.get("investigation_id", ""))
        if existing_id and existing_id != investigation_id:
            raise RemoteSessionError(
                "This remote session is already associated with another case."
            )
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE remote_sessions
                SET investigation_id = ?, record_transcript = 1,
                    investigation_attached_at = ?, evidence_finalized_at = NULL
                WHERE id = ? AND user_id = ?
                """,
                (investigation_id, time.time(), session_id, user_id),
            )
        attached = self.get_session(session_id, user_id=user_id)
        if not attached:  # pragma: no cover - ownership was checked above
            raise RemoteSessionError("Remote session not found.")
        return attached

    def mark_evidence_finalized(self, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE remote_sessions SET evidence_finalized_at = ?
                WHERE id = ? AND evidence_finalized_at IS NULL
                """,
                (time.time(), session_id),
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
            self._secure_database_files()

    def _secure_database_files(self) -> None:
        for path in (
            self.path,
            self.path.with_name(f"{self.path.name}-wal"),
            self.path.with_name(f"{self.path.name}-shm"),
        ):
            try:
                os.chmod(path, 0o600)
            except FileNotFoundError:
                pass

    @staticmethod
    def _session(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["_owner_pid"] = int(result.pop("owner_pid", 0))
        result["_control_path"] = str(result.pop("control_path", ""))
        for key in (
            "record_transcript",
            "allow_unknown_hosts",
            "allow_legacy_algorithms",
            "output_truncated",
            "telnet_username_available",
            "telnet_password_available",
        ):
            result[key] = bool(result[key])
        result["tool_key"] = "remote_terminal"
        return result


class RemoteSessionManager:
    """Own live remote terminals independently of browser request lifetimes."""

    def __init__(
        self,
        store: RemoteSessionStore,
        investigation_store: InvestigationStore,
        *,
        logger: Any = None,
        ssh_opener: Any = open_ssh_client,
        telnet_opener: Any = open_telnet_channel,
        serial_opener: Any = open_serial_channel,
    ) -> None:
        self.store = store
        self.investigation_store = investigation_store
        self.logger = logger
        self.ssh_opener = ssh_opener
        self.telnet_opener = telnet_opener
        self.serial_opener = serial_opener
        self.pid = os.getpid()
        self.instance_digest = hashlib.sha256(
            str(self.store.instance_path.resolve()).encode("utf-8")
        ).hexdigest()[:10]
        self.control_root = Path("/tmp") / f"twn-rs-{self.instance_digest}"
        self.control_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.control_root, 0o700)
        self._remove_stale_control_sockets()
        self.control_path = str(
            self.control_root / f"{self.pid}-{secrets.token_hex(4)}.sock"
        )
        self._lock = threading.RLock()
        self._runtimes: dict[str, dict[str, Any]] = {}
        self._control_socket: socket.socket | None = None
        self._control_thread: threading.Thread | None = None
        self._control_unavailable = False
        self._reconcile_orphaned_sessions()
        for session in self.store.sessions_needing_evidence_finalization():
            self._finalize_case(session)

    def close(self) -> None:
        """Release this worker's local control listener."""
        with self._lock:
            listener = self._control_socket
            self._control_socket = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        thread = self._control_thread
        if thread and thread is not threading.current_thread():
            thread.join(1)
        try:
            Path(self.control_path).unlink(missing_ok=True)
        except OSError:
            pass

    def sessions_for_user(
        self, user_id: str, *, include_finished: bool = False
    ) -> list[dict[str, Any]]:
        self._reconcile_orphaned_sessions(user_id=user_id)
        return self.store.sessions_for_user(
            user_id, include_finished=include_finished
        )

    def get_session(
        self, session_id: str, *, user_id: str
    ) -> dict[str, Any] | None:
        return self.store.get_session(session_id, user_id=user_id)

    def sessions_for_investigation(
        self, investigation_id: str, *, user_id: str
    ) -> list[dict[str, Any]]:
        self._reconcile_orphaned_sessions(user_id=user_id)
        return self.store.sessions_for_investigation(
            investigation_id, user_id=user_id
        )

    def start_session(
        self,
        *,
        protocol: str,
        user_id: str,
        username: str,
        title: str,
        host: str,
        port: int,
        remote_username: str,
        password: str,
        record_transcript: bool,
        investigation_id: str = "",
        allow_unknown_hosts: bool = False,
        allow_legacy_algorithms: bool = False,
        source_host_id: str = "",
        columns: int = 120,
        rows: int = 32,
        console_device_id: str = "",
        console_device_path: str = "",
        console_device_label: str = "",
        console_baud_rate: int = 9600,
        console_data_bits: int = 8,
        console_parity: str = "none",
        console_stop_bits: str = "1",
        console_flow_control: str = "none",
    ) -> dict[str, Any]:
        self._ensure_control_server()
        clean_protocol = str(protocol).strip().lower()
        if clean_protocol == "console":
            settings = serial_settings(
                baud_rate=console_baud_rate,
                data_bits=console_data_bits,
                parity=console_parity,
                stop_bits=console_stop_bits,
                flow_control=console_flow_control,
            )
            remote_username = ""
            password = ""
            host = console_device_path
            port = 0
        else:
            settings = serial_settings()
        session = self.store.create_session(
            user_id=user_id,
            username=username,
            title=title,
            host=host,
            port=port,
            remote_username=remote_username,
            telnet_username_available=bool(protocol == "telnet" and remote_username),
            telnet_password_available=bool(protocol == "telnet" and password),
            record_transcript=record_transcript,
            investigation_id=investigation_id,
            allow_unknown_hosts=allow_unknown_hosts,
            allow_legacy_algorithms=allow_legacy_algorithms,
            source_host_id=source_host_id,
            owner_pid=self.pid,
            control_path=self.control_path,
            protocol=clean_protocol,
            console_device_id=console_device_id,
            console_device_path=console_device_path,
            console_device_label=console_device_label,
            console_baud_rate=settings["baud_rate"],
            console_data_bits=settings["data_bits"],
            console_parity=settings["parity"],
            console_stop_bits=settings["stop_bits"],
            console_flow_control=settings["flow_control"],
            terminal_columns=columns,
            terminal_rows=rows,
        )
        self._record_started(session)
        runtime = {
            "stop": threading.Event(),
            "termination": "manual",
            "client": None,
            "channel": None,
            "password": password if clean_protocol == "ssh" else "",
            "telnet_credentials": {
                "username": remote_username if clean_protocol == "telnet" else "",
                "password": password if clean_protocol == "telnet" else "",
            },
        }
        thread = threading.Thread(
            target=self._run_session,
            name=f"remote-{clean_protocol}-{session['id'][:8]}",
            daemon=True,
            args=(session, columns, rows, runtime),
        )
        runtime["thread"] = thread
        with self._lock:
            self._runtimes[str(session["id"])] = runtime
        thread.start()
        return session

    def start_ssh_session(self, **options: Any) -> dict[str, Any]:
        """Compatibility wrapper for callers that explicitly start SSH."""
        return self.start_session(protocol="ssh", **options)

    def send_input(self, session_id: str, *, user_id: str, data: str) -> None:
        session = self.store.get_session(session_id, user_id=user_id)
        if not session or session["state"] != "running":
            raise RemoteSessionError("That remote session is not connected.")
        encoded = data.encode("utf-8")
        if not encoded or len(encoded) > REMOTE_SESSION_INPUT_LIMIT_BYTES:
            raise RemoteSessionError(
                f"Terminal input must be between 1 and {REMOTE_SESSION_INPUT_LIMIT_BYTES:,} bytes."
            )
        self._send_control(
            session,
            {"action": "input", "data": data},
        )
        self.store.touch(session_id)

    def send_telnet_credential(
        self, session_id: str, *, user_id: str, field: str
    ) -> int:
        session = self.store.get_session(session_id, user_id=user_id)
        if not session or session["state"] != "running":
            raise RemoteSessionError("That remote session is not connected.")
        if session.get("protocol") != "telnet":
            raise RemoteSessionError("Credential controls are available only for Telnet sessions.")
        clean_field = str(field).strip().lower()
        if clean_field not in {"username", "password"}:
            raise RemoteSessionError("Choose the Telnet username or password.")
        result = self._send_control(
            session,
            {"action": "telnet_credential", "field": clean_field},
        )
        self.store.touch(session_id)
        return int(result.get("accepted_bytes", 0))

    def attach_to_case(
        self,
        session_id: str,
        *,
        user_id: str,
        username: str,
        investigation_id: str,
    ) -> dict[str, Any]:
        investigation = self.investigation_store.get_for_user(
            investigation_id, user_id
        )
        if not investigation.get("is_open"):
            raise RemoteSessionError("Closed cases cannot accept terminal evidence.")
        session = self.store.get_session(session_id, user_id=user_id)
        if not session:
            raise RemoteSessionError("Remote session not found.")
        existing_id = str(session.get("investigation_id", ""))
        if existing_id and existing_id != investigation_id:
            raise RemoteSessionError(
                "This remote session is already associated with another case."
            )
        if (
            existing_id == investigation_id
            and bool(session.get("record_transcript"))
            and (
                session.get("state") in ACTIVE_REMOTE_SESSION_STATES
                or session.get("evidence_finalized_at")
            )
        ):
            return session

        completed_transcript = ""
        if session["state"] not in ACTIVE_REMOTE_SESSION_STATES:
            completed_transcript = self.store.transcript(session_id)
            if not completed_transcript:
                raise RemoteSessionError("This session has no retained output to attach.")
        attached_at = time.time()
        session = self.store.attach_investigation(
            session_id,
            user_id=user_id,
            investigation_id=investigation_id,
        )
        if session["state"] in ACTIVE_REMOTE_SESSION_STATES:
            protocol_label = str(session.get("protocol", "ssh")).upper()
            self.investigation_store.record_for_case(
                investigation_id=investigation_id,
                user_id=user_id,
                username=username,
                require_recording=False,
                operation_id=f"remote-terminal:{session_id}:attached",
                event_type="remote_terminal.session.attached",
                tool_id="tools.remote_terminal",
                action=f"Attached remote {protocol_label} session",
                outcome="info",
                summary=(
                    f"Attached {protocol_label} session {session['title']} to the case. "
                    "Its retained transcript will be added when the session ends."
                ),
                targets=_session_targets(session),
                parameters={
                    "title": session["title"],
                    "protocol": protocol_label,
                    "remote_username": session["remote_username"],
                    **_console_parameters(session),
                },
                metrics={"output_bytes_at_attachment": session["output_bytes"]},
                details={
                    "session_id": session_id,
                    "includes_pre_attachment_scrollback": True,
                },
                started_at=attached_at,
                completed_at=attached_at,
            )
            return session

        protocol_label = str(session.get("protocol", "ssh")).upper()
        self.investigation_store.add_generated_evidence_event(
            investigation_id=investigation_id,
            user_id=user_id,
            username=username,
            operation_id=f"remote-terminal:{session_id}:attached",
            event_type="remote_terminal.transcript.attached",
            tool_id="tools.remote_terminal",
            action=f"Attached {protocol_label} transcript",
            outcome="info",
            summary=f"Attached retained output from {protocol_label} session {session['title']}.",
            targets=_session_targets(session),
            parameters={
                "title": session["title"],
                "protocol": protocol_label,
                "remote_username": session["remote_username"],
                "termination": session["termination"],
                **_console_parameters(session),
            },
            metrics={
                "output_bytes": session["output_bytes"],
                "output_truncated": bool(session["output_truncated"]),
            },
            details={
                "session_id": session_id,
                "attached_after_completion": True,
            },
            started_at=attached_at,
            completed_at=attached_at,
            filename=(
                f"{str(session.get('protocol', 'ssh'))}-{safe_filename(_session_destination(session))}-{session_id[:8]}.txt"
            ),
            content_type="text/plain; charset=utf-8",
            content=completed_transcript.encode("utf-8"),
            max_bytes=REMOTE_SESSION_OUTPUT_LIMIT_BYTES + 1024,
        )
        self.store.mark_evidence_finalized(session_id)
        attached = self.store.get_session(session_id, user_id=user_id)
        if not attached:  # pragma: no cover - ownership was checked above
            raise RemoteSessionError("Remote session not found.")
        return attached

    def resize(
        self, session_id: str, *, user_id: str, columns: int, rows: int
    ) -> dict[str, Any]:
        session = self.store.get_session(session_id, user_id=user_id)
        if not session or session["state"] != "running":
            raise RemoteSessionError("That remote session is not connected.")
        self._send_control(
            session,
            {"action": "resize", "columns": columns, "rows": rows},
        )
        return self.store.update_terminal_geometry(
            session_id,
            user_id=user_id,
            columns=columns,
            rows=rows,
        )

    def stop_session(
        self,
        session_id: str,
        *,
        user_id: str,
        termination: str = "manual",
        wait_seconds: float = 12,
    ) -> dict[str, Any] | None:
        session = self.store.get_session(session_id, user_id=user_id)
        if not session:
            return None
        runtime = self._runtime(session_id)
        if session["state"] in ACTIVE_REMOTE_SESSION_STATES:
            try:
                self._send_control(
                    session,
                    {"action": "stop", "termination": termination},
                )
            except RemoteSessionError:
                current = self.store.get_session(session_id, user_id=user_id)
                if not current or current["state"] not in ACTIVE_REMOTE_SESSION_STATES:
                    return current
                raise
        thread = runtime.get("thread") if runtime else None
        if thread and thread is not threading.current_thread():
            thread.join(max(0, wait_seconds))
        elif session["state"] in ACTIVE_REMOTE_SESSION_STATES:
            deadline = time.time() + max(0, wait_seconds)
            while time.time() < deadline:
                current = self.store.get_session(session_id, user_id=user_id)
                if not current or current["state"] not in ACTIVE_REMOTE_SESSION_STATES:
                    break
                time.sleep(0.05)
        current = self.store.get_session(session_id, user_id=user_id)
        if current and current["state"] in ACTIVE_REMOTE_SESSION_STATES:
            current = self.store.finish(
                session_id, state="stopped", termination=termination
            )
            self._finalize_case(current)
            current = self.store.get_session(session_id, user_id=user_id)
        if (
            current
            and current.get("investigation_id")
            and not current.get("evidence_finalized_at")
        ):
            deadline = time.time() + max(0, wait_seconds)
            while time.time() < deadline:
                current = self.store.get_session(session_id, user_id=user_id)
                if not current or current.get("evidence_finalized_at"):
                    break
                time.sleep(0.05)
            if current and not current.get("evidence_finalized_at"):
                raise RemoteSessionError(
                    "The remote session stopped, but its case evidence could not be finalized."
                )
        return current

    def stop_case_sessions(
        self, *, investigation_id: str, user_id: str
    ) -> dict[str, int]:
        sessions = self.sessions_for_investigation(
            investigation_id, user_id=user_id
        )
        finalized = 0
        for session in sessions:
            stopped = self.stop_session(
                str(session["id"]),
                user_id=user_id,
                termination="case_closed",
            )
            if stopped and stopped.get("evidence_finalized_at"):
                finalized += 1
        return {"stopped": len(sessions), "finalized": finalized}

    def _run_session(
        self,
        session: dict[str, Any],
        columns: int,
        rows: int,
        runtime: dict[str, Any],
    ) -> None:
        session_id = str(session["id"])
        protocol = str(session.get("protocol", "ssh"))
        client = None
        channel = None
        password = str(runtime.pop("password", ""))
        try:
            if runtime["stop"].is_set():
                password = ""
                self.store.finish(
                    session_id,
                    state="stopped",
                    termination=str(runtime["termination"]),
                )
                return
            if protocol == "console":
                channel = self.serial_opener(
                    device_path=str(session["console_device_path"]),
                    baud_rate=int(session["console_baud_rate"]),
                    data_bits=int(session["console_data_bits"]),
                    parity=str(session["console_parity"]),
                    stop_bits=str(session["console_stop_bits"]),
                    flow_control=str(session["console_flow_control"]),
                )
            elif protocol == "telnet":
                channel = self.telnet_opener(
                    hostname=session["host"],
                    port=int(session["port"]),
                    width=columns,
                    height=rows,
                )
            else:
                client = self.ssh_opener(
                    hostname=session["host"],
                    port=int(session["port"]),
                    username=session["remote_username"],
                    password=password,
                    allow_unknown_hosts=bool(session["allow_unknown_hosts"]),
                    allow_legacy_algorithms=bool(session["allow_legacy_algorithms"]),
                )
                runtime["client"] = client
            if runtime["stop"].is_set():
                self.store.finish(
                    session_id,
                    state="stopped",
                    termination=str(runtime["termination"]),
                )
                return
            if protocol == "ssh":
                channel = client.invoke_shell(
                    term="xterm-256color", width=columns, height=rows
                )
            password = ""
            channel.settimeout(0.25)
            runtime["channel"] = channel
            self.store.mark_connected(session_id)
            while not runtime["stop"].is_set():
                if channel.recv_ready():
                    data = channel.recv(65535)
                    if data is None:
                        continue
                    if not data:
                        break
                    self.store.append_output(
                        session_id, data.decode("utf-8", errors="replace")
                    )
                elif channel.exit_status_ready():
                    break
                else:
                    current = self.store.get_session(session_id)
                    last_activity = float(current["last_activity_at"]) if current else 0
                    if time.time() - last_activity >= REMOTE_SESSION_IDLE_SECONDS:
                        runtime["termination"] = "idle_timeout"
                        break
                    time.sleep(0.05)
            self.store.finish(
                session_id,
                state="stopped",
                termination=(
                    str(runtime["termination"])
                    if runtime["stop"].is_set()
                    else (
                        "idle_timeout"
                        if runtime["termination"] == "idle_timeout"
                        else "remote_closed"
                    )
                ),
            )
        except (socket.timeout, TimeoutError) as exc:
            self.store.finish(
                session_id,
                state="error",
                termination="connection_error",
                error=self._connection_error(exc, protocol),
            )
        except Exception as exc:
            if runtime["stop"].is_set():
                self.store.finish(
                    session_id,
                    state="stopped",
                    termination=str(runtime["termination"]),
                )
            else:
                self.store.finish(
                    session_id,
                    state="error",
                    termination="connection_error",
                    error=self._connection_error(exc, protocol),
                )
        finally:
            credentials = runtime.get("telnet_credentials", {})
            if isinstance(credentials, dict):
                credentials["username"] = ""
                credentials["password"] = ""
            runtime["password"] = ""
            if protocol in {"telnet", "console"} and channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass
            else:
                close_ssh_client(client)
            runtime["client"] = None
            runtime["channel"] = None
            completed = self.store.get_session(session_id)
            self._finalize_case(completed)
            with self._lock:
                self._runtimes.pop(session_id, None)

    @staticmethod
    def _connection_error(exc: Exception, protocol: str) -> str:
        if protocol == "ssh":
            return format_ssh_connection_error(exc)
        if protocol == "console":
            if isinstance(exc, SerialConsoleError):
                return str(exc)
            if isinstance(exc, PermissionError):
                return "The toolkit service does not have permission to open that console device."
            if isinstance(exc, OSError):
                return f"The local console connection failed: {exc}."
            return "The local console connection failed."
        if isinstance(exc, socket.gaierror):
            return "The Telnet host name could not be resolved."
        if isinstance(exc, ConnectionRefusedError):
            return "The Telnet service refused the connection."
        if isinstance(exc, (socket.timeout, TimeoutError)):
            return "The Telnet connection timed out."
        if isinstance(exc, OSError):
            return f"The Telnet connection failed: {exc}."
        return "The Telnet connection failed."

    def _record_started(self, session: dict[str, Any]) -> None:
        if not session.get("investigation_id"):
            return
        protocol_label = str(session.get("protocol", "ssh")).upper()
        destination = _session_destination(session)
        try:
            self.investigation_store.record_for_case(
                investigation_id=str(session["investigation_id"]),
                user_id=str(session["user_id"]),
                username=str(session["username"]),
                require_recording=True,
                operation_id=f"remote-terminal:{session['id']}:started",
                event_type="remote_terminal.session.started",
                tool_id="tools.remote_terminal",
                action=f"Started remote {protocol_label} session",
                outcome="info",
                summary=(
                    f"Started {protocol_label} session {session['title']} "
                    f"{'on' if session.get('protocol') == 'console' else 'to'} "
                    f"{destination}."
                ),
                targets=_session_targets(session),
                parameters={
                    "title": session["title"],
                    "protocol": protocol_label,
                    "remote_username": session["remote_username"],
                    "transcript_enabled": bool(session["record_transcript"]),
                    **_console_parameters(session),
                },
                metrics={},
                details={"session_id": session["id"]},
                started_at=float(session["created_at"]),
                completed_at=float(session["created_at"]),
            )
        except (InvestigationError, OSError, sqlite3.Error):
            self._log_exception("Unable to record remote-session start in its case")

    def _finalize_case(self, session: dict[str, Any] | None) -> None:
        if (
            not session
            or not session.get("investigation_id")
            or session.get("evidence_finalized_at")
            or session.get("state") in ACTIVE_REMOTE_SESSION_STATES
        ):
            return
        try:
            protocol = str(session.get("protocol", "ssh"))
            protocol_label = protocol.upper()
            capture_started_at = float(
                session.get("investigation_attached_at") or session["created_at"]
            )
            completed_at = float(session.get("completed_at") or time.time())
            elapsed = max(
                0.0,
                completed_at - capture_started_at,
            )
            event = {
                "investigation_id": str(session["investigation_id"]),
                "user_id": str(session["user_id"]),
                "username": str(session["username"]),
                "operation_id": f"remote-terminal:{session['id']}:completed",
                "event_type": "remote_terminal.session.completed",
                "tool_id": "tools.remote_terminal",
                "action": f"Completed remote {protocol_label} session",
                "outcome": "failed" if session["state"] == "error" else "succeeded",
                "summary": (
                    f"{protocol_label} session {session['title']} ended: "
                    f"{str(session['termination']).replace('_', ' ')}."
                ),
                "targets": _session_targets(session),
                "parameters": {
                    "title": session["title"],
                    "protocol": protocol_label,
                    "remote_username": session["remote_username"],
                    "duration_seconds": round(elapsed, 3),
                    "termination": session["termination"],
                    "transcript_enabled": bool(session["record_transcript"]),
                    **_console_parameters(session),
                },
                "metrics": {
                    "output_bytes": int(session["output_bytes"]),
                    "output_truncated": bool(session["output_truncated"]),
                },
                "details": {
                    "session_id": session["id"],
                    "error": session["last_error"],
                    "includes_pre_attachment_scrollback": (
                        capture_started_at > float(session["created_at"])
                    ),
                },
                "started_at": completed_at,
                "completed_at": completed_at,
            }
            transcript = self.store.transcript(str(session["id"]))
            if bool(session["record_transcript"]) and transcript:
                self.investigation_store.add_generated_evidence_event(
                    **event,
                    filename=f"{protocol}-{safe_filename(_session_destination(session))}-{session['id'][:8]}.txt",
                    content_type="text/plain; charset=utf-8",
                    content=transcript.encode("utf-8"),
                    max_bytes=REMOTE_SESSION_OUTPUT_LIMIT_BYTES + 1024,
                )
            else:
                self.investigation_store.record_for_case(
                    **event, require_recording=False
                )
            self.store.mark_evidence_finalized(str(session["id"]))
        except InvestigationError:
            self.store.mark_evidence_finalized(str(session["id"]))
            self._log_exception("Unable to finalize remote-session case evidence")
        except (OSError, sqlite3.Error):
            self._log_exception("Unable to finalize remote-session case evidence")

    def _runtime(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._runtimes.get(session_id)

    def _ensure_control_server(self) -> None:
        with self._lock:
            if self._control_socket is not None or self._control_unavailable:
                return
            path = Path(self.control_path)
            try:
                path.unlink(missing_ok=True)
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(self.control_path)
                os.chmod(self.control_path, 0o600)
                listener.listen(16)
                listener.settimeout(0.5)
            except PermissionError:
                try:
                    listener.close()
                except (NameError, OSError):
                    pass
                self._control_unavailable = True
                self.control_path = ""
                return
            except Exception as exc:
                try:
                    listener.close()
                except (NameError, OSError):
                    pass
                raise RemoteSessionError(
                    "The remote-session control channel could not be started."
                ) from exc
            self._control_socket = listener
            self._control_thread = threading.Thread(
                target=self._serve_control,
                name=f"remote-control-{self.pid}",
                daemon=True,
            )
            self._control_thread.start()

    def _serve_control(self) -> None:
        listener = self._control_socket
        if listener is None:  # pragma: no cover
            return
        while True:
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                try:
                    connection.settimeout(2)
                    raw = b""
                    while b"\n" not in raw and len(raw) <= 32 * 1024:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        raw += chunk
                    if len(raw) > 32 * 1024:
                        raise RemoteSessionError("Remote-session control input is too large.")
                    message = json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
                    result = self._apply_control(message)
                    response = {"ok": True, **result}
                except Exception as exc:
                    response = {
                        "ok": False,
                        "error": (
                            str(exc)
                            if isinstance(exc, RemoteSessionError)
                            else "Remote-session control failed."
                        ),
                    }
                try:
                    connection.sendall(
                        json.dumps(response, separators=(",", ":")).encode("utf-8")
                        + b"\n"
                    )
                except OSError:
                    pass

    def _apply_control(self, message: dict[str, Any]) -> dict[str, Any]:
        session_id = str(message.get("session_id", ""))
        user_id = str(message.get("user_id", ""))
        session = self.store.get_session(session_id, user_id=user_id)
        if (
            not session
            or int(session.get("_owner_pid", 0)) != self.pid
            or str(session.get("_control_path", "")) != self.control_path
        ):
            raise RemoteSessionError("Remote session not found in its owning worker.")
        action = str(message.get("action", ""))
        if action == "ping":
            return {"state": session["state"]}
        runtime = self._runtime(session_id)
        if runtime is None:
            raise RemoteSessionError("That remote session is no longer active.")
        if action == "stop":
            runtime["termination"] = str(message.get("termination", "manual"))[:80]
            runtime["stop"].set()
            channel = runtime.get("channel")
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass
            client = runtime.get("client")
            if client is not None:
                close_ssh_client(client)
            return {}
        if session["state"] != "running":
            raise RemoteSessionError("That remote session is not connected.")
        channel = runtime.get("channel")
        if channel is None:
            raise RemoteSessionError("That remote session is not ready.")
        if action == "input":
            data = str(message.get("data", ""))
            encoded = data.encode("utf-8")
            if not encoded or len(encoded) > REMOTE_SESSION_INPUT_LIMIT_BYTES:
                raise RemoteSessionError("Terminal input is outside the allowed size.")
            try:
                channel.sendall(encoded)
            except Exception as exc:
                raise RemoteSessionError(
                    "Terminal input could not be delivered."
                ) from exc
            return {"accepted_bytes": len(encoded)}
        if action == "telnet_credential":
            if session.get("protocol") != "telnet":
                raise RemoteSessionError(
                    "Credential controls are available only for Telnet sessions."
                )
            field = str(message.get("field", "")).strip().lower()
            if field not in {"username", "password"}:
                raise RemoteSessionError("Choose the Telnet username or password.")
            credentials = runtime.get("telnet_credentials", {})
            value = str(credentials.get(field, "")) if isinstance(credentials, dict) else ""
            if not value:
                raise RemoteSessionError(
                    f"No {field} was provided for this Telnet session."
                )
            encoded = (value + "\r").encode("utf-8")
            if len(encoded) > REMOTE_SESSION_INPUT_LIMIT_BYTES:
                raise RemoteSessionError(
                    f"The Telnet {field} is outside the allowed size."
                )
            try:
                channel.sendall(encoded)
            except Exception as exc:
                raise RemoteSessionError(
                    f"The Telnet {field} could not be delivered."
                ) from exc
            return {"accepted_bytes": len(encoded)}
        if action == "resize":
            columns = int(message.get("columns", 0))
            rows = int(message.get("rows", 0))
            if not 40 <= columns <= 300 or not 10 <= rows <= 120:
                raise RemoteSessionError("Terminal dimensions are outside the allowed range.")
            channel.resize_pty(width=columns, height=rows)
            return {}
        raise RemoteSessionError("Unknown remote-session control action.")

    def _send_control(
        self, session: dict[str, Any], message: dict[str, Any]
    ) -> dict[str, Any]:
        request_message = {
            **message,
            "session_id": str(session["id"]),
            "user_id": str(session["user_id"]),
        }
        if (
            int(session.get("_owner_pid", 0)) == self.pid
            and str(session.get("_control_path", "")) == self.control_path
        ):
            return self._apply_control(request_message)
        path = str(session.get("_control_path", ""))
        if not path:
            self._interrupt_orphan(session)
            raise RemoteSessionError("The remote session lost its owning worker.")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect(path)
                connection.sendall(
                    json.dumps(request_message, separators=(",", ":")).encode("utf-8")
                    + b"\n"
                )
                raw = b""
                while b"\n" not in raw and len(raw) <= 8 * 1024:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
            response = json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            if not self._worker_endpoint_available(session):
                self._interrupt_orphan(session)
                raise RemoteSessionError(
                    "The remote session ended with its owning toolkit worker."
                ) from exc
            raise RemoteSessionError(
                "The remote session did not accept the control request."
            ) from exc
        if not response.get("ok"):
            raise RemoteSessionError(
                str(response.get("error", "Remote-session control failed."))
            )
        return response

    def _reconcile_orphaned_sessions(self, *, user_id: str = "") -> None:
        for session in self.store.active_sessions():
            if user_id and str(session["user_id"]) != user_id:
                continue
            if not self._worker_endpoint_available(session):
                self._interrupt_orphan(session)

    def _interrupt_orphan(self, session: dict[str, Any]) -> None:
        interrupted = self.store.interrupt_session(str(session["id"]))
        self._finalize_case(interrupted)

    def _worker_endpoint_available(self, session: dict[str, Any]) -> bool:
        pid = int(session.get("_owner_pid", 0))
        path = str(session.get("_control_path", ""))
        if pid == self.pid and path == self.control_path:
            return self._runtime(str(session["id"])) is not None
        if pid <= 0 or not path or not Path(path).exists():
            return False
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(1)
                connection.connect(path)
                connection.sendall(
                    json.dumps(
                        {
                            "action": "ping",
                            "session_id": str(session["id"]),
                            "user_id": str(session["user_id"]),
                        },
                        separators=(",", ":"),
                    ).encode("utf-8")
                    + b"\n"
                )
                response = connection.recv(4096)
            return bool(response and json.loads(response).get("ok"))
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def _remove_stale_control_sockets(self) -> None:
        for candidate in self.control_root.glob("*.sock"):
            try:
                pid = int(candidate.name.split("-", 1)[0])
                os.kill(pid, 0)
            except (OSError, ValueError):
                try:
                    candidate.unlink(missing_ok=True)
                except OSError:
                    pass

    def _log_exception(self, message: str) -> None:
        if self.logger is not None:
            self.logger.exception(message)


def _session_destination(session: dict[str, Any]) -> str:
    if str(session.get("protocol", "ssh")) == "console":
        label = str(session.get("console_device_label", "")).strip()
        path = str(session.get("console_device_path", "")).strip()
        line = (
            f"{int(session.get('console_baud_rate', 9600))} "
            f"{int(session.get('console_data_bits', 8))}"
            f"{str(session.get('console_parity', 'none'))[:1].upper()}"
            f"{str(session.get('console_stop_bits', '1'))}"
        )
        device = f"{label} ({path})" if label and label != path else (label or path)
        return f"{device} · {line}"
    username = str(session.get("remote_username", "")).strip()
    host = str(session.get("host", ""))
    port = int(session.get("port", 0))
    return f"{username + '@' if username else ''}{host}:{port}"


def _session_targets(session: dict[str, Any]) -> dict[str, Any]:
    if str(session.get("protocol", "ssh")) == "console":
        return {
            "device": str(session.get("console_device_label", "")),
            "device_path": str(session.get("console_device_path", "")),
        }
    return {"host": session["host"], "port": session["port"]}


def _console_parameters(session: dict[str, Any]) -> dict[str, Any]:
    if str(session.get("protocol", "ssh")) != "console":
        return {}
    return {
        "baud_rate": int(session.get("console_baud_rate", 9600)),
        "data_bits": int(session.get("console_data_bits", 8)),
        "parity": str(session.get("console_parity", "none")),
        "stop_bits": str(session.get("console_stop_bits", "1")),
        "flow_control": str(session.get("console_flow_control", "none")),
    }


def sanitize_terminal_text(value: str) -> str:
    """Render terminal edits into readable plain text without ANSI controls."""
    cleaned = _ANSI_ESCAPE.sub("", value).replace("\r\n", "\n")
    lines: list[str] = []
    line: list[str] = []
    cursor = 0
    ended_with_newline = False

    for character in cleaned:
        if character == "\n":
            lines.append("".join(line).rstrip())
            line = []
            cursor = 0
            ended_with_newline = True
            continue
        ended_with_newline = False
        if character == "\r":
            cursor = 0
            continue
        if character == "\b":
            cursor = max(0, cursor - 1)
            continue
        if character == "\t":
            next_stop = (cursor // 8 + 1) * 8
            if len(line) < next_stop:
                line.extend(" " for _ in range(next_stop - len(line)))
            cursor = next_stop
            continue
        if ord(character) < 32 or character == "\x7f":
            continue
        if cursor < len(line):
            line[cursor] = character
        else:
            if cursor > len(line):
                line.extend(" " for _ in range(cursor - len(line)))
            line.append(character)
        cursor += 1

    if line or not ended_with_newline:
        lines.append("".join(line).rstrip())
    rendered = "\n".join(lines)
    return rendered + ("\n" if ended_with_newline else "")


def safe_filename(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
    return clean[:80] or "session"


def public_remote_session(session: dict[str, Any]) -> dict[str, Any]:
    from flask import url_for

    session_id = str(session["id"])
    return {
        key: value
        for key, value in {
            **session,
            "restore_url": url_for("tools.remote_terminal", session=session_id),
            "detail_url": url_for(
                "tools.remote_terminal_session", session_id=session_id
            ),
            "popout_url": url_for(
                "tools.remote_terminal_popout", session_id=session_id
            ),
            "output_url": url_for(
                "tools.remote_terminal_output", session_id=session_id
            ),
            "checkpoint_url": url_for(
                "tools.save_remote_terminal_checkpoint", session_id=session_id
            ),
            "download_url": url_for(
                "tools.download_remote_terminal_scrollback", session_id=session_id
            ),
            "transcript_url": url_for(
                "tools.download_remote_terminal_scrollback",
                session_id=session_id,
                view="1",
            ),
            "delete_url": url_for(
                "tools.delete_remote_terminal_scrollback", session_id=session_id
            ),
            "attach_case_url": url_for(
                "tools.attach_remote_terminal_case", session_id=session_id
            ),
            "datastore_url": url_for(
                "tools.save_remote_terminal_scrollback", session_id=session_id
            ),
            "input_url": url_for(
                "tools.remote_terminal_input", session_id=session_id
            ),
            "credential_url": url_for(
                "tools.remote_terminal_credential", session_id=session_id
            ),
            "resize_url": url_for(
                "tools.resize_remote_terminal_session", session_id=session_id
            ),
            "stop_url": url_for(
                "tools.stop_remote_terminal_session", session_id=session_id
            ),
            "rename_url": url_for(
                "tools.rename_remote_terminal_session", session_id=session_id
            ),
            "can_stop": session.get("state") in ACTIVE_REMOTE_SESSION_STATES,
        }.items()
        if not key.startswith("_")
    }
