from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import selectors
import shlex
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from typing import Any, Callable, Iterator

from .iperf_tools import (
    _iperf3_executable,
    normalize_iperf3_result,
    validate_iperf3_server_config,
)
from .network_tools import ToolInputError
from .pidfiles import stop_matching_daemons
from .system_diagnostics import readonly_sqlite_connection


IPERF_SERVER_ACTIVE_STATUSES = {"queued", "running", "stopping"}
IPERF_SERVER_CYCLE_SECONDS = 10 * 60
IPERF_SERVER_OUTPUT_LIMIT = 2 * 1024 * 1024
IPERF_SERVER_RESULT_LIMIT = 50
IPERF_SERVER_SESSION_LIMIT = 20


class IperfServerStore:
    """Managed iPerf3 listener state and bounded per-user result history."""

    def __init__(self, instance_path: str | Path) -> None:
        self.instance_path = Path(instance_path).resolve()
        self.path = self.instance_path / "iperf_servers.sqlite3"
        with self._connect():
            pass

    def create(
        self,
        config: dict[str, Any],
        *,
        created_by: str,
        created_by_username: str,
    ) -> str:
        normalized = validate_iperf3_server_config(config)
        self._reconcile_workers()
        _iperf3_executable()
        assert_iperf3_listener_available(normalized)
        session_id = os.urandom(12).hex()
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_user = connection.execute(
                """
                SELECT id FROM iperf_server_sessions
                WHERE created_by = ?
                    AND desired_active = 1
                    AND status IN ('queued', 'running', 'stopping')
                LIMIT 1
                """,
                (created_by,),
            ).fetchone()
            if existing_user:
                raise ToolInputError(
                    "Stop your active iPerf3 server before starting another."
                )
            existing_port = connection.execute(
                """
                SELECT id FROM iperf_server_sessions
                WHERE port = ?
                    AND desired_active = 1
                    AND status IN ('queued', 'running', 'stopping')
                LIMIT 1
                """,
                (normalized["port"],),
            ).fetchone()
            if existing_port:
                raise ToolInputError(
                    f"Another managed iPerf3 server is already using port "
                    f"{normalized['port']}."
                )
            connection.execute(
                """
                INSERT INTO iperf_server_sessions (
                    id, status, bind_address, port, created_by,
                    created_by_username, desired_active, created_at, updated_at
                ) VALUES (?, 'queued', ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    session_id,
                    normalized["bind_address"],
                    normalized["port"],
                    created_by,
                    created_by_username[:100],
                    now,
                    now,
                ),
            )
            self._prune_sessions(connection, created_by)
        return session_id

    def launch(self, session_id: str) -> None:
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT status, desired_active, worker_pid, updated_at
                FROM iperf_server_sessions
                WHERE id = ?
                """,
                (session_id,),
            ).fetchone()
            if not row or not row["desired_active"]:
                return
            worker_pid = int(row["worker_pid"] or 0)
            if worker_pid > 0 and _process_alive(worker_pid):
                return
            if worker_pid == -1 and now - float(row["updated_at"]) < 30:
                return
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET status = 'queued', worker_pid = -1, iperf_pid = NULL,
                    stop_requested = 0, error = '', stop_reason = '',
                    updated_at = ?
                WHERE id = ? AND desired_active = 1
                """,
                (now, session_id),
            )
        command = [
            sys.executable,
            "-m",
            "twn_toolkit.iperf_server_worker",
            "--instance",
            str(self.instance_path),
            "--daemon",
            "--session-id",
            session_id,
        ]
        log_path = self.instance_path / "twn-iperf3.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_handle = log_path.open("ab", buffering=0)
        os.chmod(log_path, 0o600)
        try:
            process = subprocess.Popen(
                command,
                cwd=str(Path(__file__).resolve().parent.parent),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as exc:
            self.finish(
                session_id,
                status="error",
                reason="worker launch failed",
                error=f"Worker launch failed: {exc}",
            )
            raise ToolInputError(
                f"Could not launch the managed iPerf3 server: {exc}"
            ) from exc
        finally:
            log_handle.close()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET worker_pid = ?, updated_at = ?
                WHERE id = ? AND status = 'queued' AND desired_active = 1
                """,
                (process.pid, time.time(), session_id),
            )

    def begin(self, session_id: str) -> dict[str, Any]:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET status = 'running', worker_pid = ?,
                    started_at = COALESCE(started_at, ?),
                    error = '', stop_reason = '', updated_at = ?
                WHERE id = ? AND desired_active = 1
                    AND status IN ('queued', 'running')
                """,
                (os.getpid(), now, now, session_id),
            )
            row = connection.execute(
                "SELECT * FROM iperf_server_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
        if not row or row["status"] != "running":
            raise ToolInputError("The managed iPerf3 server is not available to run.")
        return self._session_from_row(row)

    def get(
        self, session_id: str, *, user_id: str = ""
    ) -> dict[str, Any] | None:
        self._reconcile_workers()
        with self._connect() as connection:
            query = "SELECT * FROM iperf_server_sessions WHERE id = ?"
            values: tuple[object, ...] = (session_id,)
            if user_id:
                query += " AND created_by = ?"
                values += (user_id,)
            row = connection.execute(query, values).fetchone()
        return self._session_from_row(row) if row else None

    def active_for_user(self, user_id: str) -> dict[str, Any] | None:
        self._reconcile_workers()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM iperf_server_sessions
                WHERE created_by = ?
                    AND desired_active = 1
                    AND status IN ('queued', 'running', 'stopping')
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
        return self._session_from_row(row) if row else None

    def latest_for_user(self, user_id: str) -> dict[str, Any] | None:
        self._reconcile_workers()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM iperf_server_sessions
                WHERE created_by = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
        return self._session_from_row(row) if row else None

    def request_stop(self, session_id: str, *, user_id: str) -> dict[str, Any]:
        self._reconcile_workers()
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE iperf_server_sessions
                SET desired_active = 0, stop_requested = 1,
                    status = 'stopping', updated_at = ?
                WHERE id = ? AND created_by = ?
                    AND status IN ('queued', 'running')
                """,
                (now, session_id, user_id),
            )
            row = connection.execute(
                """
                SELECT * FROM iperf_server_sessions
                WHERE id = ? AND created_by = ?
                """,
                (session_id, user_id),
            ).fetchone()
        if not row:
            raise ToolInputError("Managed iPerf3 server not found.")
        if not cursor.rowcount:
            raise ToolInputError("That managed iPerf3 server is no longer running.")
        return self._session_from_row(row)

    def stop_requested(self, session_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT stop_requested, status
                FROM iperf_server_sessions
                WHERE id = ?
                """,
                (session_id,),
            ).fetchone()
        return bool(
            not row
            or row["stop_requested"]
            or row["status"] not in IPERF_SERVER_ACTIVE_STATUSES
        )

    def desired_active(self, session_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT desired_active
                FROM iperf_server_sessions
                WHERE id = ?
                """,
                (session_id,),
            ).fetchone()
        return bool(row and row["desired_active"])

    def ensure_workers(self) -> int:
        """Restore enabled listeners whose managed worker is not running."""
        self._reconcile_workers()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id FROM iperf_server_sessions
                WHERE desired_active = 1 AND status = 'queued'
                    AND (worker_pid IS NULL OR worker_pid = 0)
                ORDER BY created_at
                """
            ).fetchall()
        for row in rows:
            self.launch(str(row["id"]))
        return len(rows)

    def pause(self, session_id: str, *, reason: str) -> None:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET status = 'queued', worker_pid = NULL, iperf_pid = NULL,
                    stop_requested = 0, stop_reason = ?, error = '',
                    updated_at = ?
                WHERE id = ? AND desired_active = 1
                """,
                (reason[:200], now, session_id),
            )

    def pause_active_for_toolkit_shutdown(self) -> int:
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE iperf_server_sessions
                SET status = 'queued', worker_pid = NULL, iperf_pid = NULL,
                    stop_requested = 0,
                    stop_reason = 'Toolkit service stopped; waiting to resume.',
                    error = '', updated_at = ?
                WHERE desired_active = 1
                    AND status IN ('queued', 'running', 'stopping')
                """,
                (now,),
            )
        return int(cursor.rowcount)

    def active_count(self) -> int:
        self._reconcile_workers()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM iperf_server_sessions
                WHERE desired_active = 1
                    AND status IN ('queued', 'running', 'stopping')
                """
            ).fetchone()
        return int(row["count"] or 0)

    def set_iperf_pid(self, session_id: str, pid: int | None) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET iperf_pid = ?, updated_at = ?
                WHERE id = ? AND status IN ('running', 'stopping')
                """,
                (pid, time.time(), session_id),
            )

    def record_result(
        self, session_id: str, result: dict[str, Any]
    ) -> bool:
        connection_info = result.get("connection") or {}
        source_ip = str(connection_info.get("remote_host") or "Unknown source")[
            :255
        ]
        source_port = int(connection_info.get("remote_port") or 0)
        sender = result.get("sender") or {}
        receiver = result.get("receiver") or {}
        primary = max(
            (sender, receiver),
            key=lambda metric: (
                int(metric.get("bytes") or 0),
                float(metric.get("megabits_per_second") or 0),
            ),
        )
        result_json = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if len(result_json.encode("utf-8")) > IPERF_SERVER_OUTPUT_LIMIT:
            bounded = dict(result)
            bounded["raw_json"] = (
                "[Raw iPerf3 JSON omitted because the retained result exceeded "
                "the managed server storage limit.]"
            )
            bounded["raw_json_truncated"] = True
            result_json = json.dumps(
                bounded,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        now = time.time()
        with self._connect() as connection:
            session = connection.execute(
                """
                SELECT created_by FROM iperf_server_sessions
                WHERE id = ? AND status IN ('running', 'stopping')
                """,
                (session_id,),
            ).fetchone()
            if not session:
                return False
            connection.execute(
                """
                INSERT INTO iperf_server_results (
                    session_id, source_ip, source_port, protocol, direction,
                    megabits_per_second, transferred_bytes, result_json,
                    completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    source_ip,
                    source_port,
                    str(result.get("protocol") or "")[:10],
                    str(result.get("direction") or "")[:20],
                    float(primary.get("megabits_per_second") or 0),
                    int(result.get("transferred_bytes") or 0),
                    result_json,
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET test_count = test_count + 1, last_test_at = ?,
                    last_error = '', updated_at = ?
                WHERE id = ?
                """,
                (now, now, session_id),
            )
            self._prune_results(connection, str(session["created_by"]))
        return True

    def record_transient_error(self, session_id: str, message: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET last_error = ?, updated_at = ?
                WHERE id = ? AND status IN ('running', 'stopping')
                """,
                (message[:1000], time.time(), session_id),
            )

    def finish(
        self,
        session_id: str,
        *,
        status: str,
        reason: str,
        error: str = "",
    ) -> None:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET status = ?, desired_active = 0, stop_reason = ?,
                    error = ?, worker_pid = NULL, iperf_pid = NULL,
                    stopped_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, reason[:200], error[:2000], now, now, session_id),
            )

    def recent_results(
        self, user_id: str, *, limit: int = IPERF_SERVER_RESULT_LIMIT
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT result.*
                FROM iperf_server_results AS result
                JOIN iperf_server_sessions AS session
                    ON session.id = result.session_id
                WHERE session.created_by = ?
                ORDER BY result.id DESC
                LIMIT ?
                """,
                (user_id, max(1, min(limit, IPERF_SERVER_RESULT_LIMIT))),
            ).fetchall()
        return [self._result_from_row(row) for row in rows]

    def result_revision(self, user_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT MAX(result.id) AS revision
                FROM iperf_server_results AS result
                JOIN iperf_server_sessions AS session
                    ON session.id = result.session_id
                WHERE session.created_by = ?
                """,
                (user_id,),
            ).fetchone()
        return int(row["revision"] or 0)

    def clear_results(self, user_id: str) -> int:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT result.id
                FROM iperf_server_results AS result
                JOIN iperf_server_sessions AS session
                    ON session.id = result.session_id
                WHERE session.created_by = ?
                """,
                (user_id,),
            ).fetchall()
            result_ids = [int(row["id"]) for row in rows]
            if result_ids:
                placeholders = ",".join("?" for _item in result_ids)
                connection.execute(
                    f"DELETE FROM iperf_server_results "
                    f"WHERE id IN ({placeholders})",
                    result_ids,
                )
        return len(result_ids)

    def _reconcile_workers(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, status, desired_active, worker_pid, iperf_pid,
                    bind_address, port, updated_at
                FROM iperf_server_sessions
                WHERE desired_active = 1
                    AND status IN ('queued', 'running', 'stopping')
                """
            ).fetchall()
            now = time.time()
            for row in rows:
                if row["worker_pid"] == -1:
                    if now - float(row["updated_at"]) <= 30:
                        continue
                    connection.execute(
                        """
                        UPDATE iperf_server_sessions
                        SET worker_pid = NULL, updated_at = ?
                        WHERE id = ? AND worker_pid = -1
                        """,
                        (now, row["id"]),
                    )
                    continue
                if row["worker_pid"] is None:
                    _stop_recorded_iperf_process(
                        int(row["iperf_pid"] or 0),
                        str(row["bind_address"]),
                        int(row["port"]),
                    )
                    if row["iperf_pid"] is not None:
                        connection.execute(
                            """
                            UPDATE iperf_server_sessions
                            SET iperf_pid = NULL, updated_at = ?
                            WHERE id = ? AND worker_pid IS NULL
                            """,
                            (now, row["id"]),
                        )
                    continue
                if not _process_alive(int(row["worker_pid"])):
                    _stop_recorded_iperf_process(
                        int(row["iperf_pid"] or 0),
                        str(row["bind_address"]),
                        int(row["port"]),
                    )
                    connection.execute(
                        """
                        UPDATE iperf_server_sessions
                        SET status = 'queued', worker_pid = NULL,
                            iperf_pid = NULL, updated_at = ?,
                            last_error = CASE WHEN last_error = ''
                                THEN 'The listener worker restarted unexpectedly; the supervisor is restoring it.'
                                ELSE last_error END
                        WHERE id = ?
                            AND desired_active = 1
                        """,
                        (now, row["id"]),
                    )

    @staticmethod
    def _prune_results(
        connection: sqlite3.Connection, user_id: str
    ) -> None:
        rows = connection.execute(
            """
            SELECT result.id
            FROM iperf_server_results AS result
            JOIN iperf_server_sessions AS session
                ON session.id = result.session_id
            WHERE session.created_by = ?
            ORDER BY result.id DESC
            LIMIT -1 OFFSET ?
            """,
            (user_id, IPERF_SERVER_RESULT_LIMIT),
        ).fetchall()
        if rows:
            connection.executemany(
                "DELETE FROM iperf_server_results WHERE id = ?",
                [(row["id"],) for row in rows],
            )

    @staticmethod
    def _prune_sessions(
        connection: sqlite3.Connection, user_id: str
    ) -> None:
        rows = connection.execute(
            """
            SELECT id FROM iperf_server_sessions
            WHERE created_by = ?
                AND desired_active = 0
                AND status NOT IN ('queued', 'running', 'stopping')
            ORDER BY created_at DESC
            LIMIT -1 OFFSET ?
            """,
            (user_id, IPERF_SERVER_SESSION_LIMIT),
        ).fetchall()
        if rows:
            connection.executemany(
                "DELETE FROM iperf_server_sessions WHERE id = ?",
                [(row["id"],) for row in rows],
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS iperf_server_sessions (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    bind_address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    worker_pid INTEGER,
                    iperf_pid INTEGER,
                    stop_requested INTEGER NOT NULL DEFAULT 0,
                    test_count INTEGER NOT NULL DEFAULT 0,
                    last_test_at REAL,
                    last_error TEXT NOT NULL DEFAULT '',
                    stop_reason TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_by_username TEXT NOT NULL DEFAULT '',
                    desired_active INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    started_at REAL,
                    stopped_at REAL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS iperf_server_sessions_active
                    ON iperf_server_sessions(status, port);
                CREATE INDEX IF NOT EXISTS iperf_server_sessions_user
                    ON iperf_server_sessions(created_by, created_at DESC);
                CREATE TABLE IF NOT EXISTS iperf_server_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL
                        REFERENCES iperf_server_sessions(id) ON DELETE CASCADE,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    megabits_per_second REAL NOT NULL,
                    transferred_bytes INTEGER NOT NULL,
                    result_json TEXT NOT NULL,
                    completed_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS iperf_server_results_recent
                    ON iperf_server_results(id DESC);
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(iperf_server_sessions)"
                ).fetchall()
            }
            if "desired_active" not in columns:
                connection.execute(
                    """
                    ALTER TABLE iperf_server_sessions
                    ADD COLUMN desired_active INTEGER NOT NULL DEFAULT 0
                    """
                )
                connection.execute(
                    """
                    UPDATE iperf_server_sessions
                    SET desired_active = 1
                    WHERE status IN ('queued', 'running', 'stopping')
                    """
                )
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
            self._secure_database_files()

    def _secure_database_files(self) -> None:
        for candidate in (
            self.path,
            self.path.with_name(f"{self.path.name}-wal"),
            self.path.with_name(f"{self.path.name}-shm"),
        ):
            try:
                os.chmod(candidate, 0o600)
            except FileNotFoundError:
                pass

    @staticmethod
    def _session_from_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["stop_requested"] = bool(item["stop_requested"])
        item["desired_active"] = bool(item.get("desired_active"))
        item["active"] = bool(
            item["desired_active"]
            and item["status"] in IPERF_SERVER_ACTIVE_STATUSES
        )
        for field in ("created_at", "started_at", "stopped_at", "last_test_at"):
            value = item.get(field)
            item[f"{field}_display"] = (
                datetime.fromtimestamp(float(value))
                .astimezone()
                .strftime("%Y-%m-%d %H:%M:%S %Z")
                if value
                else ""
            )
        return item

    @staticmethod
    def _result_from_row(row: sqlite3.Row) -> dict[str, Any]:
        result = json.loads(row["result_json"])
        result.update(
            {
                "id": row["id"],
                "session_id": row["session_id"],
                "source_ip": row["source_ip"],
                "source_port": row["source_port"],
                "summary_megabits_per_second": round(
                    float(row["megabits_per_second"]), 2
                ),
                "completed_at": row["completed_at"],
                "completed_display": datetime.fromtimestamp(
                    float(row["completed_at"])
                )
                .astimezone()
                .strftime("%Y-%m-%d %H:%M:%S %Z"),
            }
        )
        return result


def assert_iperf3_listener_available(config: dict[str, Any]) -> None:
    """Fail before launching a worker when the requested local socket is busy."""
    normalized = validate_iperf3_server_config(config)
    family = socket.AF_INET6 if ":" in normalized["bind_address"] else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.bind((normalized["bind_address"], normalized["port"]))
        listener.listen(1)
    except OSError as exc:
        raise ToolInputError(
            f"Cannot start iPerf3 on {normalized['bind_address']}:"
            f"{normalized['port']}: {exc.strerror or exc}. "
            "Stop the existing listener or choose another port."
        ) from exc
    finally:
        listener.close()


def resume_iperf_server_workers(instance_path: str | Path) -> int:
    """Restore listeners that were enabled when the toolkit last stopped."""
    return IperfServerStore(instance_path).ensure_workers()


def stop_iperf_server_workers(instance_path: str | Path) -> int:
    """Stop exact toolkit-owned listener workers and retain their On state."""
    instance = Path(instance_path).resolve()
    store = IperfServerStore(instance)
    with store._connect() as connection:
        rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, worker_pid, iperf_pid, bind_address, port
                FROM iperf_server_sessions
                WHERE desired_active = 1
                    AND status IN ('queued', 'running', 'stopping')
                """
            ).fetchall()
        ]
    stopped = stop_matching_daemons(
        "twn_toolkit.iperf_server_worker",
        instance,
        timeout=5,
    )
    stopped_workers = set(stopped)
    for row in rows:
        worker_pid = int(row["worker_pid"] or 0)
        if worker_pid not in stopped_workers and _stop_recorded_worker_process(
            worker_pid,
            instance,
            str(row["id"]),
        ):
            stopped_workers.add(worker_pid)
        _stop_recorded_iperf_process(
            int(row["iperf_pid"] or 0),
            str(row["bind_address"]),
            int(row["port"]),
        )
    store.pause_active_for_toolkit_shutdown()
    return len(stopped_workers)


def public_iperf_live_session(session: dict[str, Any]) -> dict[str, Any]:
    """Expose an active listener through the shared live-tools tray contract."""
    from flask import url_for

    session_id = str(session["id"])
    test_count = int(session.get("test_count") or 0)
    return {
        "id": session_id,
        "tool_key": "iperf3_server",
        "title": f"iPerf3 Server · {session['port']}",
        "state": (
            "error" if session.get("status") == "error" else "running"
        ),
        "listener": f"{session['bind_address']}:{session['port']}",
        "listener_status": session.get("status", ""),
        "rounds_completed": test_count,
        "last_round_at": (
            session.get("last_test_at")
            or session.get("started_at")
            or session.get("created_at")
        ),
        "last_error": session.get("error") or session.get("last_error") or "",
        "restore_url": url_for("tools.iperf3"),
        "stop_url": url_for(
            "tools.stop_iperf3_server",
            session_id=session_id,
        ),
        "rename_url": "",
        "can_stop": session.get("status") != "stopping",
    }


def iperf3_process_status(instance_path: str | Path) -> dict[str, Any]:
    """Read a bounded snapshot of toolkit-owned listener workers.

    The supervisor owns worker reconciliation. System Diagnostics must not run
    schema setup or update listener state merely to display process health.
    """
    path = Path(instance_path) / "iperf_servers.sqlite3"
    if not path.exists():
        return {"running": False, "pid": None, "count": 0, "error": ""}
    try:
        with readonly_sqlite_connection(path) as connection:
            rows = connection.execute(
                """
                SELECT worker_pid
                FROM iperf_server_sessions
                WHERE desired_active = 1
                    AND status IN ('queued', 'running', 'stopping')
                ORDER BY created_at
                """
            ).fetchall()
    except sqlite3.Error as exc:
        return {
            "running": False,
            "pid": None,
            "count": 0,
            "error": f"Listener status is temporarily unavailable: {exc}",
        }
    pids = [
        int(row["worker_pid"])
        for row in rows
        if int(row["worker_pid"] or 0) > 0
        and _process_alive(int(row["worker_pid"]))
    ]
    return {
        "running": bool(rows) and len(pids) == len(rows),
        "pid": pids[0] if pids else None,
        "count": len(rows),
        "error": "",
    }


def run_managed_iperf3_server(
    config: dict[str, Any],
    *,
    should_stop: Callable[[], bool],
    result_completed: Callable[[dict[str, Any]], None],
    transient_error: Callable[[str], None] | None = None,
    process_started: Callable[[int | None], None] | None = None,
) -> str:
    """Run a continuous JSON-stream listener until its managed stop is requested."""

    normalized = validate_iperf3_server_config(config)
    executable = _iperf3_executable()
    command = [
        executable,
        "-s",
        "--json-stream",
        "--forceflush",
        "-p",
        str(normalized["port"]),
        "-B",
        normalized["bind_address"],
        "-4" if ":" not in normalized["bind_address"] else "-6",
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
    except OSError as exc:
        raise ToolInputError(
            f"Could not start the managed iPerf3 listener: {exc}"
        ) from exc
    if process_started:
        process_started(process.pid)
    collector = IperfJsonStreamCollector(
        config=normalized,
        command=command,
    )
    selector = selectors.DefaultSelector()
    if process.stdout is None:  # pragma: no cover - PIPE is authoritative
        _terminate_process(process)
        raise ToolInputError("The managed iPerf3 listener did not expose output.")
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while True:
            if should_stop():
                _terminate_process(process)
                return "stopped"
            if (
                collector.test_started_monotonic is not None
                and time.monotonic() - collector.test_started_monotonic
                >= IPERF_SERVER_CYCLE_SECONDS
            ):
                _terminate_process(process)
                raise ToolInputError(
                    "An iPerf3 server test exceeded the managed ten-minute limit."
                )
            events = selector.select(timeout=0.25)
            for key, _mask in events:
                line = key.fileobj.readline()
                if not line:
                    continue
                try:
                    result, error = collector.feed(line)
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ToolInputError(
                        "The installed iPerf3 command did not return supported "
                        "streaming JSON. Update iPerf3 outside the toolkit."
                    ) from exc
                if error and transient_error:
                    transient_error(error)
                if result:
                    result_completed(result)
            if process.poll() is not None:
                for line in process.stdout:
                    result, error = collector.feed(line)
                    if error and transient_error:
                        transient_error(error)
                    if result:
                        result_completed(result)
                if should_stop():
                    return "stopped"
                raise ToolInputError(
                    f"The managed iPerf3 listener exited with status "
                    f"{process.returncode}."
                )
    finally:
        selector.close()
        if process.poll() is None:
            _terminate_process(process)
        if process_started:
            process_started(None)


class IperfJsonStreamCollector:
    def __init__(
        self,
        *,
        config: dict[str, Any],
        command: list[str],
    ) -> None:
        self.config = config
        self.command = command
        self.payload: dict[str, Any] | None = None
        self.test_started_monotonic: float | None = None

    def feed(
        self, line: str
    ) -> tuple[dict[str, Any] | None, str]:
        if len(line.encode("utf-8")) > IPERF_SERVER_OUTPUT_LIMIT:
            raise ValueError("iPerf3 JSON stream event exceeded the output limit.")
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError("Unexpected iPerf3 JSON stream event.")
        event_name = str(event.get("event") or "")
        data = event.get("data")
        if event_name == "start":
            if not isinstance(data, dict):
                raise ValueError("Invalid iPerf3 start event.")
            self.payload = {
                "start": data,
                "intervals": [],
                "end": {},
            }
            self.test_started_monotonic = time.monotonic()
            return None, ""
        if event_name == "interval":
            if self.payload is not None and isinstance(data, dict):
                intervals = self.payload["intervals"]
                if len(intervals) < 1200:
                    intervals.append(data)
            return None, ""
        if event_name == "error":
            self.payload = None
            self.test_started_monotonic = None
            return None, " ".join(str(data or "").split())[:1000]
        if event_name == "end":
            if self.payload is None or not isinstance(data, dict) or not data:
                self.payload = None
                self.test_started_monotonic = None
                return None, ""
            self.payload["end"] = data
            result = normalize_iperf3_result(
                self.payload,
                mode="server",
                config=self.config,
                command=self.command,
            )
            self.payload = None
            self.test_started_monotonic = None
            return result, ""
        return None, ""


def _terminate_process(process: subprocess.Popen[Any]) -> None:
    try:
        process.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _process_alive(process_id: int) -> bool:
    if process_id <= 0:
        return False
    try:
        os.kill(process_id, 0)
        return True
    except (OSError, ValueError):
        return False


def _stop_recorded_worker_process(
    process_id: int,
    instance: Path,
    session_id: str,
) -> bool:
    return _stop_process_if_command_matches(
        process_id,
        lambda command: _worker_command_matches(
            command,
            instance,
            session_id,
        ),
    )


def _stop_recorded_iperf_process(
    process_id: int,
    bind_address: str,
    port: int,
) -> bool:
    return _stop_process_if_command_matches(
        process_id,
        lambda command: _iperf_command_matches(
            command,
            bind_address,
            port,
        ),
    )


def _stop_process_if_command_matches(
    process_id: int,
    matches: Callable[[str], bool],
    *,
    timeout: float = 3,
) -> bool:
    if process_id <= 0 or not _process_alive(process_id):
        return False
    command = _process_command(process_id)
    if not command or not matches(command):
        return False
    try:
        os.kill(process_id, signal.SIGTERM)
    except OSError:
        return False
    deadline = time.time() + timeout
    while _process_alive(process_id) and time.time() < deadline:
        time.sleep(0.1)
    if _process_alive(process_id):
        current_command = _process_command(process_id)
        if current_command and matches(current_command):
            try:
                os.kill(process_id, signal.SIGKILL)
            except OSError:
                pass
    return True


def _process_command(process_id: int) -> str:
    try:
        result = subprocess.run(
            [
                "ps",
                "-ww",
                "-p",
                str(process_id),
                "-o",
                "command=",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _worker_command_matches(
    command: str,
    instance: Path,
    session_id: str,
) -> bool:
    arguments = _split_process_command(command)
    return bool(
        _option_value(arguments, "-m") == "twn_toolkit.iperf_server_worker"
        and _option_value(arguments, "--instance") == str(instance.resolve())
        and _option_value(arguments, "--session-id") == session_id
    )


def _iperf_command_matches(
    command: str,
    bind_address: str,
    port: int,
) -> bool:
    arguments = _split_process_command(command)
    if not arguments or Path(arguments[0]).name != "iperf3":
        return False
    return bool(
        any(argument in {"-s", "--server"} for argument in arguments)
        and _option_value(arguments, "-p", "--port") == str(port)
        and _option_value(arguments, "-B", "--bind") == bind_address
    )


def _split_process_command(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def _option_value(arguments: list[str], *names: str) -> str:
    for index, argument in enumerate(arguments[:-1]):
        if argument in names:
            return arguments[index + 1]
    return ""
