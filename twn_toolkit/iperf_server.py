from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import selectors
import signal
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


IPERF_SERVER_ACTIVE_STATUSES = {"queued", "running", "stopping"}
IPERF_SERVER_CYCLE_SECONDS = 10 * 60
IPERF_SERVER_MAX_RUNTIME_SECONDS = 8 * 60 * 60
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
        _iperf3_executable()
        self._reconcile_workers()
        session_id = os.urandom(12).hex()
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_user = connection.execute(
                """
                SELECT id FROM iperf_server_sessions
                WHERE created_by = ?
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
                    created_by_username, created_at, updated_at
                ) VALUES (?, 'queued', ?, ?, ?, ?, ?, ?)
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
        command = [
            sys.executable,
            "-m",
            "twn_toolkit.iperf_server_worker",
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
            self.finish(
                session_id,
                status="error",
                reason="worker launch failed",
                error=f"Worker launch failed: {exc}",
            )
            raise ToolInputError(
                f"Could not launch the managed iPerf3 server: {exc}"
            ) from exc
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET worker_pid = ?, updated_at = ?
                WHERE id = ? AND status = 'queued'
                """,
                (process.pid, time.time(), session_id),
            )

    def begin(self, session_id: str) -> dict[str, Any]:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE iperf_server_sessions
                SET status = 'running', worker_pid = ?, started_at = ?,
                    updated_at = ?
                WHERE id = ? AND status IN ('queued', 'stopping')
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
                    AND status IN ('queued', 'running', 'stopping')
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
        return self._session_from_row(row) if row else None

    def request_stop(self, session_id: str, *, user_id: str) -> dict[str, Any]:
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE iperf_server_sessions
                SET stop_requested = 1, status = 'stopping', updated_at = ?
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
                SET status = ?, stop_reason = ?, error = ?, iperf_pid = NULL,
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
                SELECT id, worker_pid, updated_at
                FROM iperf_server_sessions
                WHERE status IN ('queued', 'running', 'stopping')
                """
            ).fetchall()
            now = time.time()
            for row in rows:
                if row["worker_pid"] is None:
                    if now - float(row["updated_at"]) <= 30:
                        continue
                    connection.execute(
                        """
                        UPDATE iperf_server_sessions
                        SET status = 'error', stopped_at = ?, updated_at = ?,
                            error = 'The managed iPerf3 worker did not start.'
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
                        UPDATE iperf_server_sessions
                        SET status = 'error', stopped_at = ?, updated_at = ?,
                            error = CASE WHEN error = ''
                                THEN 'The managed iPerf3 worker exited unexpectedly.'
                                ELSE error END
                        WHERE id = ?
                            AND status IN ('queued', 'running', 'stopping')
                        """,
                        (now, now, row["id"]),
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
        item["active"] = item["status"] in IPERF_SERVER_ACTIVE_STATUSES
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
