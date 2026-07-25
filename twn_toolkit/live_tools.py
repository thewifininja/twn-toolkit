from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .activity import ActivityStore
from .network_tools import ping_engine_capability, ping_hosts
from .profiles import SNMPCredentialProfileStore, SNMPHostProfileStore
from .snmp_tools import poll_snmp_interfaces


LIVE_SESSION_LEASE_SECONDS = 5 * 60
LIVE_SESSION_LIMIT_PER_USER = 4
LIVE_PING_SAMPLE_LIMIT = 100_000
LIVE_SNMP_SAMPLE_LIMIT = 100_000
STOPPED_SESSION_RETENTION_SECONDS = 24 * 60 * 60


class LiveToolStore:
    """SQLite-backed state for tools that continue while the browser navigates."""

    def __init__(self, instance_path: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "live_tools.sqlite3"
        with self._connect():
            pass

    def create_ping_session(
        self,
        *,
        user_id: str,
        username: str,
        title: str,
        targets: list[dict[str, str]],
        interval: int,
        timeout: float,
    ) -> dict[str, Any]:
        now = time.time()
        config = {
            "targets": targets,
            "interval": interval,
            "timeout": timeout,
        }
        with self._connect() as connection:
            self._check_session_limit(connection, user_id)
            session_id = secrets.token_hex(12)
            connection.execute(
                """
                INSERT INTO live_tool_sessions (
                    id, user_id, username, tool_key, title, state, config_json,
                    revision, next_run_at, lease_expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, 'ping', ?, 'running', ?, 1, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    user_id,
                    username,
                    title,
                    json.dumps(config, separators=(",", ":")),
                    now,
                    now + LIVE_SESSION_LEASE_SECONDS,
                    now,
                    now,
                ),
            )
        session = self.get_session(session_id, user_id=user_id)
        if session is None:  # pragma: no cover - the insert above is authoritative
            raise RuntimeError("Live ping session could not be created.")
        return session

    def create_snmp_interface_session(
        self,
        *,
        user_id: str,
        username: str,
        title: str,
        targets: list[dict[str, Any]],
        interval: int,
        round_timeout: float,
    ) -> dict[str, Any]:
        now = time.time()
        config = {
            "targets": targets,
            "interval": interval,
            "round_timeout": round_timeout,
        }
        with self._connect() as connection:
            self._check_session_limit(connection, user_id)
            session_id = secrets.token_hex(12)
            connection.execute(
                """
                INSERT INTO live_tool_sessions (
                    id, user_id, username, tool_key, title, state, config_json,
                    revision, next_run_at, lease_expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, 'snmp_interface', ?, 'running', ?, 1, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    user_id,
                    username,
                    title,
                    json.dumps(config, separators=(",", ":")),
                    now,
                    now + LIVE_SESSION_LEASE_SECONDS,
                    now,
                    now,
                ),
            )
        session = self.get_session(session_id, user_id=user_id)
        if session is None:  # pragma: no cover - the insert above is authoritative
            raise RuntimeError("Live SNMP interface session could not be created.")
        return session

    def sessions_for_user(
        self, user_id: str, *, renew_lease: bool = True
    ) -> list[dict[str, Any]]:
        now = time.time()
        with self._connect() as connection:
            self._expire_abandoned(connection, now)
            if renew_lease:
                connection.execute(
                    """
                    UPDATE live_tool_sessions
                    SET lease_expires_at = ?, updated_at = ?
                    WHERE user_id = ? AND state = 'running'
                    """,
                    (now + LIVE_SESSION_LEASE_SECONDS, now, user_id),
                )
            rows = connection.execute(
                """
                SELECT * FROM live_tool_sessions
                WHERE user_id = ? AND state IN ('running', 'error')
                ORDER BY created_at
                """,
                (user_id,),
            ).fetchall()
        return [self._session_from_row(row, include_config=False) for row in rows]

    def get_session(
        self, session_id: str, *, user_id: str = ""
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            query = "SELECT * FROM live_tool_sessions WHERE id = ?"
            values: tuple[object, ...] = (session_id,)
            if user_id:
                query += " AND user_id = ?"
                values += (user_id,)
            row = connection.execute(query, values).fetchone()
        return self._session_from_row(row) if row else None

    def renew_session(self, session_id: str, *, user_id: str) -> dict[str, Any] | None:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE live_tool_sessions
                SET lease_expires_at = ?, updated_at = ?
                WHERE id = ? AND user_id = ? AND state = 'running'
                """,
                (now + LIVE_SESSION_LEASE_SECONDS, now, session_id, user_id),
            )
            row = connection.execute(
                "SELECT * FROM live_tool_sessions WHERE id = ? AND user_id = ?",
                (session_id, user_id),
            ).fetchone()
        return self._session_from_row(row) if row else None

    def update_ping_session(
        self,
        session_id: str,
        *,
        user_id: str,
        targets: list[dict[str, str]],
        interval: int,
        timeout: float,
    ) -> dict[str, Any] | None:
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM live_tool_sessions
                WHERE id = ? AND user_id = ? AND tool_key = 'ping'
                """,
                (session_id, user_id),
            ).fetchone()
            if not row:
                return None
            if row["state"] != "running":
                raise ValueError("Only a running ping session can be updated.")
            config = json.loads(row["config_json"])
            config["targets"] = targets
            config["interval"] = interval
            config["timeout"] = timeout
            connection.execute(
                """
                UPDATE live_tool_sessions
                SET config_json = ?, revision = revision + 1, next_run_at = ?,
                    lease_expires_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    json.dumps(config, separators=(",", ":")),
                    now,
                    now + LIVE_SESSION_LEASE_SECONDS,
                    now,
                    session_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM live_tool_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        return self._session_from_row(updated)

    def update_snmp_interface_session(
        self,
        session_id: str,
        *,
        user_id: str,
        interval: int,
    ) -> dict[str, Any] | None:
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM live_tool_sessions
                WHERE id = ? AND user_id = ? AND tool_key = 'snmp_interface'
                """,
                (session_id, user_id),
            ).fetchone()
            if not row:
                return None
            if row["state"] != "running":
                raise ValueError("Only a running SNMP monitor can be updated.")
            config = json.loads(row["config_json"])
            config["interval"] = interval
            connection.execute(
                """
                UPDATE live_tool_sessions
                SET config_json = ?, revision = revision + 1, next_run_at = ?,
                    lease_expires_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    json.dumps(config, separators=(",", ":")),
                    now,
                    now + LIVE_SESSION_LEASE_SECONDS,
                    now,
                    session_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM live_tool_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        return self._session_from_row(updated)

    def stop_session(
        self, session_id: str, *, user_id: str
    ) -> dict[str, Any] | None:
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM live_tool_sessions WHERE id = ? AND user_id = ?",
                (session_id, user_id),
            ).fetchone()
            if not row:
                return None
            if row["state"] == "stopped":
                session = self._session_from_row(row)
                session["_was_running"] = False
                return session
            connection.execute(
                """
                UPDATE live_tool_sessions
                SET state = 'stopped', stopped_at = ?, busy_until = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                (now, now, session_id),
            )
            stopped = connection.execute(
                "SELECT * FROM live_tool_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        session = self._session_from_row(stopped)
        session["_was_running"] = True
        return session

    def rename_session(
        self,
        session_id: str,
        *,
        user_id: str,
        title: str,
    ) -> dict[str, Any] | None:
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM live_tool_sessions
                WHERE id = ? AND user_id = ? AND state IN ('running', 'error')
                """,
                (session_id, user_id),
            ).fetchone()
            if not row:
                return None
            previous_title = str(row["title"])
            if previous_title != title:
                connection.execute(
                    """
                    UPDATE live_tool_sessions
                    SET title = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (title, now, session_id),
                )
            renamed = connection.execute(
                "SELECT * FROM live_tool_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        session = self._session_from_row(renamed)
        session["_previous_title"] = previous_title
        session["_renamed"] = previous_title != title
        return session

    def ping_samples(
        self,
        session_id: str,
        *,
        user_id: str,
        after_id: int = 0,
        limit: int = 10_000,
    ) -> dict[str, Any] | None:
        limit = max(1, min(10_000, int(limit)))
        with self._connect() as connection:
            session = connection.execute(
                """
                SELECT id FROM live_tool_sessions
                WHERE id = ? AND user_id = ? AND tool_key = 'ping'
                """,
                (session_id, user_id),
            ).fetchone()
            if not session:
                return None
            rows = connection.execute(
                """
                SELECT id, host, label, sampled_at, reachable, latency_ms
                FROM live_ping_samples
                WHERE session_id = ? AND id > ?
                ORDER BY id
                LIMIT ?
                """,
                (session_id, max(0, int(after_id)), limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        return {
            "samples": [
                {
                    "id": row["id"],
                    "host": row["host"],
                    "label": row["label"],
                    "sampled_at": row["sampled_at"],
                    "reachable": bool(row["reachable"]),
                    "latency_ms": row["latency_ms"],
                }
                for row in rows
            ],
            "has_more": has_more,
            "next_after": rows[-1]["id"] if rows else max(0, int(after_id)),
        }

    def snmp_interface_samples(
        self,
        session_id: str,
        *,
        user_id: str,
        after_id: int = 0,
        limit: int = 10_000,
    ) -> dict[str, Any] | None:
        limit = max(1, min(10_000, int(limit)))
        with self._connect() as connection:
            session = connection.execute(
                """
                SELECT id FROM live_tool_sessions
                WHERE id = ? AND user_id = ? AND tool_key = 'snmp_interface'
                """,
                (session_id, user_id),
            ).fetchone()
            if not session:
                return None
            rows = connection.execute(
                """
                SELECT id, target_key, sampled_at, status, sample_json, error
                FROM live_snmp_samples
                WHERE session_id = ? AND id > ?
                ORDER BY id
                LIMIT ?
                """,
                (session_id, max(0, int(after_id)), limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        return {
            "samples": [
                {
                    "id": row["id"],
                    "target_key": row["target_key"],
                    "sampled_at": row["sampled_at"],
                    "status": row["status"],
                    "sample": json.loads(row["sample_json"]) if row["sample_json"] else None,
                    "error": row["error"],
                }
                for row in rows
            ],
            "has_more": has_more,
            "next_after": rows[-1]["id"] if rows else max(0, int(after_id)),
        }

    def claim_due(self, *, limit: int = 4) -> list[dict[str, Any]]:
        now = time.time()
        claimed: list[dict[str, Any]] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_abandoned(connection, now)
            rows = connection.execute(
                """
                SELECT * FROM live_tool_sessions
                WHERE state = 'running'
                    AND lease_expires_at > ?
                    AND next_run_at <= ?
                    AND (busy_until IS NULL OR busy_until < ?)
                ORDER BY next_run_at
                LIMIT ?
                """,
                (now, now, now, max(1, limit)),
            ).fetchall()
            for row in rows:
                config = json.loads(row["config_json"])
                target_count = len(config.get("targets", []))
                compatibility_batches = max(1, (target_count + 19) // 20)
                if row["tool_key"] == "snmp_interface":
                    busy_seconds = max(30.0, float(config.get("round_timeout", 30)))
                else:
                    busy_seconds = max(
                        30.0,
                        float(config.get("timeout", 1)) * compatibility_batches + 10,
                    )
                connection.execute(
                    """
                    UPDATE live_tool_sessions
                    SET busy_until = ?, updated_at = ?
                    WHERE id = ? AND revision = ?
                    """,
                    (now + busy_seconds, now, row["id"], row["revision"]),
                )
                claimed.append(self._session_from_row(row))
        return claimed

    def release_stale_claims(self) -> None:
        """Make interrupted rounds immediately eligible after the singleton restarts."""
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE live_tool_sessions
                SET busy_until = NULL, next_run_at = ?, updated_at = ?
                WHERE state = 'running' AND busy_until IS NOT NULL
                """,
                (now, now),
            )

    def record_ping_round(
        self,
        session_id: str,
        *,
        revision: int,
        sampled_at: float,
        duration_ms: float,
        engine: str,
        results: list[dict[str, Any]],
    ) -> bool:
        now = time.time()
        replies = sum(1 for result in results if result.get("reachable"))
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM live_tool_sessions WHERE id = ?", (session_id,)
            ).fetchone()
            if not row or row["state"] != "running":
                return False
            if int(row["revision"]) != int(revision):
                connection.execute(
                    """
                    UPDATE live_tool_sessions
                    SET busy_until = NULL, next_run_at = ?, updated_at = ?
                    WHERE id = ? AND state = 'running'
                    """,
                    (now, now, session_id),
                )
                return False
            config = json.loads(row["config_json"])
            labels = {
                target["host"]: target.get("label", "")
                for target in config.get("targets", [])
            }
            connection.executemany(
                """
                INSERT INTO live_ping_samples (
                    session_id, host, label, sampled_at, reachable, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        session_id,
                        str(result.get("host", "")),
                        labels.get(str(result.get("host", "")), ""),
                        sampled_at,
                        1 if result.get("reachable") else 0,
                        result.get("latency_ms"),
                    )
                    for result in results
                ],
            )
            interval = max(1, min(60, int(config.get("interval", 2))))
            next_run = max(now, sampled_at + interval)
            connection.execute(
                """
                UPDATE live_tool_sessions
                SET next_run_at = ?, busy_until = NULL, last_round_at = ?,
                    last_duration_ms = ?, last_engine = ?, last_error = '',
                    rounds_completed = rounds_completed + 1,
                    probes_sent = probes_sent + ?,
                    replies_received = replies_received + ?,
                    last_up_count = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    next_run,
                    sampled_at,
                    round(duration_ms, 1),
                    engine,
                    len(results),
                    replies,
                    replies,
                    now,
                    session_id,
                ),
            )
            if (int(row["rounds_completed"]) + 1) % 20 == 0:
                threshold = connection.execute(
                    """
                    SELECT id FROM live_ping_samples
                    WHERE session_id = ?
                    ORDER BY id DESC
                    LIMIT 1 OFFSET ?
                    """,
                    (session_id, LIVE_PING_SAMPLE_LIMIT - 1),
                ).fetchone()
                if threshold:
                    connection.execute(
                        "DELETE FROM live_ping_samples WHERE session_id = ? AND id < ?",
                        (session_id, threshold["id"]),
                    )
        return True

    def record_snmp_interface_round(
        self,
        session_id: str,
        *,
        revision: int,
        sampled_at: float,
        duration_ms: float,
        results: list[dict[str, Any]],
    ) -> bool:
        now = time.time()
        successes = sum(1 for result in results if result.get("status") == "success")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM live_tool_sessions WHERE id = ?", (session_id,)
            ).fetchone()
            if not row or row["state"] != "running":
                return False
            if int(row["revision"]) != int(revision):
                connection.execute(
                    """
                    UPDATE live_tool_sessions
                    SET busy_until = NULL, next_run_at = ?, updated_at = ?
                    WHERE id = ? AND state = 'running'
                    """,
                    (now, now, session_id),
                )
                return False
            config = json.loads(row["config_json"])
            targets = {
                f"{target.get('host_name', '')}::{target.get('interface_index', '')}": target
                for target in config.get("targets", [])
            }
            records = []
            for result in results:
                sample = result.get("sample") if result.get("status") == "success" else None
                host_name = str(
                    (sample or {}).get("host_name", result.get("host_name", ""))
                )
                interface_index = int(
                    (sample or {}).get(
                        "interface_index", result.get("interface_index", 0)
                    )
                )
                target_key = f"{host_name}::{interface_index}"
                if target_key not in targets:
                    continue
                records.append(
                    (
                        session_id,
                        target_key,
                        sampled_at,
                        "success" if sample else "error",
                        json.dumps(sample, separators=(",", ":")) if sample else "",
                        str(result.get("error", ""))[:500],
                    )
                )
            connection.executemany(
                """
                INSERT INTO live_snmp_samples (
                    session_id, target_key, sampled_at, status, sample_json, error
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                records,
            )
            interval = max(1, min(60, int(config.get("interval", 5))))
            next_run = max(now, sampled_at + interval)
            last_error = ""
            if successes < len(results):
                failures = len(results) - successes
                suffix = "s" if failures != 1 else ""
                last_error = (
                    f"{failures} interface{suffix} failed on the latest round."
                )
            connection.execute(
                """
                UPDATE live_tool_sessions
                SET next_run_at = ?, busy_until = NULL, last_round_at = ?,
                    last_duration_ms = ?, last_engine = 'SNMP',
                    last_error = ?, rounds_completed = rounds_completed + 1,
                    probes_sent = probes_sent + ?,
                    replies_received = replies_received + ?,
                    last_up_count = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    next_run,
                    sampled_at,
                    round(duration_ms, 1),
                    last_error,
                    len(results),
                    successes,
                    successes,
                    now,
                    session_id,
                ),
            )
            if (int(row["rounds_completed"]) + 1) % 20 == 0:
                threshold = connection.execute(
                    """
                    SELECT id FROM live_snmp_samples
                    WHERE session_id = ?
                    ORDER BY id DESC
                    LIMIT 1 OFFSET ?
                    """,
                    (session_id, LIVE_SNMP_SAMPLE_LIMIT - 1),
                ).fetchone()
                if threshold:
                    connection.execute(
                        "DELETE FROM live_snmp_samples WHERE session_id = ? AND id < ?",
                        (session_id, threshold["id"]),
                    )
        return True

    def record_error(
        self, session_id: str, *, revision: int, message: str
    ) -> None:
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state, revision FROM live_tool_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
            if not row or row["state"] != "running":
                return
            if int(row["revision"]) != int(revision):
                connection.execute(
                    """
                    UPDATE live_tool_sessions
                    SET busy_until = NULL, next_run_at = ?, updated_at = ?
                    WHERE id = ? AND state = 'running'
                    """,
                    (now, now, session_id),
                )
                return
            connection.execute(
                """
                UPDATE live_tool_sessions
                SET state = 'error', last_error = ?, busy_until = NULL,
                    stopped_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (message[:500], now, now, session_id),
            )

    def cleanup(self) -> None:
        now = time.time()
        with self._connect() as connection:
            self._expire_abandoned(connection, now)
            connection.execute(
                """
                DELETE FROM live_tool_sessions
                WHERE state != 'running'
                    AND stopped_at IS NOT NULL
                    AND stopped_at < ?
                """,
                (now - STOPPED_SESSION_RETENTION_SECONDS,),
            )

    @staticmethod
    def _check_session_limit(
        connection: sqlite3.Connection, user_id: str
    ) -> None:
        active = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM live_tool_sessions
            WHERE user_id = ? AND state IN ('running', 'error')
            """,
            (user_id,),
        ).fetchone()["count"]
        if active >= LIVE_SESSION_LIMIT_PER_USER:
            raise ValueError(
                f"Stop one of your live tools before starting another. "
                f"Each user can keep up to {LIVE_SESSION_LIMIT_PER_USER} live tools."
            )

    @staticmethod
    def _expire_abandoned(connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            """
            UPDATE live_tool_sessions
            SET state = 'stopped', stopped_at = ?, busy_until = NULL,
                last_error = 'Stopped after the browser lease expired.',
                updated_at = ?
            WHERE state = 'running' AND lease_expires_at <= ?
            """,
            (now, now, now),
        )

    @staticmethod
    def _session_from_row(
        row: sqlite3.Row, *, include_config: bool = True
    ) -> dict[str, Any]:
        config = json.loads(row["config_json"])
        target_count = len(config.get("targets", []))
        session = {
            "id": row["id"],
            "_user_id": row["user_id"],
            "_username": row["username"],
            "tool_key": row["tool_key"],
            "title": row["title"],
            "state": row["state"],
            "revision": row["revision"],
            "target_count": target_count,
            "interval": config.get("interval"),
            "timeout": config.get("timeout"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_round_at": row["last_round_at"],
            "last_duration_ms": row["last_duration_ms"],
            "last_engine": row["last_engine"],
            "last_error": row["last_error"],
            "rounds_completed": row["rounds_completed"],
            "probes_sent": row["probes_sent"],
            "replies_received": row["replies_received"],
            "last_up_count": row["last_up_count"],
            "stopped_at": row["stopped_at"],
        }
        if include_config:
            session["config"] = config
        return session

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.execute("PRAGMA foreign_keys = ON")
            self._initialize(connection)
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
                # SQLite may remove transient WAL/SHM files between close and chmod.
                pass

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS live_tool_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                tool_key TEXT NOT NULL,
                title TEXT NOT NULL,
                state TEXT NOT NULL,
                config_json TEXT NOT NULL,
                revision INTEGER NOT NULL DEFAULT 1,
                next_run_at REAL NOT NULL,
                busy_until REAL,
                lease_expires_at REAL NOT NULL,
                last_round_at REAL,
                last_duration_ms REAL,
                last_engine TEXT NOT NULL DEFAULT '',
                last_error TEXT NOT NULL DEFAULT '',
                rounds_completed INTEGER NOT NULL DEFAULT 0,
                probes_sent INTEGER NOT NULL DEFAULT 0,
                replies_received INTEGER NOT NULL DEFAULT 0,
                last_up_count INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                stopped_at REAL
            );
            CREATE INDEX IF NOT EXISTS live_tool_sessions_due
                ON live_tool_sessions(state, next_run_at);
            CREATE INDEX IF NOT EXISTS live_tool_sessions_user
                ON live_tool_sessions(user_id, state);
            CREATE TABLE IF NOT EXISTS live_ping_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL
                    REFERENCES live_tool_sessions(id) ON DELETE CASCADE,
                host TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                sampled_at REAL NOT NULL,
                reachable INTEGER NOT NULL,
                latency_ms REAL
            );
            CREATE INDEX IF NOT EXISTS live_ping_samples_session
                ON live_ping_samples(session_id, id);
            CREATE TABLE IF NOT EXISTS live_snmp_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL
                    REFERENCES live_tool_sessions(id) ON DELETE CASCADE,
                target_key TEXT NOT NULL,
                sampled_at REAL NOT NULL,
                status TEXT NOT NULL,
                sample_json TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS live_snmp_samples_session
                ON live_snmp_samples(session_id, id);
            """
        )


class LiveToolRunner:
    """Execute one claimed live-tool polling round."""

    def __init__(self, store: LiveToolStore) -> None:
        self.store = store
        self.activity_store = ActivityStore(str(store.instance_path))

    def process(self, session: dict[str, Any]) -> None:
        if session["tool_key"] == "ping":
            self._process_ping(session)
            return
        if session["tool_key"] == "snmp_interface":
            self._process_snmp_interface(session)
            return
        self.store.record_error(
            session["id"],
            revision=session["revision"],
            message=f"Unsupported live tool type: {session['tool_key']}",
        )

    def _process_ping(self, session: dict[str, Any]) -> None:
        config = session["config"]
        targets = config.get("targets", [])
        started = time.time()
        monotonic_started = time.monotonic()
        try:
            results = ping_hosts(
                [str(target.get("host", "")) for target in targets],
                timeout=float(config.get("timeout", 1)),
            )
            capability = ping_engine_capability()
            duration_ms = (time.monotonic() - monotonic_started) * 1000
            recorded = self.store.record_ping_round(
                session["id"],
                revision=session["revision"],
                sampled_at=started,
                duration_ms=duration_ms,
                engine=str(capability.get("engine", "ping")),
                results=results,
            )
            if recorded:
                self._increment_activity(
                    "ping",
                    "probes_sent",
                    len(results),
                    session,
                )
                self._increment_activity(
                    "ping",
                    "replies_received",
                    sum(1 for result in results if result.get("reachable")),
                    session,
                )
        except Exception as exc:
            self.store.record_error(
                session["id"],
                revision=session["revision"],
                message=f"{type(exc).__name__}: {exc}",
            )

    def _process_snmp_interface(self, session: dict[str, Any]) -> None:
        config = session["config"]
        targets = config.get("targets", [])
        started = time.time()
        monotonic_started = time.monotonic()
        try:
            host_store = SNMPHostProfileStore(str(self.store.instance_path))
            credential_store = SNMPCredentialProfileStore(
                str(self.store.instance_path)
            )
            prepared = []
            prepared_indexes = []
            results: list[dict[str, Any] | None] = [None] * len(targets)
            for index, target in enumerate(targets):
                host_name = str(target.get("host_name", ""))
                interface_index = int(target.get("interface_index", 0))
                host = host_store.get(host_name)
                if not host:
                    results[index] = {
                        "host_name": host_name,
                        "interface_index": interface_index,
                        "status": "error",
                        "error": "The saved SNMP host no longer exists.",
                    }
                    continue
                credential = credential_store.get(
                    str(host.get("credential_name", ""))
                )
                if not credential:
                    results[index] = {
                        "host_name": host_name,
                        "interface_index": interface_index,
                        "status": "error",
                        "error": "The saved SNMP credential no longer exists.",
                    }
                    continue
                prepared.append((host, credential, interface_index))
                prepared_indexes.append(index)
            for index, result in zip(
                prepared_indexes, poll_snmp_interfaces(prepared)
            ):
                results[index] = result
            completed_results = [
                result
                if result is not None
                else {
                    "host_name": str(targets[index].get("host_name", "")),
                    "interface_index": int(
                        targets[index].get("interface_index", 0)
                    ),
                    "status": "error",
                    "error": "The interface poll did not return a result.",
                }
                for index, result in enumerate(results)
            ]
            duration_ms = (time.monotonic() - monotonic_started) * 1000
            recorded = self.store.record_snmp_interface_round(
                session["id"],
                revision=session["revision"],
                sampled_at=started,
                duration_ms=duration_ms,
                results=completed_results,
            )
            if recorded:
                successful_polls = sum(
                    int(result.get("sample", {}).get("poll_count", 1))
                    for result in completed_results
                    if result.get("status") == "success"
                )
                self._increment_activity(
                    "snmp", "polls", successful_polls, session
                )
        except Exception as exc:
            self.store.record_error(
                session["id"],
                revision=session["revision"],
                message=f"{type(exc).__name__}: {exc}",
            )

    def _increment_activity(
        self,
        tool_key: str,
        metric: str,
        amount: int,
        session: dict[str, Any],
    ) -> None:
        try:
            self.activity_store.increment(
                tool_key,
                metric,
                amount,
                user_id=str(session.get("_user_id", "")),
                username=str(session.get("_username", "")),
            )
        except (OSError, sqlite3.Error, ValueError):
            pass


def public_live_session(
    session: dict[str, Any], *, include_config: bool = False
) -> dict[str, Any]:
    """Build the user-facing session contract and its tool-specific URLs."""
    from flask import url_for

    public = {
        key: value
        for key, value in session.items()
        if not key.startswith("_") and (include_config or key != "config")
    }
    session_id = str(session.get("id", ""))
    if session.get("tool_key") == "snmp_interface":
        public["restore_url"] = url_for(
            "tools.snmp_test", session=session_id
        )
        public["detail_url"] = url_for(
            "tools.snmp_interface_monitor_session", session_id=session_id
        )
        public["samples_url"] = url_for(
            "tools.snmp_interface_monitor_session_samples",
            session_id=session_id,
        )
        public["update_url"] = url_for(
            "tools.update_snmp_interface_monitor_session",
            session_id=session_id,
        )
    else:
        public["restore_url"] = url_for(
            "tools.ping_tool", session=session_id
        )
        public["detail_url"] = url_for(
            "tools.ping_session", session_id=session_id
        )
        public["samples_url"] = url_for(
            "tools.ping_session_samples", session_id=session_id
        )
        public["targets_url"] = url_for(
            "tools.update_ping_session_targets", session_id=session_id
        )
    public["stop_url"] = url_for(
        "tools.stop_live_tool_session", session_id=session_id
    )
    public["rename_url"] = url_for(
        "tools.rename_live_tool_session", session_id=session_id
    )
    return public
