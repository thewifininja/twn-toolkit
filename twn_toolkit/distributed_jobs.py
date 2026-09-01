from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


MAX_JOB_PAYLOAD_BYTES = 256 * 1024
JOB_LEASE_SECONDS = 30
JOB_STATES = {"queued", "running", "succeeded", "failed", "cancelled"}


class DistributedJobStore:
    """Durable Mainframe queue with leased, idempotent agent delivery."""

    def __init__(self, instance_path: str | Path) -> None:
        instance = Path(instance_path)
        instance.mkdir(parents=True, exist_ok=True)
        self.path = instance / "distributed_jobs.sqlite3"
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS distributed_jobs (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    requester_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    capability_version TEXT NOT NULL,
                    input_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    output_json TEXT,
                    error TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    started_at REAL,
                    completed_at REAL,
                    lease_expires_at REAL
                )
                """
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def enqueue(
        self,
        *,
        agent_id: str,
        requester_id: str,
        capability_id: str,
        capability_version: str,
        inputs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        capability_id = _bounded_text(capability_id, 128, "Capability ID")
        capability_version = _bounded_text(
            capability_version, 32, "Capability version"
        )
        payload = _json_payload(inputs or {}, "Job input")
        now = time.time()
        job_id = f"job_{secrets.token_hex(16)}"
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO distributed_jobs
                    (id, agent_id, requester_id, capability_id,
                     capability_version, input_json, state, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)
                """,
                (
                    job_id,
                    _bounded_text(agent_id, 80, "Agent ID"),
                    _bounded_text(requester_id, 128, "Requester ID"),
                    capability_id,
                    capability_version,
                    payload,
                    now,
                ),
            )
        return self.get(job_id)  # type: ignore[return-value]

    def claim(
        self,
        agent_id: str,
        *,
        limit: int = 4,
        capability_id: str = "",
        exclude_capability_id: str = "",
    ) -> list[dict[str, Any]]:
        now = time.time()
        lease_expires = now + JOB_LEASE_SECONDS
        limit = max(1, min(int(limit), 16))
        with self._connect() as connection:
            capability_clause = ""
            parameters: list[Any] = [agent_id, now]
            if capability_id:
                capability_clause = " AND capability_id = ?"
                parameters.append(capability_id)
            elif exclude_capability_id:
                capability_clause = " AND capability_id != ?"
                parameters.append(exclude_capability_id)
            parameters.append(limit)
            rows = connection.execute(
                f"""
                SELECT * FROM distributed_jobs
                WHERE agent_id = ? AND (
                    state = 'queued' OR
                    (state = 'running' AND lease_expires_at <= ?)
                ){capability_clause}
                ORDER BY created_at LIMIT ?
                """,
                parameters,
            ).fetchall()
            for row in rows:
                connection.execute(
                    """
                    UPDATE distributed_jobs
                    SET state = 'running', started_at = COALESCE(started_at, ?),
                        lease_expires_at = ?
                    WHERE id = ?
                    """,
                    (now, lease_expires, row["id"]),
                )
        return [
            {
                "id": str(row["id"]),
                "capability_id": str(row["capability_id"]),
                "capability_version": str(row["capability_version"]),
                "inputs": json.loads(str(row["input_json"])),
            }
            for row in rows
        ]

    def complete(
        self,
        job_id: str,
        *,
        agent_id: str,
        state: str,
        output: dict[str, Any] | None = None,
        error: str = "",
    ) -> dict[str, Any]:
        if state not in {"succeeded", "failed"}:
            raise ValueError("Agent job result must be succeeded or failed.")
        payload = _json_payload(output or {}, "Job output")
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT agent_id, state FROM distributed_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if not row or str(row["agent_id"]) != agent_id:
                raise ValueError("Job does not belong to this agent.")
            if row["state"] in {"succeeded", "failed", "cancelled"}:
                return self.get(job_id)  # type: ignore[return-value]
            connection.execute(
                """
                UPDATE distributed_jobs
                SET state = ?, output_json = ?, error = ?, completed_at = ?,
                    lease_expires_at = NULL
                WHERE id = ?
                """,
                (state, payload, " ".join(str(error).split())[:1000], now, job_id),
            )
        return self.get(job_id)  # type: ignore[return-value]

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM distributed_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _job(row) if row else None

    def delete(self, job_id: str, *, requester_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM distributed_jobs WHERE id = ? AND requester_id = ?",
                (job_id, requester_id),
            )
        return cursor.rowcount == 1

    def recent(self, *, requester_id: str, limit: int = 25) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM distributed_jobs WHERE requester_id = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (requester_id, max(1, min(int(limit), 100))),
            ).fetchall()
        return [_job(row) for row in rows]

    def latest(
        self,
        *,
        agent_id: str,
        requester_id: str,
        capability_id: str,
        capability_version: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM distributed_jobs
                WHERE agent_id = ? AND requester_id = ?
                  AND capability_id = ? AND capability_version = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (agent_id, requester_id, capability_id, capability_version),
            ).fetchone()
        return _job(row) if row else None

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()


def _job(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["inputs"] = json.loads(item.pop("input_json"))
    raw_output = item.pop("output_json")
    item["output"] = json.loads(raw_output) if raw_output else None
    return item


def _json_payload(value: Any, label: str) -> str:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object.")
    try:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must contain JSON-compatible values.") from exc
    if len(payload.encode("utf-8")) > MAX_JOB_PAYLOAD_BYTES:
        raise ValueError(f"{label} exceeds the {MAX_JOB_PAYLOAD_BYTES}-byte limit.")
    return payload


def _bounded_text(value: str, length: int, label: str) -> str:
    clean = str(value).strip()
    if not clean or len(clean) > length:
        raise ValueError(f"{label} is invalid.")
    return clean
