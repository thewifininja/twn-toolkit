from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .operational import OperationalSettingsStore


MAX_JOB_PAYLOAD_BYTES = 256 * 1024
JOB_PROTOCOL_VERSION = 2
JOB_STATES = {"queued", "claimed", "running", "cancel_requested", "unknown", "succeeded", "failed", "cancelled"}
TERMINAL_JOB_STATES = {"succeeded", "failed", "cancelled", "unknown"}


class DistributedJobStore:
    """Durable Mainframe queue with leased delivery and atomic state transitions."""

    def __init__(self, instance_path: str | Path) -> None:
        instance = Path(instance_path)
        instance.mkdir(parents=True, exist_ok=True)
        self.path = instance / "distributed_jobs.sqlite3"
        self.operational_store = OperationalSettingsStore(str(instance))
        with self._connect(write=True) as connection:
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
                    lease_expires_at REAL,
                    activation_id TEXT NOT NULL DEFAULT ''
                )
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(distributed_jobs)")
            }
            if "activation_id" not in columns:
                connection.execute(
                    "ALTER TABLE distributed_jobs ADD COLUMN "
                    "activation_id TEXT NOT NULL DEFAULT ''"
                )
            if "attempt_token" not in columns:
                connection.execute("ALTER TABLE distributed_jobs ADD COLUMN attempt_token TEXT NOT NULL DEFAULT ''")
                # Old in-flight deliveries have no ownership proof. Never redeliver them.
                connection.execute("UPDATE distributed_jobs SET state = 'unknown', error = 'Legacy execution outcome is unknown; reconcile before retrying.' WHERE state = 'running'")
            connection.execute("CREATE INDEX IF NOT EXISTS distributed_jobs_state_lease ON distributed_jobs(state, lease_expires_at)")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS distributed_agent_activations (
                    agent_id TEXT PRIMARY KEY,
                    activation_id TEXT NOT NULL
                )
                """
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _lease_seconds(self) -> int:
        return int(self.operational_store.get()["distributed_job_lease_seconds"])

    def enqueue(
        self,
        *,
        agent_id: str,
        requester_id: str,
        capability_id: str,
        capability_version: str,
        inputs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        agent_id = _bounded_text(agent_id, 80, "Agent ID")
        requester_id = _bounded_text(requester_id, 128, "Requester ID")
        capability_id = _bounded_text(capability_id, 128, "Capability ID")
        capability_version = _bounded_text(capability_version, 32, "Capability version")
        payload = _json_payload(inputs or {}, "Job input")
        job_id = f"job_{secrets.token_hex(16)}"
        with self._connect(write=True) as connection:
            # Bind the activation in the insert, before a claimant or activation
            # change can observe the job. Legacy agents retain an empty epoch.
            connection.execute(
                """
                INSERT INTO distributed_jobs
                    (id, agent_id, requester_id, capability_id,
                     capability_version, input_json, state, created_at, activation_id)
                VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, COALESCE(
                    (SELECT activation_id FROM distributed_agent_activations
                     WHERE agent_id = ?), ''
                ))
                """,
                (job_id, agent_id, requester_id, capability_id, capability_version,
                 payload, time.time(), agent_id),
            )
            row = connection.execute(
                "SELECT * FROM distributed_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _job(row)

    def activate_agent(self, agent_id: str, activation_id: str) -> int:
        activation_id = _activation_id(activation_id)
        if not activation_id:
            return 0
        with self._connect(write=True) as connection:
            now = time.time()
            previous = connection.execute(
                "SELECT activation_id FROM distributed_agent_activations "
                "WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if previous is None:
                connection.execute(
                    "UPDATE distributed_jobs SET activation_id = ? "
                    "WHERE agent_id = ? AND activation_id = '' "
                    "AND state IN ('queued', 'claimed', 'running', 'cancel_requested')",
                    (activation_id, agent_id),
                )
                cancelled = 0
            elif str(previous["activation_id"]) != activation_id:
                cursor = connection.execute(
                    """
                    UPDATE distributed_jobs
                    SET state = CASE WHEN state IN ('queued', 'claimed') THEN 'cancelled' ELSE 'unknown' END, completed_at = ?, attempt_token = '',
                        lease_expires_at = NULL,
                        error = 'Agent activation changed. Unstarted work was cancelled; reconcile any started operation.'
                    WHERE agent_id = ? AND activation_id != ?
                      AND state IN ('queued', 'claimed', 'running', 'cancel_requested')
                    """,
                    (now, agent_id, activation_id),
                )
                cancelled = cursor.rowcount
            else:
                cancelled = 0
            connection.execute(
                """
                INSERT INTO distributed_agent_activations(agent_id, activation_id)
                VALUES (?, ?)
                ON CONFLICT(agent_id) DO UPDATE
                SET activation_id = excluded.activation_id
                """,
                (agent_id, activation_id),
            )
        return cancelled

    @staticmethod
    def _expire(connection, job_id=None):
        now = time.time()
        clause = " AND id = ?" if job_id else ""
        values = [now, now] + ([job_id] if job_id else [])
        connection.execute(
            "UPDATE distributed_jobs SET "
            "state = CASE WHEN state = 'claimed' THEN 'cancelled' ELSE 'unknown' END, "
            "completed_at = COALESCE(completed_at, ?), lease_expires_at = NULL, "
            "error = CASE WHEN state = 'claimed' "
            "THEN 'Claim expired before execution started.' "
            "ELSE 'Execution lease expired. Outcome unknown; reconcile before retrying.' END "
            "WHERE state IN ('claimed', 'running', 'cancel_requested') "
            "AND lease_expires_at <= ?" + clause,
            values,
        )

    def claim(self, agent_id: str, *, limit: int = 1, capability_id: str = "",
              exclude_capability_id: str = "", activation_id: str = "") -> list[dict[str, Any]]:
        activation_id = _activation_id(activation_id)
        limit = max(1, min(int(limit), 16))
        with self._connect(write=True) as connection:
            self._expire(connection)
            now = time.time()
            lease_seconds = self._lease_seconds()
            clauses = ["agent_id = ?", "state = 'queued'"]
            values: list[Any] = [agent_id]
            if activation_id:
                clauses.append("activation_id = ?"); values.append(activation_id)
            if capability_id:
                clauses.append("capability_id = ?"); values.append(capability_id)
            elif exclude_capability_id:
                clauses.append("capability_id != ?"); values.append(exclude_capability_id)
            rows = connection.execute("SELECT * FROM distributed_jobs WHERE " + " AND ".join(clauses) + " ORDER BY created_at LIMIT ?", [*values, limit]).fetchall()
            jobs = []
            for row in rows:
                token = secrets.token_hex(32)
                connection.execute("UPDATE distributed_jobs SET state = 'claimed', attempt_token = ?, lease_expires_at = ? WHERE id = ?", (token, now + lease_seconds, row["id"]))
                jobs.append({"id": row["id"], "capability_id": row["capability_id"], "capability_version": row["capability_version"],
                             "inputs": json.loads(row["input_json"]), "attempt_token": token, "activation_id": row["activation_id"],
                             "lease_seconds": lease_seconds, "job_protocol": JOB_PROTOCOL_VERSION})
        return jobs

    @staticmethod
    def _owned(connection, job_id, agent_id, attempt_token, activation_id):
        row = connection.execute("SELECT * FROM distributed_jobs WHERE id = ?", (job_id,)).fetchone()
        if (not row or row["agent_id"] != agent_id or not attempt_token
                or not secrets.compare_digest(str(row["attempt_token"]), str(attempt_token))
                or row["activation_id"] != _activation_id(activation_id)):
            raise ValueError("Operation ownership is no longer valid.")
        return row

    def control(self, job_id: str, *, agent_id: str, attempt_token: str, activation_id: str = "", action: str = "renew") -> dict[str, Any]:
        if action not in {"start", "renew"}:
            raise ValueError("Operation control must be start or renew.")
        lease_seconds = self._lease_seconds()
        with self._connect(write=True) as connection:
            self._expire(connection, job_id)
            row = self._owned(connection, job_id, agent_id, attempt_token, activation_id)
            if row["state"] not in {"claimed", "running", "cancel_requested"}:
                return {"state": row["state"], "lease_seconds": lease_seconds}
            now = time.time()
            if action == "start":
                if row["state"] != "claimed":
                    raise ValueError("Operation has already started; do not execute it again.")
                connection.execute("UPDATE distributed_jobs SET state = 'running', started_at = ?, lease_expires_at = ? WHERE id = ?", (now, now + lease_seconds, job_id))
            else:
                connection.execute("UPDATE distributed_jobs SET lease_expires_at = ? WHERE id = ?", (now + lease_seconds, job_id))
            state = connection.execute("SELECT state FROM distributed_jobs WHERE id = ?", (job_id,)).fetchone()["state"]
        return {"state": state, "lease_seconds": lease_seconds}

    def complete(self, job_id: str, *, agent_id: str, state: str, output: dict[str, Any] | None = None,
                 error: str = "", attempt_token: str = "", activation_id: str = "") -> dict[str, Any]:
        if state not in {"succeeded", "failed", "unknown"}:
            raise ValueError("Agent result must be succeeded, failed, or unknown.")
        payload = _json_payload(output or {}, "Job output")
        with self._connect(write=True) as connection:
            row = self._owned(connection, job_id, agent_id, attempt_token, activation_id)
            if row["state"] in {"succeeded", "failed", "cancelled"}:
                return _job(row)
            if row["state"] not in {"running", "cancel_requested", "unknown"}:
                raise ValueError("An unstarted operation cannot complete.")
            # A receipt from the same attempt may resolve a previously unknown outcome.
            connection.execute("UPDATE distributed_jobs SET state = ?, output_json = ?, error = ?, completed_at = ?, lease_expires_at = NULL WHERE id = ?",
                               (state, payload, " ".join(str(error).split())[:1000], time.time(), job_id))
            row = connection.execute("SELECT * FROM distributed_jobs WHERE id = ?", (job_id,)).fetchone()
        return _job(row)

    def cancel(self, job_id: str, *, requester_id: str) -> dict[str, Any]:
        with self._connect(write=True) as connection:
            self._expire(connection, job_id)
            row = connection.execute("SELECT * FROM distributed_jobs WHERE id = ? AND requester_id = ?", (job_id, requester_id)).fetchone()
            if not row:
                raise ValueError("Operation not found.")
            if row["state"] in {"queued", "claimed"}:
                connection.execute("UPDATE distributed_jobs SET state = 'cancelled', completed_at = ?, error = 'Cancelled before execution started.' WHERE id = ?", (time.time(), job_id))
            elif row["state"] == "running":
                connection.execute("UPDATE distributed_jobs SET state = 'cancel_requested', error = 'Cancellation requested. Execution may still finish; do not resubmit.' WHERE id = ?", (job_id,))
            row = connection.execute("SELECT * FROM distributed_jobs WHERE id = ?", (job_id,)).fetchone()
        return _job(row)

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._connect(write=True) as connection:
            self._expire(connection, job_id)
            row = connection.execute(
                "SELECT * FROM distributed_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _job(row) if row else None

    def get_for_requester(self, job_id: str, requester_id: str) -> dict[str, Any] | None:
        with self._connect(write=True) as connection:
            self._expire(connection, job_id)
            row = connection.execute(
                "SELECT * FROM distributed_jobs WHERE id = ? AND requester_id = ?",
                (job_id, requester_id),
            ).fetchone()
        return _job(row) if row else None

    def delete(self, job_id: str, *, requester_id: str) -> bool:
        with self._connect(write=True) as connection:
            self._expire(connection, job_id)
            cursor = connection.execute(
                "DELETE FROM distributed_jobs WHERE id = ? AND requester_id = ? AND state IN ('succeeded', 'failed', 'cancelled')",
                (job_id, requester_id),
            )
        return cursor.rowcount == 1

    def recent(self, *, requester_id: str, limit: int = 25) -> list[dict[str, Any]]:
        with self._connect(write=True) as connection:
            self._expire(connection)
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
        with self._connect(write=True) as connection:
            self._expire(connection)
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
    def _connect(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            if write:
                # Reserve before any read that governs a state transition.
                # A deferred transaction begins too late to make claims exclusive.
                connection.execute("BEGIN IMMEDIATE")
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


def _activation_id(value: object) -> str:
    clean = str(value).strip().lower()
    try:
        decoded = bytes.fromhex(clean)
    except ValueError:
        return ""
    return clean if len(decoded) == 16 and decoded.hex() == clean else ""
