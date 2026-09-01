from __future__ import annotations

import json
import time
from typing import Any

from .distributed_jobs import JOB_LEASE_SECONDS
from .distributed_jobs import DistributedJobStore as BaseDistributedJobStore


class DistributedJobStore(BaseDistributedJobStore):
    """Distributed queue bound to durable agent activation epochs."""

    def __init__(self, instance_path: str) -> None:
        super().__init__(instance_path)
        with self._connect() as connection:
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(distributed_jobs)")
            }
            if "activation_id" not in columns:
                connection.execute(
                    "ALTER TABLE distributed_jobs ADD COLUMN "
                    "activation_id TEXT NOT NULL DEFAULT ''"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS distributed_agent_activations (
                    agent_id TEXT PRIMARY KEY,
                    activation_id TEXT NOT NULL
                )
                """
            )

    def enqueue(self, **values: Any) -> dict[str, Any]:
        job = super().enqueue(**values)
        with self._connect() as connection:
            activation = connection.execute(
                "SELECT activation_id FROM distributed_agent_activations "
                "WHERE agent_id = ?",
                (job["agent_id"],),
            ).fetchone()
            if activation:
                connection.execute(
                    "UPDATE distributed_jobs SET activation_id = ? WHERE id = ?",
                    (str(activation["activation_id"]), job["id"]),
                )
        return self.get(job["id"])  # type: ignore[return-value]

    def activate_agent(self, agent_id: str, activation_id: str) -> int:
        activation_id = _activation_id(activation_id)
        if not activation_id:
            return 0
        now = time.time()
        with self._connect() as connection:
            previous = connection.execute(
                "SELECT activation_id FROM distributed_agent_activations "
                "WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if previous is None:
                connection.execute(
                    "UPDATE distributed_jobs SET activation_id = ? "
                    "WHERE agent_id = ? AND activation_id = '' "
                    "AND state IN ('queued', 'running')",
                    (activation_id, agent_id),
                )
                cancelled = 0
            elif str(previous["activation_id"]) != activation_id:
                cursor = connection.execute(
                    """
                    UPDATE distributed_jobs
                    SET state = 'cancelled', completed_at = ?,
                        lease_expires_at = NULL,
                        error = 'Cancelled after the agent left distributed mode.'
                    WHERE agent_id = ? AND activation_id != ?
                      AND state IN ('queued', 'running')
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

    def claim(
        self,
        agent_id: str,
        *,
        limit: int = 4,
        capability_id: str = "",
        exclude_capability_id: str = "",
        activation_id: str = "",
    ) -> list[dict[str, Any]]:
        activation_id = _activation_id(activation_id)
        if not activation_id:
            return super().claim(
                agent_id,
                limit=limit,
                capability_id=capability_id,
                exclude_capability_id=exclude_capability_id,
            )
        now = time.time()
        lease_expires = now + JOB_LEASE_SECONDS
        limit = max(1, min(int(limit), 16))
        with self._connect() as connection:
            capability_clause = ""
            parameters: list[Any] = [agent_id, activation_id, now]
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
                WHERE agent_id = ? AND activation_id = ? AND (
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


def _activation_id(value: object) -> str:
    clean = str(value).strip().lower()
    try:
        decoded = bytes.fromhex(clean)
    except ValueError:
        return ""
    return clean if len(decoded) == 16 and decoded.hex() == clean else ""
