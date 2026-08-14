from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterator

from cryptography.fernet import Fernet, InvalidToken

from .automation_registry import (
    AUTOMATION_REGISTRY,
    ActionResult,
    AutomationRegistry,
    ConditionResult,
)
from .automation_types.models import evaluation_result
from .schedule_tools import schedule_occurrence, schedule_should_fire
from .system_diagnostics import readonly_sqlite_connection
from .system_identity import collect_system_identity, startup_event


AUTOMATION_MAX_STAGE_DELAY_SECONDS = 86400
STAGE_CONTINUATION_POLICIES = {
    "all_completed",
    "success_or_partial",
    "all_success",
    "any_failed",
    "all_failed",
}
STAGE_CONTINUATION_LABELS = {
    "all_completed": "Always",
    "success_or_partial": "On success or partial success",
    "all_success": "On full success",
    "any_failed": "If any action errors",
    "all_failed": "If every action errors",
}


def stage_should_continue(policy: str, statuses: list[str]) -> bool:
    """Evaluate one completed stage against its configured routing policy."""
    failure_flags = [
        status not in {"success", "partial"} for status in statuses
    ]
    return (
        policy == "all_completed"
        or (
            policy == "success_or_partial"
            and not any(failure_flags)
        )
        or (
            policy == "all_success"
            and all(status == "success" for status in statuses)
        )
        or (policy == "any_failed" and any(failure_flags))
        or (
            policy == "all_failed"
            and bool(failure_flags)
            and all(failure_flags)
        )
    )


class AutomationStore:
    """SQLite persistence for automation definitions, state, checks, and runs."""

    def __init__(self, instance_path: str, secret_key: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "automations.sqlite3"
        self.artifact_root = self.instance_path / "automation_artifacts"
        self.artifact_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        encryption_key = base64.urlsafe_b64encode(
            hashlib.sha256(secret_key.encode("utf-8")).digest()
        )
        self._cipher = Fernet(encryption_key)
        with self._connect():
            pass

    def save(
        self,
        *,
        name: str,
        interval_seconds: int,
        trigger_after: int,
        recover_after: int,
        cooldown_seconds: int,
        condition: dict[str, Any] | None = None,
        actions: list[dict[str, Any]] | None = None,
        condition_definition_id: str = "",
        condition_definition_ids: list[str] | None = None,
        condition_operator: str = "all",
        action_definition_ids: list[str] | None = None,
        action_stages: list[dict[str, Any]] | None = None,
        created_by: str,
        automation_id: str = "",
    ) -> str:
        name = " ".join(name.strip().split())
        if not 2 <= len(name) <= 100:
            raise ValueError("Automation name must be 2–100 characters.")
        if not 1 <= interval_seconds <= 86400:
            raise ValueError("Check interval must be between 1 second and 24 hours.")
        if not 1 <= trigger_after <= 100:
            raise ValueError("Trigger threshold must be between 1 and 100 checks.")
        if not 1 <= recover_after <= 100:
            raise ValueError("Recovery threshold must be between 1 and 100 checks.")
        if not 0 <= cooldown_seconds <= 604800:
            raise ValueError("Cooldown must be between 0 seconds and 7 days.")
        condition_definition_ids = [
            str(value).strip()
            for value in (condition_definition_ids or [])
            if str(value).strip()
        ]
        if not condition_definition_ids and condition_definition_id:
            condition_definition_ids = [condition_definition_id]
        if not condition_definition_ids:
            if not condition:
                raise ValueError("Select an automation condition.")
            condition_definition_ids = [
                self.save_condition_definition(
                    name=f"{name} condition",
                    type_id=str(condition["type"]),
                    config=dict(condition["config"]),
                )
            ]
        condition_definition_ids = list(dict.fromkeys(condition_definition_ids))
        if len(condition_definition_ids) > 10:
            raise ValueError("An automation may use at most 10 conditions.")
        if condition_operator not in {"all", "any"}:
            raise ValueError("Select whether all or any conditions must be met.")
        condition_definitions = [
            self.get_condition_definition(definition_id)
            for definition_id in condition_definition_ids
        ]
        if any(definition is None for definition in condition_definitions):
            raise ValueError("One or more selected condition definitions were not found.")
        selected_conditions = [
            definition
            for definition in condition_definitions
            if definition is not None
        ]
        trigger_sources = [
            definition
            for definition in selected_conditions
            if definition["type"] in AUTOMATION_REGISTRY.triggers
        ]
        if trigger_sources and len(selected_conditions) != 1:
            raise ValueError(
                "Schedules, startup events, and manual mode cannot be combined with conditions."
            )
        condition_definition_id = condition_definition_ids[0]
        if not action_definition_ids and not action_stages:
            if not actions:
                raise ValueError("Select at least one automation action.")
            action_definition_ids = [
                self.save_action_definition(
                    name=f"{name} action" if len(actions) == 1 else f"{name} action {index}",
                    type_id=str(action["type"]),
                    config=dict(action["config"]),
                )
                for index, action in enumerate(actions, 1)
            ]
        action_stages = self._normalize_action_stages(
            action_stages,
            action_definition_ids or [],
        )
        action_definition_ids = [
            action_id
            for stage in action_stages
            for action_id in stage["action_definition_ids"]
        ]
        action_definitions = [
            self.get_action_definition(action_id, include_secrets=True)
            for action_id in action_definition_ids
        ]
        if not action_definitions or any(action is None for action in action_definitions):
            raise ValueError("One or more selected action definitions were not found.")
        condition = {
            "type": selected_conditions[0]["type"],
            "config": selected_conditions[0]["config"],
        }
        actions = [
            {"type": action["type"], "config": action["config"]}
            for action in action_definitions
            if action is not None
        ]

        now = time.time()
        encrypted_actions = self._encrypt(actions)
        with self._connect() as connection:
            duplicate = connection.execute(
                "SELECT id FROM automations WHERE lower(name) = lower(?) AND id != ?",
                (name, automation_id),
            ).fetchone()
            if duplicate:
                raise ValueError("An automation with that name already exists.")
            if automation_id:
                existing = connection.execute(
                    "SELECT id FROM automations WHERE id = ?", (automation_id,)
                ).fetchone()
                if not existing:
                    raise ValueError("Automation not found.")
                connection.execute(
                    """
                    UPDATE automations
                    SET name = ?, interval_seconds = ?, trigger_after = ?, recover_after = ?,
                        cooldown_seconds = ?, condition_type = ?, condition_config = ?,
                        actions_encrypted = ?, enabled = 0, state = 'disabled',
                        consecutive_met = 0, consecutive_clear = 0, next_check_at = NULL,
                        pending_schedule_at = NULL,
                        condition_definition_id = ?, condition_definition_ids = ?,
                        condition_operator = ?, action_definition_ids = ?,
                        action_stages = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        name,
                        interval_seconds,
                        trigger_after,
                        recover_after,
                        cooldown_seconds,
                        condition["type"],
                        json.dumps(condition["config"], separators=(",", ":")),
                        encrypted_actions,
                        condition_definition_id,
                        json.dumps(condition_definition_ids),
                        condition_operator,
                        json.dumps(action_definition_ids),
                        json.dumps(action_stages, separators=(",", ":")),
                        now,
                        automation_id,
                    ),
                )
                connection.execute(
                    "DELETE FROM automation_event_state WHERE automation_id = ?",
                    (automation_id,),
                )
                return automation_id

            automation_id = secrets.token_hex(12)
            connection.execute(
                """
                INSERT INTO automations (
                    id, name, enabled, interval_seconds, trigger_after, recover_after,
                    cooldown_seconds, condition_type, condition_config, actions_encrypted,
                    condition_definition_id, condition_definition_ids, condition_operator,
                    action_definition_ids, action_stages,
                    state, consecutive_met, consecutive_clear, next_check_at,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'disabled', 0, 0, NULL, ?, ?, ?)
                """,
                (
                    automation_id,
                    name,
                    interval_seconds,
                    trigger_after,
                    recover_after,
                    cooldown_seconds,
                    condition["type"],
                    json.dumps(condition["config"], separators=(",", ":")),
                    encrypted_actions,
                    condition_definition_id,
                    json.dumps(condition_definition_ids),
                    condition_operator,
                    json.dumps(action_definition_ids),
                    json.dumps(action_stages, separators=(",", ":")),
                    created_by,
                    now,
                    now,
                ),
            )
        return automation_id

    @staticmethod
    def _normalize_action_stages(
        stages: list[dict[str, Any]] | None,
        legacy_action_ids: list[str],
    ) -> list[dict[str, Any]]:
        if not stages:
            stages = [{
                "id": "stage-1",
                "name": "Stage 1",
                "continue_policy": "all_completed",
                "delay_seconds": 0,
                "action_definition_ids": legacy_action_ids,
            }]
        normalized = []
        seen_stage_ids: set[str] = set()
        for index, raw in enumerate(stages, 1):
            stage_id = str(raw.get("id", "")).strip() or f"stage-{index}"
            if stage_id in seen_stage_ids or len(stage_id) > 80:
                raise ValueError("Every automation stage must have a unique stable ID.")
            seen_stage_ids.add(stage_id)
            name = " ".join(str(raw.get("name", "")).strip().split()) or f"Stage {index}"
            if len(name) > 100:
                raise ValueError("Stage names must be 100 characters or fewer.")
            policy = str(raw.get("continue_policy", "all_completed"))
            if policy not in STAGE_CONTINUATION_POLICIES:
                raise ValueError("Select a valid stage continuation policy.")
            try:
                delay_seconds = int(raw.get("delay_seconds", 0))
            except (TypeError, ValueError) as exc:
                raise ValueError("Stage delays must be whole seconds.") from exc
            if not 0 <= delay_seconds <= AUTOMATION_MAX_STAGE_DELAY_SECONDS:
                raise ValueError(
                    "Stage delays must be between 0 seconds and 24 hours."
                )
            if index == 1:
                delay_seconds = 0
            action_ids = [str(value).strip() for value in raw.get("action_definition_ids", []) if str(value).strip()]
            if not action_ids:
                raise ValueError(f"{name} must contain at least one action.")
            normalized.append({
                "id": stage_id,
                "name": name,
                "continue_policy": policy,
                "delay_seconds": delay_seconds,
                "action_definition_ids": action_ids,
            })
        if not normalized:
            raise ValueError("Select at least one automation action.")
        return normalized

    def save_condition_definition(
        self,
        *,
        name: str,
        type_id: str,
        config: dict[str, Any],
        definition_id: str = "",
    ) -> str:
        name = self._validate_definition_name(name, "Condition")
        now = time.time()
        with self._connect() as connection:
            duplicate = connection.execute(
                "SELECT id FROM automation_conditions WHERE lower(name) = lower(?) AND id != ?",
                (name, definition_id),
            ).fetchone()
            if duplicate:
                raise ValueError("A condition with that name already exists.")
            if definition_id:
                if not connection.execute(
                    "SELECT id FROM automation_conditions WHERE id = ?", (definition_id,)
                ).fetchone():
                    raise ValueError("Condition definition not found.")
                connection.execute(
                    "UPDATE automation_conditions SET name = ?, type = ?, config_json = ?, updated_at = ? WHERE id = ?",
                    (name, type_id, json.dumps(config, separators=(",", ":")), now, definition_id),
                )
                self._pause_automations_for_condition(connection, definition_id, now)
                return definition_id
            definition_id = secrets.token_hex(12)
            connection.execute(
                "INSERT INTO automation_conditions (id, name, type, config_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (definition_id, name, type_id, json.dumps(config, separators=(",", ":")), now, now),
            )
        return definition_id

    def save_action_definition(
        self,
        *,
        name: str,
        type_id: str,
        config: dict[str, Any],
        definition_id: str = "",
    ) -> str:
        name = self._validate_definition_name(name, "Action")
        now = time.time()
        with self._connect() as connection:
            duplicate = connection.execute(
                "SELECT id FROM automation_actions WHERE lower(name) = lower(?) AND id != ?",
                (name, definition_id),
            ).fetchone()
            if duplicate:
                raise ValueError("An action with that name already exists.")
            if definition_id:
                if not connection.execute(
                    "SELECT id FROM automation_actions WHERE id = ?", (definition_id,)
                ).fetchone():
                    raise ValueError("Action definition not found.")
                connection.execute(
                    "UPDATE automation_actions SET name = ?, type = ?, config_encrypted = ?, updated_at = ? WHERE id = ?",
                    (name, type_id, self._encrypt(config), now, definition_id),
                )
                self._pause_automations_for_action(connection, definition_id, now)
                return definition_id
            definition_id = secrets.token_hex(12)
            connection.execute(
                "INSERT INTO automation_actions (id, name, type, config_encrypted, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (definition_id, name, type_id, self._encrypt(config), now, now),
            )
        return definition_id

    def condition_definitions(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.source_definitions()
            if item["type"] not in AUTOMATION_REGISTRY.triggers
        ]

    def trigger_definitions(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.source_definitions()
            if item["type"] in AUTOMATION_REGISTRY.triggers
        ]

    def schedule_definitions(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.source_definitions()
            if item["type"] == "schedule.calendar"
        ]

    def ensure_manual_trigger_definition(self) -> str:
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id FROM automation_conditions
                WHERE type = 'manual.trigger'
                ORDER BY created_at, id
                LIMIT 1
                """
            ).fetchone()
            if row:
                return str(row["id"])
            definition_id = secrets.token_hex(12)
            name = self._unique_definition_name(
                connection,
                "automation_conditions",
                "Manual run",
            )
            connection.execute(
                """
                INSERT INTO automation_conditions
                    (id, name, type, config_json, created_at, updated_at)
                VALUES (?, ?, 'manual.trigger', '{}', ?, ?)
                """,
                (definition_id, name, now, now),
            )
        return definition_id

    def ensure_startup_trigger_definition(
        self,
        config: dict[str, Any],
    ) -> str:
        normalized = AUTOMATION_REGISTRY.validate_trigger("system.startup", config)
        config_json = json.dumps(normalized, separators=(",", ":"), sort_keys=True)
        now = time.time()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, config_json FROM automation_conditions
                WHERE type = 'system.startup'
                ORDER BY created_at, id
                """
            ).fetchall()
            for row in rows:
                existing = json.dumps(
                    AUTOMATION_REGISTRY.validate_trigger(
                        "system.startup", json.loads(row["config_json"])
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                )
                if existing == config_json:
                    return str(row["id"])
            definition_id = secrets.token_hex(12)
            label = (
                "Host startup"
                if normalized["mode"] == "host_boot"
                else "Toolkit startup"
            )
            name = self._unique_definition_name(
                connection,
                "automation_conditions",
                label,
            )
            connection.execute(
                """
                INSERT INTO automation_conditions
                    (id, name, type, config_json, created_at, updated_at)
                VALUES (?, ?, 'system.startup', ?, ?, ?)
                """,
                (definition_id, name, config_json, now, now),
            )
        return definition_id

    def source_definitions(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM automation_conditions ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [self._condition_definition_from_row(row) for row in rows]

    def action_definitions(self, *, include_secrets: bool = False) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM automation_actions ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [self._action_definition_from_row(row, include_secrets) for row in rows]

    def get_condition_definition(self, definition_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM automation_conditions WHERE id = ?", (definition_id,)
            ).fetchone()
        return self._condition_definition_from_row(row) if row else None

    def get_action_definition(
        self, definition_id: str, *, include_secrets: bool = False
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM automation_actions WHERE id = ?", (definition_id,)
            ).fetchone()
        return self._action_definition_from_row(row, include_secrets) if row else None

    def delete_condition_definition(self, definition_id: str) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT condition_definition_id, condition_definition_ids FROM automations"
            ).fetchall()
            if any(
                definition_id
                in (
                    json.loads(row["condition_definition_ids"] or "[]")
                    or [str(row["condition_definition_id"] or "")]
                )
                for row in rows
            ):
                raise ValueError("That condition is still used by an automation.")
            cursor = connection.execute(
                "DELETE FROM automation_conditions WHERE id = ?", (definition_id,)
            )
            if not cursor.rowcount:
                raise ValueError("Condition definition not found.")

    def delete_action_definition(self, definition_id: str) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT action_definition_ids FROM automations"
            ).fetchall()
            if any(definition_id in json.loads(row[0] or "[]") for row in rows):
                raise ValueError("That action is still used by an automation.")
            cursor = connection.execute(
                "DELETE FROM automation_actions WHERE id = ?", (definition_id,)
            )
            if not cursor.rowcount:
                raise ValueError("Action definition not found.")

    def all(self, *, include_secrets: bool = False) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM automations ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [self._automation_from_row(row, include_secrets) for row in rows]

    def workspace_snapshot(
        self,
        *,
        recent_limit: int = 10,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Read the Automation workspace through one non-mutating connection."""
        now = time.time() if now is None else now
        recent_limit = max(1, min(100, int(recent_limit)))
        with readonly_sqlite_connection(
            self.path,
            timeout_seconds=1.0,
        ) as connection:
            connection.execute("BEGIN")
            source_definitions = [
                self._condition_definition_from_row(row)
                for row in connection.execute(
                    "SELECT * FROM automation_conditions ORDER BY name COLLATE NOCASE"
                )
            ]
            action_definitions = [
                self._action_definition_from_row(row, False)
                for row in connection.execute(
                    "SELECT * FROM automation_actions ORDER BY name COLLATE NOCASE"
                )
            ]
            condition_map = {
                str(definition["id"]): definition
                for definition in source_definitions
            }
            action_map = {
                str(definition["id"]): definition
                for definition in action_definitions
            }
            automations = [
                self._automation_from_row(
                    row,
                    False,
                    condition_map=condition_map,
                    action_map=action_map,
                )
                for row in connection.execute(
                    "SELECT * FROM automations ORDER BY name COLLATE NOCASE"
                )
            ]
            recent_runs: dict[str, list[dict[str, Any]]] = {}
            recent_checks: dict[str, list[dict[str, Any]]] = {}
            for automation in automations:
                automation_id = str(automation["id"])
                recent_runs[automation_id] = [
                    {**dict(row), "results": json.loads(row["results_json"])}
                    for row in connection.execute(
                        """
                        SELECT * FROM automation_runs WHERE automation_id = ?
                        ORDER BY started_at DESC LIMIT ?
                        """,
                        (automation_id, recent_limit),
                    )
                ]
                recent_checks[automation_id] = [
                    {**dict(row), "evidence": json.loads(row["evidence_json"])}
                    for row in connection.execute(
                        """
                        SELECT * FROM automation_checks WHERE automation_id = ?
                        ORDER BY checked_at DESC LIMIT ?
                        """,
                        (automation_id, recent_limit),
                    )
                ]
            job_stats = self._job_stats_from_connection(connection, now)
        return {
            "automations": automations,
            "source_definitions": source_definitions,
            "action_definitions": action_definitions,
            "recent_runs": recent_runs,
            "recent_checks": recent_checks,
            "job_stats": job_stats,
        }

    def get(
        self, automation_id: str, *, include_secrets: bool = False
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM automations WHERE id = ?", (automation_id,)
            ).fetchone()
        return self._automation_from_row(row, include_secrets) if row else None

    def delete(self, automation_id: str) -> None:
        with self._connect() as connection:
            if connection.execute(
                """
                SELECT 1 FROM automation_jobs
                WHERE automation_id = ? AND status IN ('queued', 'waiting', 'running')
                LIMIT 1
                """,
                (automation_id,),
            ).fetchone():
                raise ValueError(
                    "That automation still has queued, waiting, or running action work."
                )
            cursor = connection.execute(
                "DELETE FROM automations WHERE id = ?", (automation_id,)
            )
            if not cursor.rowcount:
                raise ValueError("Automation not found.")

    def clear(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM automations")
            connection.execute("DELETE FROM automation_conditions")
            connection.execute("DELETE FROM automation_actions")

    def set_enabled(self, automation_id: str, enabled: bool) -> None:
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT automations.*, automation_conditions.type AS definition_type,
                    automation_conditions.config_json AS definition_config
                FROM automations LEFT JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE automations.id = ?
                """,
                (automation_id,),
            ).fetchone()
            if not row:
                raise ValueError("Automation not found.")
            condition_type = str(row["definition_type"] or row["condition_type"])
            next_check = now if enabled else None
            state = "healthy" if enabled else "disabled"
            effective_enabled = enabled
            if enabled and condition_type == "schedule.calendar":
                config = json.loads(row["definition_config"] or row["condition_config"])
                occurrence = schedule_occurrence(config, now - 0.001)
                next_check = occurrence["timestamp"] if occurrence else None
                state = "scheduled" if occurrence else "completed"
                effective_enabled = occurrence is not None
            elif enabled and condition_type == "system.startup":
                config = AUTOMATION_REGISTRY.validate_trigger(
                    "system.startup",
                    json.loads(row["definition_config"] or row["condition_config"]),
                )
                identity = collect_system_identity(self.instance_path)
                event = startup_event(identity, str(config["mode"]))
                connection.execute(
                    """
                    INSERT INTO automation_event_state (
                        automation_id, source_type, event_key,
                        event_occurred_at, updated_at
                    ) VALUES (?, 'system.startup', ?, ?, ?)
                    ON CONFLICT(automation_id) DO UPDATE SET
                        source_type = excluded.source_type,
                        event_key = excluded.event_key,
                        event_occurred_at = excluded.event_occurred_at,
                        updated_at = excluded.updated_at
                    """,
                    (
                        automation_id,
                        str(event["key"]),
                        float(event["occurred_at"]),
                        now,
                    ),
                )
                next_check = None
                state = "armed"
            cursor = connection.execute(
                """
                UPDATE automations
                SET enabled = ?, state = ?, consecutive_met = 0, consecutive_clear = 0,
                    next_check_at = ?, pending_schedule_at = NULL, updated_at = ?
                WHERE id = ?
                """,
                (
                    int(effective_enabled),
                    state,
                    next_check,
                    now,
                    automation_id,
                ),
            )
            if not cursor.rowcount:
                raise ValueError("Automation not found.")

    def claim_due(
        self,
        limit: int = 10,
        *,
        exclude_automation_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        now = time.time()
        excluded_ids = sorted(set(exclude_automation_ids or set()))
        exclusion_sql = ""
        if excluded_ids:
            placeholders = ", ".join("?" for _item in excluded_ids)
            exclusion_sql = f"AND automations.id NOT IN ({placeholders})"
        claimed: list[sqlite3.Row] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                f"""
                SELECT automations.*,
                    COALESCE(automation_conditions.type, automations.condition_type)
                        AS effective_condition_type
                FROM automations
                LEFT JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE enabled = 1
                    AND COALESCE(automation_conditions.type, automations.condition_type)
                        NOT IN ('manual.trigger', 'system.startup')
                    {exclusion_sql}
                    AND (
                        (COALESCE(automation_conditions.type, automations.condition_type) = 'schedule.calendar'
                            AND next_check_at IS NOT NULL AND next_check_at <= ?)
                        OR
                        (COALESCE(automation_conditions.type, automations.condition_type) != 'schedule.calendar'
                            AND (next_check_at IS NULL OR next_check_at <= ?))
                    )
                ORDER BY COALESCE(next_check_at, 0), automations.name COLLATE NOCASE
                LIMIT ?
                """,
                (*excluded_ids, now, now, limit),
            ).fetchall()
            for row in rows:
                if row["effective_condition_type"] == "schedule.calendar":
                    connection.execute(
                        """
                        UPDATE automations
                        SET pending_schedule_at = COALESCE(pending_schedule_at, next_check_at),
                            next_check_at = ?
                        WHERE id = ?
                        """,
                        (now + 300, row["id"]),
                    )
                else:
                    next_check_at = self._next_interval_check_at(
                        row,
                        claimed_at=now,
                    )
                    connection.execute(
                        "UPDATE automations SET next_check_at = ? WHERE id = ?",
                        (next_check_at, row["id"]),
                    )
                claimed.append(row)
        return [self._automation_from_row(row, True) for row in claimed]

    def record_schedule_occurrence(
        self, automation_id: str, *, now: float | None = None
    ) -> tuple[dict[str, Any], ConditionResult, bool]:
        current_time = time.time() if now is None else now
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT automations.*, automation_conditions.config_json AS definition_config
                FROM automations JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE automations.id = ? AND automation_conditions.type = 'schedule.calendar'
                """,
                (automation_id,),
            ).fetchone()
            if not row or (row["pending_schedule_at"] is None and row["next_check_at"] is None):
                raise ValueError("Scheduled automation is not awaiting an occurrence.")
            config = json.loads(row["definition_config"])
            scheduled_at = float(row["pending_schedule_at"] or row["next_check_at"])
            occurrence = schedule_occurrence(config, scheduled_at - 0.001)
            should_fire = schedule_should_fire(config, scheduled_at, current_time)
            if occurrence is None:
                raise ValueError("Scheduled occurrence could not be resolved.")
            lateness_seconds = max(0, int(current_time - scheduled_at))
            matched = "; ".join(occurrence["rules"])
            if should_fire:
                summary = f"Calendar occurrence: {matched}."
                status = "scheduled"
            else:
                summary = f"Skipped missed calendar occurrence ({lateness_seconds}s late): {matched}."
                status = "skipped"
            result = evaluation_result(
                ConditionResult(
                    met=should_fire,
                    status=status,
                    summary=summary,
                    evidence={
                        "trigger": "schedule",
                        "occurrence": occurrence,
                        "lateness_seconds": lateness_seconds,
                    },
                ),
                kind="schedule",
                type_id="schedule.calendar",
                observed_at=current_time,
            )
            if should_fire:
                self._enqueue_execution_job(
                    connection,
                    row,
                    result,
                    scheduled_at=scheduled_at,
                    queued_at=current_time,
                )
            next_cursor = current_time if current_time - scheduled_at > 60 else scheduled_at
            following = schedule_occurrence(config, next_cursor + 0.001)
            next_check = following["timestamp"] if following else None
            state = "scheduled" if following else "completed"
            connection.execute(
                """
                UPDATE automations
                SET enabled = ?, state = ?, next_check_at = ?, pending_schedule_at = NULL,
                    last_check_at = ?,
                    last_summary = ?, last_error = NULL,
                    last_triggered_at = CASE WHEN ? THEN ? ELSE last_triggered_at END,
                    consecutive_met = 0, consecutive_clear = 0, updated_at = ?
                WHERE id = ?
                """,
                (
                    int(following is not None),
                    state,
                    next_check,
                    current_time,
                    summary,
                    int(should_fire),
                    current_time,
                    current_time,
                    automation_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO automation_checks
                    (automation_id, checked_at, met, status, summary, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    automation_id,
                    current_time,
                    int(should_fire),
                    status,
                    summary,
                    json.dumps(result.evidence, separators=(",", ":")),
                ),
            )
        updated = self.get(automation_id, include_secrets=True)
        if updated is None:
            raise ValueError("Automation not found.")
        return updated, result, should_fire

    def enqueue_startup_events(
        self,
        identity: dict[str, Any],
        *,
        now: float | None = None,
    ) -> list[str]:
        """Atomically enqueue each newly observed startup event exactly once."""
        current_time = time.time() if now is None else float(now)
        queued: list[str] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT automations.*,
                    automation_conditions.config_json AS definition_config
                FROM automations JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE automations.enabled = 1
                    AND automation_conditions.type = 'system.startup'
                ORDER BY automations.name COLLATE NOCASE
                """
            ).fetchall()
            toolkit = dict(identity.get("toolkit", {}))
            network_ready = bool(
                toolkit.get("ipv4_addresses") or toolkit.get("ipv6_addresses")
            )
            for row in rows:
                config = AUTOMATION_REGISTRY.validate_trigger(
                    "system.startup", json.loads(row["definition_config"])
                )
                event = startup_event(identity, str(config["mode"]))
                event_key = str(event["key"])
                if not event_key:
                    continue
                previous = connection.execute(
                    """
                    SELECT source_type, event_key
                    FROM automation_event_state
                    WHERE automation_id = ?
                    """,
                    (row["id"],),
                ).fetchone()
                if previous is None or previous["source_type"] != "system.startup":
                    connection.execute(
                        """
                        INSERT INTO automation_event_state (
                            automation_id, source_type, event_key,
                            event_occurred_at, updated_at
                        ) VALUES (?, 'system.startup', ?, ?, ?)
                        ON CONFLICT(automation_id) DO UPDATE SET
                            source_type = excluded.source_type,
                            event_key = excluded.event_key,
                            event_occurred_at = excluded.event_occurred_at,
                            updated_at = excluded.updated_at
                        """,
                        (
                            row["id"],
                            event_key,
                            float(event["occurred_at"]),
                            current_time,
                        ),
                    )
                    continue
                if str(previous["event_key"]) == event_key:
                    continue
                event_time = float(event["occurred_at"] or current_time)
                wait_seconds = int(config["network_wait_seconds"])
                if not network_ready and current_time < event_time + wait_seconds:
                    continue
                waited_seconds = max(0, int(current_time - event_time))
                primary_address = str(
                    toolkit.get("primary_ipv4")
                    or next(iter(toolkit.get("ipv6_addresses") or []), "")
                )
                summary = str(event["reason"])
                if primary_address:
                    summary += f"; toolkit is available at {primary_address}."
                else:
                    summary += (
                        "; no usable network address was available before the wait expired."
                    )
                result = evaluation_result(
                    ConditionResult(
                        met=True,
                        status="started",
                        summary=summary,
                        evidence={
                            "trigger": "startup",
                            "startup": {
                                "mode": config["mode"],
                                "reason": event["reason"],
                                "occurred_at": event_time,
                                "network_ready": network_ready,
                                "waited_seconds": waited_seconds,
                            },
                            "toolkit": toolkit,
                        },
                    ),
                    kind="startup",
                    type_id="system.startup",
                    observed_at=current_time,
                )
                job_id = self._enqueue_execution_job(
                    connection,
                    row,
                    result,
                    scheduled_at=event_time,
                    queued_at=current_time,
                )
                queued.append(job_id)
                connection.execute(
                    """
                    UPDATE automation_event_state
                    SET event_key = ?, event_occurred_at = ?, updated_at = ?
                    WHERE automation_id = ?
                    """,
                    (event_key, event_time, current_time, row["id"]),
                )
                connection.execute(
                    """
                    UPDATE automations
                    SET state = 'armed', last_check_at = ?, last_triggered_at = ?,
                        last_summary = ?, last_error = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        current_time,
                        current_time,
                        summary,
                        current_time,
                        row["id"],
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO automation_checks
                        (automation_id, checked_at, met, status, summary, evidence_json)
                    VALUES (?, ?, 1, 'started', ?, ?)
                    """,
                    (
                        row["id"],
                        current_time,
                        summary,
                        json.dumps(result.evidence, separators=(",", ":")),
                    ),
                )
        return queued

    def has_pending_startup_events(self, startup: dict[str, Any]) -> bool:
        """Check event generations without performing full interface discovery."""
        identity = {"startup": startup}
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT automations.id, automation_conditions.config_json,
                    automation_event_state.source_type,
                    automation_event_state.event_key
                FROM automations JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                LEFT JOIN automation_event_state
                    ON automation_event_state.automation_id = automations.id
                WHERE automations.enabled = 1
                    AND automation_conditions.type = 'system.startup'
                """
            ).fetchall()
        for row in rows:
            config = AUTOMATION_REGISTRY.validate_trigger(
                "system.startup", json.loads(row["config_json"])
            )
            event_key = str(startup_event(identity, str(config["mode"]))["key"])
            if event_key and (
                row["source_type"] != "system.startup"
                or str(row["event_key"] or "") != event_key
            ):
                return True
        return False

    def record_condition(
        self,
        automation_id: str,
        result: ConditionResult,
        *,
        scheduled_at: float | None = None,
        observed_at: float | None = None,
    ) -> tuple[dict[str, Any], bool]:
        now = time.time()
        checked_at = now if observed_at is None else float(observed_at)
        should_fire = False
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT automations.*,
                    COALESCE(automation_conditions.type, automations.condition_type)
                        AS effective_condition_type
                FROM automations
                LEFT JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE automations.id = ?
                """,
                (automation_id,),
            ).fetchone()
            if not row:
                raise ValueError("Automation not found.")
            if "evaluation" not in result.evidence:
                result = evaluation_result(
                    result,
                    kind="condition",
                    type_id=str(row["effective_condition_type"]),
                    observed_at=checked_at,
                )
            elif observed_at is not None:
                result = ConditionResult(
                    met=result.met,
                    status=result.status,
                    summary=result.summary,
                    evidence={
                        **result.evidence,
                        "evaluation": {
                            **result.evidence["evaluation"],
                            "observed_at": checked_at,
                        },
                    },
                )
            state = str(row["state"])
            met_count = int(row["consecutive_met"])
            clear_count = int(row["consecutive_clear"])
            if result.met:
                met_count += 1
                clear_count = 0
                if state not in {"triggered", "recovering"}:
                    state = "suspect"
                    last_triggered = float(row["last_triggered_at"] or 0)
                    cooldown_ready = now - last_triggered >= int(row["cooldown_seconds"])
                    if met_count >= int(row["trigger_after"]) and cooldown_ready:
                        state = "triggered"
                        should_fire = True
            else:
                met_count = 0
                if state in {"triggered", "recovering"}:
                    clear_count += 1
                    state = "recovering"
                    if clear_count >= int(row["recover_after"]):
                        state = "healthy"
                        clear_count = 0
                else:
                    state = "healthy"
                    clear_count = 0
            if should_fire:
                self._enqueue_execution_job(
                    connection,
                    row,
                    result,
                    scheduled_at=scheduled_at if scheduled_at is not None else now,
                    queued_at=now,
                )
            connection.execute(
                """
                UPDATE automations
                SET state = ?, consecutive_met = ?, consecutive_clear = ?,
                    last_check_at = ?, last_summary = ?, last_error = NULL,
                    last_triggered_at = CASE WHEN ? THEN ? ELSE last_triggered_at END,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    state,
                    met_count,
                    clear_count,
                    checked_at,
                    result.summary,
                    int(should_fire),
                    now,
                    now,
                    automation_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO automation_checks
                    (automation_id, checked_at, met, status, summary, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    automation_id,
                    checked_at,
                    int(result.met),
                    result.status,
                    result.summary,
                    json.dumps(result.evidence, separators=(",", ":")),
                ),
            )
        updated = self.get(automation_id, include_secrets=True)
        if updated is None:
            raise ValueError("Automation not found.")
        return updated, should_fire

    @staticmethod
    def _next_interval_check_at(
        row: sqlite3.Row,
        *,
        claimed_at: float,
    ) -> float:
        """Keep a stable cadence without replaying a long backlog of missed checks."""
        interval = max(1, int(row["interval_seconds"]))
        scheduled_at = (
            float(row["next_check_at"])
            if row["next_check_at"] is not None
            else claimed_at
        )
        if claimed_at - scheduled_at >= interval:
            scheduled_at = claimed_at
        return scheduled_at + interval

    def enqueue_manual_job(
        self,
        automation_id: str,
        trigger: ConditionResult,
    ) -> str:
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM automations WHERE id = ?",
                (automation_id,),
            ).fetchone()
            if not row:
                raise ValueError("Automation not found.")
            condition_type = connection.execute(
                """
                SELECT COALESCE(automation_conditions.type, automations.condition_type)
                FROM automations
                LEFT JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE automations.id = ?
                """,
                (automation_id,),
            ).fetchone()[0]
            if condition_type != "manual.trigger":
                raise ValueError("Only manual-trigger automations can be queued manually.")
            if "evaluation" not in trigger.evidence:
                trigger = evaluation_result(
                    trigger,
                    kind="manual",
                    type_id=str(condition_type),
                    observed_at=now,
                )
            return self._enqueue_execution_job(
                connection,
                row,
                trigger,
                scheduled_at=now,
                queued_at=now,
            )

    def enqueue_startup_test_job(
        self,
        automation_id: str,
        identity: dict[str, Any],
        *,
        started_by: str,
    ) -> str:
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT automations.*,
                    automation_conditions.config_json AS definition_config,
                    automation_conditions.type AS definition_type
                FROM automations JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE automations.id = ?
                """,
                (automation_id,),
            ).fetchone()
            if not row:
                raise ValueError("Automation not found.")
            if row["definition_type"] != "system.startup":
                raise ValueError("Only startup automations can queue a startup test.")
            config = AUTOMATION_REGISTRY.validate_trigger(
                "system.startup", json.loads(row["definition_config"])
            )
            toolkit = dict(identity.get("toolkit", {}))
            result = evaluation_result(
                ConditionResult(
                    met=True,
                    status="test",
                    summary="Startup notification test requested by a toolkit user.",
                    evidence={
                        "trigger": "startup",
                        "startup": {
                            "mode": config["mode"],
                            "reason": "Startup notification test",
                            "occurred_at": now,
                            "network_ready": bool(
                                toolkit.get("ipv4_addresses")
                                or toolkit.get("ipv6_addresses")
                            ),
                            "waited_seconds": 0,
                            "test": True,
                            "started_by": started_by,
                        },
                        "toolkit": toolkit,
                    },
                ),
                kind="startup",
                type_id="system.startup",
                observed_at=now,
            )
            return self._enqueue_execution_job(
                connection,
                row,
                result,
                scheduled_at=now,
                queued_at=now,
            )

    def claim_jobs(
        self,
        *,
        limit: int = 10,
        lease_seconds: int = 300,
        exclude_automation_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        now = time.time()
        lease_seconds = max(30, min(int(lease_seconds), 3600))
        claimed_ids: list[str] = []
        excluded = sorted(exclude_automation_ids or set())
        exclusion_sql = (
            f" AND automation_id NOT IN ({','.join('?' for _ in excluded)})"
            if excluded
            else ""
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                f"""
                SELECT id FROM automation_jobs
                WHERE (
                    (
                        status IN ('queued', 'waiting')
                        AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                    ) OR (
                        status = 'running'
                        AND lease_until IS NOT NULL
                        AND lease_until <= ?
                    )
                )
                {exclusion_sql}
                ORDER BY queued_at, id
                LIMIT ?
                """,
                (now, now, *excluded, max(1, int(limit))),
            ).fetchall()
            for row in rows:
                job_id = str(row["id"])
                connection.execute(
                    """
                    UPDATE automation_jobs
                    SET status = 'running',
                        claimed_at = ?,
                        started_at = COALESCE(started_at, ?),
                        lease_until = ?,
                        next_attempt_at = NULL,
                        attempt_count = attempt_count + 1
                    WHERE id = ?
                    """,
                    (now, now, now + lease_seconds, job_id),
                )
                claimed_ids.append(job_id)
            claimed = [
                connection.execute(
                    "SELECT * FROM automation_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                for job_id in claimed_ids
            ]
        return [self._job_from_row(row) for row in claimed if row is not None]

    def claim_job(
        self,
        job_id: str,
        *,
        lease_seconds: int = 300,
    ) -> dict[str, Any] | None:
        now = time.time()
        lease_seconds = max(30, min(int(lease_seconds), 3600))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE automation_jobs
                SET status = 'running',
                    claimed_at = ?,
                    started_at = COALESCE(started_at, ?),
                    lease_until = ?,
                    next_attempt_at = NULL,
                    attempt_count = attempt_count + 1
                WHERE id = ? AND status IN ('queued', 'waiting')
                    AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                """,
                (now, now, now + lease_seconds, job_id, now),
            )
            if not cursor.rowcount:
                return None
            row = connection.execute(
                "SELECT * FROM automation_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
        return self._job_from_row(row) if row is not None else None

    def renew_job_lease(self, job_id: str, *, lease_seconds: int = 300) -> bool:
        now = time.time()
        lease_seconds = max(30, min(int(lease_seconds), 3600))
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE automation_jobs
                SET lease_until = ?
                WHERE id = ? AND status = 'running'
                """,
                (now + lease_seconds, job_id),
            )
        return bool(cursor.rowcount)

    def save_job_progress(self, job_id: str, progress: dict[str, Any]) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE automation_jobs
                SET progress_encrypted = ?
                WHERE id = ? AND status = 'running'
                """,
                (self._encrypt(progress), job_id),
            )
        if not cursor.rowcount:
            raise ValueError("Automation job is not running.")

    def defer_job_for_stage(
        self,
        job_id: str,
        delay_seconds: int,
        progress: dict[str, Any],
    ) -> float:
        delay_seconds = int(delay_seconds)
        if not 1 <= delay_seconds <= AUTOMATION_MAX_STAGE_DELAY_SECONDS:
            raise ValueError("The stage delay is outside the supported range.")
        resume_at = time.time() + delay_seconds
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE automation_jobs
                SET status = 'waiting', next_attempt_at = ?, lease_until = NULL,
                    claimed_at = NULL, attempt_count = 0,
                    progress_encrypted = ?, last_error = NULL
                WHERE id = ? AND status = 'running'
                """,
                (resume_at, self._encrypt(progress), job_id),
            )
        if not cursor.rowcount:
            raise ValueError("Automation job is not running.")
        return resume_at

    def complete_job(self, job_id: str, run_id: str) -> None:
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE automation_jobs
                SET status = 'completed', finished_at = ?, lease_until = NULL,
                    run_id = ?, last_error = NULL, progress_encrypted = NULL
                WHERE id = ? AND status = 'running'
                """,
                (now, run_id, job_id),
            )
            if not cursor.rowcount:
                raise ValueError("Automation job is not running.")

    def link_job_run(self, job_id: str, run_id: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE automation_jobs
                SET run_id = ?
                WHERE id = ? AND status = 'running'
                """,
                (run_id, job_id),
            )
        if not cursor.rowcount:
            raise ValueError("Automation job is not running.")

    def fail_job(
        self,
        job_id: str,
        message: str,
        *,
        max_attempts: int = 3,
    ) -> str:
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT attempt_count FROM automation_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            if not row:
                raise ValueError("Automation job not found.")
            attempts = int(row["attempt_count"])
            terminal = attempts >= max(1, int(max_attempts))
            status = "failed" if terminal else "queued"
            retry_at = None if terminal else now + min(300, 5 * (2 ** max(0, attempts - 1)))
            connection.execute(
                """
                UPDATE automation_jobs
                SET status = ?, finished_at = ?, lease_until = NULL,
                    next_attempt_at = ?, last_error = ?
                WHERE id = ?
                """,
                (
                    status,
                    now if terminal else None,
                    retry_at,
                    str(message)[:2000],
                    job_id,
                ),
            )
        return status

    def job_stats(self) -> dict[str, Any]:
        now = time.time()
        with self._connect() as connection:
            return self._job_stats_from_connection(connection, now)

    @staticmethod
    def _job_stats_from_connection(
        connection: sqlite3.Connection,
        now: float,
    ) -> dict[str, Any]:
        counts = {
            str(row["status"]): int(row["count"])
            for row in connection.execute(
                "SELECT status, COUNT(*) AS count FROM automation_jobs GROUP BY status"
            )
        }
        oldest = connection.execute(
            """
            SELECT MIN(queued_at) FROM automation_jobs
            WHERE status IN ('queued', 'waiting', 'running')
            """
        ).fetchone()[0]
        return {
            "queued_jobs": counts.get("queued", 0),
            "waiting_jobs": counts.get("waiting", 0),
            "running_jobs": counts.get("running", 0),
            "failed_jobs": counts.get("failed", 0),
            "completed_jobs": counts.get("completed", 0),
            "oldest_pending_age": max(0, int(now - float(oldest))) if oldest else None,
        }

    def retry_failed_jobs(self) -> int:
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE automation_jobs
                SET status = 'queued', next_attempt_at = ?, attempt_count = 0,
                    claimed_at = NULL, started_at = NULL, finished_at = NULL,
                    lease_until = NULL
                WHERE status = 'failed'
                """,
                (now,),
            )
        return int(cursor.rowcount)

    def record_error(self, automation_id: str, message: str) -> None:
        now = time.time()
        with self._connect() as connection:
            condition_type_row = connection.execute(
                """
                SELECT COALESCE(automation_conditions.type, automations.condition_type) AS type,
                    automations.condition_definition_ids
                FROM automations LEFT JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE automations.id = ?
                """,
                (automation_id,),
            ).fetchone()
            is_schedule = bool(
                condition_type_row and condition_type_row["type"] == "schedule.calendar"
            )
            condition_type = (
                str(condition_type_row["type"])
                if condition_type_row
                else "unknown"
            )
            condition_ids = (
                json.loads(condition_type_row["condition_definition_ids"] or "[]")
                if condition_type_row
                else []
            )
            evidence_type = (
                "condition.group" if len(condition_ids) > 1 else condition_type
            )
            evidence = {
                "evaluation": {
                    "schema_version": 1,
                    "kind": (
                        "schedule"
                        if condition_type == "schedule.calendar"
                        else "startup"
                        if condition_type == "system.startup"
                        else "manual"
                        if condition_type == "manual.trigger"
                        else "condition"
                    ),
                    "type": evidence_type,
                    "observed_at": now,
                },
                "error": {"message": message[:2000]},
            }
            connection.execute(
                """
                UPDATE automations
                SET state = 'error', last_check_at = ?, last_error = ?,
                    last_summary = 'Condition check could not be completed.',
                    enabled = CASE WHEN ? THEN 0 ELSE enabled END,
                    next_check_at = CASE WHEN ? THEN NULL ELSE next_check_at END,
                    pending_schedule_at = CASE WHEN ? THEN NULL ELSE pending_schedule_at END,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    now,
                    message[:2000],
                    int(is_schedule),
                    int(is_schedule),
                    int(is_schedule),
                    now,
                    automation_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO automation_checks
                    (automation_id, checked_at, met, status, summary, evidence_json)
                VALUES (?, ?, 0, 'error', ?, ?)
                """,
                (
                    automation_id,
                    now,
                    message[:2000],
                    json.dumps(evidence, separators=(",", ":")),
                ),
            )

    def record_observation(self, automation_id: str, status: str, summary: str) -> None:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                "UPDATE automations SET last_check_at = ?, last_summary = ?, updated_at = ? WHERE id = ?",
                (now, summary[:2000], now, automation_id),
            )
            connection.execute(
                "INSERT INTO automation_checks (automation_id, checked_at, met, status, summary, evidence_json) VALUES (?, ?, 0, ?, ?, '{}')",
                (automation_id, now, status[:40], summary[:2000]),
            )

    def record_run(
        self,
        automation_id: str,
        trigger: ConditionResult,
        results: list[ActionResult],
    ) -> str:
        now = time.time()
        run_id = secrets.token_hex(12)
        status = (
            "success"
            if results and all(result.status == "success" for result in results)
            else "error"
            if not results or all(result.status == "error" for result in results)
            else "partial"
        )
        run_root = self.artifact_root / run_id
        payload = []
        staging_roots: set[Path] = set()
        try:
            for action_index, result in enumerate(results, 1):
                output = dict(result.output)
                sources = output.pop("_artifact_sources", [])
                artifacts = []
                for source_index, item in enumerate(sources, 1):
                    source = Path(str(item.get("source_path", ""))).resolve()
                    if not source.is_file() or source.is_symlink():
                        raise ValueError("Automation artifact source is unavailable.")
                    from .operational import ensure_storage_capacity
                    ensure_storage_capacity(self.instance_path, "automation_artifacts", source.stat().st_size)
                    staging_roots.add(source.parent)
                    action_folder = run_root / f"action-{action_index}"
                    action_folder.mkdir(parents=True, exist_ok=True, mode=0o700)
                    filename = self._artifact_filename(str(item.get("filename", source.name)), source_index)
                    target = action_folder / filename
                    if target.exists():
                        filename = f"{source_index}-{filename}"
                        target = action_folder / filename
                    shutil.move(str(source), target)
                    os.chmod(target, 0o600)
                    artifacts.append({
                        key: value for key, value in item.items() if key != "source_path"
                    } | {"artifact_path": f"action-{action_index}/{filename}"})
                if artifacts:
                    output["artifacts"] = artifacts
                payload.append({"status": result.status, "summary": result.summary, "output": output})
            with self._connect() as connection:
                connection.execute(
                """
                INSERT INTO automation_runs
                    (id, automation_id, started_at, finished_at, status,
                     trigger_summary, results_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                    run_id,
                    automation_id,
                    now,
                    time.time(),
                    status,
                    trigger.summary,
                    json.dumps(payload, separators=(",", ":")),
                    ),
                )
        except Exception:
            shutil.rmtree(run_root, ignore_errors=True)
            raise
        finally:
            for folder in staging_roots:
                shutil.rmtree(folder, ignore_errors=True)
        return run_id

    def recent_runs(self, automation_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM automation_runs WHERE automation_id = ?
                ORDER BY started_at DESC LIMIT ?
                """,
                (automation_id, limit),
            ).fetchall()
        return [
            {
                **dict(row),
                "results": json.loads(row["results_json"]),
            }
            for row in rows
        ]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT automation_runs.*, automations.name AS automation_name
                FROM automation_runs
                JOIN automations ON automations.id = automation_runs.automation_id
                WHERE automation_runs.id = ?
                """,
                (run_id,),
            ).fetchone()
        if not row:
            return None
        return {**dict(row), "results": json.loads(row["results_json"])}

    def delete_run(self, run_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM automation_jobs WHERE run_id = ?",
                (run_id,),
            )
            cursor = connection.execute(
                "DELETE FROM automation_runs WHERE id = ?", (run_id,)
            )
            if not cursor.rowcount:
                raise ValueError("Collected action run not found.")
        shutil.rmtree(self.artifact_root / run_id, ignore_errors=True)

    def clear_runs(self, automation_id: str) -> int:
        with self._connect() as connection:
            if not connection.execute(
                "SELECT 1 FROM automations WHERE id = ?", (automation_id,)
            ).fetchone():
                raise ValueError("Automation not found.")
            run_ids = [row[0] for row in connection.execute(
                "SELECT id FROM automation_runs WHERE automation_id = ?", (automation_id,)
            )]
            connection.execute(
                """
                DELETE FROM automation_jobs
                WHERE automation_id = ? AND status = 'completed'
                """,
                (automation_id,),
            )
            cursor = connection.execute(
                "DELETE FROM automation_runs WHERE automation_id = ?", (automation_id,)
            )
        for run_id in run_ids:
            shutil.rmtree(self.artifact_root / str(run_id), ignore_errors=True)
        return int(cursor.rowcount)

    def run_artifact(self, run_id: str, relative_path: str) -> Path:
        root = (self.artifact_root / run_id).resolve()
        candidate = (root / relative_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("Automation artifact path is invalid.") from exc
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError("Automation artifact was not found.")
        return candidate

    @staticmethod
    def _artifact_filename(value: str, fallback_index: int) -> str:
        name = Path(value.replace("\\", "/")).name
        cleaned = "".join(character if character.isalnum() or character in "._-" else "-" for character in name).strip(".-")
        return (cleaned or f"artifact-{fallback_index}")[:255]

    def recent_checks(self, automation_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM automation_checks WHERE automation_id = ?
                ORDER BY checked_at DESC LIMIT ?
                """,
                (automation_id, limit),
            ).fetchall()
        return [
            {**dict(row), "evidence": json.loads(row["evidence_json"])}
            for row in rows
        ]

    def retention_settings(self) -> dict[str, int | float]:
        with self._connect() as connection:
            return self._retention_settings_from_connection(connection)

    def update_retention_settings(
        self, *, check_retention_days: int, run_retention_days: int
    ) -> None:
        for value, label in (
            (check_retention_days, "Check history retention"),
            (run_retention_days, "Collected action run retention"),
        ):
            if not 0 <= value <= 3650:
                raise ValueError(f"{label} must be 0–3650 days (0 means never delete).")
        now = time.time()
        with self._connect() as connection:
            for key, value in (
                ("check_retention_days", check_retention_days),
                ("run_retention_days", run_retention_days),
            ):
                connection.execute(
                    """
                    INSERT INTO automation_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                        updated_at = excluded.updated_at
                    """,
                    (key, str(value), now),
                )

    def storage_stats(self, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        settings = self.retention_settings()
        check_days = int(settings["check_retention_days"])
        run_days = int(settings["run_retention_days"])
        check_cutoff = now - (check_days * 86400) if check_days else None
        run_cutoff = now - (run_days * 86400) if run_days else None
        with self._connect() as connection:
            checks = connection.execute(
                "SELECT COUNT(*) AS count, MIN(checked_at) AS oldest "
                "FROM automation_checks INDEXED BY automation_checks_recent"
            ).fetchone()
            runs = connection.execute(
                "SELECT COUNT(*) AS count, MIN(started_at) AS oldest FROM automation_runs"
            ).fetchone()
            eligible_checks = (
                connection.execute(
                    "SELECT COUNT(*) FROM automation_checks "
                    "INDEXED BY automation_checks_recent WHERE checked_at < ?",
                    (check_cutoff,),
                ).fetchone()[0]
                if check_cutoff is not None else 0
            )
            eligible_runs = (
                connection.execute(
                    "SELECT COUNT(*) FROM automation_runs WHERE started_at < ?",
                    (run_cutoff,),
                ).fetchone()[0]
                if run_cutoff is not None else 0
            )
        database_bytes = sum(
            path.stat().st_size
            for path in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm"))
            if path.exists()
        )
        return {
            **settings,
            "database_bytes": database_bytes,
            "check_count": int(checks["count"]),
            "oldest_check_at": checks["oldest"],
            "run_count": int(runs["count"]),
            "oldest_run_at": runs["oldest"],
            "eligible_check_count": int(eligible_checks),
            "eligible_run_count": int(eligible_runs),
        }

    def orphan_artifact_stats(self) -> dict[str, int]:
        with self._connect() as connection:
            known = {str(row[0]) for row in connection.execute("SELECT id FROM automation_runs")}
        folders = [path for path in self.artifact_root.iterdir() if path.is_dir() and path.name not in known]
        total = 0
        for folder in folders:
            for root, _dirs, files in os.walk(folder):
                for name in files:
                    try: total += (Path(root) / name).stat().st_size
                    except OSError: pass
        return {"count": len(folders), "bytes": total}

    def cleanup_orphan_artifacts(self) -> dict[str, int]:
        stats = self.orphan_artifact_stats()
        with self._connect() as connection:
            known = {str(row[0]) for row in connection.execute("SELECT id FROM automation_runs")}
        for folder in self.artifact_root.iterdir():
            if folder.is_dir() and folder.name not in known: shutil.rmtree(folder, ignore_errors=True)
        return stats

    def prune_history(self, now: float | None = None) -> dict[str, int]:
        now = time.time() if now is None else now
        settings = self.retention_settings()
        deleted_checks = 0
        deleted_runs = 0
        with self._connect() as connection:
            check_days = int(settings["check_retention_days"])
            if check_days:
                deleted_checks = connection.execute(
                    "DELETE FROM automation_checks WHERE checked_at < ?",
                    (now - check_days * 86400,),
                ).rowcount
            run_days = int(settings["run_retention_days"])
            if run_days:
                expired_run_ids = [row[0] for row in connection.execute(
                    "SELECT id FROM automation_runs WHERE started_at < ?",
                    (now - run_days * 86400,),
                )]
                if expired_run_ids:
                    connection.execute(
                        f"""
                        DELETE FROM automation_jobs
                        WHERE run_id IN ({','.join('?' for _ in expired_run_ids)})
                        """,
                        expired_run_ids,
                    )
                deleted_runs = connection.execute(
                    "DELETE FROM automation_runs WHERE started_at < ?",
                    (now - run_days * 86400,),
                ).rowcount
            else:
                expired_run_ids = []
            connection.execute(
                """
                INSERT INTO automation_settings (key, value, updated_at)
                VALUES ('last_pruned_at', ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (str(now), now),
            )
        for run_id in expired_run_ids:
            shutil.rmtree(self.artifact_root / str(run_id), ignore_errors=True)
        return {"checks": int(deleted_checks), "runs": int(deleted_runs)}

    def prune_history_if_due(self, now: float | None = None) -> dict[str, int] | None:
        now = time.time() if now is None else now
        if now - float(self.retention_settings()["last_pruned_at"]) < 86400:
            return None
        return self.prune_history(now)

    def optimize_database(self) -> None:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            connection.execute("PRAGMA busy_timeout = 30000")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("VACUUM")
        finally:
            connection.close()
            if self.path.exists():
                os.chmod(self.path, 0o600)

    def migration_status(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            return [
                {"version": f"automation-{row['version']}", "applied_at": row["applied_at"], "description": row["description"]}
                for row in connection.execute("SELECT version, applied_at, description FROM automation_schema_migrations ORDER BY version")
            ]

    def diagnostics_snapshot(self, now: float | None = None) -> dict[str, Any]:
        """Collect read-only automation health data through one short connection."""
        now = time.time() if now is None else now
        with readonly_sqlite_connection(self.path) as connection:
            settings = self._retention_settings_from_connection(connection)
            check_days = int(settings["check_retention_days"])
            run_days = int(settings["run_retention_days"])
            check_cutoff = now - (check_days * 86400) if check_days else None
            run_cutoff = now - (run_days * 86400) if run_days else None
            checks = connection.execute(
                "SELECT COUNT(*) AS count, MIN(checked_at) AS oldest "
                "FROM automation_checks INDEXED BY automation_checks_recent"
            ).fetchone()
            runs = connection.execute(
                "SELECT COUNT(*) AS count, MIN(started_at) AS oldest FROM automation_runs"
            ).fetchone()
            eligible_checks = (
                connection.execute(
                    "SELECT COUNT(*) FROM automation_checks "
                    "INDEXED BY automation_checks_recent WHERE checked_at < ?",
                    (check_cutoff,),
                ).fetchone()[0]
                if check_cutoff is not None
                else 0
            )
            eligible_runs = (
                connection.execute(
                    "SELECT COUNT(*) FROM automation_runs WHERE started_at < ?",
                    (run_cutoff,),
                ).fetchone()[0]
                if run_cutoff is not None
                else 0
            )
            migrations = [
                {
                    "version": f"automation-{row['version']}",
                    "applied_at": row["applied_at"],
                    "description": row["description"],
                }
                for row in connection.execute(
                    "SELECT version, applied_at, description "
                    "FROM automation_schema_migrations ORDER BY version"
                )
            ]
            known_run_ids = {
                str(row[0])
                for row in connection.execute("SELECT id FROM automation_runs")
            }

        database_bytes = sum(
            path.stat().st_size
            for path in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm"))
            if path.exists()
        )
        orphan_folders = [
            path
            for path in self.artifact_root.iterdir()
            if path.is_dir() and path.name not in known_run_ids
        ]
        orphan_bytes = 0
        for folder in orphan_folders:
            for root, _dirs, files in os.walk(folder):
                for name in files:
                    try:
                        orphan_bytes += (Path(root) / name).stat().st_size
                    except OSError:
                        pass
        return {
            "migrations": migrations,
            "storage": {
                **settings,
                "database_bytes": database_bytes,
                "check_count": int(checks["count"]),
                "oldest_check_at": checks["oldest"],
                "run_count": int(runs["count"]),
                "oldest_run_at": runs["oldest"],
                "eligible_check_count": int(eligible_checks),
                "eligible_run_count": int(eligible_runs),
            },
            "orphan_artifacts": {
                "count": len(orphan_folders),
                "bytes": orphan_bytes,
            },
        }

    @staticmethod
    def _retention_settings_from_connection(
        connection: sqlite3.Connection,
    ) -> dict[str, int | float]:
        values = {
            str(row["key"]): str(row["value"])
            for row in connection.execute(
                "SELECT key, value FROM automation_settings"
            )
        }
        return {
            "check_retention_days": int(values.get("check_retention_days", "7")),
            "run_retention_days": int(values.get("run_retention_days", "0")),
            "last_pruned_at": float(values.get("last_pruned_at", "0")),
        }

    def _enqueue_execution_job(
        self,
        connection: sqlite3.Connection,
        automation_row: sqlite3.Row,
        trigger: ConditionResult,
        *,
        scheduled_at: float,
        queued_at: float,
    ) -> str:
        job_id = secrets.token_hex(12)
        trigger_payload = {
            "met": bool(trigger.met),
            "status": str(trigger.status),
            "summary": str(trigger.summary),
            "evidence": trigger.evidence,
        }
        execution_plan = self._execution_plan_from_row(connection, automation_row)
        connection.execute(
            """
            INSERT INTO automation_jobs (
                id, automation_id, status, scheduled_at, queued_at,
                attempt_count, trigger_json, execution_plan_encrypted
            ) VALUES (?, ?, 'queued', ?, ?, 0, ?, ?)
            """,
            (
                job_id,
                automation_row["id"],
                float(scheduled_at),
                float(queued_at),
                json.dumps(trigger_payload, separators=(",", ":")),
                self._encrypt(execution_plan),
            ),
        )
        return job_id

    def _execution_plan_from_row(
        self,
        connection: sqlite3.Connection,
        automation_row: sqlite3.Row,
    ) -> dict[str, Any]:
        action_ids = json.loads(automation_row["action_definition_ids"] or "[]")
        action_map: dict[str, dict[str, Any]] = {}
        for action_id in action_ids:
            row = connection.execute(
                "SELECT * FROM automation_actions WHERE id = ?",
                (action_id,),
            ).fetchone()
            if not row:
                raise ValueError(
                    "An automation action disappeared before execution could be queued."
                )
            action_map[str(action_id)] = {
                "id": str(row["id"]),
                "name": str(row["name"]),
                "type": str(row["type"]),
                "config": self._decrypt(str(row["config_encrypted"])),
            }
        raw_stages = json.loads(automation_row["action_stages"] or "null")
        normalized_stages = self._normalize_action_stages(raw_stages, action_ids)
        stages = []
        for stage in normalized_stages:
            actions = [
                action_map[action_id]
                for action_id in stage["action_definition_ids"]
                if action_id in action_map
            ]
            if len(actions) != len(stage["action_definition_ids"]):
                raise ValueError(
                    "An automation stage could not snapshot all of its actions."
                )
            stages.append({**stage, "actions": actions})
        return {
            "id": str(automation_row["id"]),
            "name": str(automation_row["name"]),
            "action_stages": stages,
            "actions": [action for stage in stages for action in stage["actions"]],
        }

    def _job_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        trigger = json.loads(str(row["trigger_json"]))
        encrypted_progress = row["progress_encrypted"]
        return {
            **dict(row),
            "trigger": ConditionResult(
                met=bool(trigger["met"]),
                status=str(trigger["status"]),
                summary=str(trigger["summary"]),
                evidence=dict(trigger.get("evidence", {})),
            ),
            "automation": self._decrypt(str(row["execution_plan_encrypted"])),
            "progress": (
                self._decrypt(str(encrypted_progress))
                if encrypted_progress
                else None
            ),
        }

    def _automation_from_row(
        self,
        row: sqlite3.Row,
        include_secrets: bool,
        *,
        condition_map: dict[str, dict[str, Any]] | None = None,
        action_map: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        condition_definition_id = str(row["condition_definition_id"] or "")
        condition_definition_ids = json.loads(
            row["condition_definition_ids"] or "[]"
        )
        if not condition_definition_ids and condition_definition_id:
            condition_definition_ids = [condition_definition_id]
        action_definition_ids = json.loads(row["action_definition_ids"] or "[]")
        if condition_map is None:
            conditions = [
                definition
                for definition_id in condition_definition_ids
                if (
                    definition := self.get_condition_definition(
                        str(definition_id)
                    )
                )
                is not None
            ]
        else:
            conditions = [
                condition_map[str(definition_id)]
                for definition_id in condition_definition_ids
                if str(definition_id) in condition_map
            ]
        condition = conditions[0] if conditions else None
        if action_map is None:
            resolved_action_map = {}
            for action_id in action_definition_ids:
                action = self.get_action_definition(
                    action_id,
                    include_secrets=include_secrets,
                )
                if action is not None:
                    resolved_action_map[action_id] = action
        else:
            resolved_action_map = action_map
        raw_stages = json.loads(row["action_stages"] or "null")
        normalized_stages = self._normalize_action_stages(raw_stages, action_definition_ids)
        stages = [
            {
                **stage,
                "actions": [
                    resolved_action_map[action_id]
                    for action_id in stage["action_definition_ids"]
                    if action_id in resolved_action_map
                ],
            }
            for stage in normalized_stages
        ]
        actions = [action for stage in stages for action in stage["actions"]]
        return {
            **dict(row),
            "enabled": bool(row["enabled"]),
            "condition": condition
            or {
                "id": "",
                "name": "Legacy condition",
                "type": row["condition_type"],
                "config": json.loads(row["condition_config"]),
            },
            "conditions": conditions
            or [
                {
                    "id": "",
                    "name": "Legacy condition",
                    "type": row["condition_type"],
                    "config": json.loads(row["condition_config"]),
                }
            ],
            "condition_definition_ids": [
                str(definition_id) for definition_id in condition_definition_ids
            ],
            "condition_operator": str(row["condition_operator"] or "all"),
            "actions": actions,
            "action_stages": stages,
        }

    @staticmethod
    def _condition_definition_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            **dict(row),
            "config": json.loads(row["config_json"]),
        }

    def _action_definition_from_row(
        self, row: sqlite3.Row, include_secrets: bool
    ) -> dict[str, Any]:
        config = self._decrypt(str(row["config_encrypted"]))
        secret_fields = AUTOMATION_REGISTRY.secret_fields_for_action(str(row["type"]))
        secret_presence = {field: bool(config.get(field)) for field in secret_fields}
        if not include_secrets:
            config = {
                key: value for key, value in config.items()
                if key not in secret_fields
            }
        return {
            **dict(row),
            "config": config,
            "has_secrets": any(secret_presence.values()),
            "secret_presence": secret_presence,
            # Compatibility keys used by existing templates/tests.
            "has_password": secret_presence.get("password", False),
            "has_headers": secret_presence.get("headers", False),
        }

    @staticmethod
    def _validate_definition_name(name: str, label: str) -> str:
        name = " ".join(name.strip().split())
        if not 2 <= len(name) <= 100:
            raise ValueError(f"{label} name must be 2–100 characters.")
        return name

    @staticmethod
    def _pause_automations_for_condition(
        connection: sqlite3.Connection, definition_id: str, now: float
    ) -> None:
        rows = connection.execute(
            "SELECT id, condition_definition_id, condition_definition_ids FROM automations"
        ).fetchall()
        ids = [
            str(row["id"])
            for row in rows
            if definition_id
            in (
                json.loads(row["condition_definition_ids"] or "[]")
                or [str(row["condition_definition_id"] or "")]
            )
        ]
        for automation_id in ids:
            connection.execute(
                """
                UPDATE automations SET enabled = 0, state = 'disabled',
                    consecutive_met = 0, consecutive_clear = 0, next_check_at = NULL,
                    pending_schedule_at = NULL,
                    updated_at = ? WHERE id = ?
                """,
                (now, automation_id),
            )

    @staticmethod
    def _pause_automations_for_action(
        connection: sqlite3.Connection, definition_id: str, now: float
    ) -> None:
        rows = connection.execute(
            "SELECT id, action_definition_ids FROM automations"
        ).fetchall()
        ids = [
            row["id"]
            for row in rows
            if definition_id in json.loads(row["action_definition_ids"] or "[]")
        ]
        for automation_id in ids:
            connection.execute(
                """
                UPDATE automations SET enabled = 0, state = 'disabled',
                    consecutive_met = 0, consecutive_clear = 0, next_check_at = NULL,
                    pending_schedule_at = NULL,
                    updated_at = ? WHERE id = ?
                """,
                (now, automation_id),
            )

    def _encrypt(self, value: Any) -> str:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return self._cipher.encrypt(payload).decode("ascii")

    def _decrypt(self, value: str) -> Any:
        try:
            return json.loads(self._cipher.decrypt(value.encode("ascii")))
        except (InvalidToken, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Could not decrypt saved automation actions.") from exc

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA busy_timeout = 10000")
            self._initialize(connection)
            self._migrate_reusable_definitions(connection)
            self._run_migrations(connection)
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
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS automations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                interval_seconds INTEGER NOT NULL,
                trigger_after INTEGER NOT NULL,
                recover_after INTEGER NOT NULL,
                cooldown_seconds INTEGER NOT NULL DEFAULT 0,
                condition_type TEXT NOT NULL,
                condition_config TEXT NOT NULL,
                actions_encrypted TEXT NOT NULL,
                condition_definition_id TEXT,
                condition_definition_ids TEXT,
                condition_operator TEXT NOT NULL DEFAULT 'all',
                action_definition_ids TEXT,
                action_stages TEXT,
                state TEXT NOT NULL DEFAULT 'disabled',
                consecutive_met INTEGER NOT NULL DEFAULT 0,
                consecutive_clear INTEGER NOT NULL DEFAULT 0,
                next_check_at REAL,
                pending_schedule_at REAL,
                last_check_at REAL,
                last_triggered_at REAL,
                last_summary TEXT,
                last_error TEXT,
                created_by TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS automations_due
                ON automations(enabled, next_check_at);
            CREATE TABLE IF NOT EXISTS automation_conditions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                type TEXT NOT NULL,
                config_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS automation_actions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                type TEXT NOT NULL,
                config_encrypted TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS automation_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                automation_id TEXT NOT NULL REFERENCES automations(id) ON DELETE CASCADE,
                checked_at REAL NOT NULL,
                met INTEGER NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS automation_checks_recent
                ON automation_checks(automation_id, checked_at DESC);
            CREATE TABLE IF NOT EXISTS automation_runs (
                id TEXT PRIMARY KEY,
                automation_id TEXT NOT NULL REFERENCES automations(id) ON DELETE CASCADE,
                started_at REAL NOT NULL,
                finished_at REAL,
                status TEXT NOT NULL,
                trigger_summary TEXT NOT NULL,
                results_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS automation_runs_recent
                ON automation_runs(automation_id, started_at DESC);
            CREATE TABLE IF NOT EXISTS automation_jobs (
                id TEXT PRIMARY KEY,
                automation_id TEXT NOT NULL REFERENCES automations(id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                scheduled_at REAL NOT NULL,
                queued_at REAL NOT NULL,
                claimed_at REAL,
                started_at REAL,
                finished_at REAL,
                lease_until REAL,
                next_attempt_at REAL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                trigger_json TEXT NOT NULL,
                execution_plan_encrypted TEXT NOT NULL,
                progress_encrypted TEXT,
                run_id TEXT REFERENCES automation_runs(id) ON DELETE SET NULL,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS automation_jobs_due
                ON automation_jobs(status, next_attempt_at, lease_until, queued_at);
            CREATE INDEX IF NOT EXISTS automation_jobs_automation
                ON automation_jobs(automation_id, queued_at DESC);
            CREATE TABLE IF NOT EXISTS automation_event_state (
                automation_id TEXT PRIMARY KEY
                    REFERENCES automations(id) ON DELETE CASCADE,
                source_type TEXT NOT NULL,
                event_key TEXT NOT NULL,
                event_occurred_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS automation_schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at REAL NOT NULL,
                description TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS automation_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            """
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(automations)")
        }
        if "condition_definition_id" not in columns:
            connection.execute(
                "ALTER TABLE automations ADD COLUMN condition_definition_id TEXT"
            )
        if "action_definition_ids" not in columns:
            connection.execute(
                "ALTER TABLE automations ADD COLUMN action_definition_ids TEXT"
            )
        if "condition_definition_ids" not in columns:
            connection.execute(
                "ALTER TABLE automations ADD COLUMN condition_definition_ids TEXT"
            )
        if "condition_operator" not in columns:
            connection.execute(
                "ALTER TABLE automations ADD COLUMN condition_operator TEXT NOT NULL DEFAULT 'all'"
            )
        if "pending_schedule_at" not in columns:
            connection.execute(
                "ALTER TABLE automations ADD COLUMN pending_schedule_at REAL"
            )
        connection.execute("PRAGMA foreign_keys = ON")

    @staticmethod
    def _run_migrations(connection: sqlite3.Connection) -> None:
        applied = {
            int(row["version"])
            for row in connection.execute(
                "SELECT version FROM automation_schema_migrations"
            )
        }
        if 1 not in applied:
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(automations)")
            }
            if "action_stages" not in columns:
                connection.execute(
                    "ALTER TABLE automations ADD COLUMN action_stages TEXT"
                )
            rows = connection.execute(
                "SELECT id, action_definition_ids FROM automations WHERE action_stages IS NULL"
            ).fetchall()
            for row in rows:
                action_ids = json.loads(row["action_definition_ids"] or "[]")
                stages = [{
                    "id": "stage-1",
                    "name": "Stage 1",
                    "continue_policy": "all_completed",
                    "delay_seconds": 0,
                    "action_definition_ids": action_ids,
                }]
                connection.execute(
                    "UPDATE automations SET action_stages = ? WHERE id = ?",
                    (json.dumps(stages, separators=(",", ":")), row["id"]),
                )
            connection.execute(
                "INSERT INTO automation_schema_migrations (version, applied_at, description) VALUES (1, ?, ?)",
                (time.time(), "Add ordered parallel action stages"),
            )
        if 2 not in applied:
            rows = connection.execute(
                "SELECT id, config_json FROM automation_conditions WHERE type = 'snmp.value'"
            ).fetchall()
            normalized_by_id: dict[str, dict[str, Any]] = {}
            for row in rows:
                config = json.loads(row["config_json"] or "{}")
                if isinstance(config.get("rules"), list):
                    continue
                normalized = AUTOMATION_REGISTRY.validate_condition("snmp.value", config)
                normalized_by_id[row["id"]] = normalized
                connection.execute(
                    "UPDATE automation_conditions SET config_json = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(normalized, separators=(",", ":")), time.time(), row["id"]),
                )
            for definition_id, normalized in normalized_by_id.items():
                connection.execute(
                    """
                    UPDATE automations
                    SET condition_config = ?, enabled = 0, state = 'disabled',
                        consecutive_met = 0, consecutive_clear = 0,
                        next_check_at = NULL, pending_schedule_at = NULL,
                        updated_at = ?
                    WHERE condition_definition_id = ?
                    """,
                    (
                        json.dumps(normalized, separators=(",", ":")),
                        time.time(),
                        definition_id,
                    ),
                )
            connection.execute(
                "INSERT INTO automation_schema_migrations (version, applied_at, description) VALUES (2, ?, ?)",
                (time.time(), "Normalize SNMP conditions into per-host AND rules"),
            )
        if 3 not in applied:
            now = time.time()
            connection.executemany(
                "INSERT OR IGNORE INTO automation_settings (key, value, updated_at) VALUES (?, ?, ?)",
                [
                    ("check_retention_days", "7", now),
                    ("run_retention_days", "0", now),
                    ("last_pruned_at", "0", now),
                ],
            )
            connection.execute(
                "INSERT INTO automation_schema_migrations (version, applied_at, description) VALUES (3, ?, ?)",
                (now, "Add configurable automation history retention"),
            )
        if 4 not in applied:
            connection.execute(
                """
                INSERT INTO automation_schema_migrations
                    (version, applied_at, description)
                VALUES (4, ?, ?)
                """,
                (time.time(), "Add durable leased automation execution jobs"),
            )
        if 5 not in applied:
            rows = connection.execute(
                """
                SELECT id, condition_definition_id
                FROM automations
                WHERE condition_definition_ids IS NULL
                    AND condition_definition_id IS NOT NULL
                """
            ).fetchall()
            for row in rows:
                connection.execute(
                    """
                    UPDATE automations
                    SET condition_definition_ids = ?, condition_operator = 'all'
                    WHERE id = ?
                    """,
                    (json.dumps([str(row["condition_definition_id"])]), row["id"]),
                )
            connection.execute(
                """
                INSERT INTO automation_schema_migrations
                    (version, applied_at, description)
                VALUES (5, ?, ?)
                """,
                (time.time(), "Add ALL and ANY condition groups"),
            )
        if 6 not in applied:
            job_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(automation_jobs)"
                )
            }
            if "progress_encrypted" not in job_columns:
                connection.execute(
                    "ALTER TABLE automation_jobs ADD COLUMN progress_encrypted TEXT"
                )
            connection.execute(
                """
                INSERT INTO automation_schema_migrations
                    (version, applied_at, description)
                VALUES (6, ?, ?)
                """,
                (time.time(), "Add durable delayed-stage pipeline progress"),
            )
        if 7 not in applied:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS automation_event_state (
                    automation_id TEXT PRIMARY KEY
                        REFERENCES automations(id) ON DELETE CASCADE,
                    source_type TEXT NOT NULL,
                    event_key TEXT NOT NULL,
                    event_occurred_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO automation_schema_migrations
                    (version, applied_at, description)
                VALUES (7, ?, ?)
                """,
                (time.time(), "Add durable startup-event deduplication state"),
            )

    def _migrate_reusable_definitions(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            """
            SELECT * FROM automations
            WHERE condition_definition_id IS NULL OR action_definition_ids IS NULL
            """
        ).fetchall()
        now = time.time()
        for row in rows:
            condition_id = secrets.token_hex(12)
            condition_name = self._unique_definition_name(
                connection, "automation_conditions", f"{row['name']} condition"
            )
            connection.execute(
                "INSERT INTO automation_conditions (id, name, type, config_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    condition_id,
                    condition_name,
                    row["condition_type"],
                    row["condition_config"],
                    now,
                    now,
                ),
            )
            action_ids = []
            for index, action in enumerate(self._decrypt(row["actions_encrypted"]), 1):
                action_id = secrets.token_hex(12)
                suffix = "" if index == 1 else f" {index}"
                action_name = self._unique_definition_name(
                    connection, "automation_actions", f"{row['name']} action{suffix}"
                )
                connection.execute(
                    "INSERT INTO automation_actions (id, name, type, config_encrypted, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        action_id,
                        action_name,
                        action["type"],
                        self._encrypt(action["config"]),
                        now,
                        now,
                    ),
                )
                action_ids.append(action_id)
            stages = [{
                "id": "stage-1",
                "name": "Stage 1",
                "continue_policy": "all_completed",
                "delay_seconds": 0,
                "action_definition_ids": action_ids,
            }]
            connection.execute(
                """
                UPDATE automations
                SET condition_definition_id = ?, condition_definition_ids = ?,
                    condition_operator = 'all', action_definition_ids = ?,
                    action_stages = ?
                WHERE id = ?
                """,
                (
                    condition_id,
                    json.dumps([condition_id]),
                    json.dumps(action_ids),
                    json.dumps(stages, separators=(",", ":")),
                    row["id"],
                ),
            )

    @staticmethod
    def _unique_definition_name(
        connection: sqlite3.Connection, table: str, requested: str
    ) -> str:
        candidate = requested
        number = 2
        while connection.execute(
            f"SELECT 1 FROM {table} WHERE lower(name) = lower(?)", (candidate,)
        ).fetchone():
            candidate = f"{requested} {number}"
            number += 1
        return candidate


class AutomationEngine:
    def __init__(
        self,
        store: AutomationStore,
        registry: AutomationRegistry = AUTOMATION_REGISTRY,
    ) -> None:
        self.store = store
        self.registry = registry

    def test_condition(
        self,
        automation: dict[str, Any],
        *,
        observed_at: float | None = None,
    ) -> ConditionResult:
        conditions = automation.get("conditions") or [automation["condition"]]
        if len(conditions) == 1:
            if conditions[0]["type"] in self.registry.triggers:
                return self.registry.evaluate_trigger(
                    conditions[0]["type"],
                    conditions[0]["config"],
                )
            return self.registry.evaluate_condition(
                conditions[0]["type"],
                conditions[0]["config"],
                observed_at=observed_at,
            )
        evaluated = []
        for condition in conditions:
            try:
                result = self.registry.evaluate_condition(
                    condition["type"],
                    condition["config"],
                    observed_at=observed_at,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"{condition['name']}: {type(exc).__name__}: {exc}"
                ) from exc
            evaluated.append(
                {
                    "id": condition["id"],
                    "name": condition["name"],
                    "type": condition["type"],
                    "met": result.met,
                    "status": result.status,
                    "summary": result.summary,
                    "evidence": result.evidence,
                }
            )
        operator = str(automation.get("condition_operator", "all"))
        met_count = sum(bool(item["met"]) for item in evaluated)
        met = (
            met_count == len(evaluated)
            if operator == "all"
            else met_count > 0
        )
        label = "ALL" if operator == "all" else "ANY"
        return evaluation_result(
            ConditionResult(
                met=met,
                status="met" if met else "clear",
                summary=(
                    f"{label}: {met_count} of {len(evaluated)} conditions met."
                ),
                evidence={
                    "operator": operator,
                    "met_count": met_count,
                    "condition_count": len(evaluated),
                    "conditions": evaluated,
                },
            ),
            kind="condition",
            type_id="condition.group",
            observed_at=observed_at,
        )

    def run_once(self) -> int:
        processed = 0
        for automation in self.store.claim_due():
            processed += 1
            self.process_automation(automation)
        for job in self.store.claim_jobs():
            self.process_job(job)
        return processed

    def process_automation(self, automation: dict[str, Any]) -> None:
        if automation["condition"]["type"] == "schedule.calendar":
            try:
                updated, result, should_fire = self.store.record_schedule_occurrence(
                    automation["id"]
                )
            except Exception as exc:
                self.store.record_error(
                    automation["id"], f"{type(exc).__name__}: {exc}"
                )
                return
            return
        observed_at = time.time()
        try:
            result = self.test_condition(automation, observed_at=observed_at)
        except Exception as exc:
            self.store.record_error(
                automation["id"], f"{type(exc).__name__}: {exc}"
            )
            return
        self.store.record_condition(
            automation["id"],
            result,
            scheduled_at=automation.get("next_check_at"),
            observed_at=observed_at,
        )

    def process_job(self, job: dict[str, Any]) -> str | None:
        trigger = ConditionResult(
            met=job["trigger"].met,
            status=job["trigger"].status,
            summary=job["trigger"].summary,
            evidence={
                **job["trigger"].evidence,
                "execution": {
                    "job_id": job["id"],
                    "attempt": job["attempt_count"],
                    "scheduled_at": job["scheduled_at"],
                    "queued_at": job["queued_at"],
                },
            },
        )
        try:
            if job.get("run_id"):
                run_id = str(job["run_id"])
                self.store.complete_job(job["id"], run_id)
                return run_id
            action_results = self._execute_pipeline(
                job["automation"],
                trigger,
                progress=job.get("progress"),
                job_id=job["id"],
            )
            if action_results is None:
                return None
            run_id = self.store.record_run(
                job["automation"]["id"], trigger, action_results
            )
            self.store.link_job_run(job["id"], run_id)
            self.store.complete_job(job["id"], run_id)
            return run_id
        except Exception as exc:
            self.store.fail_job(
                job["id"],
                f"{type(exc).__name__}: {exc}",
            )
            raise

    def record_backpressure(self, automation_id: str, reason: str) -> None:
        self.store.record_observation(automation_id, "skipped", reason)

    def execute_actions(
        self, automation: dict[str, Any], trigger: ConditionResult
    ) -> str:
        action_results = self._execute_pipeline(automation, trigger)
        if action_results is None:
            raise RuntimeError("A synchronous pipeline cannot be deferred.")
        return self.store.record_run(automation["id"], trigger, action_results)

    def _execute_pipeline(
        self,
        automation: dict[str, Any],
        trigger: ConditionResult,
        *,
        progress: dict[str, Any] | None = None,
        job_id: str = "",
    ) -> list[ActionResult] | None:
        progress = progress or {}
        start_stage_index = int(progress.get("next_stage_index", 0))
        delay_completed_stage_id = str(
            progress.get("delay_completed_stage_id", "")
        )
        if not 0 <= start_stage_index <= len(automation["action_stages"]):
            raise ValueError("Saved automation pipeline progress is invalid.")
        restored_results = progress.get("action_results", [])
        action_results = [
            ActionResult(
                status=str(item["status"]),
                summary=str(item["summary"]),
                output=dict(item.get("output", {})),
            )
            for item in restored_results
        ]
        prior_context = dict(
            progress.get("prior_context")
            or {"results": [], "successful": [], "partial": [], "failed": []}
        )
        for stage_offset in range(start_stage_index, len(automation["action_stages"])):
            stage = automation["action_stages"][stage_offset]
            stage_index = stage_offset + 1
            delay_seconds = int(stage.get("delay_seconds", 0))
            if (
                stage_offset > 0
                and delay_seconds > 0
                and delay_completed_stage_id != stage["id"]
            ):
                if job_id:
                    deferred_progress = self._pipeline_progress(
                        stage_offset,
                        stage["id"],
                        action_results,
                        prior_context,
                    )
                    self.store.defer_job_for_stage(
                        job_id,
                        delay_seconds,
                        deferred_progress,
                    )
                    return None
                time.sleep(delay_seconds)
            stage_results = self._execute_stage(
                stage, trigger, prior_context, stage_index
            )
            action_results.extend(stage_results)
            self._add_stage_context(
                prior_context,
                stage,
                stage_results,
            )
            delay_completed_stage_id = ""
            policy = stage["continue_policy"]
            statuses = [result.status for result in stage_results]
            should_continue = stage_should_continue(policy, statuses)
            next_stage_index = (
                stage_offset + 1
                if should_continue
                else len(automation["action_stages"])
            )
            if job_id:
                self.store.save_job_progress(
                    job_id,
                    self._pipeline_progress(
                        next_stage_index,
                        delay_completed_stage_id,
                        action_results,
                        prior_context,
                    ),
                )
            if not should_continue:
                break
        return action_results

    @staticmethod
    def _pipeline_progress(
        next_stage_index: int,
        delay_completed_stage_id: str,
        action_results: list[ActionResult],
        prior_context: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "next_stage_index": next_stage_index,
            "delay_completed_stage_id": delay_completed_stage_id,
            "action_results": [
                {
                    "status": result.status,
                    "summary": result.summary,
                    "output": result.output,
                }
                for result in action_results
            ],
            "prior_context": prior_context,
        }

    def _add_stage_context(
        self,
        prior_context: dict[str, Any],
        stage: dict[str, Any],
        stage_results: list[ActionResult],
    ) -> None:
        for action_definition, result in zip(stage["actions"], stage_results):
            item = {
                "id": action_definition["id"],
                "name": action_definition["name"],
                "type": action_definition["type"],
                "stage_id": stage["id"],
                "stage_name": stage["name"],
                "status": result.status,
                "summary": result.summary,
                "output": self._bounded_action_context(result.output),
            }
            prior_context["results"].append(item)
            bucket = (
                "successful"
                if result.status == "success"
                else "partial"
                if result.status == "partial"
                else "failed"
            )
            prior_context[bucket].append(action_definition["name"])

    def _execute_stage(
        self,
        stage: dict[str, Any],
        trigger: ConditionResult,
        prior_context: dict[str, Any],
        stage_index: int,
    ) -> list[ActionResult]:
        contextual_trigger = ConditionResult(
            trigger.met,
            trigger.status,
            trigger.summary,
            {**trigger.evidence, "actions": prior_context},
        )

        def execute(action_definition: dict[str, Any]) -> ActionResult:
            try:
                action = self.registry.actions[action_definition["type"]]
                result = action.execute(
                    {
                        **action_definition["config"],
                        "_instance_path": str(self.store.instance_path),
                        "_action_name": action_definition["name"],
                    },
                    contextual_trigger,
                )
                return ActionResult(
                    result.status,
                    result.summary,
                    {
                        **result.output,
                        "_pipeline": {
                            "action_id": action_definition["id"],
                            "action_name": action_definition["name"],
                            "stage_id": stage["id"],
                            "stage_name": stage["name"],
                            "stage_index": stage_index,
                        },
                    },
                )
            except Exception as exc:
                return ActionResult(
                    status="error",
                    summary=(
                        f"{action_definition['type']} failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                    output={
                        "_pipeline": {
                            "action_id": action_definition["id"],
                            "action_name": action_definition["name"],
                            "stage_id": stage["id"],
                            "stage_name": stage["name"],
                            "stage_index": stage_index,
                        }
                    },
                )

        actions = stage["actions"]
        results: list[ActionResult | None] = [None] * len(actions)
        with ThreadPoolExecutor(max_workers=min(len(actions), 20)) as executor:
            futures = {
                executor.submit(execute, action): index
                for index, action in enumerate(actions)
            }
            for future in as_completed(futures):
                results[futures[future]] = future.result()
        return [result for result in results if result is not None]

    @staticmethod
    def _bounded_action_context(output: dict[str, Any]) -> dict[str, Any]:
        context: dict[str, Any] = {}
        for key, value in output.items():
            if key == "hosts" and isinstance(value, list):
                context["hosts"] = [
                    {
                        "host": item.get("host"),
                        "host_label": item.get("host_label", ""),
                        "status": item.get("status"),
                        "error": str(item.get("error", ""))[:500],
                    }
                    for item in value[:100]
                ]
            elif key == "transfers" and isinstance(value, list):
                context["transfers"] = [
                    {
                        "host": item.get("host"),
                        "host_label": item.get("host_label", ""),
                        "remote_path": str(item.get("remote_path", ""))[:500],
                        "status": item.get("status"),
                        "filename": str(item.get("filename", ""))[:255],
                        "stored_path": str(item.get("stored_path", ""))[:500],
                        "size": item.get("size", 0),
                        "error": str(item.get("error", ""))[:500],
                    }
                    for item in value[:200]
                ]
            elif key != "_pipeline" and isinstance(value, (str, int, float, bool, type(None))):
                context[key] = value[:2000] if isinstance(value, str) else value
        return context


class AutomationBackupStore:
    """Profile-backup adapter that excludes runtime state and incident history."""

    def __init__(self, store: AutomationStore) -> None:
        self.store = store

    def all(self) -> list[dict[str, Any]]:
        sources = [
            {
                "name": (
                    f"schedule::{item['name']}"
                    if item["type"] == "schedule.calendar"
                    else f"startup::{item['name']}"
                    if item["type"] == "system.startup"
                    else f"manual::{item['name']}"
                    if item["type"] == "manual.trigger"
                    else f"condition::{item['name']}"
                ),
                "kind": (
                    "schedule"
                    if item["type"] == "schedule.calendar"
                    else "startup"
                    if item["type"] == "system.startup"
                    else "manual"
                    if item["type"] == "manual.trigger"
                    else "condition"
                ),
                "definition_name": item["name"],
                "type": item["type"],
                "config": item["config"],
            }
            for item in self.store.source_definitions()
        ]
        actions = [
            {
                "name": f"action::{item['name']}",
                "kind": "action",
                "definition_name": item["name"],
                "type": item["type"],
                "config": item["config"],
            }
            for item in self.store.action_definitions(include_secrets=True)
        ]
        automations = [
            {
                "name": f"automation::{item['name']}",
                "kind": "automation",
                "automation_name": item["name"],
                "interval_seconds": item["interval_seconds"],
                "trigger_after": item["trigger_after"],
                "recover_after": item["recover_after"],
                "cooldown_seconds": item["cooldown_seconds"],
                "condition_name": item["condition"]["name"],
                "condition_names": [
                    condition["name"] for condition in item["conditions"]
                ],
                "condition_operator": item["condition_operator"],
                "action_names": [action["name"] for action in item["actions"]],
                "action_stages": [
                    {
                        "id": stage["id"],
                        "name": stage["name"],
                        "continue_policy": stage["continue_policy"],
                        "delay_seconds": stage["delay_seconds"],
                        "action_names": [action["name"] for action in stage["actions"]],
                    }
                    for stage in item["action_stages"]
                ],
            }
            for item in self.store.all(include_secrets=True)
        ]
        return [*sources, *actions, *automations]

    def count(self) -> int:
        return (
            len(self.store.source_definitions())
            + len(self.store.action_definitions())
            + len(self.store.all())
        )

    def replace_all(self, definitions: list[dict[str, Any]]) -> None:
        conditions: dict[str, tuple[str, dict[str, Any]]] = {}
        actions: dict[str, tuple[str, dict[str, Any]]] = {}
        automations: list[dict[str, Any]] = []
        for definition in definitions:
            kind = definition.get("kind")
            if kind in {"condition", "trigger", "schedule", "manual", "startup"}:
                name = str(definition.get("definition_name", ""))
                type_id = str(definition.get("type", ""))
                conditions[name] = (
                    type_id,
                    (
                        AUTOMATION_REGISTRY.validate_trigger(
                            type_id, dict(definition.get("config", {}))
                        )
                        if type_id in AUTOMATION_REGISTRY.triggers
                        else AUTOMATION_REGISTRY.validate_condition(
                            type_id, dict(definition.get("config", {}))
                        )
                    ),
                )
            elif kind == "action":
                name = str(definition.get("definition_name", ""))
                type_id = str(definition.get("type", ""))
                actions[name] = (
                    type_id,
                    AUTOMATION_REGISTRY.validate_action(
                        type_id, dict(definition.get("config", {}))
                    ),
                )
            elif kind == "automation":
                automations.append(definition)
            else:
                # Compatibility with the first embedded-definition backup format.
                condition = dict(definition.get("condition", {}))
                condition_name = str(condition.get("name") or f"{definition['name']} condition")
                condition_type = str(condition.get("type", ""))
                conditions[condition_name] = (
                    condition_type,
                    (
                        AUTOMATION_REGISTRY.validate_trigger(
                            condition_type, dict(condition.get("config", {}))
                        )
                        if condition_type in AUTOMATION_REGISTRY.triggers
                        else AUTOMATION_REGISTRY.validate_condition(
                            condition_type, dict(condition.get("config", {}))
                        )
                    ),
                )
                action_names = []
                for index, action in enumerate(definition.get("actions", []), 1):
                    action_name = str(
                        action.get("name")
                        or f"{definition['name']} action{'' if index == 1 else f' {index}'}"
                    )
                    action_type = str(action.get("type", ""))
                    actions[action_name] = (
                        action_type,
                        AUTOMATION_REGISTRY.validate_action(
                            action_type, dict(action.get("config", {}))
                        ),
                    )
                    action_names.append(action_name)
                automations.append(
                    {
                        **definition,
                        "automation_name": definition["name"],
                        "condition_name": condition_name,
                        "action_names": action_names,
                    }
                )
        self.store.clear()
        condition_ids = {
            name: self.store.save_condition_definition(
                name=name, type_id=value[0], config=value[1]
            )
            for name, value in conditions.items()
        }
        action_ids = {
            name: self.store.save_action_definition(
                name=name, type_id=value[0], config=value[1]
            )
            for name, value in actions.items()
        }
        for definition in automations:
            condition_names = [
                str(name)
                for name in definition.get("condition_names", [])
                if str(name)
            ]
            if not condition_names:
                condition_names = [str(definition.get("condition_name", ""))]
            selected_action_names = [str(name) for name in definition.get("action_names", [])]
            stage_definitions = definition.get("action_stages") or [{
                "id": "stage-1", "name": "Stage 1",
                "continue_policy": "all_completed",
                "delay_seconds": 0,
                "action_names": selected_action_names,
            }]
            if any(name not in condition_ids for name in condition_names) or any(
                name not in action_ids for name in selected_action_names
            ):
                raise ValueError("Automation backup references a missing condition or action.")
            self.store.save(
                name=str(definition.get("automation_name", "")),
                interval_seconds=int(definition.get("interval_seconds", 30)),
                trigger_after=int(definition.get("trigger_after", 3)),
                recover_after=int(definition.get("recover_after", 3)),
                cooldown_seconds=int(definition.get("cooldown_seconds", 300)),
                condition_definition_ids=[
                    condition_ids[name] for name in condition_names
                ],
                condition_operator=str(
                    definition.get("condition_operator", "all")
                ),
                action_stages=[
                    {
                        "id": str(stage.get("id", "")),
                        "name": str(stage.get("name", "")),
                        "continue_policy": str(stage.get("continue_policy", "all_completed")),
                        "delay_seconds": int(stage.get("delay_seconds", 0)),
                        "action_definition_ids": [
                            action_ids[str(name)] for name in stage.get("action_names", [])
                        ],
                    }
                    for stage in stage_definitions
                ],
                created_by="backup-import",
            )

    def import_records(
        self, definitions: list[dict[str, Any]], import_mode: str
    ) -> int:
        if import_mode != "merge":
            raise ValueError(
                "Automation definitions support Combine only so runtime history remains attached to its local automation."
            )

        # Fully exercise the existing compatibility parser and validators in an
        # isolated store before changing the destination database.
        with tempfile.TemporaryDirectory() as directory:
            validation_store = AutomationBackupStore(
                AutomationStore(directory, secrets.token_urlsafe(48))
            )
            validation_store.replace_all(deepcopy(definitions))
            validated = validation_store.all()

        source_definitions = [
            item
            for item in validated
            if item.get("kind")
            in {"condition", "trigger", "schedule", "manual", "startup"}
        ]
        action_definitions = [
            item for item in validated if item.get("kind") == "action"
        ]
        automations = [
            item for item in validated if item.get("kind") == "automation"
        ]

        existing_sources = {
            str(item["name"]).casefold(): item
            for item in self.store.source_definitions()
        }
        condition_ids: dict[str, str] = {}
        for item in source_definitions:
            name = str(item["definition_name"])
            existing = existing_sources.get(name.casefold())
            condition_ids[name] = self.store.save_condition_definition(
                name=name,
                type_id=str(item["type"]),
                config=dict(item["config"]),
                definition_id=str(existing["id"]) if existing else "",
            )

        existing_actions = {
            str(item["name"]).casefold(): item
            for item in self.store.action_definitions(include_secrets=True)
        }
        action_ids: dict[str, str] = {}
        for item in action_definitions:
            name = str(item["definition_name"])
            existing = existing_actions.get(name.casefold())
            action_ids[name] = self.store.save_action_definition(
                name=name,
                type_id=str(item["type"]),
                config=dict(item["config"]),
                definition_id=str(existing["id"]) if existing else "",
            )

        existing_automations = {
            str(item["name"]).casefold(): item
            for item in self.store.all(include_secrets=True)
        }
        for definition in automations:
            condition_names = [
                str(name)
                for name in definition.get("condition_names", [])
                if str(name)
            ] or [str(definition.get("condition_name", ""))]
            selected_action_names = [
                str(name) for name in definition.get("action_names", [])
            ]
            if any(name not in condition_ids for name in condition_names) or any(
                name not in action_ids for name in selected_action_names
            ):
                raise ValueError(
                    "Automation backup references a missing condition or action."
                )
            action_stages = [
                {
                    "id": str(stage.get("id", "")),
                    "name": str(stage.get("name", "")),
                    "continue_policy": str(
                        stage.get("continue_policy", "all_completed")
                    ),
                    "delay_seconds": int(stage.get("delay_seconds", 0)),
                    "action_definition_ids": [
                        action_ids[str(name)]
                        for name in stage.get("action_names", [])
                    ],
                }
                for stage in definition.get("action_stages", [])
            ]
            automation_name = str(definition["automation_name"])
            existing = existing_automations.get(automation_name.casefold())
            self.store.save(
                name=automation_name,
                interval_seconds=int(definition["interval_seconds"]),
                trigger_after=int(definition["trigger_after"]),
                recover_after=int(definition["recover_after"]),
                cooldown_seconds=int(definition["cooldown_seconds"]),
                condition_definition_ids=[
                    condition_ids[name] for name in condition_names
                ],
                condition_operator=str(
                    definition.get("condition_operator", "all")
                ),
                action_stages=action_stages,
                created_by="backup-import",
                automation_id=str(existing["id"]) if existing else "",
            )
        return len(validated)

    def backup_snapshot(self) -> dict[str, list[dict[str, Any]]]:
        with self.store._connect() as connection:
            return {
                table: [
                    dict(row)
                    for row in connection.execute(f"SELECT * FROM {table}")
                ]
                for table in (
                    "automation_conditions",
                    "automation_actions",
                    "automations",
                    "automation_event_state",
                )
            }

    def restore_backup_snapshot(
        self, snapshot: dict[str, list[dict[str, Any]]]
    ) -> None:
        with self.store._connect() as connection:
            self._remove_added_rows(
                connection,
                "automations",
                "id",
                snapshot["automations"],
            )
            self._upsert_snapshot_rows(
                connection,
                "automation_conditions",
                "id",
                snapshot["automation_conditions"],
            )
            self._upsert_snapshot_rows(
                connection,
                "automation_actions",
                "id",
                snapshot["automation_actions"],
            )
            self._upsert_snapshot_rows(
                connection,
                "automations",
                "id",
                snapshot["automations"],
            )
            self._remove_added_rows(
                connection,
                "automation_conditions",
                "id",
                snapshot["automation_conditions"],
            )
            self._remove_added_rows(
                connection,
                "automation_actions",
                "id",
                snapshot["automation_actions"],
            )
            automation_ids = [str(row["id"]) for row in snapshot["automations"]]
            if automation_ids:
                connection.execute(
                    "DELETE FROM automation_event_state WHERE automation_id IN "
                    f"({', '.join('?' for _ in automation_ids)})",
                    tuple(automation_ids),
                )
            self._upsert_snapshot_rows(
                connection,
                "automation_event_state",
                "automation_id",
                snapshot["automation_event_state"],
            )

    @staticmethod
    def _remove_added_rows(
        connection: sqlite3.Connection,
        table: str,
        key: str,
        snapshot_rows: list[dict[str, Any]],
    ) -> None:
        snapshot_ids = {str(row[key]) for row in snapshot_rows}
        current_ids = {
            str(row[0])
            for row in connection.execute(f"SELECT {key} FROM {table}")
        }
        added_ids = current_ids - snapshot_ids
        if added_ids:
            connection.execute(
                f"DELETE FROM {table} WHERE {key} IN "
                f"({', '.join('?' for _ in added_ids)})",
                tuple(added_ids),
            )

    @staticmethod
    def _upsert_snapshot_rows(
        connection: sqlite3.Connection,
        table: str,
        key: str,
        rows: list[dict[str, Any]],
    ) -> None:
        for row in rows:
            columns = list(row)
            updated = [column for column in columns if column != key]
            connection.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _ in columns)}) "
                f"ON CONFLICT({key}) DO UPDATE SET "
                + ", ".join(
                    f"{column} = excluded.{column}" for column in updated
                ),
                tuple(row[column] for column in columns),
            )

    def clear(self) -> None:
        self.store.clear()
