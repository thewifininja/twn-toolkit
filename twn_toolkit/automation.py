from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from cryptography.fernet import Fernet, InvalidToken

from .automation_registry import (
    AUTOMATION_REGISTRY,
    ActionResult,
    AutomationRegistry,
    ConditionResult,
)
from .schedule_tools import schedule_occurrence, schedule_should_fire


class AutomationStore:
    """SQLite persistence for automation definitions, state, checks, and runs."""

    def __init__(self, instance_path: str, secret_key: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "automations.sqlite3"
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
        if not condition_definition_id:
            if not condition:
                raise ValueError("Select an automation condition.")
            condition_definition_id = self.save_condition_definition(
                name=f"{name} condition",
                type_id=str(condition["type"]),
                config=dict(condition["config"]),
            )
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
        condition_definition = self.get_condition_definition(condition_definition_id)
        if not condition_definition:
            raise ValueError("Selected condition definition was not found.")
        action_definitions = [
            self.get_action_definition(action_id, include_secrets=True)
            for action_id in action_definition_ids
        ]
        if not action_definitions or any(action is None for action in action_definitions):
            raise ValueError("One or more selected action definitions were not found.")
        condition = {
            "type": condition_definition["type"],
            "config": condition_definition["config"],
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
                        condition_definition_id = ?, action_definition_ids = ?,
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
                        json.dumps(action_definition_ids),
                        json.dumps(action_stages, separators=(",", ":")),
                        now,
                        automation_id,
                    ),
                )
                return automation_id

            automation_id = secrets.token_hex(12)
            connection.execute(
                """
                INSERT INTO automations (
                    id, name, enabled, interval_seconds, trigger_after, recover_after,
                    cooldown_seconds, condition_type, condition_config, actions_encrypted,
                    condition_definition_id, action_definition_ids, action_stages,
                    state, consecutive_met, consecutive_clear, next_check_at,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'disabled', 0, 0, NULL, ?, ?, ?)
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
                "action_definition_ids": legacy_action_ids,
            }]
        normalized = []
        seen_stage_ids: set[str] = set()
        seen_action_ids: set[str] = set()
        for index, raw in enumerate(stages, 1):
            stage_id = str(raw.get("id", "")).strip() or f"stage-{index}"
            if stage_id in seen_stage_ids or len(stage_id) > 80:
                raise ValueError("Every automation stage must have a unique stable ID.")
            seen_stage_ids.add(stage_id)
            name = " ".join(str(raw.get("name", "")).strip().split()) or f"Stage {index}"
            if len(name) > 100:
                raise ValueError("Stage names must be 100 characters or fewer.")
            policy = str(raw.get("continue_policy", "all_completed"))
            if policy not in {"all_completed", "success_or_partial", "all_success"}:
                raise ValueError("Select a valid stage continuation policy.")
            action_ids = [str(value).strip() for value in raw.get("action_definition_ids", []) if str(value).strip()]
            if not action_ids:
                raise ValueError(f"{name} must contain at least one action.")
            if any(action_id in seen_action_ids for action_id in action_ids):
                raise ValueError("Each reusable action may appear only once in an automation pipeline.")
            seen_action_ids.update(action_ids)
            normalized.append({
                "id": stage_id,
                "name": name,
                "continue_policy": policy,
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
            if connection.execute(
                "SELECT 1 FROM automations WHERE condition_definition_id = ? LIMIT 1",
                (definition_id,),
            ).fetchone():
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

    def claim_due(self, limit: int = 10) -> list[dict[str, Any]]:
        now = time.time()
        claimed: list[sqlite3.Row] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT automations.*,
                    COALESCE(automation_conditions.type, automations.condition_type)
                        AS effective_condition_type
                FROM automations
                LEFT JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE enabled = 1
                    AND COALESCE(automation_conditions.type, automations.condition_type) != 'manual.trigger'
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
                (now, now, limit),
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
                    connection.execute(
                        "UPDATE automations SET next_check_at = ? WHERE id = ?",
                        (now + int(row["interval_seconds"]), row["id"]),
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
            result = ConditionResult(
                met=should_fire,
                status=status,
                summary=summary,
                evidence={
                    "trigger": "schedule",
                    "occurrence": occurrence,
                    "lateness_seconds": lateness_seconds,
                },
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

    def record_condition(
        self, automation_id: str, result: ConditionResult
    ) -> tuple[dict[str, Any], bool]:
        now = time.time()
        should_fire = False
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM automations WHERE id = ?", (automation_id,)
            ).fetchone()
            if not row:
                raise ValueError("Automation not found.")
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
                    now,
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
                    now,
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

    def record_error(self, automation_id: str, message: str) -> None:
        now = time.time()
        with self._connect() as connection:
            condition_type_row = connection.execute(
                """
                SELECT COALESCE(automation_conditions.type, automations.condition_type) AS type
                FROM automations LEFT JOIN automation_conditions
                    ON automation_conditions.id = automations.condition_definition_id
                WHERE automations.id = ?
                """,
                (automation_id,),
            ).fetchone()
            is_schedule = bool(
                condition_type_row and condition_type_row["type"] == "schedule.calendar"
            )
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
                VALUES (?, ?, 0, 'error', ?, '{}')
                """,
                (automation_id, now, message[:2000]),
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
        payload = [
            {"status": result.status, "summary": result.summary, "output": result.output}
            for result in results
        ]
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
            cursor = connection.execute(
                "DELETE FROM automation_runs WHERE id = ?", (run_id,)
            )
            if not cursor.rowcount:
                raise ValueError("Collected action run not found.")

    def clear_runs(self, automation_id: str) -> int:
        with self._connect() as connection:
            if not connection.execute(
                "SELECT 1 FROM automations WHERE id = ?", (automation_id,)
            ).fetchone():
                raise ValueError("Automation not found.")
            cursor = connection.execute(
                "DELETE FROM automation_runs WHERE automation_id = ?", (automation_id,)
            )
            return int(cursor.rowcount)

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

    def _automation_from_row(
        self, row: sqlite3.Row, include_secrets: bool
    ) -> dict[str, Any]:
        condition_definition_id = str(row["condition_definition_id"] or "")
        action_definition_ids = json.loads(row["action_definition_ids"] or "[]")
        condition = self.get_condition_definition(condition_definition_id)
        action_map = {}
        for action_id in action_definition_ids:
            action = self.get_action_definition(action_id, include_secrets=include_secrets)
            if action is not None:
                action_map[action_id] = action
        raw_stages = json.loads(row["action_stages"] or "null")
        normalized_stages = self._normalize_action_stages(raw_stages, action_definition_ids)
        stages = [
            {
                **stage,
                "actions": [
                    action_map[action_id]
                    for action_id in stage["action_definition_ids"]
                    if action_id in action_map
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
        connection.execute(
            """
            UPDATE automations SET enabled = 0, state = 'disabled',
                consecutive_met = 0, consecutive_clear = 0, next_check_at = NULL,
                pending_schedule_at = NULL,
                updated_at = ? WHERE condition_definition_id = ?
            """,
            (now, definition_id),
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
            CREATE TABLE IF NOT EXISTS automation_schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at REAL NOT NULL,
                description TEXT NOT NULL
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
                "action_definition_ids": action_ids,
            }]
            connection.execute(
                "UPDATE automations SET condition_definition_id = ?, action_definition_ids = ?, action_stages = ? WHERE id = ?",
                (
                    condition_id,
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

    def test_condition(self, automation: dict[str, Any]) -> ConditionResult:
        condition = self.registry.conditions[automation["condition"]["type"]]
        return condition.evaluate(automation["condition"]["config"])

    def run_once(self) -> int:
        processed = 0
        for automation in self.store.claim_due():
            processed += 1
            if automation["condition"]["type"] == "schedule.calendar":
                try:
                    updated, result, should_fire = self.store.record_schedule_occurrence(
                        automation["id"]
                    )
                except Exception as exc:
                    self.store.record_error(
                        automation["id"], f"{type(exc).__name__}: {exc}"
                    )
                    continue
                if should_fire:
                    self.execute_actions(updated, result)
                continue
            try:
                result = self.test_condition(automation)
            except Exception as exc:
                self.store.record_error(
                    automation["id"], f"{type(exc).__name__}: {exc}"
                )
                continue
            updated, should_fire = self.store.record_condition(automation["id"], result)
            if not should_fire:
                continue
            self.execute_actions(updated, result)
        return processed

    def execute_actions(
        self, automation: dict[str, Any], trigger: ConditionResult
    ) -> str:
        action_results: list[ActionResult] = []
        prior_context: dict[str, Any] = {
            "results": [], "successful": [], "partial": [], "failed": []
        }
        for stage_index, stage in enumerate(automation["action_stages"], 1):
            stage_results = self._execute_stage(
                stage, trigger, prior_context, stage_index
            )
            action_results.extend(stage_results)
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
                bucket = "successful" if result.status == "success" else "partial" if result.status == "partial" else "failed"
                prior_context[bucket].append(action_definition["name"])
            policy = stage["continue_policy"]
            statuses = [result.status for result in stage_results]
            should_continue = (
                policy == "all_completed"
                or (policy == "success_or_partial" and all(status in {"success", "partial"} for status in statuses))
                or (policy == "all_success" and all(status == "success" for status in statuses))
            )
            if not should_continue:
                break
        return self.store.record_run(automation["id"], trigger, action_results)

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
                result = action.execute(action_definition["config"], contextual_trigger)
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
            elif key != "_pipeline" and isinstance(value, (str, int, float, bool, type(None))):
                context[key] = value[:2000] if isinstance(value, str) else value
        return context


class AutomationBackupStore:
    """Profile-backup adapter that excludes runtime state and incident history."""

    def __init__(self, store: AutomationStore) -> None:
        self.store = store

    def all(self) -> list[dict[str, Any]]:
        conditions = [
            {
                "name": f"condition::{item['name']}",
                "kind": "condition",
                "definition_name": item["name"],
                "type": item["type"],
                "config": item["config"],
            }
            for item in self.store.condition_definitions()
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
                "action_names": [action["name"] for action in item["actions"]],
                "action_stages": [
                    {
                        "id": stage["id"],
                        "name": stage["name"],
                        "continue_policy": stage["continue_policy"],
                        "action_names": [action["name"] for action in stage["actions"]],
                    }
                    for stage in item["action_stages"]
                ],
            }
            for item in self.store.all(include_secrets=True)
        ]
        return [*conditions, *actions, *automations]

    def replace_all(self, definitions: list[dict[str, Any]]) -> None:
        conditions: dict[str, tuple[str, dict[str, Any]]] = {}
        actions: dict[str, tuple[str, dict[str, Any]]] = {}
        automations: list[dict[str, Any]] = []
        for definition in definitions:
            kind = definition.get("kind")
            if kind == "condition":
                name = str(definition.get("definition_name", ""))
                type_id = str(definition.get("type", ""))
                conditions[name] = (
                    type_id,
                    AUTOMATION_REGISTRY.validate_condition(
                        type_id, dict(definition.get("config", {}))
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
                    AUTOMATION_REGISTRY.validate_condition(
                        condition_type, dict(condition.get("config", {}))
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
            condition_name = str(definition.get("condition_name", ""))
            selected_action_names = [str(name) for name in definition.get("action_names", [])]
            stage_definitions = definition.get("action_stages") or [{
                "id": "stage-1", "name": "Stage 1",
                "continue_policy": "all_completed",
                "action_names": selected_action_names,
            }]
            if condition_name not in condition_ids or any(
                name not in action_ids for name in selected_action_names
            ):
                raise ValueError("Automation backup references a missing condition or action.")
            self.store.save(
                name=str(definition.get("automation_name", "")),
                interval_seconds=int(definition.get("interval_seconds", 30)),
                trigger_after=int(definition.get("trigger_after", 3)),
                recover_after=int(definition.get("recover_after", 3)),
                cooldown_seconds=int(definition.get("cooldown_seconds", 300)),
                condition_definition_id=condition_ids[condition_name],
                action_stages=[
                    {
                        "id": str(stage.get("id", "")),
                        "name": str(stage.get("name", "")),
                        "continue_policy": str(stage.get("continue_policy", "all_completed")),
                        "action_definition_ids": [
                            action_ids[str(name)] for name in stage.get("action_names", [])
                        ],
                    }
                    for stage in stage_definitions
                ],
                created_by="backup-import",
            )

    def clear(self) -> None:
        self.store.clear()
