from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from .datastore import DatastoreError, LocalDatastore, MAX_UPLOAD_BYTES
from .time_settings import TimeSettingsStore, localized_time_values


OPEN_STATES = frozenset({"recording", "paused"})
INVESTIGATION_STATES = frozenset({*OPEN_STATES, "completed", "archived"})
EVENT_OUTCOMES = frozenset(
    {"succeeded", "failed", "cancelled", "incomplete", "info"}
)
MAX_EVENT_JSON_BYTES = 4 * 1024 * 1024
SCHEMA_VERSION = 2


class InvestigationError(ValueError):
    pass


class InvestigationStore:
    """Durable investigations, immutable journal events, and evidence metadata."""

    def __init__(self, instance_path: str | Path) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "investigations.sqlite3"
        self.initialization_lock_path = self.instance_path / ".investigations.sqlite3.init.lock"
        self.datastore = LocalDatastore(str(self.instance_path))

    def create(
        self,
        *,
        owner_user_id: str,
        owner_username: str,
        title: str,
        description: str = "",
    ) -> dict[str, Any]:
        clean_title = self._clean_text(title, "Case title", 120, required=True)
        clean_description = self._clean_text(description, "Description", 2_000)
        user_id = self._clean_identity(owner_user_id, "owner")
        username = self._clean_identity(owner_username, "operator")
        investigation_id = f"inv_{secrets.token_hex(12)}"
        datastore_path = self._prepare_datastore_folders(investigation_id)
        now = time.time()
        try:
            with self._connect() as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    """
                    SELECT i.id FROM investigations i
                    JOIN investigation_participants p ON p.investigation_id = i.id
                    WHERE p.user_id = ? AND i.state IN ('recording', 'paused')
                    LIMIT 1
                    """,
                    (user_id,),
                ).fetchone()
                if existing:
                    raise InvestigationError(
                        "Close the current case before starting another one."
                    )
                connection.execute(
                    """
                    INSERT INTO investigations (
                        id, title, description, owner_user_id, owner_username,
                        state, datastore_path, created_at, started_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'recording', ?, ?, ?, ?)
                    """,
                    (
                        investigation_id,
                        clean_title,
                        clean_description,
                        user_id,
                        username,
                        datastore_path,
                        now,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO investigation_participants (
                        investigation_id, user_id, username, role,
                        added_by_user_id, added_by_username, created_at
                    ) VALUES (?, ?, ?, 'owner', ?, ?, ?)
                    """,
                    (
                        investigation_id,
                        user_id,
                        username,
                        user_id,
                        username,
                        now,
                    ),
                )
                self._insert_event(
                    connection,
                    investigation_id=investigation_id,
                    operation_id=f"investigation-created:{investigation_id}",
                    event_type="investigation.started",
                    tool_id="investigations.workspace",
                    action="Case opened",
                    outcome="info",
                    summary=f"Opened case: {clean_title}.",
                    targets=[],
                    parameters={},
                    metrics={},
                    details={},
                    started_at=now,
                    completed_at=now,
                    created_by_user_id=user_id,
                    created_by_username=username,
                )
        except sqlite3.IntegrityError as exc:
            raise InvestigationError(
                "Close the current case before starting another one."
            ) from exc
        return self.get_for_user(investigation_id, user_id)

    def list_for_user(self, user_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT i.*, p.role AS access_role,
                    (SELECT COUNT(*) FROM investigation_events e
                     WHERE e.investigation_id = i.id) AS event_count,
                    (SELECT COUNT(*) FROM investigation_artifacts a
                     WHERE a.investigation_id = i.id) AS artifact_count,
                    (SELECT COUNT(*) FROM investigation_participants members
                     WHERE members.investigation_id = i.id) AS participant_count
                FROM investigations i
                JOIN investigation_participants p ON p.investigation_id = i.id
                WHERE p.user_id = ?
                ORDER BY
                    CASE i.state
                        WHEN 'recording' THEN 0
                        WHEN 'paused' THEN 1
                        WHEN 'completed' THEN 2
                        ELSE 3
                    END,
                    i.updated_at DESC
                """,
                (self._clean_identity(user_id, "user"),),
            ).fetchall()
        return [self._investigation(row) for row in rows]

    def active_for_user(self, user_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT i.*, p.role AS access_role,
                    (SELECT COUNT(*) FROM investigation_events e
                     WHERE e.investigation_id = i.id) AS event_count,
                    (SELECT COUNT(*) FROM investigation_artifacts a
                     WHERE a.investigation_id = i.id) AS artifact_count,
                    (SELECT COUNT(*) FROM investigation_participants members
                     WHERE members.investigation_id = i.id) AS participant_count
                FROM investigations i
                JOIN investigation_participants p ON p.investigation_id = i.id
                WHERE p.user_id = ? AND i.state IN ('recording', 'paused')
                ORDER BY CASE p.role WHEN 'owner' THEN 0 ELSE 1 END, i.updated_at DESC
                LIMIT 1
                """,
                (self._clean_identity(user_id, "user"),),
            ).fetchone()
        return self._investigation(row) if row else None

    def get_for_user(self, investigation_id: str, user_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT i.*, p.role AS access_role,
                    (SELECT COUNT(*) FROM investigation_events e
                     WHERE e.investigation_id = i.id) AS event_count,
                    (SELECT COUNT(*) FROM investigation_artifacts a
                     WHERE a.investigation_id = i.id) AS artifact_count,
                    (SELECT COUNT(*) FROM investigation_participants members
                     WHERE members.investigation_id = i.id) AS participant_count
                FROM investigations i
                JOIN investigation_participants p ON p.investigation_id = i.id
                WHERE i.id = ? AND p.user_id = ?
                """,
                (investigation_id, self._clean_identity(user_id, "user")),
            ).fetchone()
        if not row:
            raise InvestigationError("Case not found.")
        return self._investigation(row)

    def participants_for_user(
        self, investigation_id: str, user_id: str
    ) -> list[dict[str, Any]]:
        self.get_for_user(investigation_id, user_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM investigation_participants
                WHERE investigation_id = ?
                ORDER BY CASE role WHEN 'owner' THEN 0 ELSE 1 END,
                    username COLLATE NOCASE, user_id
                """,
                (investigation_id,),
            ).fetchall()
        return [self._participant(row) for row in rows]

    def add_participant(
        self,
        investigation_id: str,
        owner_user_id: str,
        owner_username: str,
        participant_user_id: str,
        participant_username: str,
    ) -> list[dict[str, Any]]:
        owner_user_id = self._clean_identity(owner_user_id, "owner")
        owner_username = self._clean_identity(owner_username, "operator")
        participant_user_id = self._clean_identity(participant_user_id, "user")
        participant_username = self._clean_identity(
            participant_username, "operator"
        )
        now = time.time()
        with self._connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            investigation = self._require_owner(
                connection, investigation_id, owner_user_id
            )
            if str(investigation["state"]) not in OPEN_STATES:
                raise InvestigationError(
                    "Collaborators can only be added while a case is open."
                )
            if participant_user_id == owner_user_id:
                raise InvestigationError("The case owner is already on this case.")
            existing = connection.execute(
                """
                SELECT 1 FROM investigation_participants
                WHERE investigation_id = ? AND user_id = ?
                """,
                (investigation_id, participant_user_id),
            ).fetchone()
            if existing:
                raise InvestigationError("That operator is already on this case.")
            active = connection.execute(
                """
                SELECT i.title FROM investigation_participants p
                JOIN investigations i ON i.id = p.investigation_id
                WHERE p.user_id = ? AND i.state IN ('recording', 'paused')
                LIMIT 1
                """,
                (participant_user_id,),
            ).fetchone()
            if active:
                raise InvestigationError(
                    f'{participant_username} is already active in case '
                    f'"{active["title"]}".'
                )
            connection.execute(
                """
                INSERT INTO investigation_participants (
                    investigation_id, user_id, username, role,
                    added_by_user_id, added_by_username, created_at
                ) VALUES (?, ?, ?, 'collaborator', ?, ?, ?)
                """,
                (
                    investigation_id,
                    participant_user_id,
                    participant_username,
                    owner_user_id,
                    owner_username,
                    now,
                ),
            )
            self._insert_event(
                connection,
                investigation_id=investigation_id,
                operation_id=f"participant-added:{secrets.token_hex(12)}",
                event_type="investigation.participant.added",
                tool_id="investigations.workspace",
                action="Collaborator added",
                outcome="info",
                summary=f"Added {participant_username} to the case.",
                targets=[],
                parameters={"role": "collaborator"},
                metrics={},
                details={
                    "participant_user_id": participant_user_id,
                    "participant_username": participant_username,
                },
                started_at=now,
                completed_at=now,
                created_by_user_id=owner_user_id,
                created_by_username=owner_username,
            )
            connection.execute(
                "UPDATE investigations SET updated_at = ? WHERE id = ?",
                (now, investigation_id),
            )
        return self.participants_for_user(investigation_id, owner_user_id)

    def remove_participant(
        self,
        investigation_id: str,
        owner_user_id: str,
        owner_username: str,
        participant_user_id: str,
    ) -> list[dict[str, Any]]:
        owner_user_id = self._clean_identity(owner_user_id, "owner")
        owner_username = self._clean_identity(owner_username, "operator")
        participant_user_id = self._clean_identity(participant_user_id, "user")
        now = time.time()
        with self._connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            investigation = self._require_owner(
                connection, investigation_id, owner_user_id
            )
            participant = connection.execute(
                """
                SELECT * FROM investigation_participants
                WHERE investigation_id = ? AND user_id = ?
                """,
                (investigation_id, participant_user_id),
            ).fetchone()
            if not participant:
                raise InvestigationError("That collaborator is not on this case.")
            if str(participant["role"]) == "owner":
                raise InvestigationError("The case owner cannot be removed.")
            connection.execute(
                """
                DELETE FROM investigation_participants
                WHERE investigation_id = ? AND user_id = ?
                """,
                (investigation_id, participant_user_id),
            )
            if str(investigation["state"]) in OPEN_STATES:
                self._insert_event(
                    connection,
                    investigation_id=investigation_id,
                    operation_id=f"participant-removed:{secrets.token_hex(12)}",
                    event_type="investigation.participant.removed",
                    tool_id="investigations.workspace",
                    action="Collaborator removed",
                    outcome="info",
                    summary=f'Removed {participant["username"]} from the case.',
                    targets=[],
                    parameters={"role": "collaborator"},
                    metrics={},
                    details={
                        "participant_user_id": participant_user_id,
                        "participant_username": str(participant["username"]),
                    },
                    started_at=now,
                    completed_at=now,
                    created_by_user_id=owner_user_id,
                    created_by_username=owner_username,
                )
                connection.execute(
                    "UPDATE investigations SET updated_at = ? WHERE id = ?",
                    (now, investigation_id),
                )
        return self.participants_for_user(investigation_id, owner_user_id)

    def events_for_user(
        self, investigation_id: str, user_id: str
    ) -> list[dict[str, Any]]:
        self.get_for_user(investigation_id, user_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM investigation_events
                WHERE investigation_id = ?
                ORDER BY started_at ASC, created_at ASC, id ASC
                """,
                (investigation_id,),
            ).fetchall()
        return [self._event(row) for row in rows]

    def artifacts_for_user(
        self, investigation_id: str, user_id: str
    ) -> list[dict[str, Any]]:
        self.get_for_user(investigation_id, user_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM investigation_artifacts
                WHERE investigation_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (investigation_id,),
            ).fetchall()
        return [self._artifact(row) for row in rows]

    def artifact_for_user(
        self, investigation_id: str, artifact_id: str, user_id: str
    ) -> dict[str, Any]:
        self.get_for_user(investigation_id, user_id)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM investigation_artifacts
                WHERE id = ? AND investigation_id = ?
                """,
                (artifact_id, investigation_id),
            ).fetchone()
        if not row:
            raise InvestigationError("Evidence file not found.")
        return self._artifact(row)

    def set_report_contents(
        self,
        investigation_id: str,
        user_id: str,
        *,
        event_ids: list[str],
        artifact_ids: list[str],
    ) -> dict[str, int]:
        """Update report presentation without changing retained source evidence."""
        user_id = self._clean_identity(user_id, "user")
        selected_events = {
            str(item).strip() for item in event_ids if str(item).strip()
        }
        selected_artifacts = {
            str(item).strip() for item in artifact_ids if str(item).strip()
        }
        if len(selected_events) > 10_000 or len(selected_artifacts) > 10_000:
            raise InvestigationError("The report selection is too large.")

        with self._connect() as connection, connection:
            self._require_owner(connection, investigation_id, user_id)
            available_events = {
                str(row["id"])
                for row in connection.execute(
                    "SELECT id FROM investigation_events WHERE investigation_id = ?",
                    (investigation_id,),
                ).fetchall()
            }
            available_artifacts = {
                str(row["id"])
                for row in connection.execute(
                    "SELECT id FROM investigation_artifacts WHERE investigation_id = ?",
                    (investigation_id,),
                ).fetchall()
            }
            if not selected_events.issubset(available_events):
                raise InvestigationError("The report contains an unknown journal event.")
            if not selected_artifacts.issubset(available_artifacts):
                raise InvestigationError("The report contains an unknown evidence file.")

            connection.execute(
                """
                UPDATE investigation_events
                SET report_placement = 'excluded'
                WHERE investigation_id = ?
                """,
                (investigation_id,),
            )
            connection.executemany(
                """
                UPDATE investigation_events
                SET report_placement = 'main'
                WHERE investigation_id = ? AND id = ?
                """,
                [(investigation_id, event_id) for event_id in selected_events],
            )
            connection.execute(
                """
                UPDATE investigation_artifacts
                SET report_placement = 'excluded'
                WHERE investigation_id = ?
                """,
                (investigation_id,),
            )
            connection.executemany(
                """
                UPDATE investigation_artifacts
                SET report_placement = 'appendix'
                WHERE investigation_id = ? AND id = ?
                """,
                [(investigation_id, artifact_id) for artifact_id in selected_artifacts],
            )
        return {
            "included_events": len(selected_events),
            "included_artifacts": len(selected_artifacts),
        }

    def set_state(
        self,
        investigation_id: str,
        user_id: str,
        username: str,
        state: str,
    ) -> dict[str, Any]:
        if state not in {"recording", "paused", "completed"}:
            raise InvestigationError("Choose a valid case state.")
        now = time.time()
        user_id = self._clean_identity(user_id, "user")
        username = self._clean_identity(username, "operator")
        try:
            with self._connect() as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                row = self._require_owner(connection, investigation_id, user_id)
                current = str(row["state"])
                if current == state:
                    participant_count = connection.execute(
                        """
                        SELECT COUNT(*) AS count
                        FROM investigation_participants
                        WHERE investigation_id = ?
                        """,
                        (investigation_id,),
                    ).fetchone()
                    result = self._investigation(row)
                    result["participant_count"] = int(participant_count["count"])
                    result["is_shared"] = result["participant_count"] > 1
                    return result
                reopening = current == "completed" and state == "paused"
                if current not in OPEN_STATES and not reopening:
                    if current == "completed" and state == "recording":
                        raise InvestigationError(
                            "Reopen the case in paused mode before resuming recording."
                        )
                    raise InvestigationError("Archived cases cannot be reopened.")
                if reopening:
                    existing = connection.execute(
                        """
                        SELECT current.username, current.role, other_case.title
                        FROM investigation_participants current
                        JOIN investigation_participants other
                          ON other.user_id = current.user_id
                         AND other.investigation_id != current.investigation_id
                        JOIN investigations other_case
                          ON other_case.id = other.investigation_id
                        WHERE current.investigation_id = ?
                          AND other_case.state IN ('recording', 'paused')
                        LIMIT 1
                        """,
                        (investigation_id,),
                    ).fetchone()
                    if existing:
                        if str(existing["role"]) == "owner":
                            raise InvestigationError(
                                f'Close the current case "{existing["title"]}" '
                                "before reopening this one."
                            )
                        raise InvestigationError(
                            f'{existing["username"]} is already active in case '
                            f'"{existing["title"]}". Remove that collaborator or '
                            "close the other case before reopening this one."
                        )
                ended_at = now if state == "completed" else None
                connection.execute(
                    """
                    UPDATE investigations
                    SET state = ?, ended_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (state, ended_at, now, investigation_id),
                )
                if reopening:
                    event_type = "investigation.reopened"
                    action = "Case reopened"
                    summary = "Reopened the case with automatic recording paused."
                else:
                    labels = {
                        "recording": (
                            "investigation.resumed",
                            "Case recording resumed",
                            "Resumed automatic journal recording for the case.",
                        ),
                        "paused": (
                            "investigation.paused",
                            "Case recording paused",
                            "Paused automatic journal recording for the case.",
                        ),
                        "completed": (
                            "investigation.completed",
                            "Case closed",
                            "Closed the troubleshooting case.",
                        ),
                    }
                    event_type, action, summary = labels[state]
                self._insert_event(
                    connection,
                    investigation_id=investigation_id,
                    operation_id=f"state:{state}:{secrets.token_hex(10)}",
                    event_type=event_type,
                    tool_id="investigations.workspace",
                    action=action,
                    outcome="info",
                    summary=summary,
                    targets=[],
                    parameters={"previous_state": current, "state": state},
                    metrics={},
                    details={},
                    started_at=now,
                    completed_at=now,
                    created_by_user_id=user_id,
                    created_by_username=username,
                )
        except sqlite3.IntegrityError as exc:
            raise InvestigationError(
                "Close the current case before reopening this one."
            ) from exc
        return self.get_for_user(investigation_id, user_id)

    def add_note(
        self,
        investigation_id: str,
        user_id: str,
        username: str,
        note: str,
    ) -> dict[str, Any]:
        clean_note = self._clean_text(note, "Note", 4_000, required=True)
        now = time.time()
        user_id = self._clean_identity(user_id, "user")
        with self._connect() as connection, connection:
            self._require_open_member(connection, investigation_id, user_id)
            event_id = self._insert_event(
                connection,
                investigation_id=investigation_id,
                operation_id=f"note:{secrets.token_hex(12)}",
                event_type="note.added",
                tool_id="investigations.workspace",
                action="Operator note",
                outcome="info",
                summary=clean_note,
                targets=[],
                parameters={},
                metrics={},
                details={},
                started_at=now,
                completed_at=now,
                created_by_user_id=user_id,
                created_by_username=self._clean_identity(username, "operator"),
            )
            connection.execute(
                "UPDATE investigations SET updated_at = ? WHERE id = ?",
                (now, investigation_id),
            )
            row = connection.execute(
                "SELECT * FROM investigation_events WHERE id = ?", (event_id,)
            ).fetchone()
        return self._event(row)

    def record_for_active(
        self,
        *,
        user_id: str,
        username: str,
        operation_id: str,
        event_type: str,
        tool_id: str,
        action: str,
        outcome: str,
        summary: str,
        targets: Any,
        parameters: Any,
        metrics: Any,
        details: Any,
        started_at: float,
        completed_at: float,
    ) -> dict[str, Any] | None:
        user_id = self._clean_identity(user_id, "user")
        with self._connect() as connection, connection:
            investigation = connection.execute(
                """
                SELECT i.id FROM investigations i
                JOIN investigation_participants p ON p.investigation_id = i.id
                WHERE p.user_id = ? AND i.state = 'recording'
                ORDER BY CASE p.role WHEN 'owner' THEN 0 ELSE 1 END, i.updated_at DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            if not investigation:
                return None
            event_id = self._insert_event(
                connection,
                investigation_id=str(investigation["id"]),
                operation_id=operation_id,
                event_type=event_type,
                tool_id=tool_id,
                action=action,
                outcome=outcome,
                summary=summary,
                targets=targets,
                parameters=parameters,
                metrics=metrics,
                details=details,
                started_at=started_at,
                completed_at=completed_at,
                created_by_user_id=user_id,
                created_by_username=self._clean_identity(username, "operator"),
            )
            connection.execute(
                """
                UPDATE investigations
                SET updated_at = MAX(updated_at, ?)
                WHERE id = ?
                """,
                (completed_at, str(investigation["id"])),
            )
            row = connection.execute(
                "SELECT * FROM investigation_events WHERE id = ?", (event_id,)
            ).fetchone()
        return self._event(row)

    def record_for_case(
        self,
        *,
        investigation_id: str,
        user_id: str,
        username: str,
        require_recording: bool = False,
        operation_id: str,
        event_type: str,
        tool_id: str,
        action: str,
        outcome: str,
        summary: str,
        targets: Any,
        parameters: Any,
        metrics: Any,
        details: Any,
        started_at: float,
        completed_at: float,
    ) -> dict[str, Any]:
        """Append a participant lifecycle event, including completion while paused."""
        user_id = self._clean_identity(user_id, "user")
        with self._connect() as connection, connection:
            investigation = self._require_open_member(
                connection, investigation_id, user_id
            )
            if require_recording and str(investigation["state"]) != "recording":
                raise InvestigationError(
                    "Automatic case recording is not currently running."
                )
            event_id = self._insert_event(
                connection,
                investigation_id=investigation_id,
                operation_id=operation_id,
                event_type=event_type,
                tool_id=tool_id,
                action=action,
                outcome=outcome,
                summary=summary,
                targets=targets,
                parameters=parameters,
                metrics=metrics,
                details=details,
                started_at=started_at,
                completed_at=completed_at,
                created_by_user_id=user_id,
                created_by_username=self._clean_identity(username, "operator"),
            )
            connection.execute(
                """
                UPDATE investigations
                SET updated_at = MAX(updated_at, ?)
                WHERE id = ?
                """,
                (completed_at, investigation_id),
            )
            row = connection.execute(
                "SELECT * FROM investigation_events WHERE id = ?", (event_id,)
            ).fetchone()
        return self._event(row)

    def add_generated_evidence_event(
        self,
        *,
        investigation_id: str,
        user_id: str,
        username: str,
        operation_id: str,
        event_type: str,
        tool_id: str,
        action: str,
        outcome: str,
        summary: str,
        targets: Any,
        parameters: Any,
        metrics: Any,
        details: Any,
        started_at: float,
        completed_at: float,
        filename: str,
        content_type: str,
        content: bytes | None = None,
        stream: BinaryIO | None = None,
        max_bytes: int = MAX_UPLOAD_BYTES,
    ) -> dict[str, dict[str, Any]]:
        """Atomically describe generated evidence without adding timeline noise."""
        user_id = self._clean_identity(user_id, "user")
        username = self._clean_identity(username, "operator")
        clean_operation_id = self._clean_text(
            operation_id, "Operation ID", 200, required=True
        )
        investigation = self.get_for_user(investigation_id, user_id)
        if investigation["state"] not in OPEN_STATES:
            raise InvestigationError("Closed cases cannot accept new evidence.")
        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT id FROM investigation_events
                WHERE investigation_id = ? AND operation_id = ?
                """,
                (investigation_id, clean_operation_id),
            ).fetchone()
            if existing:
                event_row = connection.execute(
                    "SELECT * FROM investigation_events WHERE id = ?",
                    (existing["id"],),
                ).fetchone()
                artifact_row = connection.execute(
                    """
                    SELECT * FROM investigation_artifacts
                    WHERE investigation_id = ? AND event_id = ?
                    ORDER BY created_at LIMIT 1
                    """,
                    (investigation_id, existing["id"]),
                ).fetchone()
                if event_row and artifact_row:
                    return {
                        "event": self._event(event_row),
                        "artifact": self._artifact(artifact_row),
                    }

        if (content is None) == (stream is None):
            raise InvestigationError(
                "Generated evidence requires exactly one content source."
            )
        stored_name = self._available_evidence_name(
            str(investigation["datastore_path"]), filename
        )
        relative_folder = f"{investigation['datastore_path']}/Evidence"
        saved, size = self.datastore.save_upload(
            relative_folder,
            stored_name,
            io.BytesIO(content) if content is not None else stream,
            max_bytes=max_bytes,
        )
        digest = self._sha256_file(saved)
        artifact_id = f"art_{secrets.token_hex(12)}"
        now = time.time()
        relative_path = self.datastore.relative(saved)
        retained_details = dict(details) if isinstance(details, dict) else {}
        retained_details["evidence"] = {
            "artifact_id": artifact_id,
            "filename": stored_name,
            "byte_count": size,
            "sha256": digest,
        }
        try:
            with self._connect() as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                self._require_open_member(connection, investigation_id, user_id)
                existing = connection.execute(
                    """
                    SELECT id FROM investigation_events
                    WHERE investigation_id = ? AND operation_id = ?
                    """,
                    (investigation_id, clean_operation_id),
                ).fetchone()
                if existing:
                    event_row = connection.execute(
                        "SELECT * FROM investigation_events WHERE id = ?",
                        (existing["id"],),
                    ).fetchone()
                    artifact_row = connection.execute(
                        """
                        SELECT * FROM investigation_artifacts
                        WHERE investigation_id = ? AND event_id = ?
                        ORDER BY created_at LIMIT 1
                        """,
                        (investigation_id, existing["id"]),
                    ).fetchone()
                    if event_row and artifact_row:
                        saved.unlink(missing_ok=True)
                        return {
                            "event": self._event(event_row),
                            "artifact": self._artifact(artifact_row),
                        }
                event_id = self._insert_event(
                    connection,
                    investigation_id=investigation_id,
                    operation_id=clean_operation_id,
                    event_type=event_type,
                    tool_id=tool_id,
                    action=action,
                    outcome=outcome,
                    summary=summary,
                    targets=targets,
                    parameters=parameters,
                    metrics=metrics,
                    details=retained_details,
                    started_at=started_at,
                    completed_at=completed_at,
                    created_by_user_id=user_id,
                    created_by_username=username,
                )
                connection.execute(
                    """
                    INSERT INTO investigation_artifacts (
                        id, investigation_id, event_id, kind, display_name,
                        relative_path, content_type, byte_count, sha256,
                        report_placement, created_by_user_id,
                        created_by_username, created_at
                    ) VALUES (?, ?, ?, 'generated', ?, ?, ?, ?, ?, 'appendix', ?, ?, ?)
                    """,
                    (
                        artifact_id,
                        investigation_id,
                        event_id,
                        stored_name,
                        relative_path,
                        self._clean_text(content_type, "Content type", 160),
                        size,
                        digest,
                        user_id,
                        username,
                        now,
                    ),
                )
                connection.execute(
                    """
                    UPDATE investigations
                    SET updated_at = MAX(updated_at, ?)
                    WHERE id = ?
                    """,
                    (completed_at, investigation_id),
                )
                event_row = connection.execute(
                    "SELECT * FROM investigation_events WHERE id = ?", (event_id,)
                ).fetchone()
                artifact_row = connection.execute(
                    "SELECT * FROM investigation_artifacts WHERE id = ?",
                    (artifact_id,),
                ).fetchone()
        except BaseException:
            saved.unlink(missing_ok=True)
            raise
        return {
            "event": self._event(event_row),
            "artifact": self._artifact(artifact_row),
        }

    def add_evidence(
        self,
        *,
        investigation_id: str,
        user_id: str,
        username: str,
        filename: str,
        content_type: str,
        stream: BinaryIO,
        max_bytes: int = MAX_UPLOAD_BYTES,
    ) -> dict[str, Any]:
        investigation = self.get_for_user(investigation_id, user_id)
        if investigation["state"] not in OPEN_STATES:
            raise InvestigationError("Closed cases cannot accept new evidence.")
        stored_name = self._available_evidence_name(
            investigation["datastore_path"], filename
        )
        relative_folder = f"{investigation['datastore_path']}/Evidence"
        saved, size = self.datastore.save_upload(
            relative_folder,
            stored_name,
            stream,
            max_bytes=max_bytes,
        )
        digest = self._sha256_file(saved)
        artifact_id = f"art_{secrets.token_hex(12)}"
        now = time.time()
        user_id = self._clean_identity(user_id, "user")
        username = self._clean_identity(username, "operator")
        relative_path = self.datastore.relative(saved)
        try:
            with self._connect() as connection, connection:
                self._require_open_member(connection, investigation_id, user_id)
                event_id = self._insert_event(
                    connection,
                    investigation_id=investigation_id,
                    operation_id=f"evidence:{artifact_id}",
                    event_type="evidence.added",
                    tool_id="investigations.workspace",
                    action="Evidence added",
                    outcome="info",
                    summary=f"Added evidence file {stored_name}.",
                    targets=[],
                    parameters={},
                    metrics={"bytes": size},
                    details={
                        "artifact_id": artifact_id,
                        "filename": stored_name,
                        "sha256": digest,
                    },
                    started_at=now,
                    completed_at=now,
                    created_by_user_id=user_id,
                    created_by_username=username,
                )
                connection.execute(
                    """
                    INSERT INTO investigation_artifacts (
                        id, investigation_id, event_id, kind, display_name,
                        relative_path, content_type, byte_count, sha256,
                        report_placement, created_by_user_id,
                        created_by_username, created_at
                    ) VALUES (?, ?, ?, 'upload', ?, ?, ?, ?, ?, 'appendix', ?, ?, ?)
                    """,
                    (
                        artifact_id,
                        investigation_id,
                        event_id,
                        stored_name,
                        relative_path,
                        self._clean_text(content_type, "Content type", 160),
                        size,
                        digest,
                        user_id,
                        username,
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE investigations SET updated_at = ? WHERE id = ?",
                    (now, investigation_id),
                )
                row = connection.execute(
                    "SELECT * FROM investigation_artifacts WHERE id = ?",
                    (artifact_id,),
                ).fetchone()
        except BaseException:
            saved.unlink(missing_ok=True)
            raise
        return self._artifact(row)

    def _prepare_datastore_folders(self, investigation_id: str) -> str:
        self._ensure_folder("", "Investigations")
        self._ensure_folder("Investigations", investigation_id)
        base = f"Investigations/{investigation_id}"
        self._ensure_folder(base, "Evidence")
        self._ensure_folder(base, "Reports")
        return base

    def _ensure_folder(self, parent: str, name: str) -> None:
        path = "/".join(part for part in (parent, name) if part)
        try:
            self.datastore.folder(path)
        except DatastoreError:
            try:
                self.datastore.create_folder(parent, name)
            except DatastoreError:
                self.datastore.folder(path)

    def _available_evidence_name(self, datastore_path: str, filename: str) -> str:
        clean = Path(str(filename or "evidence.bin")).name.strip()
        clean = "".join(character if character.isalnum() or character in " ._-" else "_" for character in clean)
        clean = clean.strip(" .")[:240] or "evidence.bin"
        folder = f"{datastore_path}/Evidence"
        existing = {str(item["name"]).casefold() for item in self.datastore.list(folder)["entries"]}
        if clean.casefold() not in existing:
            return clean
        path = Path(clean)
        for index in range(2, 10_002):
            candidate = f"{path.stem[:220]}-{index}{path.suffix[:20]}"
            if candidate.casefold() not in existing:
                return candidate
        raise InvestigationError("Unable to choose an unused evidence filename.")

    def _require_owner(
        self, connection: sqlite3.Connection, investigation_id: str, user_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM investigations WHERE id = ? AND owner_user_id = ?",
            (investigation_id, user_id),
        ).fetchone()
        if not row:
            raise InvestigationError("Case not found.")
        return row

    def _require_open_member(
        self, connection: sqlite3.Connection, investigation_id: str, user_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT i.* FROM investigations i
            JOIN investigation_participants p ON p.investigation_id = i.id
            WHERE i.id = ? AND p.user_id = ?
            """,
            (investigation_id, user_id),
        ).fetchone()
        if not row:
            raise InvestigationError("Case not found.")
        if str(row["state"]) not in OPEN_STATES:
            raise InvestigationError("Closed cases cannot be changed.")
        return row

    def _insert_event(
        self,
        connection: sqlite3.Connection,
        *,
        investigation_id: str,
        operation_id: str,
        event_type: str,
        tool_id: str,
        action: str,
        outcome: str,
        summary: str,
        targets: Any,
        parameters: Any,
        metrics: Any,
        details: Any,
        started_at: float,
        completed_at: float,
        created_by_user_id: str,
        created_by_username: str,
    ) -> str:
        if outcome not in EVENT_OUTCOMES:
            raise InvestigationError("Choose a valid journal outcome.")
        if completed_at < started_at:
            raise InvestigationError("Journal completion time cannot precede its start time.")
        event_id = f"evt_{secrets.token_hex(12)}"
        try:
            connection.execute(
                """
                INSERT INTO investigation_events (
                    id, investigation_id, operation_id, event_type, tool_id,
                    action, outcome, summary, targets_json, parameters_json,
                    metrics_json, details_json, report_placement, important,
                    started_at, completed_at, created_by_user_id,
                    created_by_username, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'main', 0, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    investigation_id,
                    self._clean_text(operation_id, "Operation ID", 200, required=True),
                    self._clean_text(event_type, "Event type", 120, required=True),
                    self._clean_text(tool_id, "Tool ID", 160, required=True),
                    self._clean_text(action, "Action", 160, required=True),
                    outcome,
                    self._clean_text(summary, "Summary", 4_000, required=True),
                    self._json(targets),
                    self._json(parameters),
                    self._json(metrics),
                    self._json(details),
                    float(started_at),
                    float(completed_at),
                    self._clean_identity(created_by_user_id, "user"),
                    self._clean_identity(created_by_username, "operator"),
                    time.time(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            existing = connection.execute(
                """
                SELECT id FROM investigation_events
                WHERE investigation_id = ? AND operation_id = ?
                """,
                (investigation_id, operation_id),
            ).fetchone()
            if existing:
                return str(existing["id"])
            raise InvestigationError("The journal event could not be recorded.") from exc
        return event_id

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            self._ensure_initialized(connection)
            yield connection
        finally:
            connection.close()
            self._secure_database_files()

    def _ensure_initialized(self, connection: sqlite3.Connection) -> None:
        if self._schema_version(connection) >= SCHEMA_VERSION:
            return
        with self.initialization_lock_path.open("a+", encoding="utf-8") as lock_handle:
            os.chmod(self.initialization_lock_path, 0o600)
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                if self._schema_version(connection) < SCHEMA_VERSION:
                    self._initialize(connection)
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _schema_version(connection: sqlite3.Connection) -> int:
        try:
            row = connection.execute(
                "SELECT value FROM investigation_meta WHERE key = 'schema_version'"
            ).fetchone()
            return int(row["value"]) if row else 0
        except (sqlite3.OperationalError, TypeError, ValueError):
            return 0

    def _initialize(self, connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS investigation_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                owner_user_id TEXT NOT NULL,
                owner_username TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('recording', 'paused', 'completed', 'archived')
                ),
                datastore_path TEXT NOT NULL UNIQUE,
                created_at REAL NOT NULL,
                started_at REAL NOT NULL,
                ended_at REAL,
                updated_at REAL NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS investigations_one_open_owner_idx
                ON investigations(owner_user_id)
                WHERE state IN ('recording', 'paused');
            CREATE INDEX IF NOT EXISTS investigations_owner_time_idx
                ON investigations(owner_user_id, updated_at DESC);
            CREATE TABLE IF NOT EXISTS investigation_participants (
                investigation_id TEXT NOT NULL
                    REFERENCES investigations(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('owner', 'collaborator')),
                added_by_user_id TEXT NOT NULL,
                added_by_username TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (investigation_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS investigation_participants_user_idx
                ON investigation_participants(user_id, investigation_id);
            INSERT OR IGNORE INTO investigation_participants (
                investigation_id, user_id, username, role,
                added_by_user_id, added_by_username, created_at
            )
            SELECT id, owner_user_id, owner_username, 'owner',
                owner_user_id, owner_username, created_at
            FROM investigations;
            CREATE TABLE IF NOT EXISTS investigation_events (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL
                    REFERENCES investigations(id) ON DELETE CASCADE,
                operation_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK (
                    outcome IN ('succeeded', 'failed', 'cancelled', 'incomplete', 'info')
                ),
                summary TEXT NOT NULL,
                targets_json TEXT NOT NULL DEFAULT '[]',
                parameters_json TEXT NOT NULL DEFAULT '{}',
                metrics_json TEXT NOT NULL DEFAULT '{}',
                details_json TEXT NOT NULL DEFAULT '{}',
                report_placement TEXT NOT NULL DEFAULT 'main' CHECK (
                    report_placement IN ('main', 'appendix', 'excluded')
                ),
                important INTEGER NOT NULL DEFAULT 0 CHECK (important IN (0, 1)),
                started_at REAL NOT NULL,
                completed_at REAL NOT NULL,
                created_by_user_id TEXT NOT NULL,
                created_by_username TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(investigation_id, operation_id)
            );
            CREATE INDEX IF NOT EXISTS investigation_events_timeline_idx
                ON investigation_events(investigation_id, started_at, created_at);
            CREATE TABLE IF NOT EXISTS investigation_artifacts (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL
                    REFERENCES investigations(id) ON DELETE CASCADE,
                event_id TEXT REFERENCES investigation_events(id) ON DELETE SET NULL,
                kind TEXT NOT NULL,
                display_name TEXT NOT NULL,
                relative_path TEXT NOT NULL UNIQUE,
                content_type TEXT NOT NULL DEFAULT '',
                byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
                sha256 TEXT NOT NULL,
                report_placement TEXT NOT NULL DEFAULT 'appendix' CHECK (
                    report_placement IN ('main', 'appendix', 'excluded')
                ),
                created_by_user_id TEXT NOT NULL,
                created_by_username TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS investigation_artifacts_investigation_idx
                ON investigation_artifacts(investigation_id, created_at DESC);
            INSERT OR IGNORE INTO investigation_meta(key, value)
                VALUES ('schema_version', '2');
            UPDATE investigation_meta SET value = '2' WHERE key = 'schema_version';
            """
        )
        connection.commit()
        self._secure_database_files()

    def _investigation(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["is_open"] = result["state"] in OPEN_STATES
        result["is_recording"] = result["state"] == "recording"
        result["access_role"] = str(result.get("access_role") or "owner")
        result["can_manage_case"] = result["access_role"] == "owner"
        result["participant_count"] = int(result.get("participant_count") or 1)
        result["is_shared"] = result["participant_count"] > 1
        result["state_label"] = {
            "recording": "Recording",
            "paused": "Paused",
            "completed": "Closed",
            "archived": "Archived",
        }.get(str(result["state"]), str(result["state"]).title())
        result["started_display"] = self._display_time(float(result["started_at"]))
        result["updated_display"] = self._display_time(float(result["updated_at"]))
        result["ended_display"] = (
            self._display_time(float(result["ended_at"]))
            if result.get("ended_at") is not None
            else ""
        )
        return result

    def _participant(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["created_display"] = self._display_time(float(result["created_at"]))
        result["is_owner"] = result["role"] == "owner"
        return result

    def _event(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        for key in ("targets", "parameters", "metrics", "details"):
            result[key] = json.loads(result.pop(f"{key}_json"))
        result["important"] = bool(result["important"])
        result["started_display"] = self._display_time(float(result["started_at"]))
        result["completed_display"] = self._display_time(float(result["completed_at"]))
        result["duration_seconds"] = round(
            max(0.0, float(result["completed_at"]) - float(result["started_at"])), 3
        )
        return result

    def _artifact(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["created_display"] = self._display_time(float(result["created_at"]))
        return result

    def _display_time(self, value: float) -> str:
        timezone_name = TimeSettingsStore(self.instance_path).resolved_timezone()
        return localized_time_values(value, timezone_name)["display"]

    @staticmethod
    def _clean_text(value: Any, label: str, limit: int, *, required: bool = False) -> str:
        cleaned = str(value or "").strip()
        if required and not cleaned:
            raise InvestigationError(f"{label} is required.")
        if len(cleaned) > limit:
            raise InvestigationError(f"{label} must be {limit} characters or fewer.")
        return cleaned

    @staticmethod
    def _clean_identity(value: Any, fallback: str) -> str:
        return str(value or fallback).strip()[:160] or fallback

    @staticmethod
    def _json(value: Any) -> str:
        try:
            encoded = json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise InvestigationError("Journal evidence must be valid structured data.") from exc
        if len(encoded.encode("utf-8")) > MAX_EVENT_JSON_BYTES:
            raise InvestigationError("Journal evidence exceeds the per-field retention limit.")
        return encoded

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

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
