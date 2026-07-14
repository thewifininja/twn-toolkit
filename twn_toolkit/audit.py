from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from flask import g


_SECRET_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "private_key",
    "api_key",
    "community",
)
_REDACTED = "[redacted]"


def annotate_audit_event(
    *,
    category: str,
    action: str,
    summary: str,
    resource_type: str = "",
    resource_id: str = "",
    resource_name: str = "",
    details: dict[str, Any] | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> None:
    """Attach explicitly curated, secret-sanitized context to this request."""
    context: dict[str, Any] = {
        "category": category,
        "action": action,
        "summary": summary,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_name": resource_name,
        "details": details or {},
    }
    if before is not None or after is not None:
        context["details"] = {
            **context["details"],
            "changes": audit_changes(before or {}, after or {}),
        }
    g.audit_event = context


def suppress_audit_event() -> None:
    """Exclude high-frequency or otherwise non-administrative request traffic."""
    g.audit_suppressed = True


def audit_changes(
    before: dict[str, Any], after: dict[str, Any]
) -> list[dict[str, Any]]:
    safe_before = _flatten_changes(_sanitize(before))
    safe_after = _flatten_changes(_sanitize(after))
    changes = []
    for field in sorted(set(safe_before) | set(safe_after)):
        previous = safe_before.get(field)
        current = safe_after.get(field)
        if previous != current:
            changes.append({"field": field, "before": previous, "after": current})
    return changes[:100]


class AuditStore:
    def __init__(self, instance_path: str) -> None:
        self.path = Path(instance_path) / "audit.sqlite3"
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY, recorded_at REAL NOT NULL, user_id TEXT NOT NULL,
                    username TEXT NOT NULL, remote_ip TEXT NOT NULL, method TEXT NOT NULL,
                    endpoint TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS audit_events_recent ON audit_events(recorded_at DESC);
                CREATE TABLE IF NOT EXISTS audit_event_details (
                    audit_event_id TEXT PRIMARY KEY,
                    category TEXT NOT NULL DEFAULT '', action TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL DEFAULT '', resource_type TEXT NOT NULL DEFAULT '',
                    resource_id TEXT NOT NULL DEFAULT '', resource_name TEXT NOT NULL DEFAULT '',
                    detail_json TEXT NOT NULL DEFAULT '{}'
                );
            """)
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(audit_events)")
            }
            rich_columns = {
                "category", "action", "summary", "resource_type",
                "resource_id", "resource_name", "detail_json",
            }
            if rich_columns.issubset(columns):
                self._normalize_expanded_schema(connection)

    @staticmethod
    def _normalize_expanded_schema(connection: sqlite3.Connection) -> None:
        """Move preview-era inline detail columns into the rollback-safe side table."""
        connection.execute(
            """
            INSERT OR REPLACE INTO audit_event_details (
                audit_event_id, category, action, summary, resource_type,
                resource_id, resource_name, detail_json
            )
            SELECT id, category, action, summary, resource_type,
                   resource_id, resource_name, detail_json
            FROM audit_events
            """
        )
        connection.executescript(
            """
            CREATE TABLE audit_events_rollback_safe (
                id TEXT PRIMARY KEY, recorded_at REAL NOT NULL, user_id TEXT NOT NULL,
                username TEXT NOT NULL, remote_ip TEXT NOT NULL, method TEXT NOT NULL,
                endpoint TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL
            );
            INSERT INTO audit_events_rollback_safe
                SELECT id, recorded_at, user_id, username, remote_ip, method,
                       endpoint, path, status_code
                FROM audit_events;
            DROP TABLE audit_events;
            ALTER TABLE audit_events_rollback_safe RENAME TO audit_events;
            CREATE INDEX audit_events_recent ON audit_events(recorded_at DESC);
            """
        )

    def record(self, **values: Any) -> None:
        detail_json = json.dumps(
            _sanitize(values.get("details", {})),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if len(detail_json) > 32768:
            detail_json = json.dumps(
                {
                    "truncated": True,
                    "notice": "Audit detail exceeded the storage limit.",
                },
                separators=(",", ":"),
            )
        event_id = secrets.token_hex(12)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_events (
                    id, recorded_at, user_id, username, remote_ip, method,
                    endpoint, path, status_code
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    event_id, time.time(), str(values.get("user_id", "")),
                    str(values.get("username", ""))[:128], str(values.get("remote_ip", ""))[:128],
                    str(values.get("method", ""))[:12], str(values.get("endpoint", ""))[:160],
                    str(values.get("path", ""))[:500], int(values.get("status_code", 0)),
                ),
            )
            connection.execute(
                """
                INSERT INTO audit_event_details (
                    audit_event_id, category, action, summary, resource_type,
                    resource_id, resource_name, detail_json
                ) VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    str(values.get("category", ""))[:80], str(values.get("action", ""))[:120],
                    str(values.get("summary", ""))[:500], str(values.get("resource_type", ""))[:80],
                    str(values.get("resource_id", ""))[:160], str(values.get("resource_name", ""))[:240],
                    detail_json,
                ),
            )
            connection.execute("DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY recorded_at DESC LIMIT 10000)")
            connection.execute("DELETE FROM audit_event_details WHERE audit_event_id NOT IN (SELECT id FROM audit_events)")

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            events = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT events.*,
                           COALESCE(details.category, '') AS category,
                           COALESCE(details.action, '') AS action,
                           COALESCE(details.summary, '') AS summary,
                           COALESCE(details.resource_type, '') AS resource_type,
                           COALESCE(details.resource_id, '') AS resource_id,
                           COALESCE(details.resource_name, '') AS resource_name,
                           COALESCE(details.detail_json, '{}') AS detail_json
                    FROM audit_events AS events
                    LEFT JOIN audit_event_details AS details
                      ON details.audit_event_id = events.id
                    ORDER BY events.recorded_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            ]
        for event in events:
            try:
                event["details"] = json.loads(event.pop("detail_json", "{}"))
            except (TypeError, json.JSONDecodeError):
                event["details"] = {}
        return events

    def search(
        self, query: str = "", *, page: int = 1, per_page: int = 40
    ) -> dict[str, Any]:
        """Return one bounded page of audit events matching safe text fields."""
        normalized_query = str(query).strip()[:160]
        normalized_page = max(1, int(page))
        normalized_per_page = min(100, max(10, int(per_page)))
        where = ""
        parameters: list[Any] = []
        if normalized_query:
            escaped = (
                normalized_query.casefold()
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            where = """
                WHERE LOWER(
                    events.username || ' ' || events.remote_ip || ' ' ||
                    events.method || ' ' || events.endpoint || ' ' || events.path || ' ' ||
                    COALESCE(details.category, '') || ' ' ||
                    COALESCE(details.action, '') || ' ' ||
                    COALESCE(details.summary, '') || ' ' ||
                    COALESCE(details.resource_type, '') || ' ' ||
                    COALESCE(details.resource_id, '') || ' ' ||
                    COALESCE(details.resource_name, '') || ' ' ||
                    COALESCE(details.detail_json, '')
                ) LIKE ? ESCAPE '\\'
            """
            parameters.append(f"%{escaped}%")
        joined_tables = """
            FROM audit_events AS events
            LEFT JOIN audit_event_details AS details
              ON details.audit_event_id = events.id
        """
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) {joined_tables} {where}", parameters
                ).fetchone()[0]
            )
            total_pages = max(1, (total + normalized_per_page - 1) // normalized_per_page)
            normalized_page = min(normalized_page, total_pages)
            offset = (normalized_page - 1) * normalized_per_page
            events = [
                dict(row)
                for row in connection.execute(
                    f"""
                    SELECT events.*,
                           COALESCE(details.category, '') AS category,
                           COALESCE(details.action, '') AS action,
                           COALESCE(details.summary, '') AS summary,
                           COALESCE(details.resource_type, '') AS resource_type,
                           COALESCE(details.resource_id, '') AS resource_id,
                           COALESCE(details.resource_name, '') AS resource_name,
                           COALESCE(details.detail_json, '{{}}') AS detail_json
                    {joined_tables}
                    {where}
                    ORDER BY events.recorded_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    [*parameters, normalized_per_page, offset],
                )
            ]
        for event in events:
            try:
                event["details"] = json.loads(event.pop("detail_json", "{}"))
            except (TypeError, json.JSONDecodeError):
                event["details"] = {}
        return {
            "events": events,
            "query": normalized_query,
            "page": normalized_page,
            "per_page": normalized_per_page,
            "total": total,
            "total_pages": total_pages,
            "first_item": offset + 1 if total else 0,
            "last_item": min(offset + len(events), total),
        }

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10); connection.row_factory = sqlite3.Row
        try: yield connection; connection.commit()
        except Exception: connection.rollback(); raise
        finally:
            connection.close()
            if self.path.exists(): os.chmod(self.path, 0o600)


def _sanitize(value: Any, *, key: str = "", depth: int = 0) -> Any:
    normalized_key = key.casefold().replace("-", "_").replace(" ", "_")
    if normalized_key and any(fragment in normalized_key for fragment in _SECRET_FRAGMENTS):
        return _REDACTED
    if depth >= 6:
        return "[depth limited]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:1000]
    if isinstance(value, dict):
        return {
            str(item_key)[:160]: _sanitize(item_value, key=str(item_key), depth=depth + 1)
            for item_key, item_value in list(value.items())[:100]
        }
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item, depth=depth + 1) for item in list(value)[:100]]
    return str(value)[:1000]


def _flatten_changes(
    value: Any, *, prefix: str = "", depth: int = 0
) -> dict[str, Any]:
    """Flatten nested mappings into readable dotted fields for change display."""
    if not isinstance(value, dict):
        return {prefix or "value": value}
    flattened: dict[str, Any] = {}
    for key, item in value.items():
        field = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, dict) and depth < 4:
            flattened.update(
                _flatten_changes(item, prefix=field, depth=depth + 1)
            )
        else:
            flattened[field] = item
    return flattened
