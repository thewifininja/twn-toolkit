from __future__ import annotations

import sqlite3

from flask import current_app, g

from .activity import ActivityStore


def record_current_activity(
    category: str,
    title: str,
    detail: str = "",
    *,
    counters: dict[str, dict[str, int]] | None = None,
    count_action: bool = True,
) -> None:
    """Record one authenticated user operation using the shared activity policy."""
    user = getattr(g, "current_user", {}) or {}
    try:
        ActivityStore(current_app.instance_path).record_event(
            category,
            title,
            detail,
            counters=counters,
            user_id=str(user.get("id", "")),
            username=str(user.get("username", "")),
            count_action=count_action,
        )
    except (OSError, sqlite3.Error) as exc:
        current_app.logger.warning("Unable to record toolkit activity: %s", exc)


def increment_current_activity(category: str, counter: str, amount: int) -> None:
    """Record raw work without creating a recent event or activity-score point."""
    user = getattr(g, "current_user", {}) or {}
    try:
        ActivityStore(current_app.instance_path).increment(
            category,
            counter,
            amount,
            user_id=str(user.get("id", "")),
            username=str(user.get("username", "")),
        )
    except (OSError, sqlite3.Error) as exc:
        current_app.logger.warning("Unable to record toolkit activity: %s", exc)
