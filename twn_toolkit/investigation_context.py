from __future__ import annotations

import sqlite3
from typing import Any

from flask import current_app, g

from .investigations import InvestigationError, InvestigationStore


def record_current_investigation_event(**event: Any) -> dict[str, Any] | None:
    """Record a sanitized event only when this user is actively recording."""
    user = getattr(g, "current_user", {}) or {}
    try:
        store = current_app.extensions.get("investigation_store")
        if not isinstance(store, InvestigationStore):
            store = InvestigationStore(current_app.instance_path)
        return store.record_for_active(
            user_id=str(user.get("id", "")),
            username=str(user.get("username", "")),
            **event,
        )
    except (InvestigationError, OSError, sqlite3.Error) as exc:
        current_app.logger.warning("Unable to record investigation journal event: %s", exc)
        return None
