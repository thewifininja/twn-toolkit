from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class DashboardLayoutStore:
    """Persist the administrator-managed metric-card order and visibility."""

    def __init__(self, instance_path: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "dashboard_layout.json"

    def get(self, available_ids: list[str]) -> dict[str, list[str]]:
        available = list(dict.fromkeys(available_ids))
        raw = self._read()
        saved_order = self._valid_ids(raw.get("order"), available)
        hidden = self._valid_ids(raw.get("hidden"), available)
        combined = saved_order + [item for item in available if item not in saved_order]
        order = [item for item in combined if item not in hidden] + hidden
        return {"order": order, "hidden": hidden}

    def arrange(self, cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_id = {str(card["metric"]): card for card in cards}
        layout = self.get(list(by_id))
        hidden = set(layout["hidden"])
        return [
            {**by_id[metric], "dashboard_hidden": metric in hidden}
            for metric in layout["order"]
            if metric in by_id
        ]

    def save(
        self,
        order: list[str],
        hidden: list[str],
        available_ids: list[str],
    ) -> dict[str, list[str]]:
        available = list(dict.fromkeys(available_ids))
        normalized_order = self._valid_ids(order, available)
        normalized_order.extend(
            item for item in available if item not in normalized_order
        )
        normalized_hidden = self._valid_ids(hidden, available)
        normalized_order = [
            item for item in normalized_order if item not in normalized_hidden
        ] + normalized_hidden
        layout = {"version": 1, "order": normalized_order, "hidden": normalized_hidden}
        self._write(layout)
        return {"order": normalized_order, "hidden": normalized_hidden}

    def reset(self) -> None:
        if self.path.exists():
            self.path.unlink()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _valid_ids(values: Any, available: list[str]) -> list[str]:
        if not isinstance(values, list):
            return []
        allowed = set(available)
        return [
            value
            for value in dict.fromkeys(str(item) for item in values)
            if value in allowed
        ]

    def _write(self, data: dict[str, Any]) -> None:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            dir=self.instance_path, prefix=".dashboard-layout-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, self.path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
