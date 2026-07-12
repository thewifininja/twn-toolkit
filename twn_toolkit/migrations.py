from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Callable


class MigrationManager:
    """Toolkit-level numbered migrations with a pre-change SQLite snapshot."""
    def __init__(self, instance_path: str) -> None:
        self.instance = Path(instance_path); self.path = self.instance / "schema_migrations.json"

    def applied(self) -> list[dict]:
        try: value = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError): return []
        return value if isinstance(value, list) else []

    def run(self, migrations: list[tuple[int, str, Callable[[Path], None]]]) -> list[int]:
        records = self.applied(); applied = {int(item["version"]) for item in records}; completed = []
        for version, description, callback in sorted(migrations):
            if version in applied: continue
            self._snapshot(version); callback(self.instance)
            records.append({"version": version, "description": description, "applied_at": time.time()}); completed.append(version)
            self.instance.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".tmp"); temporary.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
            os.chmod(temporary, 0o600); os.replace(temporary, self.path)
        return completed

    def _snapshot(self, version: int) -> None:
        databases = list(self.instance.glob("*.sqlite3"))
        if not databases: return
        target = self.instance / "migration_backups" / f"v{version}-{int(time.time())}"
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        for database in databases:
            destination = target / database.name
            try:
                source = sqlite3.connect(database); backup = sqlite3.connect(destination)
                try: source.backup(backup)
                finally: source.close(); backup.close()
            except sqlite3.Error:
                shutil.copy2(database, destination)
            os.chmod(destination, 0o600)


def run_toolkit_migrations(instance_path: str) -> list[int]:
    return MigrationManager(instance_path).run([
        (1, "Establish toolkit-wide migration tracking and operational hardening baseline", lambda _instance: None),
    ])
