"""Private capture and automation output sharing upload capacity reservations."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import time

from .datastore import LocalDatastore, DatastoreError

ROOTS = ('automation_artifacts', 'packet_captures', 'automation_staging')


class ArtifactStore(LocalDatastore):
    def __init__(self, instance, area, limit):
        if area not in ROOTS:
            raise ValueError('Unknown artifact area.')
        self.instance = Path(instance).resolve()
        self.root_name = area
        self.root = self.instance / area
        if self.root.is_symlink():
            raise DatastoreError('Artifact roots cannot be symbolic links.')
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.limit = limit

    def upload_limit(self):
        return self.limit


def staging_directory(instance, limit):
    store = ArtifactStore(instance, 'automation_staging', limit)
    return store, Path(tempfile.mkdtemp(prefix='run-', dir=store.root))


def checked_automation_source(instance, source):
    """Accept current staging and the two legacy temporary roots during upgrades."""
    source = Path(source)
    if source.is_symlink() or source.parent.is_symlink() or not source.is_file():
        raise ValueError('Automation artifact source is unavailable.')
    source = source.resolve()
    staging = Path(instance).resolve() / 'automation_staging'
    current = source.parent.parent == staging and source.parent.name.startswith('run-') and not staging.is_symlink()
    legacy = source.parent.parent == Path(tempfile.gettempdir()).resolve() and source.parent.name.startswith(('twn-automation-sftp-', 'twn-automation-pcap-'))
    if not (current or legacy) or source.stat().st_uid != os.getuid() or source.parent.stat().st_uid != os.getuid():
        raise ValueError('Automation artifact source is outside its private staging area.')
    return source


def cleanup_staging(store, *, now=None):
    """Reap old abandoned stages while preserving durable delayed-pipeline inputs."""
    now = time.time() if now is None else now
    root = store.instance_path / 'automation_staging'
    if not root.exists() or root.is_symlink():
        return 0
    retained = set()
    with store._connect() as db:
        rows = db.execute("SELECT progress_encrypted FROM automation_jobs WHERE status IN ('queued','running','waiting','failed') AND progress_encrypted IS NOT NULL").fetchall()
    for row in rows:
        progress = store._decrypt(str(row[0]))
        for result in progress.get('action_results', []):
            for source in result.get('output', {}).get('_artifact_sources', []):
                retained.add(Path(str(source.get('source_path', ''))).parent.resolve())
    removed = 0
    for stage in root.iterdir():
        if stage.is_symlink() or not stage.is_dir() or not stage.name.startswith('run-'):
            continue
        if stage.resolve() in retained or now - stage.stat().st_mtime < 86400:
            continue
        shutil.rmtree(stage)
        removed += 1
    return removed
