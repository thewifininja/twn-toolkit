"""Retention of owner-only artifacts belonging to finite diagnostic jobs."""
from __future__ import annotations

import re
import os
from pathlib import Path
from .datastore import LocalDatastore, DatastoreError
import shutil

FAMILIES = {'case_export': 'case_export_job_artifacts', 'transfer': 'transfer_job_artifacts', 'fac_inventory_devices': 'inventory_device_job_artifacts', 'fac_inventory_memberships': 'inventory_membership_job_artifacts'}


def artifact_directory(store, job_id, family='transfer'):
    if family not in FAMILIES or not re.fullmatch(r'[a-f0-9]{32}', job_id):
        raise ValueError('Invalid diagnostic artifact identity.')
    return store.instance / FAMILIES[family] / job_id


def cleanup_artifacts(store, family):
    root = store.instance / FAMILIES[family]
    try:
        paths = list(root.iterdir())
    except OSError:
        return
    with store.connect() as db:
        retained = {row['id'] for row in db.execute(
            "SELECT id FROM diagnostic_jobs WHERE tool=? AND (state IN ('queued','running','cancel_requested','succeeded') OR token!='')", (family,))}
    for path in paths:
        if re.fullmatch(r'[a-f0-9]{32}', path.name) and path.name not in retained:
            try:
                if path.is_symlink():
                    path.unlink()
                else:
                    shutil.rmtree(path)
            except OSError:
                pass


class PrivateArtifactStore(LocalDatastore):
    """Internal-only roots; these are never accepted by public datastore routes."""
    def __init__(self, instance, family, limit):
        if family not in FAMILIES:
            raise ValueError("Unknown private artifact family.")
        self.instance = Path(instance).resolve()
        self.root_name = FAMILIES[family]
        self.root = self.instance / self.root_name
        if self.root.is_symlink():
            raise DatastoreError("Private artifact roots cannot be symbolic links.")
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.limit = limit

    def upload_limit(self):
        return self.limit
