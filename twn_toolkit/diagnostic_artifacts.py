"""Retention of owner-only artifacts belonging to finite diagnostic jobs."""
from __future__ import annotations

import re
import shutil

FAMILIES = {'transfer': 'transfer_job_artifacts', 'fac_inventory_devices': 'inventory_device_job_artifacts', 'fac_inventory_memberships': 'inventory_membership_job_artifacts'}


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
