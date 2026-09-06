"""Shared request-side access to finite diagnostic jobs."""
from flask import abort, current_app, g

from .diagnostic_jobs import DiagnosticJobStore


def diagnostic_store():
    store = current_app.extensions.get("diagnostic_job_store")
    if store is None:
        store = DiagnosticJobStore(current_app.instance_path)
        current_app.extensions["diagnostic_job_store"] = store
    return store


def owned_diagnostic(job_id, tool):
    job = diagnostic_store().get(job_id, g.current_user["id"])
    if job is None or job["tool"] != tool:
        abort(404)
    return job
