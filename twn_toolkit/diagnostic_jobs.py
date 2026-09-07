"""Durable finite diagnostics, separate from distributed delivery ownership."""
from __future__ import annotations

import json
from dataclasses import asdict
import os
import secrets
import shutil
import time
from contextlib import contextmanager
from pathlib import Path

from .diagnostic_policy import MAX_RESULT_BYTES, MAX_RESULT_ROWS, RESULT_PAGE_SIZE
from .distributed_payloads import DistributedPayloadCipher
from .operational import OperationalSettingsStore
from .sqlite_store import bootstrap_sqlite_store, sqlite_store_connection

ACTIVE = ("queued", "running", "cancel_requested")
TERMINAL = ("succeeded", "failed", "cancelled", "unknown")


class DiagnosticJobStore:
    def __init__(self, instance):
        self.instance = Path(instance).resolve()
        self.path = self.instance / "diagnostic_jobs.sqlite3"
        self.policy = OperationalSettingsStore(str(instance))
        self.cipher = DistributedPayloadCipher(self.instance)
        bootstrap_sqlite_store(self.path, self._schema)
        os.chmod(self.path, 0o600)

    @staticmethod
    def _schema(db):
        db.execute("""CREATE TABLE IF NOT EXISTS diagnostic_jobs (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL, tool TEXT NOT NULL,
            state TEXT NOT NULL, token TEXT NOT NULL DEFAULT '',
            config TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '{}',
            error TEXT NOT NULL DEFAULT '', created REAL NOT NULL,
            started REAL, completed REAL, timeout REAL NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS diagnostic_rows (
            job_id TEXT NOT NULL REFERENCES diagnostic_jobs(id) ON DELETE CASCADE,
            position INTEGER NOT NULL, is_open INTEGER NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY(job_id, position))""")
        db.execute("CREATE INDEX IF NOT EXISTS diagnostic_owner ON diagnostic_jobs(user_id, created DESC)")
        db.execute("CREATE INDEX IF NOT EXISTS diagnostic_queue ON diagnostic_jobs(state, created)")
        db.execute("CREATE INDEX IF NOT EXISTS diagnostic_expiry ON diagnostic_jobs(completed)")
        db.execute("CREATE INDEX IF NOT EXISTS diagnostic_open_rows ON diagnostic_rows(job_id, is_open, position)")

    @contextmanager
    def connect(self, *, write=False):
        with sqlite_store_connection(self.path) as db:
            db.execute("PRAGMA secure_delete = ON")
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db

    def _prune(self, db, policy, *, reserve=False):
        db.execute("DELETE FROM diagnostic_jobs WHERE completed < ? AND token=''", (time.time() - policy["diagnostic_retention_hours"] * 3600,))
        count = db.execute("SELECT COUNT(*) FROM diagnostic_jobs").fetchone()[0]
        remove = max(0, count - policy["diagnostic_history_limit"] + int(reserve))
        if remove:
            db.execute("DELETE FROM diagnostic_jobs WHERE id IN (SELECT id FROM diagnostic_jobs WHERE completed IS NOT NULL AND token='' ORDER BY completed LIMIT ?)", (remove,))

    def cleanup(self):
        policy = self.policy.get()
        with self.connect(write=True) as db:
            self._prune(db, policy)
        from .transfer_diagnostic import cleanup_transfer_artifacts
        cleanup_transfer_artifacts(self)

    def enqueue(self, *, user_id, config, tool="tcp_scan"):
        if tool not in {"tcp_scan", "dns", "transfer", "wireless_history"} or not user_id:
            raise ValueError("Invalid diagnostic request.")
        policy = self.policy.get()
        if tool == "transfer":
            from .transfer_deadlines import TransferPolicy
            config = {**config, "transfer_policy": asdict(TransferPolicy.from_settings(policy))}
        raw = json.dumps(config, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 64 * 1024:
            raise ValueError("Diagnostic configuration exceeds the storage envelope.")
        job_id = secrets.token_hex(16)
        sealed = self.cipher.seal(raw, job_id + ":diagnostic-config")
        with self.connect(write=True) as db:
            self._prune(db, policy, reserve=True)
            if db.execute("SELECT COUNT(*) FROM diagnostic_jobs").fetchone()[0] >= policy["diagnostic_history_limit"]:
                raise ValueError("Diagnostic storage capacity is busy. Wait for an active run to finish.")
            if db.execute("SELECT COUNT(*) FROM diagnostic_jobs WHERE state = 'queued'").fetchone()[0] >= policy["diagnostic_queue_limit"]:
                raise ValueError("The diagnostic queue is full. Try again after a run finishes.")
            if db.execute("SELECT COUNT(*) FROM diagnostic_jobs WHERE user_id = ? AND state IN ('queued','running','cancel_requested')", (user_id,)).fetchone()[0] >= policy["diagnostic_user_limit"]:
                raise ValueError("Your active diagnostic limit is reached. Finish or cancel a run first.")
            active = db.execute("SELECT COUNT(*) FROM diagnostic_jobs WHERE state IN ('queued','running','cancel_requested')").fetchone()[0]
            # Reserve headroom for this queue's active result envelopes, including
            # encryption/journal overhead. Other artifact writers remain separate.
            reserved = (active + 1) * 32 * 1024**2
            if tool == "transfer":
                reserved += 2 * config["transfer_policy"]["run_bytes"]
            for queued in db.execute("SELECT id,config FROM diagnostic_jobs WHERE tool='transfer' AND state IN ('queued','running','cancel_requested')"):
                saved = json.loads(self.cipher.open(queued["config"], queued["id"] + ":diagnostic-config"))
                reserved += 2 * saved["transfer_policy"]["run_bytes"]
            if shutil.disk_usage(self.instance).free - reserved < policy["minimum_free_gib"] * 1024**3:
                raise ValueError("Diagnostic results would cross the configured free-disk reserve.")
            db.execute("INSERT INTO diagnostic_jobs(id,user_id,tool,state,config,created,timeout) VALUES (?,?,?,'queued',?,?,?)",
                       (job_id, user_id, tool, sealed, time.time(), policy["diagnostic_timeout_seconds"]))
        return job_id

    def claim(self):
        with self.connect() as db:
            if not db.execute("SELECT 1 FROM diagnostic_jobs WHERE state='queued' LIMIT 1").fetchone():
                return None
        with self.connect(write=True) as db:
            row = db.execute("SELECT * FROM diagnostic_jobs WHERE state = 'queued' ORDER BY created LIMIT 1").fetchone()
            if row is None:
                return None
            token = secrets.token_hex(32)
            db.execute("UPDATE diagnostic_jobs SET state='running', token=?, started=? WHERE id=?", (token, time.time(), row["id"]))
            return {**dict(row), "token": token, "state": "running", "started": time.time()}

    def owned(self, job_id, token):
        with self.connect() as db:
            row = db.execute("SELECT * FROM diagnostic_jobs WHERE id=? AND token=?", (job_id, token)).fetchone()
        return dict(row) if row else None

    def get(self, job_id, user_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM diagnostic_jobs WHERE id=? AND user_id=?", (job_id, user_id)).fetchone()
        if row is None:
            return None
        job = dict(row)
        job.pop("token")
        job["config"] = json.loads(self.cipher.open(job["config"], job_id + ":diagnostic-config"))
        job["summary"] = json.loads(self.cipher.open(job["summary"], job_id + ":diagnostic-summary"))
        return job

    def recent(self, user_id, tool="tcp_scan"):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT id,state,created FROM diagnostic_jobs WHERE user_id=? AND tool=? ORDER BY created DESC LIMIT 10", (user_id, tool))]

    def cancel(self, job_id, user_id):
        with self.connect(write=True) as db:
            previous = db.execute("SELECT * FROM diagnostic_jobs WHERE id=? AND user_id=? AND state='queued'", (job_id, user_id)).fetchone()
            db.execute("""UPDATE diagnostic_jobs SET
                state=CASE WHEN state='queued' THEN 'cancelled' ELSE 'cancel_requested' END,
                completed=CASE WHEN state='queued' THEN ? ELSE NULL END
                WHERE id=? AND user_id=? AND state IN ('queued','running')""", (time.time(), job_id, user_id))
            return dict(previous) if previous else None

    def abort(self, job_id, token, state, error):
        if state not in TERMINAL:
            raise ValueError("Invalid diagnostic outcome.")
        with self.connect(write=True) as db:
            previous = db.execute("SELECT * FROM diagnostic_jobs WHERE id=? AND token=? AND state IN ('running','cancel_requested')", (job_id, token)).fetchone()
            db.execute("UPDATE diagnostic_jobs SET state=?, error=?, completed=? WHERE id=? AND token=? AND state IN ('running','cancel_requested')",
                       (state, error[:500], time.time(), job_id, token))
            return dict(previous) if previous else None

    def release(self, job_id, token):
        with self.connect(write=True) as db:
            db.execute("UPDATE diagnostic_jobs SET token='' WHERE id=? AND token=? AND completed IS NOT NULL", (job_id, token))

    def recover(self):
        # Called only by the singleton scheduler at startup. Never replay work
        # that may have started under a previous scheduler.
        with self.connect(write=True) as db:
            previous = [dict(row) for row in db.execute("SELECT * FROM diagnostic_jobs WHERE state IN ('running','cancel_requested')")]
            db.execute("UPDATE diagnostic_jobs SET state='unknown', error='Scheduler restarted before confirming completion. This run was not replayed.', completed=?, token='' WHERE state IN ('running','cancel_requested')", (time.time(),))
            db.execute("UPDATE diagnostic_jobs SET token='' WHERE completed IS NOT NULL")
            return previous

    def progress(self, job_id, token, summary):
        sealed = self.cipher.seal(json.dumps(summary), job_id + ":diagnostic-summary")
        with self.connect(write=True) as db:
            return db.execute("UPDATE diagnostic_jobs SET summary=? WHERE id=? AND token=? AND state='running'",
                              (sealed, job_id, token)).rowcount == 1

    def finish(self, job_id, token, rows, summary):
        if len(rows) > MAX_RESULT_ROWS:
            raise ValueError("Diagnostic result row limit exceeded.")
        encoded = [json.dumps(row, separators=(",", ":"), allow_nan=False) for row in rows]
        raw_summary = json.dumps(summary, separators=(",", ":"), allow_nan=False)
        if sum(len(row.encode()) for row in encoded) + len(raw_summary.encode()) > MAX_RESULT_BYTES:
            raise ValueError("Diagnostic result storage envelope exceeded.")
        sealed = [(job_id, i, int(rows[i].get("status") == "open"), self.cipher.seal(raw, f"{job_id}:diagnostic-row:{i}")) for i, raw in enumerate(encoded)]
        with self.connect(write=True) as db:
            row = db.execute("SELECT state FROM diagnostic_jobs WHERE id=? AND token=?", (job_id, token)).fetchone()
            if not row or row["state"] != "running":
                return False
            db.executemany("INSERT INTO diagnostic_rows VALUES (?,?,?,?)", sealed)
            db.execute("UPDATE diagnostic_jobs SET state='succeeded', summary=?, completed=? WHERE id=?",
                       (self.cipher.seal(raw_summary, job_id + ":diagnostic-summary"), time.time(), job_id))
        return True

    def page(self, job_id, user_id, page=1, *, open_only=False):
        page = max(1, min(int(page), 50))
        with self.connect() as db:
            if not db.execute("SELECT 1 FROM diagnostic_jobs WHERE id=? AND user_id=?", (job_id, user_id)).fetchone():
                return [], 0
            clause = "job_id=?" + (" AND is_open=1" if open_only else "")
            count = db.execute("SELECT COUNT(*) FROM diagnostic_rows WHERE " + clause, (job_id,)).fetchone()[0]
            rows = db.execute("SELECT position,payload FROM diagnostic_rows WHERE " + clause + " ORDER BY position LIMIT ? OFFSET ?", (job_id, RESULT_PAGE_SIZE, (page - 1) * RESULT_PAGE_SIZE)).fetchall()
        return [json.loads(self.cipher.open(row["payload"], f"{job_id}:diagnostic-row:{row['position']}")) for row in rows], count
