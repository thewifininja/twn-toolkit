"""Durable agent execution receipts and bounded transport lease maintenance."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from .distributed_jobs import JOB_PROTOCOL_VERSION, MAX_JOB_PAYLOAD_BYTES
from .operational import OperationalSettingsStore
_BOOT_ID = secrets.token_hex(16)


class OperationReceipts:
    def __init__(self, instance):
        root = Path(instance)
        self.path = root / "distributed-operation-receipts.sqlite3"
        self.operational_store = OperationalSettingsStore(str(root))
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, token TEXT NOT NULL, activation TEXT NOT NULL, lane TEXT NOT NULL, boot TEXT NOT NULL, result TEXT, acknowledged INTEGER NOT NULL DEFAULT 0, updated REAL NOT NULL)")
            for row in db.execute("SELECT * FROM receipts WHERE result IS NULL AND boot != ?", (_BOOT_ID,)).fetchall():
                result = {"id": row["id"], "attempt_token": row["token"], "state": "unknown", "output": {}, "error": "Agent restarted after accepting execution. Reconcile before retrying."}
                db.execute("UPDATE receipts SET result = ?, updated = ? WHERE id = ?", (json.dumps(result), time.time(), row["id"]))
            db.execute("DELETE FROM receipts WHERE acknowledged = 1 AND updated < ?", (time.time() - self._retention_seconds(),))
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _receipt_limit(self) -> int:
        return int(self.operational_store.get()["distributed_receipt_limit"])

    def _retention_seconds(self) -> int:
        return int(self.operational_store.get()["distributed_receipt_retention_hours"]) * 60 * 60

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level="IMMEDIATE")
        db.row_factory = sqlite3.Row
        return _Connection(db)

    def begin(self, job, lane):
        receipt_limit = self._receipt_limit()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM receipts WHERE id = ?", (job["id"],)).fetchone():
                return False
            db.execute(
                "DELETE FROM receipts WHERE id IN ("
                "SELECT id FROM receipts WHERE acknowledged = 1 ORDER BY updated "
                "LIMIT CASE WHEN (SELECT COUNT(*) FROM receipts) >= ? "
                "THEN (SELECT COUNT(*) FROM receipts) - ? + 1 ELSE 0 END)",
                (receipt_limit, receipt_limit),
            )
            if db.execute(
                "SELECT COUNT(*) FROM receipts WHERE acknowledged = 0"
            ).fetchone()[0] >= receipt_limit:
                raise OSError(
                    "Agent operation receipt capacity reached; execution was not started."
                )
            db.execute("INSERT INTO receipts (id, token, activation, lane, boot, updated) VALUES (?, ?, ?, ?, ?, ?)",
                       (job["id"], job["attempt_token"], job.get("activation_id", ""), lane, _BOOT_ID, time.time()))
        return True

    def finish(self, job, result):
        try:
            payload = json.dumps(result, separators=(",", ":"), sort_keys=True)
        except (TypeError, ValueError):
            result = {
                **result,
                "state": "unknown",
                "output": {},
                "error": "Result could not be encoded. The operation may have completed; reconcile before retrying.",
            }
            payload = json.dumps(result, separators=(",", ":"), sort_keys=True)
        if len(payload.encode("utf-8")) > MAX_JOB_PAYLOAD_BYTES:
            result = {
                **result,
                "state": "unknown",
                "output": {},
                "error": "Result exceeds the control envelope. The operation may have completed; reconcile before retrying.",
            }
            payload = json.dumps(result, separators=(",", ":"), sort_keys=True)
        with self.connect() as db:
            db.execute(
                "UPDATE receipts SET result = ?, updated = ?, acknowledged = 0 "
                "WHERE id = ? AND token = ?",
                (payload, time.time(), job["id"], job["attempt_token"]),
            )

    def pending(self, lane, activation):
        with self.connect() as db:
            rows = db.execute("SELECT result FROM receipts WHERE lane = ? AND activation = ? AND result IS NOT NULL AND acknowledged = 0 ORDER BY updated LIMIT 1", (lane, activation)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def discard_other_activations(self, activation):
        """Release receipts that cannot be reconciled after activation changes."""
        with self.connect() as db:
            db.execute(
                "UPDATE receipts SET acknowledged = 1, result = '{}', updated = ? "
                "WHERE activation != ? AND acknowledged = 0",
                (time.time(), activation),
            )

    def acknowledge(self, items):
        with self.connect() as db:
            for item in items:
                if isinstance(item, dict) and item.get("status") in {"accepted", "rejected"}:
                    # Keep a small tombstone; never retain bulk output after acknowledgement.
                    db.execute("UPDATE receipts SET acknowledged = 1, result = '{}', updated = ? WHERE id = ? AND token = ? AND result IS NOT NULL",
                               (time.time(), item.get("id"), item.get("attempt_token")))


class _Connection:
    def __init__(self, db):
        self.db = db
    def __enter__(self):
        return self.db
    def __exit__(self, *exc):
        try:
            return self.db.__exit__(*exc)
        finally:
            self.db.close()


def execute_owned(instance, jobs, client, lane, execute):
    receipts = OperationReceipts(instance)
    if not isinstance(jobs, list):
        return
    for job in jobs[:1]:
        if not isinstance(job, dict) or job.get("job_protocol") != JOB_PROTOCOL_VERSION or not job.get("attempt_token"):
            raise ValueError("Upgrade the Mainframe for owned operation delivery; legacy work will not execute.")
        if not receipts.begin(job, lane):
            continue
        result = {"id": job["id"], "attempt_token": job["attempt_token"], "state": "unknown", "output": {}, "error": "Execution outcome could not be confirmed."}
        stop = threading.Event()
        renewer = None
        try:
            grant = client.job_control(job, "start")
            if grant.get("state") != "running":
                result.update(state="failed", error="Execution was not started: the claim was cancelled or expired.")
            else:
                interval = max(0.05, float(grant["lease_seconds"]) / 3)
                def renew():
                    while not stop.wait(interval):
                        try:
                            state = client.job_control(job, "renew").get("state")
                            # Arbitrary capability handlers cannot be killed here.
                            # Stop extending their lease after cancellation so the
                            # coordinator will surface an unresolved outcome.
                            if state != "running":
                                return
                        except (OSError, ValueError):
                            # Lost contact cannot safely interrupt arbitrary external effects.
                            # Coordinator expiry exposes unknown; a later receipt may resolve it.
                            pass
                renewer = threading.Thread(target=renew, name="twn-operation-lease", daemon=True)
                renewer.start()
                output = execute(
                    instance,
                    str(job.get("capability_id", "")),
                    str(job.get("capability_version", "")),
                    job.get("inputs", {}),
                )
                result.update(state="succeeded", output=output, error="")
        except Exception as exc:
            # Generic handlers may raise after an external effect. Never claim a safe retry.
            result.update(error=" ".join(str(exc).split())[:1000])
        finally:
            stop.set()
            if renewer is not None:
                renewer.join()
            receipts.finish(job, result)
