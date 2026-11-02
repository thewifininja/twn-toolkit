"""One-use API admission and safe receipt metadata, never request/response content.

Only an existing, unexpired issued token can be claimed. Pruning cannot make an
old token executable again. There is deliberately no queue, dispatcher or retry.
"""
from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import re
import secrets
import time

from .network_tools import ToolInputError
from .sqlite_store import bootstrap_sqlite_store, sqlite_store_connection

ISSUE_TTL = 15 * 60
TERMINAL_RETENTION = 24 * 60 * 60
STALE_AFTER = 35  # Sender deadline is at most 30 seconds; allow completion bookkeeping.
OWNER_ISSUED_LIMIT = 128
GLOBAL_LIMIT = 4096
TOKEN = re.compile(r"[0-9a-f]{64}\Z")


class ReceiptCapacityError(ToolInputError):
    pass


class ApiRequestReceiptStore:
    def __init__(self, instance_path):
        self.path = Path(instance_path).resolve() / "api_request_receipts.sqlite3"
        bootstrap_sqlite_store(self.path, self._schema)
        os.chmod(self.path, 0o600)

    @staticmethod
    def _schema(db):
        db.execute("""CREATE TABLE IF NOT EXISTS api_request_receipts (
            token TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('issued','admitted','confirmed','unconfirmed')),
            issued REAL NOT NULL, expires REAL NOT NULL, admitted REAL, completed REAL,
            status INTEGER, elapsed_ms REAL, bytes INTEGER, truncated INTEGER)""")
        db.execute("CREATE INDEX IF NOT EXISTS api_receipt_owner ON api_request_receipts(owner_id, state)")
        db.execute("CREATE INDEX IF NOT EXISTS api_receipt_expiry ON api_request_receipts(state, expires, completed)")

    @contextmanager
    def _write(self):
        with sqlite_store_connection(self.path) as db:
            db.execute("PRAGMA synchronous = FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db

    @staticmethod
    def _prune(db, now):
        db.execute("""UPDATE api_request_receipts SET state='unconfirmed', completed=admitted+?
            WHERE state='admitted' AND admitted+? <= ?""", (STALE_AFTER, STALE_AFTER, now))
        db.execute("DELETE FROM api_request_receipts WHERE state='issued' AND expires <= ?", (now,))
        db.execute("DELETE FROM api_request_receipts WHERE completed IS NOT NULL AND completed <= ?", (now - TERMINAL_RETENTION,))

    def issue(self, owner_id):
        if not isinstance(owner_id, str) or not owner_id:
            raise ValueError("An API request owner is required.")
        now = time.time()
        with self._write() as db:
            self._prune(db, now)
            if db.execute("SELECT COUNT(*) FROM api_request_receipts").fetchone()[0] >= GLOBAL_LIMIT:
                raise ReceiptCapacityError("API request receipt capacity is busy. Wait for older receipts to expire.")
            if db.execute("SELECT COUNT(*) FROM api_request_receipts WHERE owner_id=? AND state='issued'", (owner_id,)).fetchone()[0] >= OWNER_ISSUED_LIMIT:
                raise ReceiptCapacityError("Too many unused API request forms. Reuse an open form or wait for older forms to expire.")
            token = secrets.token_hex(32)
            db.execute("INSERT INTO api_request_receipts(token,owner_id,state,issued,expires) VALUES (?,?,'issued',?,?)", (token, owner_id, now, now + ISSUE_TTL))
        return token

    def claim(self, owner_id, token):
        if not isinstance(token, str) or not TOKEN.fullmatch(token) or not isinstance(owner_id, str) or not owner_id:
            return False
        now = time.time()
        with self._write() as db:
            self._prune(db, now)
            return db.execute("""UPDATE api_request_receipts SET state='admitted', admitted=?
                WHERE token=? AND owner_id=? AND state='issued' AND expires>?""", (now, token, owner_id, now)).rowcount == 1

    def finish(self, owner_id, token, *, confirmed, status=None, elapsed_ms=None, bytes=None, truncated=None):
        if not isinstance(confirmed, bool):
            raise ValueError("Confirmation must be a boolean.")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError("Invalid HTTP status metadata.")
        if elapsed_ms is not None and (type(elapsed_ms) not in (int, float) or not 0 <= elapsed_ms <= 1e12 or not math.isfinite(elapsed_ms)):
            raise ValueError("Invalid request timing metadata.")
        if bytes is not None and (type(bytes) is not int or not 0 <= bytes <= 1024 * 1024):
            raise ValueError("Invalid response size metadata.")
        if truncated is not None and not isinstance(truncated, bool):
            raise ValueError("Invalid truncation metadata.")
        if not isinstance(token, str) or not TOKEN.fullmatch(token) or not isinstance(owner_id, str) or not owner_id:
            return
        now = time.time()
        with self._write() as db:
            self._prune(db, now)
            db.execute("""UPDATE api_request_receipts SET state=?, completed=?, status=?, elapsed_ms=?, bytes=?, truncated=?
                WHERE token=? AND owner_id=? AND state='admitted'""", ("confirmed" if confirmed else "unconfirmed", now, status, elapsed_ms, bytes, int(truncated) if truncated is not None else None, token, owner_id))

    def get(self, owner_id, token):
        if not isinstance(token, str) or not TOKEN.fullmatch(token) or not isinstance(owner_id, str) or not owner_id:
            return None
        with self._write() as db:
            self._prune(db, time.time())
            row = db.execute("SELECT token,state,issued,expires,admitted,completed,status,elapsed_ms,bytes,truncated FROM api_request_receipts WHERE token=? AND owner_id=?", (token, owner_id)).fetchone()
            if row is None:
                return None
            result = dict(row)
            if result["truncated"] is not None:
                result["truncated"] = bool(result["truncated"])
            return result
