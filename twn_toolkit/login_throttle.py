"""Shared, bounded admission control for public password verification."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import ipaddress
import math
import os
import time
from contextlib import contextmanager
from pathlib import Path

from .sqlite_store import bootstrap_sqlite_store, sqlite_store_connection

# Central code policy values; not per-user or UI settings.
WINDOW_SECONDS = 60
SOURCE_ATTEMPTS = 20
USERNAME_ATTEMPTS = 10
INSTANCE_ATTEMPTS = 120
MAX_BUCKETS = 4096
MAX_PASSWORD_CHECKS = 4
LOGIN_BODY_BYTES = 16 * 1024
DATABASE_WAIT_SECONDS = 0.25
AUDIT_INTERVAL_SECONDS = 60


class LoginThrottled(Exception):
    def __init__(self, retry_after: int, *, audit: bool = False):
        self.retry_after = max(1, retry_after)
        self.audit = audit
        super().__init__("Too many sign-in attempts. Try again shortly.")


class LoginThrottle:
    def __init__(self, instance_path: str | Path, secret: str | bytes):
        self.root = Path(instance_path)
        self.path = self.root / "login_throttle.sqlite3"
        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.root.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        bootstrap_sqlite_store(self.path, self._schema)

    @staticmethod
    def _schema(db):
        db.execute("CREATE TABLE IF NOT EXISTS buckets (key TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires REAL NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS buckets_expiry ON buckets(expires)")
        db.execute("CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY CHECK(id=1), rejected INTEGER NOT NULL, last_audit REAL NOT NULL)")
        db.execute("INSERT OR IGNORE INTO stats VALUES (1, 0, 0)")

    def _key(self, kind: str, value: str) -> str:
        return hmac.new(self.secret, (kind + ":" + value).encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _source(value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
            if isinstance(address, ipaddress.IPv6Address):
                if address.ipv4_mapped:
                    return str(address.ipv4_mapped)
                return str(ipaddress.ip_network((address, 64), strict=False))
            return str(address)
        except ValueError:
            return "unknown"

    def _reserve(self, source: str, username: str) -> None:
        keys = [
            ("instance", INSTANCE_ATTEMPTS),
            (self._key("source", self._source(source)), SOURCE_ATTEMPTS),
            (self._key("username", username.strip().casefold()), USERNAME_ATTEMPTS),
        ]
        denied = None
        with sqlite_store_connection(self.path, timeout_seconds=DATABASE_WAIT_SECONDS) as db:
            db.execute("BEGIN IMMEDIATE")
            # Sample time after acquiring the transaction: a waiting request
            # must not mistake a newer committed window for a clock rollback.
            now = time.time()
            # Expire counters, including timestamps invalidated by a backward
            # clock jump. Rejected requests never move an expiry forward.
            db.execute("DELETE FROM buckets WHERE expires <= ? OR expires > ?", (now, now + WINDOW_SECONDS))
            rows = {row["key"]: row for row in db.execute(
                "SELECT key, attempts, expires FROM buckets WHERE key IN (?, ?, ?)",
                tuple(key for key, _ in keys),
            )}
            wait = max(
                [rows[key]["expires"] - now for key, limit in keys
                 if key in rows and rows[key]["attempts"] >= limit],
                default=0,
            )
            missing = sum(key not in rows for key, _ in keys)
            if db.execute("SELECT COUNT(*) FROM buckets").fetchone()[0] + missing > MAX_BUCKETS:
                wait = max(wait, WINDOW_SECONDS)
            if wait:
                stats = db.execute("SELECT last_audit FROM stats WHERE id=1").fetchone()
                audit = now - stats["last_audit"] >= AUDIT_INTERVAL_SECONDS or now < stats["last_audit"]
                db.execute(
                    "UPDATE stats SET rejected=rejected+1, last_audit=? WHERE id=1",
                    (now if audit else stats["last_audit"],),
                )
                denied = LoginThrottled(math.ceil(wait), audit=audit)
            else:
                for key, _limit in keys:
                    db.execute(
                        "INSERT INTO buckets VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET attempts=attempts+1",
                        (key, now + WINDOW_SECONDS),
                    )
        # Raise only after committing the bounded rejection/audit counters.
        if denied:
            raise denied

    @contextmanager
    def attempt(self, source: str, username: str):
        # Stable slot files provide a cross-process cap without expiring an
        # active verifier's lease. The OS releases locks if a worker exits.
        slot = None
        for index in range(MAX_PASSWORD_CHECKS):
            fd = os.open(self.root / f".login-check-{index}.lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                continue
            except BaseException:
                os.close(fd)
                raise
            slot = fd
            break
        if slot is None:
            raise LoginThrottled(1)
        try:
            self._reserve(source, username)
            yield
        finally:
            os.close(slot)

    def reset(self) -> None:
        with sqlite_store_connection(self.path, timeout_seconds=DATABASE_WAIT_SECONDS) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM buckets")
            db.execute("UPDATE stats SET rejected=0, last_audit=0 WHERE id=1")

    def status(self) -> dict:
        with sqlite_store_connection(self.path, timeout_seconds=DATABASE_WAIT_SECONDS) as db:
            rejected = db.execute("SELECT rejected FROM stats WHERE id=1").fetchone()[0]
            active = db.execute("SELECT COUNT(*) FROM buckets WHERE expires>?", (time.time(),)).fetchone()[0]
        return {"active_buckets": active, "rate_rejections": rejected}
