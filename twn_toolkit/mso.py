"""Versioned saved objects, durable proposals and bounded fleet replication.

SQLite is authoritative for registered local objects. Mainframe revisions are
accepted using compare-and-swap; delivery never executes the stored definition.
"""
from __future__ import annotations

import json
import math
import os
import uuid
from contextlib import contextmanager
from pathlib import Path

from .backup_source_reads import read_json_file, current_source_budget, source_json_loads, checked_source_json_text, SourceReadLimit
from .distributed_agents import DistributedIdentityStore, DistributedSettingsStore
from .file_transactions import file_transaction
from .sqlite_store import bootstrap_sqlite_store, sqlite_store_connection
from .mso_types import LIST_TYPES, default_profiles, validate_list
from .mso_secrets import transform as transform_secrets
from . import mso_references as references

PROTOCOL = 1
BATCH = 4
MAX_OBJECT_BYTES = 64 * 1024
MAX_FLEET_OBJECTS = 5000
PING = "ping.profile"


class MsoConflict(ValueError):
    pass


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _uuid(value):
    try:
        result = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid MSO object identity.") from exc
    if result != value:
        raise ValueError("Invalid MSO object identity.")
    return result


def _ping(value):
    from .network_tools import parse_ping_targets
    if not isinstance(value, dict):
        raise ValueError("Invalid Ping profile.")
    name = value.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise ValueError("Profile names must be 1–100 characters.")
    targets = value.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 250:
        raise ValueError("MSO Ping profiles require 1–250 targets.")
    lines = []
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("Invalid Ping target.")
        host, label = target.get("host"), target.get("label", "")
        if not isinstance(host, str) or not isinstance(label, str) or any(c in host + label for c in "\r\n="):
            raise ValueError("Invalid Ping target.")
        lines.append(f"{label} = {host}" if label else host)
    parsed = parse_ping_targets("\n".join(lines), limit=250)
    interval, timeout = value.get("interval", 2), value.get("timeout", 1)
    if isinstance(interval, bool) or not isinstance(interval, int) or not 1 <= interval <= 60:
        raise ValueError("Invalid Ping interval.")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not .01 <= timeout <= 60:
        raise ValueError("Invalid Ping timeout.")
    thresholds = value.get("health_thresholds", {})
    if not isinstance(thresholds, dict):
        raise ValueError("Invalid Ping thresholds.")
    cleaned = {}
    for key, maximum in (("loss_pct", 100), ("latency_ms", 60000), ("jitter_ms", 60000)):
        if key not in thresholds:
            continue
        number = thresholds[key]
        if number is not None and (isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number) or not 0 <= number <= maximum):
            raise ValueError("Invalid Ping thresholds.")
        cleaned[key] = number
    return {"name": name.strip(), "targets": parsed, "interval": interval,
            "timeout": timeout, "health_thresholds": cleaned}


# Adding a type requires an explicit validator, not arbitrary file replication.
OBJECT_TYPES = {PING: _ping, **{kind: (lambda payload, kind=kind: validate_list(kind, payload)) for kind in LIST_TYPES if kind != PING}}


def validate(kind, payload):
    if not isinstance(kind, str) or kind not in OBJECT_TYPES:
        raise ValueError("Unsupported MSO object type. Upgrade this instance.")
    if len(_json(payload).encode()) > MAX_OBJECT_BYTES:
        raise ValueError("MSO object exceeds 64 KiB.")
    return OBJECT_TYPES[kind](payload)


class MsoStore:
    def __init__(self, instance_path, kind=PING):
        if kind not in OBJECT_TYPES:
            raise ValueError("Unsupported MSO object type.")
        self.kind = kind
        self.instance = Path(instance_path)
        self.path = self.instance / "mso.sqlite3"
        self.settings = DistributedSettingsStore(self.instance)
        self.node = DistributedIdentityStore(self.instance).load_or_create()["device_id"]
        bootstrap_sqlite_store(self.path, self._schema)
        os.chmod(self.path, 0o600)

    def _dump(self, value):
        return _json(transform_secrets(value, self.instance, encrypt=True))

    def _load(self, value):
        return transform_secrets(source_json_loads(value), self.instance, encrypt=False)

    def _schema(self, db):
        db.execute("CREATE TABLE IF NOT EXISTS mso_meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        db.execute("""CREATE TABLE IF NOT EXISTS mso_objects (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0,
            dirty INTEGER NOT NULL DEFAULT 0, deleted INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 1, origin TEXT NOT NULL DEFAULT '',
            inflight TEXT NOT NULL DEFAULT '', conflict TEXT NOT NULL DEFAULT '')""")
        db.execute("""CREATE TABLE IF NOT EXISTS mso_hub (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
            revision INTEGER NOT NULL, deleted INTEGER NOT NULL, origin TEXT NOT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS mso_hub_revision ON mso_hub(revision)")
        db.execute("""CREATE TABLE IF NOT EXISTS mso_receipts (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, peer TEXT NOT NULL, operation TEXT NOT NULL,
            object_id TEXT NOT NULL, revision INTEGER NOT NULL, UNIQUE(peer, operation))""")
        for key, value in (("epoch", str(uuid.uuid4())), ("fleet", ""), ("cursor", "0"), ("sequence", "0")):
            db.execute("INSERT OR IGNORE INTO mso_meta VALUES (?,?)", (key, value))
        self._migrate(db, self.kind)
        if self.kind == references.CREDENTIAL:
            self._migrate(db, references.HOST)

    def _migrate(self, db, kind):
        spec = LIST_TYPES[kind]
        marker = "ping_migrated" if kind == PING else "migrated:" + kind
        if self._meta(db, marker):
            return
        try:
            profiles = read_json_file(self.instance / spec.filename)
        except FileNotFoundError:
            profiles = default_profiles(kind)
        if not isinstance(profiles, list) or any(
            not isinstance(profile, dict) or not isinstance(profile.get("name"), str)
            for profile in profiles
        ):
            raise ValueError(f"Invalid saved-list file: {spec.filename}. Repair it before migration.")
        if kind == 'snmp.credentials':
            from .profile_secrets import transform_profiles
            from .mso_secrets import SNMP_SECRET_FIELDS
            profiles = transform_profiles(profiles, self.instance, spec.filename, SNMP_SECRET_FIELDS, encrypt=False)
        if kind == 'snmp.hosts':
            self._migrate(db, 'snmp.credentials')
            credentials = {self._load(row['payload'])['name']: row['id'] for row in db.execute("SELECT id,payload FROM mso_objects WHERE kind='snmp.credentials' AND deleted=0")}
            profiles = [{**profile, 'credential_id': credentials.get(profile.get('credential_name'), '')} for profile in profiles]
        for profile in profiles:
            db.execute("INSERT INTO mso_objects(id,kind,payload,origin) VALUES (?,?,?,?)",
                       (str(uuid.uuid4()), kind, self._dump(profile), self.node))
        self._set(db, marker, "1")

    @staticmethod
    def _meta(db, key):
        row = db.execute("SELECT value FROM mso_meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else ""

    @staticmethod
    def _set(db, key, value):
        db.execute("INSERT INTO mso_meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    @contextmanager
    def _tx(self):
        # Same lock order as coordination-role changes; late replies cannot reattach.
        with file_transaction(self.settings.path), sqlite_store_connection(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            yield db

    def _role(self):
        return self.settings.get()["role"]

    def _ensure_fleet(self, db):
        fleet = self._meta(db, "fleet")
        if not fleet:
            fleet = str(uuid.uuid4())
            self._set(db, "fleet", fleet)
        return fleet

    def profiles(self, *, metadata=False):
        with self._tx() as db:
            self._charge_source(db)
            rows = db.execute("SELECT * FROM mso_objects WHERE kind=? AND (deleted=0 OR conflict!='')", (self.kind,)).fetchall()
            result = []
            payloads = [self._load(row["payload"]) for row in rows]
            live_names = {payload["name"] for row, payload in zip(rows, payloads) if not row["deleted"]}
            for row, payload in zip(rows, payloads):
                if row["deleted"] and row["conflict"] and payload["name"] in live_names:
                    payload["name"] = payload["name"][:56] + " [MSO " + row["id"] + "]"
                if self.kind == references.HOST:
                    payload = references.project_host(self, db, payload)
                if metadata:
                    payload["mso"] = self._info(row)
                result.append(payload)
            return sorted(result, key=lambda value: value["name"].lower())

    def profile(self, identifier):
        with self._tx() as db:
            row = db.execute("SELECT * FROM mso_objects WHERE id=? AND kind=? AND (deleted=0 OR conflict!='')", (_uuid(identifier), self.kind)).fetchone()
            if not row:
                return None
            payload = self._load(row["payload"])
            if row["deleted"] and row["conflict"] and any(
                self._load(other["payload"])["name"] == payload["name"]
                for other in db.execute("SELECT payload FROM mso_objects WHERE kind=? AND deleted=0", (self.kind,))
            ):
                payload["name"] = payload["name"][:56] + " [MSO " + row["id"] + "]"
            if self.kind == references.HOST:
                payload = references.project_host(self, db, payload)
            return {**payload, "mso": self._info(row)}

    def _info(self, row):
        state = "Conflict" if row["conflict"] else "Pending" if row["dirty"] else "Synced" if row["enabled"] else "Local"
        return {"id": row["id"], "enabled": bool(row["enabled"]), "version": row["version"],
                "kind": row["kind"], "revision": row["revision"], "state": state, "origin": row["origin"],
                "can_withdraw": True, "deleted": bool(row["deleted"]), "conflict": self._load(row["conflict"]) if row["conflict"] else None}

    def save(self, payload, original_name="", *, enabled=None, expected=None, object_id=None, guarded=False):
        if enabled is not None and not isinstance(enabled, bool):
            raise ValueError("MSO must be on or off.")
        payload = dict(payload)
        payload.pop("mso", None)
        with self._tx() as db:
            rows = db.execute("SELECT * FROM mso_objects WHERE kind=? AND deleted=0", (self.kind,)).fetchall()
            old = next((r for r in rows if self._load(r["payload"])["name"] == (original_name or payload["name"])), None)
            self._guard(old, object_id, expected, guarded)
            if any(self._load(r["payload"])["name"] == payload["name"] and (not old or r["id"] != old["id"]) for r in rows):
                raise MsoConflict("Another profile already uses that name. Choose a different name.")
            if old and expected is not None and expected != old["version"]:
                raise MsoConflict("This profile changed. Reload before saving your changes.")
            active = bool(old["enabled"]) if enabled is None and old else bool(enabled)
            if active and self._role() == "standalone":
                raise ValueError("Connect to a Mainframe or enable Mainframe mode before using MSO.")
            if self.kind == references.HOST:
                payload = references.prepare_host(self, db, payload, active)
            if active:
                payload = validate(self.kind, payload)
            if old and old["conflict"]:
                raise MsoConflict("Resolve the MSO conflict before editing this profile.")
            if old and old["enabled"] and not active:
                if self.kind == references.CREDENTIAL and (references.has_references(self, db, old['id'], shared_only=True) or references.has_references(self, db, old['id'], hub=True)):
                    raise MsoConflict('Shared hosts still use this credential. Reassign them or turn off their MSO first.')
                self._withdraw(db, old)
                identifier = str(uuid.uuid4())
                db.execute("INSERT INTO mso_objects(id,kind,payload,origin) VALUES (?,?,?,?)", (identifier, self.kind, self._dump(payload), self.node))
                if self.kind == references.CREDENTIAL:
                    references.remap_references(self, db, {old['id']: identifier})
            elif old:
                identifier = old["id"]
                db.execute("UPDATE mso_objects SET payload=?,enabled=?,dirty=?,version=version+1 WHERE id=?",
                           (self._dump(payload), active, active, identifier))
            else:
                identifier = str(uuid.uuid4())
                db.execute("INSERT INTO mso_objects(id,kind,payload,enabled,dirty,origin) VALUES (?,?,?,?,?,?)",
                           (identifier, self.kind, self._dump(payload), active, active, self.node))
            if self._role() == "mainframe":
                self._flush(db)
            if self.kind == references.HOST:
                payload = references.project_host(self, db, payload)
            return {**payload, "mso": self._info(db.execute("SELECT * FROM mso_objects WHERE id=?", (identifier,)).fetchone())}

    @staticmethod
    def _guard(row, object_id, expected, guarded):
        if object_id is not None and (not row or row["id"] != object_id):
            raise MsoConflict("This profile was renamed or removed. Refresh profiles before saving.")
        if expected is not None and (isinstance(expected, bool) or not isinstance(expected, int) or not row or expected != row["version"]):
            raise MsoConflict("This profile changed. Reload before continuing.")
        if guarded and row and row["enabled"] and (object_id is None or expected is None):
            raise MsoConflict("Reload this shared profile before continuing.")

    def _withdraw(self, db, row):
        db.execute("UPDATE mso_objects SET deleted=1,dirty=1,version=version+1 WHERE id=?", (row["id"],))

    def delete(self, name, expected=None, *, object_id=None, guarded=False):
        with self._tx() as db:
            row = next((r for r in db.execute("SELECT * FROM mso_objects WHERE kind=? AND deleted=0", (self.kind,)) if self._load(r["payload"])["name"] == name), None)
            self._guard(row, object_id, expected, guarded)
            if not row:
                return False
            if expected is not None and expected != row["version"]:
                raise MsoConflict("This profile changed. Reload before deleting it.")
            if self.kind == references.CREDENTIAL and (references.has_references(self, db, row['id']) or references.has_references(self, db, row['id'], hub=True)):
                raise MsoConflict('Hosts still use this credential. Reassign or remove them first.')
            if row["enabled"]:
                if row["conflict"]:
                    raise MsoConflict("Resolve the MSO conflict before deleting this profile.")
                self._withdraw(db, row)
                if self._role() == "mainframe":
                    self._flush(db)
            else:
                db.execute("DELETE FROM mso_objects WHERE id=?", (row["id"],))
            return True

    def _charge_source(self, db):
        budget = current_source_budget()
        if budget is None:
            return
        size, count = db.execute("SELECT COALESCE(SUM(length(CAST(payload AS BLOB))+length(CAST(inflight AS BLOB))+length(CAST(conflict AS BLOB))+256),0), COUNT(*) FROM mso_objects WHERE kind=?", (self.kind,)).fetchone()
        if size > budget[0] or count * 14 > budget[1]:
            raise SourceReadLimit("Selected MSO backup data exceeds the read limit. Export fewer groups or reduce a large source.")
        budget[0] -= size
        budget[1] -= count * 14

    def backup_snapshot(self):
        with self._tx() as db:
            self._charge_source(db)
            rows = [dict(row) for row in db.execute("SELECT * FROM mso_objects WHERE kind=?", (self.kind,))]
            for row in rows:
                for column in ("payload", "inflight", "conflict"):
                    checked_source_json_text(row[column])
            return rows

    def restore_backup_snapshot(self, rows):
        # Private rollback only: preserve UUIDs, revisions and pending operations.
        with self._tx() as db:
            previous = references.credential_ids(self, db) if self.kind == references.CREDENTIAL else {}
            db.execute("DELETE FROM mso_objects WHERE kind=?", (self.kind,))
            for row in rows:
                db.execute("INSERT INTO mso_objects(id,kind,payload,enabled,revision,dirty,deleted,version,origin,inflight,conflict) VALUES (:id,:kind,:payload,:enabled,:revision,:dirty,:deleted,:version,:origin,:inflight,:conflict)", row)
            if previous:
                references.remap_replaced_credentials(self, db, previous)

    def replace_local(self, profiles):
        with self._tx() as db:
            if db.execute("SELECT 1 FROM mso_objects WHERE kind=? AND enabled=1 AND (deleted=0 OR dirty=1 OR conflict!='') LIMIT 1", (self.kind,)).fetchone():
                raise ValueError("Withdraw MSO profiles before replacing this library from a configuration backup.")
            previous = references.credential_ids(self, db) if self.kind == references.CREDENTIAL else {}
            db.execute("DELETE FROM mso_objects WHERE kind=?", (self.kind,))
            for payload in profiles:
                if self.kind == references.HOST:
                    payload = references.prepare_host(self, db, payload, False)
                payload = {k: v for k, v in payload.items() if k != "mso"}
                db.execute("INSERT INTO mso_objects(id,kind,payload,origin) VALUES (?,?,?,?)", (str(uuid.uuid4()), self.kind, self._dump(payload), self.node))
            if previous:
                references.remap_replaced_credentials(self, db, previous)

    def _proposal(self, db, row):
        if row["inflight"]:
            return self._load(row["inflight"])
        proposal = {"operation": str(uuid.uuid4()), "id": row["id"], "kind": row["kind"],
                    "base": row["revision"], "payload": self._load(row["payload"]),
                    "deleted": bool(row["deleted"]), "version": row["version"]}
        db.execute("UPDATE mso_objects SET inflight=? WHERE id=?", (self._dump(proposal), row["id"]))
        return proposal

    @staticmethod
    def _supported_types(types):
        if not isinstance(types, list) or not 1 <= len(types) <= 64 or any(not isinstance(kind, str) or len(kind) > 64 for kind in types):
            raise ValueError("Invalid MSO type capabilities.")
        supported = sorted(set(types) & set(OBJECT_TYPES))
        if not supported:
            raise ValueError("No compatible MSO object types.")
        return supported

    def request(self, types=None):
        supported = self._supported_types(list(OBJECT_TYPES) if types is None else types)
        with self._tx() as db:
            signature = self._dump(supported)
            history = max(int(self._meta(db, "history") or 0), int(self._meta(db, "cursor")))
            self._set(db, "history", history)
            previous_types = self._load(self._meta(db, "cursor_types")) if self._meta(db, "cursor_types") else [PING]
            if self._meta(db, "cursor_types") != signature:
                # Rescan newly supported kinds without forgetting the recovery watermark.
                if set(supported) - set(previous_types):
                    self._set(db, "cursor", "0")
                self._set(db, "cursor_types", signature)
                self._set(db, "epoch", str(uuid.uuid4()))
            placeholders = ",".join("?" for _ in supported)
            proposals = [self._proposal(db, row) for row in db.execute(
                f"SELECT * FROM mso_objects WHERE dirty=1 AND conflict='' AND kind IN ({placeholders}) ORDER BY {references.ORDER} LIMIT ?", (*supported, BATCH)).fetchall()]
            return {"protocol": PROTOCOL, "fleet": self._meta(db, "fleet"), "epoch": self._meta(db, "epoch"),
                    "cursor": int(self._meta(db, "cursor")), "history": history, "types": supported, "proposals": proposals}

    def _hub_record(self, row):
        return {"id": row["id"], "kind": row["kind"], "payload": self._load(row["payload"]),
                "revision": row["revision"], "deleted": bool(row["deleted"]), "origin": row["origin"]}

    def _accept(self, db, peer, proposal):
        if not isinstance(proposal, dict):
            raise ValueError("Invalid MSO proposal.")
        ident, operation = _uuid(proposal.get("id")), _uuid(proposal.get("operation"))
        base = proposal.get("base")
        if isinstance(base, bool) or not isinstance(base, int) or base < 0 or not isinstance(proposal.get("deleted"), bool):
            raise ValueError("Invalid MSO revision or deletion.")
        payload = validate(proposal.get("kind"), proposal.get("payload"))
        old = db.execute("SELECT * FROM mso_hub WHERE id=?", (ident,)).fetchone()
        receipt = db.execute("SELECT * FROM mso_receipts WHERE peer=? AND operation=?", (peer, operation)).fetchone()
        if receipt:
            if receipt["object_id"] != ident:
                raise ValueError("MSO operation identity was reused.")
            return {"id": ident, "operation": operation, "revision": receipt["revision"], "accepted": True}
        if old and old["kind"] != proposal["kind"]:
            raise ValueError("MSO object type cannot change.")
        dependency_error = references.hub_dependency_error(self, db, proposal, payload)
        if dependency_error:
            return {"id": ident, "operation": operation, "accepted": False, "error": dependency_error,
                    "remote": self._hub_record(old) if old else None}
        stale = base != (old["revision"] if old else 0) or bool(old and old["deleted"])
        if stale:
            return {"id": ident, "operation": operation, "accepted": False,
                    "error": "The shared profile changed.",
                    "remote": self._hub_record(old) if old else None}
        if not old and db.execute("SELECT COUNT(*) FROM mso_hub").fetchone()[0] >= MAX_FLEET_OBJECTS:
            raise ValueError("MSO fleet capacity reached.")
        revision = int(self._meta(db, "sequence")) + 1
        self._set(db, "sequence", revision)
        origin = old["origin"] if old else peer
        db.execute("INSERT INTO mso_hub VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,revision=excluded.revision,deleted=excluded.deleted",
                   (ident, proposal["kind"], self._dump(payload), revision, proposal["deleted"], origin))
        db.execute("INSERT INTO mso_receipts(peer,operation,object_id,revision) VALUES (?,?,?,?)", (peer, operation, ident, revision))
        db.execute("DELETE FROM mso_receipts WHERE sequence < (SELECT COALESCE(MAX(sequence),0)-10000 FROM mso_receipts)")
        return {"id": ident, "operation": operation, "revision": revision, "accepted": True}

    def exchange(self, peer, request):
        with self._tx() as db:
            if self._role() != "mainframe":
                raise ValueError("MSO exchange requires a Mainframe.")
            if not isinstance(request, dict):
                raise ValueError("Invalid MSO request.")
            _uuid(request.get("epoch"))
            fleet = self._ensure_fleet(db)
            if request.get("protocol") != PROTOCOL or request.get("fleet") not in ("", fleet):
                raise ValueError("MSO fleet or protocol mismatch. Detach explicitly before changing fleets.")
            cursor, proposals = request.get("cursor"), request.get("proposals")
            if isinstance(cursor, bool) or not isinstance(cursor, int) or not 0 <= cursor <= int(self._meta(db, "sequence")):
                raise ValueError("Invalid MSO cursor; recovery requires explicit reconciliation.")
            history = request.get("history", cursor)
            if isinstance(history, bool) or not isinstance(history, int) or history < cursor or history > int(self._meta(db, "sequence")):
                raise ValueError("Invalid MSO history; recovery requires explicit reconciliation.")
            if not isinstance(proposals, list) or len(proposals) > BATCH:
                raise ValueError("MSO batch is too large.")
            supported = self._supported_types(request.get("types", [PING]))
            if any(not isinstance(p, dict) or p.get("kind") not in supported for p in proposals):
                raise ValueError("Unsupported proposal type for this exchange.")
            self._flush(db)
            acknowledgements = [self._accept(db, peer, p) for p in proposals]
            placeholders = ",".join("?" for _ in supported)
            rows = db.execute(f"SELECT * FROM mso_hub WHERE revision>? AND kind IN ({placeholders}) ORDER BY revision LIMIT ?", (cursor, *supported, BATCH)).fetchall()
            # Mainframe's own local projection sees accepted agent edits immediately.
            for proposal in proposals:
                row = db.execute("SELECT * FROM mso_hub WHERE id=?", (proposal["id"],)).fetchone()
                if row:
                    self._apply(db, self._hub_record(row))
            return {"protocol": PROTOCOL, "fleet": fleet, "epoch": request.get("epoch"),
                    "acknowledgements": acknowledgements, "objects": [self._hub_record(r) for r in rows],
                    "cursor": rows[-1]["revision"] if rows else cursor}

    def _ack(self, db, acknowledgement):
        row = db.execute("SELECT * FROM mso_objects WHERE id=?", (acknowledgement["id"],)).fetchone()
        if not row or not row["inflight"]:
            return
        sent = self._load(row["inflight"])
        if sent["operation"] != acknowledgement["operation"]:
            return
        if acknowledgement["accepted"]:
            db.execute("UPDATE mso_objects SET revision=?,dirty=?,inflight='' WHERE id=?",
                       (acknowledgement["revision"], row["version"] != sent["version"], row["id"]))
        else:
            db.execute("UPDATE mso_objects SET conflict=?,inflight='',version=version+1 WHERE id=?", (self._dump(acknowledgement), row["id"]))

    def _apply(self, db, remote):
        self._migrate(db, remote["kind"])
        if remote["kind"] == references.CREDENTIAL:
            self._migrate(db, references.HOST)
        ident = _uuid(remote["id"])
        payload = validate(remote["kind"], remote["payload"])
        row = db.execute("SELECT * FROM mso_objects WHERE id=?", (ident,)).fetchone()
        if row and row["kind"] != remote["kind"]:
            raise ValueError("MSO object type cannot change.")
        if row and remote["revision"] <= row["revision"]:
            return
        if row and (row["dirty"] or row["conflict"]):
            conflict = self._dump({"remote": remote, "error": "The shared profile changed while local edits were pending."})
            if not row["conflict"] or self._load(row["conflict"]) != self._load(conflict):
                db.execute("UPDATE mso_objects SET conflict=?,version=version+1 WHERE id=?", (conflict, ident))
            return
        # Names are display labels, never identity. Preserve colliding local data.
        collision = next((r for r in db.execute("SELECT id,payload FROM mso_objects WHERE kind=? AND deleted=0 AND id!=?", (remote["kind"], ident)) if self._load(r["payload"])["name"] == payload["name"]), None)
        if collision and not remote["deleted"]:
            payload["name"] = payload["name"][:56] + " [MSO " + ident + "]"
        collision_state = self._dump({"remote": remote, "error": "A local profile already uses this name. Rename it or explicitly keep this MSO name."}) if collision and not remote["deleted"] else ""
        db.execute("""INSERT INTO mso_objects(id,kind,payload,enabled,revision,deleted,origin)
            VALUES (?,?,?,1,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,
            revision=excluded.revision,deleted=excluded.deleted,origin=excluded.origin,
            version=mso_objects.version+1,enabled=1,conflict='',dirty=0,inflight=''""",
                   (ident, remote["kind"], self._dump(payload), remote["revision"], remote["deleted"], remote["origin"]))
        if collision_state:
            db.execute("UPDATE mso_objects SET conflict=? WHERE id=?", (collision_state, ident))

    def receive(self, response, request):
        with self._tx() as db:
            if self._role() != "agent" or request["epoch"] != self._meta(db, "epoch"):
                return
            fleet = _uuid(response.get("fleet"))
            if response.get("protocol") != PROTOCOL or response.get("epoch") != request["epoch"] or self._meta(db, "fleet") not in {"", fleet}:
                raise ValueError("Invalid MSO response identity.")
            objects, acknowledgements, cursor = response.get("objects"), response.get("acknowledgements"), response.get("cursor")
            if not isinstance(objects, list) or not isinstance(acknowledgements, list) or len(objects) > BATCH or len(acknowledgements) > BATCH:
                raise ValueError("Invalid MSO response batch.")
            if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < request["cursor"]:
                raise ValueError("Invalid MSO response cursor.")
            previous = request["cursor"]
            for remote in objects:
                self._validate_remote(remote)
                if remote["kind"] not in request.get("types", [PING]):
                    raise ValueError("Unexpected MSO response type.")
                if not previous < remote["revision"] <= cursor:
                    raise ValueError("Invalid MSO response order.")
                previous = remote["revision"]
            if cursor != previous:
                raise ValueError("Invalid MSO response cursor.")
            sent = {(p["operation"], p["id"]) for p in request["proposals"]}
            seen = set()
            for ack in acknowledgements:
                if not isinstance(ack, dict) or not isinstance(ack.get("accepted"), bool):
                    raise ValueError("Invalid MSO acknowledgement.")
                key = (_uuid(ack.get("operation")), _uuid(ack.get("id")))
                if key not in sent or key in seen:
                    raise ValueError("Unexpected MSO acknowledgement.")
                seen.add(key)
                if ack["accepted"]:
                    if isinstance(ack.get("revision"), bool) or not isinstance(ack.get("revision"), int) or ack["revision"] < 1:
                        raise ValueError("Invalid MSO acknowledgement revision.")
                elif ack.get("remote") is not None:
                    self._validate_remote(ack["remote"])
                    sent_kind = next(p["kind"] for p in request["proposals"] if p["id"] == ack["id"])
                    if ack["remote"]["kind"] != sent_kind:
                        raise ValueError("Invalid MSO conflict type.")
                    if ack["remote"]["id"] != ack["id"]:
                        raise ValueError("Invalid MSO conflict identity.")
            if seen != sent:
                raise ValueError("Missing MSO acknowledgement.")
            self._set(db, "fleet", fleet)
            for acknowledgement in response["acknowledgements"]:
                self._ack(db, acknowledgement)
            for remote in response["objects"]:
                self._apply(db, remote)
            self._set(db, "cursor", max(int(self._meta(db, "cursor")), response["cursor"]))
            self._set(db, "history", max(int(self._meta(db, "history") or 0), response["cursor"]))

    @staticmethod
    def _validate_remote(remote):
        if not isinstance(remote, dict):
            raise ValueError("Invalid MSO record.")
        _uuid(remote.get("id"))
        revision = remote.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1 or not isinstance(remote.get("deleted"), bool):
            raise ValueError("Invalid MSO record revision.")
        if not isinstance(remote.get("origin"), str) or not 1 <= len(remote["origin"]) <= 128:
            raise ValueError("Invalid MSO origin.")
        validate(remote.get("kind"), remote.get("payload"))

    def sync_status(self, error=None):
        with self._tx() as db:
            if error is not None:
                self._set(db, "sync_error", str(error)[:240])
            return {"error": self._meta(db, "sync_error")}

    def _flush(self, db):
        self._ensure_fleet(db)
        for row in db.execute(f"SELECT * FROM mso_objects WHERE dirty=1 AND conflict='' ORDER BY {references.ORDER}").fetchall():
            proposal = self._proposal(db, row)
            self._ack(db, self._accept(db, self.node, proposal))

    def resolve(self, ident, choice, expected):
        with self._tx() as db:
            row = db.execute("SELECT * FROM mso_objects WHERE id=?", (_uuid(ident),)).fetchone()
            if not row or not row["conflict"] or row["version"] != expected:
                raise MsoConflict("The conflict changed. Reload this profile.")
            remote = self._load(row["conflict"]).get("remote")
            if not remote:
                raise ValueError("Reconnect to retrieve the shared revision before resolving.")
            if choice == "fleet":
                db.execute("UPDATE mso_objects SET dirty=0,conflict='',inflight='',revision=0 WHERE id=?", (ident,))
                self._apply(db, remote)
                if db.execute("SELECT conflict FROM mso_objects WHERE id=?", (ident,)).fetchone()[0]:
                    raise MsoConflict("Rename the existing local profile before using this fleet name.")
            elif choice == "local" and not remote["deleted"]:
                db.execute("UPDATE mso_objects SET revision=?,dirty=1,conflict='',inflight='',version=version+1 WHERE id=?", (remote["revision"], ident))
                if self._role() == "mainframe":
                    self._flush(db)
            else:
                raise ValueError("The shared profile was removed. Keep a local duplicate or accept the removal.")

    @contextmanager
    def changing_role(self):
        with self._tx() as db:
            identities = {}
            for row in db.execute("SELECT * FROM mso_objects WHERE enabled=1").fetchall():
                if row["deleted"] and not row["conflict"]:
                    db.execute("DELETE FROM mso_objects WHERE id=?", (row["id"],))
                else:
                    identities[row["id"]] = str(uuid.uuid4())
                    db.execute("UPDATE mso_objects SET id=?,enabled=0,revision=0,dirty=0,deleted=0,inflight='',conflict='',origin=?,version=version+1 WHERE id=?", (identities[row["id"]], self.node, row["id"]))
            references.remap_references(self, db, identities)
            db.execute("DELETE FROM mso_hub")
            db.execute("DELETE FROM mso_receipts")
            for key, value in (("fleet", ""), ("cursor", "0"), ("history", "0"), ("sequence", "0"), ("epoch", str(uuid.uuid4()))):
                self._set(db, key, value)
            yield

    def detach(self):
        with self.changing_role():
            pass
