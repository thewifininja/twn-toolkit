from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


COORDINATION_ROLES = {"standalone", "mainframe", "agent"}
ENROLLMENT_STATES = {"pending", "approved", "denied", "revoked"}
DEFAULT_AGENT_PORT = 5051
PAIRING_CODE_DIGITS = 6
AGENT_ONLINE_SECONDS = 30
MAX_ENROLLMENT_WINDOW_MINUTES = 24 * 60
GUI_TUNNEL_CAPABILITY = ("system.http.tunnel", "1")


class DistributedSettingsStore:
    """Owner-readable coordination settings; local operation is always enabled."""

    def __init__(self, instance_path: str | Path) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "distributed_settings.json"

    def get(self) -> dict[str, Any]:
        defaults = {
            "role": "standalone",
            "mainframe_listen_interfaces": ["127.0.0.1"],
            "mainframe_port": DEFAULT_AGENT_PORT,
            "mainframe_advertised_hosts": [],
            "agent_mainframe_url": "",
            "agent_mainframe_fallback_url": "",
        }
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return defaults
        if not isinstance(payload, dict):
            return defaults
        try:
            return normalize_distributed_settings(payload)
        except ValueError:
            return defaults

    def save(self, settings: dict[str, Any]) -> dict[str, Any]:
        normalized = normalize_distributed_settings(settings)
        self.instance_path.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            dir=self.instance_path, prefix=".distributed-settings-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(normalized, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, self.path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        return normalized


class DistributedEnrollmentWindow:
    """Persistent, closed-by-default authorization for new enrollment requests."""

    def __init__(self, instance_path: str | Path) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "distributed_enrollment_window.json"

    def status(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            open_until = float(payload.get("open_until", 0))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            open_until = 0
        now = time.time()
        remaining = max(0, int(open_until - now))
        return {
            "open": remaining > 0,
            "open_until": open_until if remaining > 0 else 0,
            "remaining_seconds": remaining,
        }

    def open(self, minutes: int) -> dict[str, Any]:
        try:
            minutes = int(minutes)
        except (TypeError, ValueError) as exc:
            raise ValueError("Enrollment duration must be a whole number of minutes.") from exc
        if not 1 <= minutes <= MAX_ENROLLMENT_WINDOW_MINUTES:
            raise ValueError("Enrollment duration must be between 1 minute and 24 hours.")
        self._write(time.time() + minutes * 60)
        return self.status()

    def close(self) -> dict[str, Any]:
        self._write(0)
        return self.status()

    def _write(self, open_until: float) -> None:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            dir=self.instance_path, prefix=".enrollment-window-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"open_until": float(open_until)}, handle)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, self.path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)


def normalize_distributed_settings(settings: dict[str, Any]) -> dict[str, Any]:
    role = str(settings.get("role", "standalone")).strip().lower()
    if role not in COORDINATION_ROLES:
        raise ValueError("Coordination role must be standalone, mainframe, or agent.")

    raw_interfaces = settings.get("mainframe_listen_interfaces", ["127.0.0.1"])
    if isinstance(raw_interfaces, str):
        raw_interfaces = raw_interfaces.replace(",", "\n").splitlines()
    if not isinstance(raw_interfaces, list):
        raise ValueError("Mainframe listen interfaces must be IP addresses.")
    interfaces: list[str] = []
    for raw_value in raw_interfaces:
        value = str(raw_value).strip()
        if not value:
            continue
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(f"Invalid mainframe listen interface: {value}") from exc
        if normalized not in interfaces:
            interfaces.append(normalized)
    if not interfaces:
        raise ValueError("Configure at least one mainframe listen interface.")

    try:
        port = int(settings.get("mainframe_port", DEFAULT_AGENT_PORT))
    except (TypeError, ValueError) as exc:
        raise ValueError("Mainframe agent port must be a whole number.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Mainframe agent port must be between 1 and 65535.")

    raw_advertised = settings.get("mainframe_advertised_hosts", [])
    if isinstance(raw_advertised, str):
        raw_advertised = raw_advertised.replace(",", "\n").splitlines()
    if not isinstance(raw_advertised, list):
        raise ValueError("Mainframe advertised hosts must be hostnames or IP addresses.")
    advertised_hosts: list[str] = []
    for raw_value in raw_advertised:
        value = _normalize_advertised_host(str(raw_value).strip())
        if value and value not in advertised_hosts:
            advertised_hosts.append(value)

    mainframe_url = _normalize_agent_mainframe_url(
        settings.get("agent_mainframe_url", ""), "Agent mainframe URL"
    )
    fallback_url = _normalize_agent_mainframe_url(
        settings.get("agent_mainframe_fallback_url", ""),
        "Agent fallback mainframe URL",
    )
    if role == "agent" and not mainframe_url:
        raise ValueError("Agent mode requires a mainframe HTTPS URL.")
    if fallback_url and fallback_url == mainframe_url:
        raise ValueError("Agent fallback mainframe URL must differ from the primary URL.")

    return {
        "role": role,
        "mainframe_listen_interfaces": interfaces,
        "mainframe_port": port,
        "mainframe_advertised_hosts": advertised_hosts,
        "agent_mainframe_url": mainframe_url,
        "agent_mainframe_fallback_url": fallback_url,
    }


def _normalize_agent_mainframe_url(value: object, label: str) -> str:
    url = str(value or "").strip().rstrip("/")
    if not url:
        return ""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{label} must be an HTTPS URL without credentials.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError(f"{label} cannot contain a path, query, or fragment.")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} contains an invalid port.") from exc
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        raise ValueError(f"{label} contains an invalid port.")
    return url


def split_mainframe_certificate_hosts(
    listen_interfaces: list[str], advertised_hosts: list[str]
) -> tuple[list[str], list[str]]:
    addresses = list(listen_interfaces)
    dns_names: list[str] = []
    for host in advertised_hosts:
        try:
            address = str(ipaddress.ip_address(host))
        except ValueError:
            dns_names.append(host)
        else:
            if address not in addresses:
                addresses.append(address)
    return addresses, dns_names


def _normalize_advertised_host(value: str) -> str:
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        hostname = value.rstrip(".").lower()
        if len(hostname) > 253:
            raise ValueError(f"Invalid mainframe advertised host: {value}")
        labels = hostname.split(".")
        if any(
            not label
            or len(label) > 63
            or label[0] == "-"
            or label[-1] == "-"
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        ):
            raise ValueError(f"Invalid mainframe advertised host: {value}")
        return hostname


class DistributedIdentityStore:
    """Persistent device identity whose private key never leaves this instance."""

    def __init__(self, instance_path: str | Path) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "distributed_identity.pem"

    def load_or_create(self) -> dict[str, str]:
        try:
            private_key = serialization.load_pem_private_key(
                self.path.read_bytes(), password=None
            )
        except FileNotFoundError:
            private_key = self._create()
        except (OSError, ValueError, TypeError) as exc:
            raise RuntimeError("Could not read the distributed device identity.") from exc
        if not isinstance(private_key, Ed25519PrivateKey):
            raise RuntimeError("Distributed device identity is not an Ed25519 key.")
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        fingerprint = hashlib.sha256(public_bytes).hexdigest()
        return {
            "device_id": f"twn_{fingerprint[:32]}",
            "public_key": public_bytes.hex(),
            "fingerprint": fingerprint,
        }

    def _create(self) -> Ed25519PrivateKey:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        content = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd, temporary_name = tempfile.mkstemp(
            dir=self.instance_path, prefix=".distributed-identity-", suffix=".pem"
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            try:
                os.link(temporary_name, self.path)
            except FileExistsError:
                pass
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        loaded = serialization.load_pem_private_key(self.path.read_bytes(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise RuntimeError("Could not create the distributed device identity.")
        return loaded


def pairing_code(handshake_transcript: bytes) -> str:
    """Return a comparison code; callers must pass the canonical full transcript."""
    if not handshake_transcript:
        raise ValueError("Pairing transcript cannot be empty.")
    digest = hashlib.sha256(b"twn-pairing-v1\0" + handshake_transcript).digest()
    value = int.from_bytes(digest[:8], "big") % (10**PAIRING_CODE_DIGITS)
    return f"{value:0{PAIRING_CODE_DIGITS}d}"


class DistributedAgentStore:
    """Mainframe trust records. Connection liveness remains runtime state."""

    def __init__(self, instance_path: str | Path) -> None:
        instance = Path(instance_path)
        instance.mkdir(parents=True, exist_ok=True)
        self.path = instance / "distributed_agents.sqlite3"
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS distributed_agents (
                    id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL UNIQUE,
                    fingerprint TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    state TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL DEFAULT '[]',
                    allowed_capabilities_json TEXT NOT NULL DEFAULT '[]',
                    requested_at REAL NOT NULL,
                    approved_at REAL,
                    revoked_at REAL,
                    last_seen_at REAL,
                    last_address TEXT NOT NULL DEFAULT '',
                    protocol_version INTEGER NOT NULL DEFAULT 0,
                    toolkit_version TEXT NOT NULL DEFAULT '',
                    platform TEXT NOT NULL DEFAULT '',
                    hostname TEXT NOT NULL DEFAULT ''
                );
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(distributed_agents)")
            }
            for name, declaration in {
                "protocol_version": "INTEGER NOT NULL DEFAULT 0",
                "toolkit_version": "TEXT NOT NULL DEFAULT ''",
                "platform": "TEXT NOT NULL DEFAULT ''",
                "hostname": "TEXT NOT NULL DEFAULT ''",
            }.items():
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE distributed_agents ADD COLUMN {name} {declaration}"
                    )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def request_enrollment(
        self, *, public_key: str, fingerprint: str, name: str, address: str = ""
    ) -> dict[str, Any]:
        public_key = _hex_value(public_key, 32, "public key")
        fingerprint = _hex_value(fingerprint, 32, "fingerprint")
        expected = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
        if not secrets.compare_digest(fingerprint, expected):
            raise ValueError("Agent fingerprint does not match its public key.")
        clean_name = " ".join(str(name).split())[:128]
        if not clean_name:
            raise ValueError("Agent name is required.")
        now = time.time()
        agent_id = f"agent_{fingerprint[:32]}"
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT state FROM distributed_agents WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if existing and existing["state"] in {"approved", "revoked"}:
                raise ValueError(f"That agent identity is already {existing['state']}.")
            connection.execute(
                """
                INSERT INTO distributed_agents
                    (id, public_key, fingerprint, name, state, requested_at,
                     last_seen_at, last_address)
                VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    name = excluded.name,
                    state = 'pending',
                    requested_at = excluded.requested_at,
                    revoked_at = NULL,
                    last_seen_at = excluded.last_seen_at,
                    last_address = excluded.last_address
                """,
                (agent_id, public_key, fingerprint, clean_name, now, now, address),
            )
        return self.get(agent_id)  # type: ignore[return-value]

    def set_state(self, agent_id: str, state: str) -> dict[str, Any]:
        if state not in {"approved", "denied", "revoked"}:
            raise ValueError("Agent state transition must approve, deny, or revoke enrollment.")
        now = time.time()
        timestamp_column = "approved_at" if state == "approved" else "revoked_at"
        with self._connect() as connection:
            current = connection.execute(
                "SELECT state FROM distributed_agents WHERE id = ?", (agent_id,)
            ).fetchone()
            if not current:
                raise ValueError("Agent enrollment does not exist.")
            if state in {"approved", "denied"} and current["state"] != "pending":
                raise ValueError("Only a pending agent can be approved or denied.")
            if state == "revoked" and current["state"] != "approved":
                raise ValueError("Only an approved agent can be revoked.")
            connection.execute(
                f"UPDATE distributed_agents SET state = ?, {timestamp_column} = ? WHERE id = ?",
                (state, now, agent_id),
            )
        return self.get(agent_id)  # type: ignore[return-value]

    def remove_revoked(self, agent_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM distributed_agents WHERE id = ?", (agent_id,)
            ).fetchone()
            if not row:
                raise ValueError("Agent enrollment does not exist.")
            if row["state"] != "revoked":
                raise ValueError("Only a revoked agent can be removed.")
            # Pairing sessions share this trust database and have no value after
            # the durable device trust record is deliberately removed.
            pairing_table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'distributed_pairing_sessions'"
            ).fetchone()
            if pairing_table:
                connection.execute(
                    "DELETE FROM distributed_pairing_sessions WHERE agent_id = ?",
                    (agent_id,),
                )
            connection.execute(
                "DELETE FROM distributed_agents WHERE id = ?", (agent_id,)
            )
        return _agent_record(row)

    def get(self, agent_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM distributed_agents WHERE id = ?", (agent_id,)
            ).fetchone()
        return _agent_record(row) if row else None

    def list(self, state: str | None = None) -> list[dict[str, Any]]:
        if state is not None and state not in ENROLLMENT_STATES:
            raise ValueError("Unknown enrollment state.")
        with self._connect() as connection:
            if state is None:
                rows = connection.execute(
                    "SELECT * FROM distributed_agents ORDER BY requested_at DESC"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM distributed_agents WHERE state = ? ORDER BY requested_at DESC",
                    (state,),
                ).fetchall()
        return [_agent_record(row) for row in rows]

    def record_heartbeat(
        self,
        agent_id: str,
        *,
        capabilities: list[dict[str, Any]],
        address: str,
        protocol_version: int = 0,
        toolkit_version: str = "",
        platform: str = "",
        hostname: str = "",
    ) -> dict[str, Any]:
        normalized = normalize_capabilities(capabilities)
        now = time.time()
        with self._connect() as connection:
            current = connection.execute(
                "SELECT state FROM distributed_agents WHERE id = ?", (agent_id,)
            ).fetchone()
            if not current or current["state"] != "approved":
                raise ValueError("Agent identity is not approved.")
            connection.execute(
                """
                UPDATE distributed_agents
                SET capabilities_json = ?, last_seen_at = ?, last_address = ?,
                    protocol_version = ?, toolkit_version = ?, platform = ?, hostname = ?
                WHERE id = ?
                """,
                (
                    json.dumps(normalized, separators=(",", ":")),
                    now,
                    address[:128],
                    max(0, min(int(protocol_version), 65535)),
                    " ".join(str(toolkit_version).split())[:64],
                    " ".join(str(platform).split())[:128],
                    " ".join(str(hostname).split())[:253],
                    agent_id,
                ),
            )
        return self.get(agent_id)  # type: ignore[return-value]

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()


def _hex_value(value: str, byte_length: int, label: str) -> str:
    clean = str(value).strip().lower()
    try:
        decoded = bytes.fromhex(clean)
    except ValueError as exc:
        raise ValueError(f"Agent {label} must be hexadecimal.") from exc
    if len(decoded) != byte_length or decoded.hex() != clean:
        raise ValueError(f"Agent {label} must contain {byte_length} bytes.")
    return clean


def _agent_record(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["capabilities"] = json.loads(item.pop("capabilities_json"))
    item["allowed_capabilities"] = json.loads(item.pop("allowed_capabilities_json"))
    last_seen = float(item.get("last_seen_at") or 0)
    item["online"] = bool(
        item.get("state") == "approved"
        and last_seen
        and time.time() - last_seen <= AGENT_ONLINE_SECONDS
    )
    return item


def agent_supports_capability(
    agent: dict[str, Any], capability_id: str, capability_version: str
) -> bool:
    return any(
        isinstance(item, dict)
        and str(item.get("id", "")) == capability_id
        and str(item.get("version", "")) == capability_version
        for item in agent.get("capabilities", [])
    )


def selectable_gui_agents(agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return approved, online agents that can serve their native web UI."""
    capability_id, capability_version = GUI_TUNNEL_CAPABILITY
    return [
        agent
        for agent in agents
        if agent.get("state") == "approved"
        and agent.get("online") is True
        and agent_supports_capability(agent, capability_id, capability_version)
    ]


def normalize_capabilities(values: Any) -> list[dict[str, str]]:
    if not isinstance(values, list) or len(values) > 256:
        raise ValueError("Agent capabilities must be a bounded list.")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("Each agent capability must be an object.")
        capability_id = str(value.get("id", "")).strip()
        version = str(value.get("version", "")).strip()
        if (
            not capability_id
            or len(capability_id) > 128
            or not version
            or len(version) > 32
        ):
            raise ValueError("Agent capability identifiers or versions are invalid.")
        if capability_id not in seen:
            normalized.append({"id": capability_id, "version": version})
            seen.add(capability_id)
    return normalized
