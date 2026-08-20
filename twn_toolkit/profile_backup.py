from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from datetime import datetime
from typing import Any

from .version import APP_VERSION

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


BACKUP_KDF_ITERATIONS = 390_000
CONFIGURATION_BACKUP_FORMAT = "twn-toolkit-configuration-backup"
LEGACY_BACKUP_FORMAT = "twn-toolkit-profile-backup"
ENCRYPTED_CONFIGURATION_BACKUP_FORMAT = "twn-toolkit-encrypted-configuration-backup"
LEGACY_ENCRYPTED_BACKUP_FORMAT = "twn-toolkit-encrypted-profile-backup"
IMPORT_PREVIEW_TTL_SECONDS = 30 * 60


# Every durable toolkit domain must have an explicit transfer boundary. This is
# intentionally broader than the portable catalog so a new database cannot be
# mistaken for an automatically portable configuration group.
SAVED_DATA_INVENTORY: tuple[dict[str, str], ...] = (
    {"id": "fortigate_profiles", "boundary": "portable", "reason": "Reusable device connection profile."},
    {"id": "fortiauthenticator_profiles", "boundary": "portable", "reason": "Reusable device connection profile."},
    {"id": "network_profiles", "boundary": "portable", "reason": "Reusable targets, credentials, and request templates."},
    {"id": "automation_definitions", "boundary": "portable", "reason": "Reusable definitions; runtime history is excluded."},
    {"id": "dashboard_layout", "boundary": "portable", "reason": "Reusable presentation preference without counters."},
    {"id": "remote_connection_library", "boundary": "portable", "reason": "User-owned reusable SSH and Telnet hosts and credentials."},
    {"id": "certificate_automation_profiles", "boundary": "portable", "reason": "Reusable PKI connection profiles without issued key material."},
    {"id": "access_profiles", "boundary": "portable", "reason": "Reusable authorization definitions without users or assignments."},
    {"id": "smtp_settings", "boundary": "portable", "reason": "Reusable delivery configuration re-encrypted on import."},
    {"id": "time_settings", "boundary": "portable", "reason": "Toolkit-local display and scheduling timezone."},
    {"id": "users_and_sessions", "boundary": "recovery", "reason": "Passwords, assignments, and session secrets are instance identity."},
    {"id": "server_identity", "boundary": "recovery", "reason": "Listener and allowlist settings can lock out a different host."},
    {"id": "operational_limits", "boundary": "recovery", "reason": "Capacity limits are host-specific."},
    {"id": "raspberry_pi_networking", "boundary": "recovery", "reason": "Interfaces, Wi-Fi credentials, certificates, and active NetworkManager profiles are host-specific."},
    {"id": "transfer_services", "boundary": "recovery", "reason": "Listeners, password hashes, host keys, and paths are host-specific."},
    {"id": "tls_and_issued_certificates", "boundary": "recovery", "reason": "Private keys and issued material remain bound to the instance."},
    {"id": "investigations", "boundary": "case", "reason": "Cases use portable case export and explicit merge workflows."},
    {"id": "datastore", "boundary": "recovery", "reason": "Operational files are protected by full recovery points."},
    {"id": "runtime_and_history", "boundary": "recovery", "reason": "Audit, activity, scrollback, captures, artifacts, and live state are not configuration."},
)


def build_backup_catalog(instance_path: str) -> list[dict[str, Any]]:
    from .tool_modules import admin, automation, fortiauthenticator, fortigate, network

    items = [
        *fortigate.backup_items(instance_path),
        *fortiauthenticator.backup_items(instance_path),
        *network.backup_items(instance_path),
        *automation.backup_items(instance_path),
        *admin.backup_items(instance_path),
    ]
    normalized: list[dict[str, Any]] = []
    for item in items:
        normalized.append(
            {
                **item,
                "category": str(item.get("category") or "Other"),
                "boundary": "portable",
                "supports_merge": bool(item.get("supports_merge", True)),
                "supports_replace": bool(item.get("supports_replace", True)),
            }
        )
    ids = [str(item["id"]) for item in normalized]
    if len(ids) != len(set(ids)):
        raise RuntimeError("Configuration backup group IDs must be unique.")
    return normalized


def build_reset_stores(instance_path: str) -> list[Any]:
    # Reset scope is deliberately separate from portability. Adding a portable
    # group must never silently broaden a destructive maintenance command.
    return [
        item["store"]
        for item in build_backup_catalog(instance_path)
        if item["id"]
        in {
            "fortigate_profiles",
            "fortiauthenticator_profiles",
            "ping_profiles",
            "dns_host_profiles",
            "dns_server_profiles",
            "radius_server_profiles",
            "radius_credential_profiles",
            "radius_attribute_profiles",
            "snmp_credential_profiles",
            "snmp_host_profiles",
            "snmp_oid_profiles",
            "port_scan_host_profiles",
            "port_scan_port_profiles",
            "ntp_host_profiles",
            "traceroute_host_profiles",
            "wol_target_profiles",
            "ssh_commandlets",
            "automation_definitions",
            "dashboard_layout",
        }
    ]


def selected_backup_items(
    backup_catalog: list[dict[str, Any]],
    selected_ids: set[str],
) -> list[dict[str, Any]]:
    return [item for item in backup_catalog if item["id"] in selected_ids]


def build_profile_backup(selected_items: list[dict[str, Any]]) -> dict[str, Any]:
    exported = {item["id"]: item["store"].all() for item in selected_items}
    return {
        "format": CONFIGURATION_BACKUP_FORMAT,
        "version": 2,
        "toolkit_version": APP_VERSION,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "groups": [
            {
                "id": item["id"],
                "label": item["label"],
                "category": item["category"],
                "sensitive": bool(item["sensitive"]),
                "record_count": len(exported[item["id"]]),
                "entry_count": backup_entry_count(
                    item["store"], exported[item["id"]]
                ),
            }
            for item in selected_items
        ],
        "items": exported,
    }


def encrypt_backup(payload: bytes, password: str) -> dict[str, Any]:
    salt = os.urandom(16)
    token = Fernet(_backup_key(password, salt)).encrypt(payload)
    return {
        "format": ENCRYPTED_CONFIGURATION_BACKUP_FORMAT,
        "version": 2,
        "kdf": "PBKDF2HMAC-SHA256",
        "iterations": BACKUP_KDF_ITERATIONS,
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "ciphertext": token.decode("ascii"),
    }


def decrypt_backup(encrypted_backup: dict[str, Any], password: str) -> dict[str, Any]:
    supported_container = (
        encrypted_backup.get("format") == ENCRYPTED_CONFIGURATION_BACKUP_FORMAT
        and int(encrypted_backup.get("version", 0)) == 2
    ) or (
        encrypted_backup.get("format") == LEGACY_ENCRYPTED_BACKUP_FORMAT
        and int(encrypted_backup.get("version", 0)) == 1
    )
    if (
        not supported_container
        or encrypted_backup.get("kdf") != "PBKDF2HMAC-SHA256"
        or int(encrypted_backup.get("iterations", 0)) != BACKUP_KDF_ITERATIONS
        or not isinstance(encrypted_backup.get("salt"), str)
        or not isinstance(encrypted_backup.get("ciphertext"), str)
    ):
        raise ValueError("This encrypted backup format is not supported.")
    try:
        salt = base64.urlsafe_b64decode(encrypted_backup["salt"].encode("ascii"))
        ciphertext = encrypted_backup["ciphertext"].encode("ascii")
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("This encrypted backup is not valid.") from exc
    try:
        plaintext = Fernet(_backup_key(password, salt)).decrypt(ciphertext)
    except InvalidToken as exc:
        raise ValueError("The backup password is incorrect or the encrypted file is damaged.") from exc
    return json.loads(plaintext.decode("utf-8"))


def is_encrypted_backup(value: Any) -> bool:
    return isinstance(value, dict) and value.get("format") in {
        ENCRYPTED_CONFIGURATION_BACKUP_FORMAT,
        LEGACY_ENCRYPTED_BACKUP_FORMAT,
    }


def validate_profile_backup(backup: dict[str, Any]) -> None:
    if not isinstance(backup, dict):
        raise ValueError("This does not look like a toolkit configuration backup.")
    supported = (
        (backup.get("format") == LEGACY_BACKUP_FORMAT and int(backup.get("version", 0)) == 1)
        or (
            backup.get("format") == CONFIGURATION_BACKUP_FORMAT
            and int(backup.get("version", 0)) == 2
        )
    )
    if not supported or not isinstance(backup.get("items"), dict):
        raise ValueError("This does not look like a toolkit configuration backup.")
    if not all(isinstance(records, list) for records in backup["items"].values()):
        raise ValueError("Configuration backup group data must be a list.")
    if backup.get("format") == CONFIGURATION_BACKUP_FORMAT:
        groups = backup.get("groups")
        if not isinstance(groups, list):
            raise ValueError("This configuration backup is missing its group manifest.")
        manifested = []
        for group in groups:
            if (
                not isinstance(group, dict)
                or not isinstance(group.get("id"), str)
                or group["id"] not in backup["items"]
                or not isinstance(group.get("record_count"), int)
                or group["record_count"] < 0
            ):
                raise ValueError("This configuration backup group manifest is invalid.")
            if group["record_count"] != len(backup["items"][group["id"]]):
                raise ValueError("This configuration backup group count does not match its data.")
            entry_count = group.get("entry_count", group["record_count"])
            if not isinstance(entry_count, int) or entry_count < 0:
                raise ValueError("This configuration backup group entry count is invalid.")
            manifested.append(group["id"])
        if set(manifested) != set(backup["items"]) or len(manifested) != len(set(manifested)):
            raise ValueError("This configuration backup group manifest is incomplete.")


def inspect_profile_backup(
    backup: dict[str, Any], backup_catalog: list[dict[str, Any]]
) -> dict[str, Any]:
    validate_profile_backup(backup)
    catalog = {str(item["id"]): item for item in backup_catalog}
    manifest = {
        str(group.get("id")): group
        for group in backup.get("groups", [])
        if isinstance(group, dict)
    }
    groups = []
    for item_id, records in backup["items"].items():
        if not isinstance(records, list):
            raise ValueError("Configuration backup group data must be a list.")
        item = catalog.get(str(item_id))
        groups.append(
            {
                "id": str(item_id),
                "label": item["label"] if item else str(item_id),
                "category": item["category"] if item else "Unavailable",
                "sensitive": bool(item["sensitive"]) if item else False,
                "record_count": int(
                    manifest.get(str(item_id), {}).get("entry_count", len(records))
                ),
                "available": item is not None,
                "supports_merge": bool(item and item["supports_merge"]),
                "supports_replace": bool(item and item["supports_replace"]),
            }
        )
    return {
        "format_version": int(backup.get("version", 0)),
        "legacy": backup.get("format") == LEGACY_BACKUP_FORMAT,
        "toolkit_version": str(backup.get("toolkit_version", "Unknown")),
        "created_at": str(backup.get("created_at", "Unknown")),
        "groups": groups,
        "record_count": sum(group["record_count"] for group in groups),
        "sensitive": any(group["sensitive"] for group in groups),
        "unavailable_count": sum(not group["available"] for group in groups),
    }


def backup_entry_count(store: Any, records: list[dict[str, Any]] | None = None) -> int:
    if records is None:
        counter = getattr(store, "count", None)
        if callable(counter):
            return int(counter())
    values = records if records is not None else store.all()
    custom_count = getattr(store, "record_count", None)
    return int(custom_count(values)) if callable(custom_count) else len(values)


def preview_import_items(
    backup_items: dict[str, Any],
    selected_items: list[dict[str, Any]],
    import_mode: str,
) -> list[dict[str, Any]]:
    """Describe import effects without mutating a destination store."""
    if import_mode not in {"merge", "replace"}:
        raise ValueError("Choose Combine or Replace for the import mode.")
    preview = []
    for item in selected_items:
        records = backup_items.get(item["id"])
        if not isinstance(records, list):
            continue
        existing = item["store"].all()
        existing_names = {
            str(record.get("name", "")).casefold()
            for record in existing
            if isinstance(record, dict)
        }
        incoming_names = {
            str(record.get("name", "")).casefold()
            for record in records
            if isinstance(record, dict)
        }
        preview.append(
            {
                "id": item["id"],
                "label": item["label"],
                "category": item["category"],
                "incoming": len(records),
                "added": len(incoming_names - existing_names),
                "updated": len(incoming_names & existing_names),
                "removed": (
                    len(existing_names - incoming_names)
                    if import_mode == "replace"
                    else 0
                ),
                "supported": bool(item[f"supports_{import_mode}"]),
            }
        )
    return preview


def remote_connection_owner_mappings(
    backup_items: dict[str, Any], local_users: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    local_by_name = {
        str(user["username"]).casefold(): str(user["username"])
        for user in local_users
    }
    mappings = []
    records = backup_items.get("remote_connection_library", [])
    if not isinstance(records, list):
        return mappings
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        source = str(record.get("owner_username") or record.get("name") or "").strip()
        if not source:
            continue
        mappings.append(
            {
                "index": index,
                "source": source,
                "matched_username": local_by_name.get(source.casefold(), ""),
            }
        )
    return mappings


def apply_remote_connection_owner_mappings(
    backup_items: dict[str, Any], mappings: dict[int, str]
) -> dict[str, Any]:
    prepared = deepcopy(backup_items)
    records = prepared.get("remote_connection_library")
    if not isinstance(records, list):
        return prepared
    mapped = []
    for index, record in enumerate(records):
        destination = mappings.get(index, "").strip()
        if destination == "__exclude__":
            continue
        if not destination:
            source = str(record.get("owner_username") or record.get("name") or "")
            raise ValueError(f"Choose a destination operator for {source}.")
        record["owner_username"] = destination
        record["name"] = destination
        mapped.append(record)
    prepared["remote_connection_library"] = mapped
    return prepared


class ConfigurationImportStore:
    """Short-lived, instance-key-encrypted storage for inspected imports."""

    _TOKEN_PATTERN = re.compile(r"^[0-9a-f]{48}$")

    def __init__(self, instance_path: str, secret_key: str) -> None:
        self.directory = Path(instance_path) / ".configuration-imports"
        key = base64.urlsafe_b64encode(
            hashlib.sha256(secret_key.encode("utf-8")).digest()
        )
        self._cipher = Fernet(key)

    def create(
        self,
        backup: dict[str, Any],
        *,
        user_id: str,
        encrypted_input: bool,
        import_mode: str,
    ) -> str:
        self.cleanup()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        token = secrets.token_hex(24)
        payload = json.dumps(
            {
                "created_at": time.time(),
                "user_id": user_id,
                "encrypted_input": bool(encrypted_input),
                "import_mode": import_mode,
                "backup": backup,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        path = self.directory / f"{token}.token"
        temporary = self.directory / f".{token}.tmp"
        temporary.write_bytes(self._cipher.encrypt(payload))
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        return token

    def get(self, token: str, *, user_id: str) -> dict[str, Any]:
        path = self._path(token)
        try:
            payload = json.loads(
                self._cipher.decrypt(path.read_bytes()).decode("utf-8")
            )
        except (FileNotFoundError, InvalidToken, UnicodeError, ValueError) as exc:
            raise ValueError("This import preview expired or is no longer available.") from exc
        if (
            str(payload.get("user_id", "")) != user_id
            or time.time() - float(payload.get("created_at", 0)) > IMPORT_PREVIEW_TTL_SECONDS
            or not isinstance(payload.get("backup"), dict)
        ):
            path.unlink(missing_ok=True)
            raise ValueError("This import preview expired or is no longer available.")
        return payload

    def delete(self, token: str) -> None:
        self._path(token).unlink(missing_ok=True)

    def cleanup(self) -> None:
        try:
            paths = tuple(self.directory.glob("*.token"))
        except OSError:
            return
        cutoff = time.time() - IMPORT_PREVIEW_TTL_SECONDS
        for path in paths:
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
            except OSError:
                continue

    def _path(self, token: str) -> Path:
        if not self._TOKEN_PATTERN.fullmatch(str(token)):
            raise ValueError("This import preview is not valid.")
        return self.directory / f"{token}.token"


def import_backup_items(
    backup_items: dict[str, Any],
    selected_items: list[dict[str, Any]],
    import_mode: str,
) -> list[tuple[str, int]]:
    if import_mode not in {"merge", "replace"}:
        raise ValueError("Choose Combine or Replace for the import mode.")
    validated: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for item in selected_items:
        item_id = item["id"]
        if item_id not in backup_items:
            continue
        profiles = backup_items[item_id]
        if not isinstance(profiles, list) or not all(
            isinstance(profile, dict)
            and isinstance(profile.get("name"), str)
            and profile["name"].strip()
            for profile in profiles
        ):
            raise ValueError(f"{item['label']} contains invalid profile data.")
        if import_mode == "merge" and not item["supports_merge"]:
            raise ValueError(f"{item['label']} does not support Combine imports.")
        if import_mode == "replace" and not item["supports_replace"]:
            raise ValueError(f"{item['label']} does not support Replace imports.")
        validated.append((item, profiles))
    if not validated:
        raise ValueError("None of the selected profile groups were present in the backup.")

    validated.sort(key=lambda pair: bool(pair[0].get("atomic_last")))
    imported: list[tuple[str, int]] = []
    snapshots: list[tuple[dict[str, Any], Any, bool]] = []
    try:
        for item, profiles in validated:
            store = item["store"]
            snapshotter = getattr(store, "backup_snapshot", None)
            custom_snapshot = callable(snapshotter)
            snapshot = (
                snapshotter()
                if custom_snapshot
                else deepcopy(store.all())
            )
            snapshots.append((item, snapshot, custom_snapshot))
            custom_import = getattr(store, "import_records", None)
            if callable(custom_import):
                count = int(custom_import(deepcopy(profiles), import_mode))
            else:
                imported_profiles = deepcopy(profiles)
                if import_mode == "merge":
                    # A custom snapshot may contain private rollback state
                    # rather than the portable records exposed by all().
                    imported_profiles = merge_profiles_by_name(
                        deepcopy(store.all()), imported_profiles
                    )
                store.replace_all(imported_profiles)
                count = len(imported_profiles)
            imported.append((item["label"], count))
    except BaseException as exc:
        rollback_errors = []
        for item, snapshot, custom_snapshot in reversed(snapshots):
            try:
                if custom_snapshot:
                    item["store"].restore_backup_snapshot(snapshot)
                else:
                    item["store"].replace_all(snapshot)
            except BaseException as rollback_exc:  # pragma: no cover - defensive
                rollback_errors.append(str(rollback_exc))
        if rollback_errors:
            raise RuntimeError(
                "Configuration import failed and its rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        if isinstance(exc, Exception):
            raise ValueError(
                f"{item['label']} could not be imported: {exc}"
            ) from exc
        raise
    return imported


def merge_profiles_by_name(
    existing_profiles: list[dict[str, Any]],
    imported_profiles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {
        profile["name"]: profile for profile in existing_profiles
    }
    for profile in imported_profiles:
        merged[profile["name"]] = profile
    profiles = list(merged.values())
    default_names = [profile["name"] for profile in imported_profiles if profile.get("is_default")]
    if default_names:
        default_name = default_names[-1]
        profiles = [
            {**profile, "is_default": profile["name"] == default_name}
            if "is_default" in profile
            else profile
            for profile in profiles
        ]
    return profiles


def _backup_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=BACKUP_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
