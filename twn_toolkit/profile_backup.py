from __future__ import annotations

import base64
import json
import os
from datetime import datetime
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


BACKUP_KDF_ITERATIONS = 390_000


def build_backup_catalog(instance_path: str) -> list[dict[str, Any]]:
    from .tool_modules import automation, fortiauthenticator, fortigate, network

    return [
        *fortigate.backup_items(instance_path),
        *fortiauthenticator.backup_items(instance_path),
        *network.backup_items(instance_path),
        *automation.backup_items(instance_path),
    ]


def build_reset_stores(instance_path: str) -> list[Any]:
    return [item["store"] for item in build_backup_catalog(instance_path)]


def selected_backup_items(
    backup_catalog: list[dict[str, Any]],
    selected_ids: set[str],
) -> list[dict[str, Any]]:
    return [item for item in backup_catalog if item["id"] in selected_ids]


def build_profile_backup(selected_items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "format": "twn-toolkit-profile-backup",
        "version": 1,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "items": {item["id"]: item["store"].all() for item in selected_items},
    }


def encrypt_backup(payload: bytes, password: str) -> dict[str, Any]:
    salt = os.urandom(16)
    token = Fernet(_backup_key(password, salt)).encrypt(payload)
    return {
        "format": "twn-toolkit-encrypted-profile-backup",
        "version": 1,
        "kdf": "PBKDF2HMAC-SHA256",
        "iterations": BACKUP_KDF_ITERATIONS,
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "ciphertext": token.decode("ascii"),
    }


def decrypt_backup(encrypted_backup: dict[str, Any], password: str) -> dict[str, Any]:
    if (
        int(encrypted_backup.get("version", 0)) != 1
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


def validate_profile_backup(backup: dict[str, Any]) -> None:
    if (
        backup.get("format") != "twn-toolkit-profile-backup"
        or int(backup.get("version", 0)) != 1
        or not isinstance(backup.get("items"), dict)
    ):
        raise ValueError("This does not look like a toolkit profile backup.")


def import_backup_items(
    backup_items: dict[str, Any],
    selected_items: list[dict[str, Any]],
    import_mode: str,
) -> list[tuple[str, int]]:
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
        validated.append((item, profiles))
    if not validated:
        raise ValueError("None of the selected profile groups were present in the backup.")

    imported: list[tuple[str, int]] = []
    for item, profiles in validated:
        if import_mode == "merge":
            profiles = merge_profiles_by_name(item["store"].all(), profiles)
        item["store"].replace_all(profiles)
        imported.append((item["label"], len(profiles)))
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
