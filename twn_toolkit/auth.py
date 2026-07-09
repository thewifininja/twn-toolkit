from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")
MIN_PASSWORD_LENGTH = 8
MIN_CONFIGURABLE_PASSWORD_LENGTH = 8
MAX_CONFIGURABLE_PASSWORD_LENGTH = 128
DEFAULT_IDLE_TIMEOUT_MINUTES = 30


class AuthStore:
    """Owner-readable local authentication settings and password hashes."""

    def __init__(self, instance_path: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "auth.json"

    def is_configured(self) -> bool:
        return bool(self._read().get("users"))

    def users(self) -> list[dict[str, Any]]:
        return sorted(
            self._read().get("users", []),
            key=lambda user: user["username"].casefold(),
        )

    def get_user(self, username: str) -> dict[str, Any] | None:
        folded = username.casefold()
        return next(
            (user for user in self.users() if user["username"].casefold() == folded),
            None,
        )

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        user = self.get_user(username)
        if not user or not user.get("enabled", True):
            return None
        return user if check_password_hash(user["password_hash"], password) else None

    def create_user(
        self,
        username: str,
        password: str,
        *,
        is_admin: bool = False,
        access_profile_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        username = validate_username(username)
        validate_password(password, self.password_policy())
        data = self._read()
        users = data.setdefault("users", [])
        if any(user["username"].casefold() == username.casefold() for user in users):
            raise ValueError("That username already exists.")
        if not users:
            is_admin = True
        user = {
            "id": secrets.token_hex(16),
            "username": username,
            "password_hash": generate_password_hash(password, method="scrypt"),
            "is_admin": bool(is_admin),
            "enabled": True,
            "theme": "light",
            "access_profile_ids": _valid_profile_ids(data, access_profile_ids or []),
            "session_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        users.append(user)
        self._write(data)
        return user

    def set_user_theme(self, user_id: str, theme: str) -> None:
        if theme not in {"light", "dark"}:
            raise ValueError("Theme must be light or dark.")
        data = self._read()
        user = _find_user(data, user_id)
        user["theme"] = theme
        self._write(data)

    def favorite_tool_ids(self, user_id: str) -> list[str]:
        try:
            user = _find_user(self._read(), user_id)
        except ValueError:
            return []
        favorites = user.get("favorite_tools", [])
        return [str(tool_id) for tool_id in favorites if isinstance(tool_id, str)]

    def toggle_favorite_tool(self, user_id: str, tool_id: str) -> bool:
        data = self._read()
        user = _find_user(data, user_id)
        favorites = [
            str(item)
            for item in user.get("favorite_tools", [])
            if isinstance(item, str)
        ]
        if tool_id in favorites:
            favorites = [item for item in favorites if item != tool_id]
            enabled = False
        else:
            favorites.append(tool_id)
            enabled = True
        user["favorite_tools"] = favorites
        self._write(data)
        return enabled

    def update_password(self, user_id: str, password: str) -> None:
        validate_password(password, self.password_policy())
        data = self._read()
        user = _find_user(data, user_id)
        user["password_hash"] = generate_password_hash(password, method="scrypt")
        user["session_version"] = int(user.get("session_version", 1)) + 1
        self._write(data)

    def update_user_access(
        self,
        user_id: str,
        *,
        is_admin: bool,
        access_profile_ids: list[str],
    ) -> None:
        data = self._read()
        user = _find_user(data, user_id)
        users = data.get("users", [])
        if user.get("is_admin") and not is_admin and sum(bool(item.get("is_admin")) for item in users) <= 1:
            raise ValueError("The only administrator cannot be changed to a standard user.")
        user["is_admin"] = bool(is_admin)
        user["access_profile_ids"] = [] if is_admin else _valid_profile_ids(data, access_profile_ids)
        user["session_version"] = int(user.get("session_version", 1)) + 1
        self._write(data)

    def delete_user(self, user_id: str) -> None:
        data = self._read()
        user = _find_user(data, user_id)
        users = data.get("users", [])
        if user.get("is_admin") and sum(bool(item.get("is_admin")) for item in users) <= 1:
            raise ValueError("The only administrator cannot be deleted.")
        data["users"] = [item for item in users if item["id"] != user_id]
        self._write(data)

    def access_profiles(self) -> list[dict[str, Any]]:
        profiles = self._read().get("access_profiles", [])
        return sorted(
            [_normalize_access_profile(profile) for profile in profiles if isinstance(profile, dict)],
            key=lambda profile: profile["name"].casefold(),
        )

    def get_access_profile(self, profile_id: str) -> dict[str, Any] | None:
        return next(
            (profile for profile in self.access_profiles() if profile["id"] == profile_id),
            None,
        )

    def save_access_profile(
        self,
        *,
        name: str,
        tool_ids: list[str],
        description: str = "",
        profile_id: str = "",
    ) -> dict[str, Any]:
        name = _validate_access_profile_name(name)
        cleaned_tool_ids = _clean_tool_ids(tool_ids)
        data = self._read()
        profiles = data.setdefault("access_profiles", [])
        folded = name.casefold()
        if profile_id:
            profile = _find_access_profile(data, profile_id)
            if any(
                item.get("id") != profile_id
                and str(item.get("name", "")).casefold() == folded
                for item in profiles
            ):
                raise ValueError("That access profile name already exists.")
        else:
            if any(str(item.get("name", "")).casefold() == folded for item in profiles):
                raise ValueError("That access profile name already exists.")
            profile = {"id": secrets.token_hex(12)}
            profiles.append(profile)
        profile["name"] = name
        profile["description"] = description.strip()[:240]
        profile["tool_ids"] = cleaned_tool_ids
        self._write(data)
        return _normalize_access_profile(profile)

    def delete_access_profile(self, profile_id: str) -> None:
        data = self._read()
        _find_access_profile(data, profile_id)
        data["access_profiles"] = [
            profile for profile in data.get("access_profiles", []) if profile.get("id") != profile_id
        ]
        for user in data.get("users", []):
            existing_profile_ids = user.get("access_profile_ids", [])
            updated_profile_ids = [
                item for item in existing_profile_ids if item != profile_id
            ]
            if updated_profile_ids != existing_profile_ids:
                user["access_profile_ids"] = updated_profile_ids
                user["session_version"] = int(user.get("session_version", 1)) + 1
        self._write(data)

    def effective_tool_ids(self, user: dict[str, Any]) -> set[str] | None:
        if user.get("is_admin"):
            return None
        profile_ids = set(
            str(item) for item in user.get("access_profile_ids", []) if isinstance(item, str)
        )
        allowed: set[str] = set()
        for profile in self.access_profiles():
            if profile["id"] in profile_ids:
                allowed.update(profile["tool_ids"])
        return allowed

    def idle_timeout_minutes(self) -> int:
        value = self._read().get("settings", {}).get(
            "idle_timeout_minutes", DEFAULT_IDLE_TIMEOUT_MINUTES
        )
        try:
            return max(0, min(1440, int(value)))
        except (TypeError, ValueError):
            return DEFAULT_IDLE_TIMEOUT_MINUTES

    def set_idle_timeout_minutes(self, minutes: int) -> None:
        if not 0 <= minutes <= 1440:
            raise ValueError(
                "Idle timeout must be 0 (never expire) or between 1 minute and 24 hours."
            )
        data = self._read()
        data.setdefault("settings", {})["idle_timeout_minutes"] = minutes
        self._write(data)

    def min_password_length(self) -> int:
        value = self._read().get("settings", {}).get(
            "min_password_length", MIN_PASSWORD_LENGTH
        )
        try:
            return max(
                MIN_CONFIGURABLE_PASSWORD_LENGTH,
                min(MAX_CONFIGURABLE_PASSWORD_LENGTH, int(value)),
            )
        except (TypeError, ValueError):
            return MIN_PASSWORD_LENGTH

    def password_policy(self) -> dict[str, Any]:
        settings = self._read().get("settings", {})
        return {
            "min_length": self.min_password_length(),
            "require_uppercase": bool(settings.get("require_uppercase", False)),
            "require_lowercase": bool(settings.get("require_lowercase", False)),
            "require_number": bool(settings.get("require_number", False)),
            "require_special": bool(settings.get("require_special", False)),
        }

    def set_min_password_length(self, length: int) -> None:
        if not MIN_CONFIGURABLE_PASSWORD_LENGTH <= length <= MAX_CONFIGURABLE_PASSWORD_LENGTH:
            raise ValueError(
                "Minimum password length must be between "
                f"{MIN_CONFIGURABLE_PASSWORD_LENGTH} and "
                f"{MAX_CONFIGURABLE_PASSWORD_LENGTH} characters."
            )
        data = self._read()
        data.setdefault("settings", {})["min_password_length"] = length
        self._write(data)

    def set_policy(
        self,
        *,
        idle_timeout_minutes: int,
        min_password_length: int,
        require_uppercase: bool = False,
        require_lowercase: bool = False,
        require_number: bool = False,
        require_special: bool = False,
    ) -> None:
        if not 0 <= idle_timeout_minutes <= 1440:
            raise ValueError(
                "Idle timeout must be 0 (never expire) or between 1 minute and 24 hours."
            )
        if not (
            MIN_CONFIGURABLE_PASSWORD_LENGTH
            <= min_password_length
            <= MAX_CONFIGURABLE_PASSWORD_LENGTH
        ):
            raise ValueError(
                "Minimum password length must be between "
                f"{MIN_CONFIGURABLE_PASSWORD_LENGTH} and "
                f"{MAX_CONFIGURABLE_PASSWORD_LENGTH} characters."
            )
        data = self._read()
        settings = data.setdefault("settings", {})
        settings["idle_timeout_minutes"] = idle_timeout_minutes
        settings["min_password_length"] = min_password_length
        settings["require_uppercase"] = bool(require_uppercase)
        settings["require_lowercase"] = bool(require_lowercase)
        settings["require_number"] = bool(require_number)
        settings["require_special"] = bool(require_special)
        self._write(data)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "settings": {
                    "idle_timeout_minutes": DEFAULT_IDLE_TIMEOUT_MINUTES,
                    "min_password_length": MIN_PASSWORD_LENGTH,
                    "require_uppercase": False,
                    "require_lowercase": False,
                    "require_number": False,
                    "require_special": False,
                },
                "users": [],
                "access_profiles": [],
            }
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(f"Could not read authentication data: {exc}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Authentication data is not a JSON object.")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            dir=self.instance_path, prefix=".auth-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, self.path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)


def load_or_create_secret_key(instance_path: str) -> str:
    override = os.environ.get("TWN_TOOLKIT_SECRET_KEY")
    if override:
        return override
    directory = Path(instance_path)
    path = directory / "session_secret"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    directory.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(48)
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(secret)
        os.chmod(path, 0o600)
        return secret
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()


def validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError(
            "Username must be 3–64 characters using letters, numbers, dots, dashes, "
            "underscores, or @."
        )
    return username


def validate_password(
    password: str,
    policy: dict[str, Any] | int = MIN_PASSWORD_LENGTH,
) -> None:
    if isinstance(policy, int):
        policy = {"min_length": policy}
    min_length = int(policy.get("min_length", MIN_PASSWORD_LENGTH))
    problems = []
    if len(password) < min_length:
        problems.append(f"at least {min_length} characters")
    if policy.get("require_uppercase") and not any(char.isupper() for char in password):
        problems.append("an uppercase letter")
    if policy.get("require_lowercase") and not any(char.islower() for char in password):
        problems.append("a lowercase letter")
    if policy.get("require_number") and not any(char.isdigit() for char in password):
        problems.append("a number")
    if policy.get("require_special") and not any(
        not char.isalnum() and not char.isspace() for char in password
    ):
        problems.append("a special character")
    if problems:
        raise ValueError(f"Password must contain {_join_requirements(problems)}.")
    if len(password) > 1024:
        raise ValueError("Password is too long.")


def _join_requirements(requirements: list[str]) -> str:
    if len(requirements) == 1:
        return requirements[0]
    return f"{', '.join(requirements[:-1])}, and {requirements[-1]}"


def _find_user(data: dict[str, Any], user_id: str) -> dict[str, Any]:
    user = next((item for item in data.get("users", []) if item["id"] == user_id), None)
    if not user:
        raise ValueError("User not found.")
    return user


def _find_access_profile(data: dict[str, Any], profile_id: str) -> dict[str, Any]:
    profile = next(
        (item for item in data.get("access_profiles", []) if item.get("id") == profile_id),
        None,
    )
    if not profile:
        raise ValueError("Access profile not found.")
    return profile


def _validate_access_profile_name(name: str) -> str:
    name = " ".join(name.strip().split())
    if not 2 <= len(name) <= 80:
        raise ValueError("Access profile name must be 2–80 characters.")
    return name


def _clean_tool_ids(tool_ids: list[str]) -> list[str]:
    cleaned = []
    for tool_id in tool_ids:
        tool_id = str(tool_id).strip()
        if not tool_id or tool_id in cleaned:
            continue
        cleaned.append(tool_id)
    return cleaned


def _normalize_access_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(profile.get("id", "")),
        "name": str(profile.get("name", "")),
        "description": str(profile.get("description", "")),
        "tool_ids": _clean_tool_ids(profile.get("tool_ids", [])),
    }


def _valid_profile_ids(data: dict[str, Any], profile_ids: list[str]) -> list[str]:
    known = {
        str(profile.get("id"))
        for profile in data.get("access_profiles", [])
        if isinstance(profile, dict)
    }
    return [
        profile_id
        for profile_id in _clean_tool_ids(profile_ids)
        if profile_id in known
    ]
