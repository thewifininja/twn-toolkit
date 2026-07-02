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
            "session_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        users.append(user)
        self._write(data)
        return user

    def update_password(self, user_id: str, password: str) -> None:
        validate_password(password, self.password_policy())
        data = self._read()
        user = _find_user(data, user_id)
        user["password_hash"] = generate_password_hash(password, method="scrypt")
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

    def idle_timeout_minutes(self) -> int:
        value = self._read().get("settings", {}).get(
            "idle_timeout_minutes", DEFAULT_IDLE_TIMEOUT_MINUTES
        )
        try:
            return max(1, min(1440, int(value)))
        except (TypeError, ValueError):
            return DEFAULT_IDLE_TIMEOUT_MINUTES

    def set_idle_timeout_minutes(self, minutes: int) -> None:
        if not 1 <= minutes <= 1440:
            raise ValueError("Idle timeout must be between 1 minute and 24 hours.")
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
        if not 1 <= idle_timeout_minutes <= 1440:
            raise ValueError("Idle timeout must be between 1 minute and 24 hours.")
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
