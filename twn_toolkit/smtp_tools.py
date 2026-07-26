from __future__ import annotations

import base64
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, getaddresses, make_msgid
import hashlib
import json
import os
from pathlib import Path
import secrets
import smtplib
import ssl
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .network_tools import ToolInputError


DEFAULT_SMTP_SETTINGS = {
    "host": "",
    "port": 587,
    "security": "starttls",
    "verify_tls": True,
    "username": "",
    "from_name": "The WiFi Ninja's Toolkit",
    "from_address": "",
    "timeout": 10.0,
}
SMTP_SECURITY_MODES = {"starttls", "tls", "none"}
MAX_EMAIL_RECIPIENTS = 50


class SMTPSettingsStore:
    def __init__(self, instance_path: str, secret_key: str) -> None:
        self.instance_path = Path(instance_path)
        self.path = self.instance_path / "smtp_settings.json"
        encryption_key = base64.urlsafe_b64encode(
            hashlib.sha256(secret_key.encode("utf-8")).digest()
        )
        self._cipher = Fernet(encryption_key)

    def get(self, *, include_password: bool = False) -> dict[str, Any]:
        raw = self._read()
        settings = validate_smtp_settings(
            {**DEFAULT_SMTP_SETTINGS, **raw},
            require_configured=False,
        )
        encrypted = str(raw.get("password_encrypted", ""))
        settings["configured"] = bool(settings["host"] and settings["from_address"])
        settings["has_password"] = bool(encrypted)
        if include_password:
            settings["password"] = self._decrypt(encrypted) if encrypted else ""
        return settings

    def save(
        self,
        values: dict[str, Any],
        *,
        password: str = "",
        clear_password: bool = False,
    ) -> dict[str, Any]:
        existing = self._read()
        settings = validate_smtp_settings(values, require_configured=True)
        encrypted = str(existing.get("password_encrypted", ""))
        if clear_password:
            encrypted = ""
        elif password:
            encrypted = self._encrypt(password)
        if settings["username"] and not encrypted:
            raise ToolInputError("Enter an SMTP password for the configured username.")
        if not settings["username"]:
            encrypted = ""
        payload = {**settings, "password_encrypted": encrypted}
        self.instance_path.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(
            f".{self.path.name}.{secrets.token_hex(5)}.tmp"
        )
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
        return self.get()

    def _read(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise RuntimeError("Could not read saved SMTP settings.") from exc
        return value if isinstance(value, dict) else {}

    def _encrypt(self, value: str) -> str:
        return self._cipher.encrypt(value.encode("utf-8")).decode("ascii")

    def _decrypt(self, value: str) -> str:
        try:
            return self._cipher.decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError) as exc:
            raise RuntimeError("Could not decrypt the saved SMTP password.") from exc


def validate_smtp_settings(
    values: dict[str, Any], *, require_configured: bool = True
) -> dict[str, Any]:
    host = str(values.get("host", "")).strip()
    if host and (
        len(host) > 253
        or any(character.isspace() for character in host)
        or any(character in host for character in "\x00\r\n")
    ):
        raise ToolInputError("Enter a valid SMTP hostname or IP address.")
    if require_configured and not host:
        raise ToolInputError("Enter an SMTP hostname or IP address.")
    try:
        port = int(values.get("port", 587))
        timeout = float(values.get("timeout", 10))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("SMTP port and timeout must be numbers.") from exc
    if not 1 <= port <= 65535:
        raise ToolInputError("SMTP port must be between 1 and 65535.")
    if not 1 <= timeout <= 60:
        raise ToolInputError("SMTP timeout must be between 1 and 60 seconds.")
    security = str(values.get("security", "starttls")).lower()
    if security not in SMTP_SECURITY_MODES:
        raise ToolInputError("Choose STARTTLS, implicit TLS, or plaintext SMTP.")
    username = str(values.get("username", "")).strip()
    if len(username) > 320 or any(character in username for character in "\x00\r\n"):
        raise ToolInputError("SMTP usernames must be 320 characters or fewer.")
    from_name = str(values.get("from_name", "")).strip()
    if len(from_name) > 120 or any(character in from_name for character in "\x00\r\n"):
        raise ToolInputError("SMTP From names must be 120 characters or fewer.")
    from_address = str(values.get("from_address", "")).strip()
    if from_address:
        from_address = parse_email_recipients(from_address, limit=1)[0]["address"]
    elif require_configured:
        raise ToolInputError("Enter the SMTP From address.")
    return {
        "host": host,
        "port": port,
        "security": security,
        "verify_tls": bool(values.get("verify_tls", True)),
        "username": username,
        "from_name": from_name,
        "from_address": from_address,
        "timeout": timeout,
    }


def parse_email_recipients(
    value: str, *, limit: int = MAX_EMAIL_RECIPIENTS
) -> list[dict[str, str]]:
    text = str(value or "").strip()
    if not text:
        return []
    if "\x00" in text or "\r" in text:
        raise ToolInputError("Email recipients contain invalid characters.")
    parsed = getaddresses([text.replace(";", ",").replace("\n", ",")])
    recipients: list[dict[str, str]] = []
    seen: set[str] = set()
    for name, address in parsed:
        address = address.strip()
        if (
            len(address) > 254
            or address.count("@") != 1
            or not all(address.split("@", 1))
            or any(character.isspace() for character in address)
        ):
            raise ToolInputError(f"Invalid email recipient: {address or text}")
        key = address.casefold()
        if key in seen:
            continue
        seen.add(key)
        clean_name = " ".join(str(name).split())
        recipients.append(
            {
                "address": address,
                "display": formataddr((clean_name, address)) if clean_name else address,
            }
        )
    if len(recipients) > limit:
        raise ToolInputError(f"A maximum of {limit} email recipients is allowed.")
    return recipients


def send_smtp_message(
    settings: dict[str, Any],
    *,
    to: list[dict[str, str]],
    cc: list[dict[str, str]] | None = None,
    bcc: list[dict[str, str]] | None = None,
    subject: str,
    body: str,
) -> dict[str, Any]:
    cc = cc or []
    bcc = bcc or []
    recipients = [*to, *cc, *bcc]
    if not recipients:
        raise ToolInputError("Enter at least one email recipient.")
    if len(recipients) > MAX_EMAIL_RECIPIENTS:
        raise ToolInputError(
            f"A maximum of {MAX_EMAIL_RECIPIENTS} email recipients is allowed."
        )
    message = EmailMessage()
    message["From"] = formataddr(
        (str(settings.get("from_name", "")), str(settings["from_address"]))
    )
    message["To"] = ", ".join(item["display"] for item in to)
    if cc:
        message["Cc"] = ", ".join(item["display"] for item in cc)
    message["Subject"] = subject
    message["Date"] = datetime.now(timezone.utc)
    message["Message-ID"] = make_msgid(
        domain=str(settings["from_address"]).rsplit("@", 1)[-1]
    )
    message.set_content(body)

    context = ssl.create_default_context()
    if not bool(settings.get("verify_tls", True)):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        if settings["security"] == "tls":
            server_connection = smtplib.SMTP_SSL(
                settings["host"],
                int(settings["port"]),
                timeout=float(settings["timeout"]),
                context=context,
            )
        else:
            server_connection = smtplib.SMTP(
                settings["host"],
                int(settings["port"]),
                timeout=float(settings["timeout"]),
            )
        with server_connection as server:
            server.ehlo()
            if settings["security"] == "starttls":
                server.starttls(context=context)
                server.ehlo()
            if settings.get("username"):
                server.login(settings["username"], settings.get("password", ""))
            refused = server.send_message(
                message,
                from_addr=settings["from_address"],
                to_addrs=[item["address"] for item in recipients],
            )
    except (OSError, smtplib.SMTPException, ssl.SSLError) as exc:
        raise ToolInputError(f"SMTP delivery failed: {exc}") from exc

    refused_addresses = {str(address).casefold(): detail for address, detail in refused.items()}
    deliveries = []
    for recipient in recipients:
        detail = refused_addresses.get(recipient["address"].casefold())
        deliveries.append(
            {
                "address": recipient["address"],
                "status": "error" if detail else "success",
                "error": _smtp_refusal_text(detail) if detail else "",
            }
        )
    return {
        "message_id": str(message["Message-ID"]),
        "deliveries": deliveries,
        "accepted": sum(item["status"] == "success" for item in deliveries),
    }


def _smtp_refusal_text(value: Any) -> str:
    if isinstance(value, tuple) and len(value) == 2:
        code, message = value
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")
        return f"SMTP {code}: {message}"
    return str(value or "Recipient was refused by the SMTP server.")
