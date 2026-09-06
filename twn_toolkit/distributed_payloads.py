"""Instance-bound encryption for bounded distributed control payloads."""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

from .auth import load_or_create_secret_key

SEALED_PREFIX = "twn-sealed-v1:"
PAYLOAD_CLEANUP_INTERVAL_SECONDS = 60


class DistributedPayloadCipher:
    def __init__(self, instance):
        secret = load_or_create_secret_key(str(instance))
        key = hashlib.sha256(("twn-distributed-payload-v1:" + secret).encode()).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(key))

    def seal(self, value: str, context: str) -> str:
        if value in {"", "{}"}:
            return value
        envelope = json.dumps([context, value], separators=(",", ":")).encode()
        return SEALED_PREFIX + self._fernet.encrypt(envelope).decode("ascii")

    def open(self, value: str, context: str) -> str:
        if value in {"", "{}"}:
            return value
        if not value.startswith(SEALED_PREFIX):
            raise ValueError("Distributed payload is not encrypted.")
        try:
            envelope = json.loads(self._fernet.decrypt(value[len(SEALED_PREFIX):].encode()))
            if not isinstance(envelope, list) or len(envelope) != 2 or envelope[0] != context or not isinstance(envelope[1], str):
                raise ValueError
            return envelope[1]
        except (InvalidToken, ValueError, TypeError, UnicodeError) as exc:
            raise ValueError("Distributed payload could not be decrypted; check the instance key.") from exc
