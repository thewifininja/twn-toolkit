"""Expiring, actor/instance-bound confirmations without persisting payloads."""
from __future__ import annotations

import hmac
import json

from flask import current_app, g
from itsdangerous import BadData, URLSafeTimedSerializer

PREVIEW_MAX_AGE_SECONDS = 15 * 60


def _serializer(scope):
    return URLSafeTimedSerializer(current_app.secret_key, salt=scope)


def _binding(scope, context):
    bound = {**context, "instance": current_app.instance_path,
             "actor": (getattr(g, "current_user", None) or {}).get("id", "")}
    encoded = json.dumps(bound, sort_keys=True, separators=(",", ":")).encode()
    return hmac.digest(_serializer(scope).secret_key, encoded, "sha256").hex()


def issue_bound_preview(scope, context):
    return _serializer(scope).dumps(_binding(scope, context))


def valid_bound_preview(token, scope, context, *, max_age=PREVIEW_MAX_AGE_SECONDS):
    try:
        binding = _serializer(scope).loads(token, max_age=max_age)
    except BadData:
        return False
    return isinstance(binding, str) and hmac.compare_digest(binding, _binding(scope, context))
