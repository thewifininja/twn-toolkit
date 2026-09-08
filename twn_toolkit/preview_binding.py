"""Expiring actor/instance-bound confirmations, usable by requests and workers."""
from __future__ import annotations

import hmac
import json
from flask import current_app, g
from itsdangerous import BadData, URLSafeTimedSerializer

PREVIEW_MAX_AGE_SECONDS = 15 * 60


class PreviewSigner:
    def __init__(self, secret_key, instance, actor):
        self.secret_key = secret_key
        self.instance = str(instance)
        self.actor = actor

    def serializer(self, scope):
        return URLSafeTimedSerializer(self.secret_key, salt=scope)

    def binding(self, scope, context):
        bound = {**context, "instance": self.instance, "actor": self.actor}
        encoded = json.dumps(bound, sort_keys=True, separators=(",", ":")).encode()
        return hmac.digest(self.serializer(scope).secret_key, encoded, "sha256").hex()

    def issue(self, scope, context):
        return self.serializer(scope).dumps(self.binding(scope, context))

    def valid(self, token, scope, context, *, max_age=PREVIEW_MAX_AGE_SECONDS):
        try:
            binding = self.serializer(scope).loads(token, max_age=max_age)
        except BadData:
            return False
        return isinstance(binding, str) and hmac.compare_digest(binding, self.binding(scope, context))


def _request_signer():
    return PreviewSigner(current_app.secret_key, current_app.instance_path,
                         (getattr(g, "current_user", None) or {}).get("id", ""))


def issue_bound_preview(scope, context):
    return _request_signer().issue(scope, context)


def valid_bound_preview(token, scope, context, *, max_age=PREVIEW_MAX_AGE_SECONDS):
    return _request_signer().valid(token, scope, context, max_age=max_age)
