"""TLS certificate automation condition registration."""

from .monitoring import (
    _evaluate_certificate,
    _parse_certificate_form,
    _validate_certificate,
)
from ..models import ConditionType


def registered_conditions() -> tuple[ConditionType, ...]:
    return (
        ConditionType("certificate.health", "Certificate health", "Trigger when TLS certificates are unavailable, expiring, untrusted, mismatched, or incorrectly chained.", _validate_certificate, _evaluate_certificate, _parse_certificate_form),
    )
