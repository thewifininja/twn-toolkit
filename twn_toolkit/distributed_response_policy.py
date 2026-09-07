"""Operator limits for encrypted Mainframe response staging."""
RESPONSE_CHUNK_BYTES = 64 * 1024
RESPONSE_LIMITS = {
    'distributed_response_mib': (16, 1, 256, 'Maximum Agent response (MiB)'),
    'distributed_response_quota_mib': (128, 16, 8192, 'Agent response storage quota (MiB)'),
    'distributed_response_retention_minutes': (15, 1, 1440, 'Agent response retention (minutes)'),
}


def validate_response_limits(values):
    result = {}
    for key, (default, low, high, label) in RESPONSE_LIMITS.items():
        raw = values.get(key, default)
        if isinstance(raw, bool) or not isinstance(raw, (int, str)):
            raise ValueError(f'{label} must be a whole number.')
        try:
            number = int(raw)
        except ValueError as exc:
            raise ValueError(f'{label} must be a whole number.') from exc
        if not low <= number <= high:
            raise ValueError(f'{label} must be {low}–{high}.')
        result[key] = number
    return result
