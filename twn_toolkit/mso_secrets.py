"""Protect credential fields in every persisted MSO payload and delivery state."""
from .profile_secrets import transform_profiles

SNMP_SECRET_FIELDS = ('community', 'auth_key', 'priv_key')
SECRET_FIELDS = (*SNMP_SECRET_FIELDS, 'secret', 'password', 'api_key', 'matrix', 'commands')
LEGACY_SECRET_FIELDS = {
    'fortigate.profile': ('api_key',),
    'fortiauthenticator.profile': ('password',),
    'snmp.credentials': SNMP_SECRET_FIELDS,
    'radius.servers': ('secret',),
    'radius.credentials': ('password',),
}


def transform(value, instance, *, encrypt):
    if isinstance(value, list):
        return [transform(item, instance, encrypt=encrypt) for item in value]
    if not isinstance(value, dict):
        return value
    result = dict(value)
    if isinstance(result.get('name'), str) and any(key in result for key in SECRET_FIELDS):
        result = transform_profiles([result], instance, 'mso-snmp-credentials', SECRET_FIELDS, encrypt=encrypt)[0]
    return {key: transform(item, instance, encrypt=encrypt) for key, item in result.items()}


def redact(value):
    """Keep secrets out of editor metadata and conflict comparisons."""
    if isinstance(value, list):
        return [redact(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {key: ('Stored secret' if item else 'Not set') if key in (*SNMP_SECRET_FIELDS, 'secret', 'password', 'api_key') else redact(item)
            for key, item in value.items()}
