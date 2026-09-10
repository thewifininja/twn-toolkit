"""Explicit HTTP boundary for saved-list MSO controls."""
from functools import wraps

from flask import current_app, g, jsonify, request

from .mso import MsoConflict, MsoStore
from .mso_types import LIST_TYPES


def allowed(kind):
    user = getattr(g, 'current_user', {}) or {}
    return kind in LIST_TYPES and (user.get('is_admin') or LIST_TYPES[kind].permission in (getattr(g, 'allowed_tool_ids', None) or set()))


def metadata(kind):
    if not allowed(kind):
        return {}
    cache = g.setdefault('_mso_list_metadata', {})
    if kind not in cache:
        cache[kind] = {p['name']: {**p['mso'], 'conflict': bool(p['mso']['conflict'])} for p in MsoStore(current_app.instance_path, kind).profiles(metadata=True)}
    return cache[kind]


def mutation(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except MsoConflict as exc:
            return jsonify(error=str(exc)), 409
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
    return wrapped


def guard_args(store):
    kind = request.form.get('mso_kind')
    if kind and kind != store._mso_kind:
        raise ValueError('This MSO control belongs to a different list.')
    raw = request.form.get('mso_version', '')
    if raw and not raw.isdecimal():
        raise ValueError('Invalid saved-list version.')
    return dict(expected=int(raw) if raw else None,
                object_id=request.form.get('mso_id') or None, guarded=True)


def save_profile(store, profile, original_name=''):
    if not store._uses_mso:
        store.upsert(profile, original_name=original_name)
        return
    enabled = request.form.get('mso_enabled')
    if enabled not in (None, 'true', 'false'):
        raise ValueError('MSO must be on or off.')
    saved = store.mso_store().save(profile, original_name,
                                  enabled=None if enabled is None else enabled == 'true',
                                  **guard_args(store))
    profile.update(saved)


def delete_profile(store, name):
    if not store._uses_mso:
        return store.delete(name)
    return store.mso_store().delete(name, **guard_args(store))
