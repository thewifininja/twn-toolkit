"""Presentation helpers for retained run histories; no job/configuration reads."""
from flask import current_app, g
from .time_settings import localized_time_values, resolve_toolkit_timezone


def history_time(value):
    if value is None:
        return ''
    if not hasattr(g, '_run_history_timezone'):
        g._run_history_timezone = resolve_toolkit_timezone(current_app.instance_path)
    try:
        return localized_time_values(value, g._run_history_timezone)['display']
    except (TypeError, ValueError, OverflowError, OSError):
        return 'Time unavailable'
