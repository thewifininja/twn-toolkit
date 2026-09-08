"""The page URL identifies its target; account and login state do not route work."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from flask import g, request

_AGENT_PATH = re.compile(r'^/agents/(agent_[A-Za-z0-9_-]{1,74})(?:/|$)')


def page_target(path: str) -> str:
    match = _AGENT_PATH.match(path)
    return match[1] if match else 'local'


def request_target() -> str:
    # A retained operation page has already resolved owner-scoped job metadata.
    return getattr(g, 'operation_agent_id', None) or page_target(request.path)


def switch_destination(source: str, target: str) -> tuple[str, str]:
    """Return the old target and an origin-relative destination for this tab."""
    try:
        parsed = urlsplit(source)
        decoded = unquote(parsed.path)
        if (parsed.scheme or parsed.netloc or not decoded.startswith('/')
                or decoded.startswith('//') or '\\' in decoded
                or any(ord(char) < 32 for char in source + decoded)
                or any(part in {'.', '..'} for part in decoded.split('/'))):
            raise ValueError('Invalid page path')
    except ValueError:
        parsed = urlsplit('/')
    before = page_target(parsed.path)
    path = parsed.path
    if before != 'local':
        path = path[len('/agents/' + before):] or '/'
        if path == '/ui' or path.startswith('/ui/'):
            path = path[3:] or '/'
    # Operation pages are Mainframe records, not routes to replay on an agent.
    if path.startswith('/operations/'):
        path = '/'
    if not path.startswith('/') or path.startswith('//') or '\\' in path:
        path = '/'
    query = urlencode([(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
                       if key != '_twn_response'])
    prefix = '' if target == 'local' else f'/agents/{target}/ui'
    return before, urlunsplit(('', '', prefix + path, query, parsed.fragment))
