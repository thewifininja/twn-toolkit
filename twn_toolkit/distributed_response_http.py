"""Deliver a retained Agent response without re-executing its request."""
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from flask import Response


def build_agent_response(store, job, requester_id):
    output = job.get('output') or {}
    status = output.get('status', 502)
    if type(status) is not int or not 200 <= status <= 599:
        raise ValueError('The Agent returned an invalid HTTP status.')
    headers = []
    allowed = {'content-type', 'content-disposition', 'location', 'cache-control', 'etag',
               'last-modified', 'retry-after', 'content-range', 'accept-ranges'}
    for pair in output.get('headers', []):
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError('The Agent returned invalid response headers.')
        name, value = pair
        if not isinstance(name, str) or not isinstance(value, str) or '\r' in value or '\n' in value:
            raise ValueError('The Agent returned invalid response headers.')
        if name.lower() in allowed:
            headers.append((name, value))
    content, verified = store.consume_response(job['id'], requester_id)
    response = Response(content, status=status, headers=headers)
    if verified.get('body_transfer'):
        response.content_length = verified['body_size']
        response.call_on_close(lambda: store.discard_tunnel_output(job['id'], requester_id=requester_id))
    response.headers['X-TWN-Instance'] = job['agent_id']
    response.headers['Cache-Control'] = 'no-store'
    return response


def completed_response_location(job):
    """Keep recovered HTML at its Agent tool URL so same-page forms still work."""
    path = (job.get('output') or {}).get('request_path')
    if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or len(path) > 8192:
        raise ValueError('The Agent response has no valid original URL.')
    if '\\' in path or any(ord(char) < 32 for char in path):
        raise ValueError('The Agent response has an invalid original URL.')
    parts = urlsplit(path)
    decoded_path = unquote(parts.path)
    if parts.fragment or '\\' in decoded_path or any(segment in {'.', '..'} for segment in decoded_path.split('/')):
        raise ValueError('The Agent response has an invalid original URL.')
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key != '_twn_response']
    query.append(('_twn_response', job['id']))
    return f"/agents/{quote(job['agent_id'], safe='')}/ui{quote(parts.path, safe='/%')}?{urlencode(query)}"
