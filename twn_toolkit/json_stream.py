"""Chunked, ASCII JSON with the standard encoder's two-space formatting."""
from __future__ import annotations

import json


JSON_STRING_CHUNK = 16 * 1024
JSON_MAX_DEPTH = 64


def iter_pretty_json(value):
    """Yield bounded string fragments without copying an entire escaped scalar.

    The caller owns the aggregate byte budget. Input objects are already loaded;
    this bounds serialization scratch space, not the caller's input graph.
    """
    ancestors = set()

    def string_parts(value):
        yield '"'
        for offset in range(0, len(value), JSON_STRING_CHUNK):
            yield json.encoder.encode_basestring_ascii(value[offset:offset + JSON_STRING_CHUNK])[1:-1]
        yield '"'

    def encode(item, depth):
        if isinstance(item, str):
            yield from string_parts(item)
        elif isinstance(item, (dict, list, tuple)):
            if depth > JSON_MAX_DEPTH:
                raise ValueError('JSON metadata nesting exceeds 64 levels.')
            identity = id(item)
            if identity in ancestors:
                raise ValueError('JSON metadata contains a circular reference.')
            ancestors.add(identity)
            try:
                mapping = isinstance(item, dict)
                opening, closing = ('{', '}') if mapping else ('[', ']')
                yield opening
                if item:
                    indent = '  ' * (depth + 1)
                    entries = item.items() if mapping else enumerate(item)
                    for index, (key, child) in enumerate(entries):
                        yield (',\n' if index else '\n') + indent
                        if mapping:
                            if not isinstance(key, str):
                                if key is None or isinstance(key, (bool, int, float)):
                                    key = json.dumps(key)
                                else:
                                    raise TypeError('JSON metadata object keys must be strings or scalar numbers.')
                            yield from string_parts(key)
                            yield ': '
                        yield from encode(child, depth + 1)
                    yield '\n' + '  ' * depth
                yield closing
            finally:
                ancestors.remove(identity)
        else:
            # Retained JSON primitives; strings and containers never reach dumps.
            yield json.dumps(item)

    yield from encode(value, 0)
