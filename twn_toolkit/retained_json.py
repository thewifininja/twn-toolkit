"""Finite JSON parsing for already size-gated retained records."""
import json

MAX_RETAINED_JSON_BYTES = 64 * 1024 * 1024


def decode_retained_json(data, encoding='utf-8'):
    if len(data) > MAX_RETAINED_JSON_BYTES:
        raise ValueError('Retained JSON exceeds the 64 MiB read limit.')
    text = data.decode(encoding)
    depth = nodes = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            nodes += 1
        elif char in '[{':
            depth += 1
            nodes += 1
            if depth > 64:
                raise ValueError('Retained JSON nesting exceeds 64 levels. Download the retained results JSON directly.')
        elif char in ']}':
            depth -= 1
        elif char == ',':
            nodes += 1
        if nodes > 500_000:
            raise ValueError('Retained JSON is too complex for an archive read. Download the retained results JSON directly.')
    return json.loads(text)
