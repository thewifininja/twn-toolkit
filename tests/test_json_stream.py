"""Archive JSON remains byte-compatible while strings are encoded in chunks."""
import json

import pytest

from twn_toolkit.json_stream import iter_pretty_json, JSON_STRING_CHUNK


@pytest.mark.parametrize('value', [
    {}, [], [[], {}, [1, 2]], {'first': [True, False, None, -1, 1.5, float('inf')]},
    {'quoted"\\\n': '\x00\t\n中文😀\ud800'},
    {None: 1, False: 2, 3: 4, 1.5: 6},
    ('tuple', {'nested': [1, {'last': 'value'}]}),
    {'x' * (JSON_STRING_CHUNK + 1): '\\"\x00😀' * JSON_STRING_CHUNK},
])
def test_matches_standard_pretty_json(value):
    chunks = list(iter_pretty_json(value))
    assert ''.join(chunks) == json.dumps(value, indent=2)
    assert max(map(len, chunks)) <= JSON_STRING_CHUNK * 12


def test_deep_and_circular_metadata_fail_explicitly():
    deep = []
    for _ in range(66):
        deep = [deep]
    with pytest.raises(ValueError, match='64 levels'):
        ''.join(iter_pretty_json(deep))
    cycle = []; cycle.append(cycle)
    with pytest.raises(ValueError, match='circular'):
        ''.join(iter_pretty_json(cycle))


def test_shared_child_is_not_a_cycle():
    child = {'value': [1, 2]}
    value = [child, child]
    assert ''.join(iter_pretty_json(value)) == json.dumps(value, indent=2)
