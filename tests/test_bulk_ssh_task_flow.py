"""Per-run composition resolves current saved commands without editing the library."""
import json

import pytest

from twn_toolkit.ssh_routes import _resolve_run_steps, _run_steps_payload
from twn_toolkit.network_tools import ToolInputError


def resolve(steps, saved=None):
    return _resolve_run_steps(saved or [{'name': 'Status', 'commands': 'show current', 'command_timeout': 300}],
                              {'run_steps': json.dumps(steps)}, strict=True)


def test_interleaved_steps_preserve_order_and_saved_source_of_truth():
    steps = [{'source': 'inline', 'id': 'one', 'name': 'First', 'commands': 'show clock', 'command_timeout': 12},
             {'source': 'saved', 'name': 'Status', 'commands': 'untrusted replacement'},
             {'source': 'inline', 'id': 'two', 'name': 'Last', 'commands': 'show version', 'command_timeout': 30}]
    result = resolve(steps)
    assert [row['commands'] for row in result] == ['show clock', 'show current', 'show version']
    assert [row['order'] for row in result] == [1, 2, 3]
    assert [row['source'] for row in result] == ['inline', 'saved', 'inline']
    assert _run_steps_payload(result)[1] == {'source': 'saved', 'name': 'Status'}
    assert _run_steps_payload(resolve(_run_steps_payload(result))) == _run_steps_payload(result)


@pytest.mark.parametrize('steps', [
    [{'source': 'saved', 'name': 'deleted'}],
    [{'source': 'saved', 'name': 'Status'}, {'source': 'saved', 'name': 'Status'}],
    [{'source': 'inline', 'id': None, 'commands': 'show clock'}],
    [{'source': 'inline', 'id': 'one', 'commands': {'malformed': True}}],
    [{'source': 'inline', 'id': 'one', 'name': [], 'commands': 'show clock'}],
    [{'source': 'inline', 'id': 'one', 'commands': ''}],
    [{'source': 'inline', 'id': 'one', 'commands': 'show clock', 'command_timeout': 0}],
    [{'source': 'inline', 'id': 'one', 'commands': 'show clock'}, {'source': 'inline', 'id': 'one', 'commands': 'show version'}],
    [{'source': 'other', 'name': 'Status'}],
    [None],
    'not a list',
])
def test_invalid_composition_fails_closed(steps):
    with pytest.raises(ToolInputError):
        resolve(steps)


def test_saved_library_remains_unchanged_by_typed_composition():
    library = [{'name': 'Status', 'commands': 'show current', 'command_timeout': 300}]
    before = json.dumps(library)
    resolve([{'source': 'inline', 'id': 'one', 'commands': 'show clock'}, {'source': 'saved', 'name': 'Status'}], library)
    assert json.dumps(library) == before
