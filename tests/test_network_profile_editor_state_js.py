"""Run dependency-free models of the shipped editor when Node is available."""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_network_profile_editor_state_machine():
    node = shutil.which("node") or shutil.which("nodejs")
    if not node:
        pytest.skip("Node unavailable; editor state model runs separately in host V8")
    script = """
const fs = require('fs');
const source = name => fs.readFileSync('./twn_toolkit/static/' + name + '.js', 'utf8');
require('./tests/js/network_profile_editor_state.js')(
  source('unsaved-forms'), source('network-profile-receipt'), source('network-profile-editor')
).then(results => console.log(JSON.stringify(results))).catch(error => {
  console.error(error); process.exit(1);
});
"""
    result = subprocess.run(
        [node, "-e", script], cwd=Path(__file__).resolve().parents[1],
        check=True, capture_output=True, text=True, timeout=20,
    )
    assert "stale GET success/error" in result.stdout
    assert "requires New before another save" in result.stdout
    assert "canceling dirty Create another" in result.stdout
