"""Optional Node runner for the dependency-free in-memory client state tests.

Browser rendering/keyboard/layout remains a separate CUA fixture check.
"""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_diagnostic_client_state_machine():
    node = shutil.which('node') or shutil.which('nodejs')
    if not node:
        pytest.skip('Node unavailable; run the dependency-free JS model in the host JS runtime and the browser fixture separately')
    root = Path(__file__).resolve().parents[1]
    script = "const fs=require('fs');require('./tests/js/diagnostic_continuity.js')(fs.readFileSync('./twn_toolkit/static/diagnostic-job.js','utf8')).then(x=>console.log(JSON.stringify(x))).catch(e=>{console.error(e);process.exit(1)});"
    response = subprocess.run([node, '-e', script], cwd=root, check=True, capture_output=True, text=True, timeout=20)
    assert 'dirty completion keeps draft' in response.stdout
