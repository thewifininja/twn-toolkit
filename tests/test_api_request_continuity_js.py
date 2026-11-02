"""Optional Node wrapper; shipped client model also executes in host V8."""
import shutil
import subprocess
from pathlib import Path
import pytest

def test_api_request_client_state_machine():
    node = shutil.which('node') or shutil.which('nodejs')
    if not node:
        pytest.skip('Node unavailable; API client model runs separately in host V8')
    result = subprocess.run([node, '-e', "const fs=require('fs');require('./tests/js/api_request_continuity.js')(fs.readFileSync('./twn_toolkit/static/api-request.js','utf8')).then(x=>console.log(JSON.stringify(x))).catch(e=>{console.error(e);process.exit(1)})"], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=True, timeout=20)
    assert 'newer pending edits' in result.stdout
    assert 'never replay' in result.stdout
