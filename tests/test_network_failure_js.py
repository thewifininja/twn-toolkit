import shutil
import subprocess
from pathlib import Path
import pytest

def test_network_failure_clients_preserve_intent():
    node=shutil.which('node') or shutil.which('nodejs')
    if not node:pytest.skip('Node unavailable; dependency-free shipped-client model runs separately in host V8')
    script="const fs=require('fs');console.log(JSON.stringify(require('./tests/js/network_failure_continuity.js')(...['ntp-test.js','radius-test.js','workspace-tabs.js'].map(x=>fs.readFileSync('./twn_toolkit/static/'+x,'utf8')))));"
    result=subprocess.run([node,'-e',script],cwd=Path(__file__).resolve().parents[1],check=True,capture_output=True,text=True,timeout=20)
    assert 'empty POST and canceled blank naming stay empty' in result.stdout
