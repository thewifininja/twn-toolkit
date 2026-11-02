import shutil
import subprocess
from pathlib import Path
import pytest

def test_network_profile_receipt_matches_submitted_public_metadata():
    node=shutil.which('node') or shutil.which('nodejs')
    if not node:pytest.skip('Node unavailable; dependency-free shipped receipt model runs separately in host V8')
    script="const fs=require('fs');console.log(JSON.stringify(require('./tests/js/network_profile_receipt.js')(fs.readFileSync('./twn_toolkit/static/network-profile-receipt.js','utf8'))));"
    result=subprocess.run([node,'-e',script],cwd=Path(__file__).resolve().parents[1],check=True,capture_output=True,text=True,timeout=20)
    assert 'receipt binds captured submission rather than newer draft' in result.stdout
