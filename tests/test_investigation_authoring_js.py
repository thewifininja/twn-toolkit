import shutil
import subprocess
from pathlib import Path
import pytest

def test_acknowledged_note_protocol_preserves_drafts():
    node=shutil.which('node') or shutil.which('nodejs')
    if not node: pytest.skip('Node unavailable; shipped note client model runs separately in host V8')
    script="const fs=require('fs');require('./tests/js/investigation_authoring.js')(fs.readFileSync('./twn_toolkit/static/unsaved-forms.js','utf8'),fs.readFileSync('./twn_toolkit/static/investigation-authoring.js','utf8')).then(x=>console.log(JSON.stringify(x))).catch(e=>{console.error(e);process.exit(1)});"
    result=subprocess.run([node,'-e',script],cwd=Path(__file__).resolve().parents[1],check=True,capture_output=True,text=True,timeout=20)
    assert 'one pending save preserves tool' in result.stdout
