"""Optional dependency-free fake DOM client model; actual browser checks are separate."""
import shutil
import subprocess
from pathlib import Path
import pytest

def test_catalogue_refresh_preserves_unsaved_intent():
    node = shutil.which('node') or shutil.which('nodejs')
    if not node:
        pytest.skip('Node unavailable; execute dependency-free model in host V8 and browser fixture separately')
    script = "const fs=require('fs');require('./tests/js/automation_prerequisites.js')(fs.readFileSync('./twn_toolkit/static/unsaved-forms.js','utf8'),fs.readFileSync('./twn_toolkit/static/automation-prerequisites.js','utf8')).then(x=>console.log(JSON.stringify(x))).catch(e=>{console.error(e);process.exit(1)});"
    result = subprocess.run([node,'-e',script],cwd=Path(__file__).resolve().parents[1],check=True,capture_output=True,text=True,timeout=20)
    assert 'clean catalogue refresh remains clean' in result.stdout
