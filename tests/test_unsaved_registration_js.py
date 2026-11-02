import shutil
import subprocess
from pathlib import Path
import pytest

def test_late_note_registration_never_resets_existing_editors():
    node=shutil.which('node') or shutil.which('nodejs')
    if not node: pytest.skip('Node unavailable; dependency-free registration model runs separately in host V8')
    script="const fs=require('fs');console.log(JSON.stringify(require('./tests/js/unsaved_registration.js')(fs.readFileSync('./twn_toolkit/static/unsaved-forms.js','utf8'))));"
    result=subprocess.run([node,'-e',script],cwd=Path(__file__).resolve().parents[1],check=True,capture_output=True,text=True,timeout=20)
    assert 'repeat load preserves dirty/pending baselines' in result.stdout
