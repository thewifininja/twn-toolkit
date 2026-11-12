#!/usr/bin/env python3
"""Build the stdlib bootstrap/isolated-worker zipapp shipped with releases."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def build(output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('__main__.py', 'from twn_toolkit.runtime_migration import main\nraise SystemExit(main())\n')
        for source in sorted((ROOT / 'twn_toolkit').rglob('*.py')):
            if '__pycache__' not in source.parts:
                archive.write(source, source.relative_to(ROOT).as_posix())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + '.sha256').write_text(digest + '  ' + output.name + '\n')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/twn-runtime-migrate.pyz')
    args = parser.parse_args()
    print(build(args.output))


if __name__ == '__main__':
    main()
