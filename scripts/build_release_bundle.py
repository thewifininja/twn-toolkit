#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from twn_toolkit.upgrade_manager import build_release_bundle, bundle_name  # noqa: E402
from twn_toolkit.version import APP_VERSION  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a verified toolkit upgrade bundle.")
    parser.add_argument("--output-dir", default="dist")
    parser.add_argument("--minimum-upgrade-version", default="0.9.0")
    args = parser.parse_args()
    output_dir = (ROOT / args.output_dir).resolve()
    output = output_dir / bundle_name(APP_VERSION)
    build_release_bundle(
        ROOT, output, version=APP_VERSION,
        minimum_upgrade_version=args.minimum_upgrade_version,
    )
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    checksum = output.with_name(f"{output.name}.sha256")
    checksum.write_text(f"{digest}  {output.name}\n", encoding="ascii")
    print(output)
    print(checksum)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
