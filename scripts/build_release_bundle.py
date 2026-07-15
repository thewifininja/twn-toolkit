#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_release_bundle_module():
    path = ROOT / "twn_toolkit" / "release_bundle.py"
    spec = importlib.util.spec_from_file_location("twn_release_bundle", path)
    if not spec or not spec.loader:
        raise RuntimeError("The release bundle module could not be loaded.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _app_version() -> str:
    source = (ROOT / "twn_toolkit" / "version.py").read_text(encoding="utf-8")
    match = re.search(
        r'^APP_VERSION\s*=\s*["\']([^"\']+)["\']', source, re.MULTILINE,
    )
    if not match:
        raise RuntimeError("APP_VERSION was not found in twn_toolkit/version.py")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a verified toolkit upgrade bundle.")
    parser.add_argument("--output-dir", default="dist")
    parser.add_argument("--minimum-upgrade-version", default="0.9.0")
    parser.add_argument("--expected-version")
    args = parser.parse_args()
    release_bundle = _load_release_bundle_module()
    app_version = _app_version()
    if args.expected_version:
        expected = args.expected_version.removeprefix("v")
        if app_version != expected:
            raise SystemExit(
                f"Expected release version {expected}, but APP_VERSION is {app_version}."
            )
    output_dir = (ROOT / args.output_dir).resolve()
    output = output_dir / release_bundle.bundle_name(app_version)
    release_bundle.build_release_bundle(
        ROOT, output, version=app_version,
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
