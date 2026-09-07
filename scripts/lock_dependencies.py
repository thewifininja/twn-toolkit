#!/usr/bin/env python3
"""Generate and verify the reviewed runtime/development dependency locks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
RESOLVER_VERSION = "0.8.15"
INDEX = "https://pypi.org/simple"
FILES = ("requirements.in", "requirements-dev.in", "requirements.txt", "requirements-dev.txt")
MANIFEST = "requirements-lock.json"
POLICY = {"format": 1, "resolver": f"uv {RESOLVER_VERSION}", "index": INDEX,
          "minimum_python": "3.10", "universal": True, "generate_hashes": True}


def provenance(root: Path) -> dict:
    return {**POLICY, "sha256": {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES
    }}


def check(root: Path) -> None:
    try:
        recorded = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        current = provenance(root)
    except (OSError, ValueError) as exc:
        raise ValueError("Dependency lock files or provenance are missing/unreadable.") from exc
    if recorded != current:
        raise ValueError("Dependency inputs/locks changed. Regenerate with scripts/lock_dependencies.py and review the result.")


def generate(root: Path, uv: str, *, upgrade: bool = False) -> None:
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("UV_", "PIP_"))}
    version = subprocess.check_output([uv, "--version"], text=True, env=environment).split()
    if version[:2] != ["uv", RESOLVER_VERSION]:
        raise ValueError(f"Install uv=={RESOLVER_VERSION} in a separate maintainer environment.")
    common = [uv, "--no-config", "pip", "compile", "--universal", "--python-version", "3.10",
              "--generate-hashes", "--no-strip-markers", "--default-index", INDEX,
              "--custom-compile-command", "python scripts/lock_dependencies.py"]
    if upgrade:
        common.append("--upgrade")
    for source, output in (("requirements.in", "requirements.txt"),
                           ("requirements-dev.in", "requirements-dev.txt")):
        command = [*common, source, "-o", output]
        if source == "requirements-dev.in":
            command += ["--constraint", "requirements.txt"]
        subprocess.run(command, cwd=root, env=environment, check=True, stdout=subprocess.DEVNULL)
    # Publish provenance only after both resolutions succeeded. Interrupted or
    # edited generations fail the installer/CI check instead of silently drifting.
    (root / MANIFEST).write_text(json.dumps(provenance(root), indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify committed inputs and locks without network access")
    parser.add_argument("--uv", default="uv", help="Path to the pinned maintainer resolver")
    parser.add_argument("--upgrade", action="store_true", help="Explicitly refresh transitive versions")
    args = parser.parse_args()
    try:
        if args.check:
            check(ROOT)
        else:
            generate(ROOT, args.uv, upgrade=args.upgrade)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Dependency lock error: {exc}\n")
    print("Dependency locks verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
