# Dependency locks and recovery

`requirements.in` and `requirements-dev.in` are the editable direct dependencies.
`requirements.txt` and `requirements-dev.txt` are generated, hash-pinned locks for
the runtime and development dependency graphs. The development resolution is
constrained by the runtime lock so testing does not silently select different
runtime versions.

The locks use environment markers from a universal resolution targeting Python
3.10 and newer. CI installs them on Ubuntu Python 3.10/3.13, macOS Python 3.13,
and Arch's current Python, then runs `pip check` and the full suite. Universal
resolution does not promise compatibility with every future Python, operating
system, or architecture; changes still need the supported-platform CI and native
device acceptance.

## Updating dependencies

Use a separate maintainer environment; deployed installations continue using pip
and do not require uv:

```bash
python3 -m venv /tmp/twn-lock-tools
/tmp/twn-lock-tools/bin/python -m pip install uv==0.8.15
python3 scripts/lock_dependencies.py --uv /tmp/twn-lock-tools/bin/uv
python3 scripts/lock_dependencies.py --check
```

Edit the `.in` files first. Normal regeneration prefers existing locked versions;
use `--upgrade` explicitly to refresh transitive dependencies. The generator uses
the public PyPI index, ignores uv/pip environment configuration, and records the
resolver version, resolution policy, and input/output SHA-256 digests in
`requirements-lock.json`. Review and commit both inputs, both outputs, and that
provenance file together. The initial resolution was generated on CPython 3.12
Linux; the Python 3.10 target controls dependency resolution, while source-package
metadata builds may use the generator's available interpreter.

[uv documents compiled requirements and constrained resolutions](https://docs.astral.sh/uv/pip/compile/).
The pinned generator is a maintainer tool, not a runtime dependency. Provenance
verification detects stale or partially generated files; it is not a signature
or proof against a malicious change that updates both files and provenance.

## Installation and rollback

`install.sh` verifies the committed inputs and locks before changing packages.
The launcher performs the same check before its dependency-stamp comparison.
Installations require package hashes and run `pip check`; a changed runtime lock
changes the existing requirements checksum and triggers installation. Release
bundles and recovery points include the locks, inputs, and provenance. Restoring
a recovery point restores its dependency choices before installation resumes.
Old releases without locks retain their historical behavior.

A compatible Python interpreter and access to the selected package archives
(index, mirror, or pip cache) are still required. Hashes accept the reviewed
upstream wheel/source archives for different platforms. Existing unrelated
packages are not automatically removed. OS packages, Python itself, pip, source
build dependencies, compilers, native helpers, and system libraries are outside
these runtime locks: this is not a bit-for-bit machine or native-build image.
Preserve the instance key and data recovery point separately; locking Python
packages does not make old application versions understand newer data formats.
