# Contributing

The WiFi Ninja's Toolkit keeps `main` in a releasable state. Changes should be
developed on a focused branch, validated locally and by GitHub Actions, and
merged through a pull request.

## Branch workflow

1. Update local `main` and create a focused branch. Codex-created branches use
   the `codex/` prefix.
2. Keep the branch limited to one feature, fix, or maintenance concern.
3. Run the complete local test suite:

   ```bash
   .venv/bin/python -m pip install -r requirements-dev.txt
   .venv/bin/python -m pytest -q
   ```

4. Push the branch and open a pull request against `main`.
5. Merge only after the Ubuntu and macOS CI jobs pass and the change has been
   reviewed.

Direct pushes to `main` should be reserved for repository recovery. GitHub
branch protection can enforce this policy once it is enabled for the
repository.

## Pull requests

A pull request should explain:

- what changed and why;
- what was tested locally;
- any platform, permission, migration, or compatibility considerations;
- screenshots for meaningful interface changes.

Avoid committing `instance/`, `.venv/`, captured credentials, automation
artifacts, or local packet/log files.

## Releases

1. Merge all intended changes into `main` and confirm CI passes.
2. Update `APP_VERSION` and the built-in release notes in
   `twn_toolkit/version.py`.
3. Update README, Quick Start, Help, and focused documentation where behavior
   changed.
4. Run the complete test suite from a clean checkout or fresh virtual
   environment.
5. Create an annotated `vX.Y.Z` tag that exactly matches `APP_VERSION`.
6. Push the tag, wait for tag CI to pass, and publish the GitHub release.

The tag CI job rejects a release tag whose version does not match the
application version.
