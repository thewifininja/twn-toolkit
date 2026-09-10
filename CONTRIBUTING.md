# Contributing

TWN Toolkit keeps `main` in a releasable state. Changes should be
developed on a focused branch, validated locally and by GitHub Actions, and
merged through a pull request.

## Branch workflow

1. Update local `main` and create a focused branch. Codex-created branches use
   the `codex/` prefix.
2. Keep the branch limited to one feature, fix, or maintenance concern.
3. Run the complete local test suite:

   ```bash
   .venv/bin/python -m pip install --require-hashes -r requirements-dev.txt
   .venv/bin/python -m pytest -q
   ```

4. Push the branch and open a pull request against `main`.
5. Merge only after the Ubuntu, macOS, and Arch CI jobs pass and the change has been
   reviewed.

Direct pushes to `main` should be reserved for repository recovery. GitHub
branch protection can enforce this policy once it is enabled for the
repository.

## Pull requests

For interface changes, follow [the shared UI control guidelines](docs/ui-controls.md)
and reuse existing components and theme classes. Check new controls beside their
neighbors at desktop and mobile widths, including keyboard focus and hidden states.

A pull request should explain:

- what changed and why;
- what was tested locally;
- any platform, permission, migration, or compatibility considerations;
- screenshots for meaningful interface changes.

Avoid committing `instance/`, `.venv/`, captured credentials, automation
artifacts, or local packet/log files.

## Releases

For pilot and beta builds, follow [beta release versioning](docs/beta-releases.md)
before choosing an installed version. Preserve a forward upgrade path to the
intended GA; prerelease suffixes require updater support before use.

1. Freeze the intended feature scope. Create a release-preparation branch and
   record scope, compatibility, validation and publication gates in
   `docs/release-X.Y.Z-checklist.md`. Distinguish automated tests, operator
   observations and release-owner waivers; an unperformed check is never a pass.
2. Update `APP_VERSION` and the built-in release notes in
   `twn_toolkit/version.py`. Consolidate changes since the last published release,
   including any intervening development versions.
3. Update README, Quick Start, Help, version assertions and focused documentation
   where behavior changed. Preserve historical release notes.
4. Run the complete test suite from a clean checkout or fresh virtual environment
   using the hash-locked development dependencies. Build and verify the upgrade
   bundle, its manifest and checksum, including exclusion of private/runtime files.
5. Review and merge the release-preparation PR only after all Ubuntu, macOS,
   Arch, repository and dependency checks pass. Confirm merged-main CI passes
   and that its source tree matches the reviewed release candidate.
6. Create an annotated `vX.Y.Z` tag on that exact main commit. The tag must match
   `APP_VERSION`; push it and wait for all tag CI checks to pass.
7. Publish the GitHub release with user-facing changes, compatibility notes and
   validation evidence. Verify the **Release upgrade bundle** workflow succeeds
   and attaches both `twn-toolkit-vX.Y.Z.zip` and its `.sha256` asset.
8. Download the published assets, verify the checksum and manifest against the
   tagged source, and confirm normal release discovery offers the version before
   announcing upgrade availability. Never substitute an earlier candidate bundle.

Keep the release checklist's validation entries factual at commit time. Publication
and post-merge evidence can be recorded in the GitHub release with links to the
PR, main CI and tag CI; do not move a published tag or claim future checks passed
merely to check every box in the tagged checklist. A later documentation-only PR
may reconcile the checklist if needed.

The tag CI job rejects a release tag whose version does not match the application
version. Main CI builds and validates the bundle format; the published-release
workflow rebuilds it from the tag itself. In-app and CLI discovery intentionally
withhold a release until both upgrade assets exist.

## Dependency changes

Edit the `.in` files and regenerate both locks and provenance using the [dependency lock workflow](docs/dependency-locks.md). Do not hand-edit generated `.txt` locks. CI and installation reject stale provenance and require package hashes.
