# v0.14.1 release checklist

## Unified Multi-SSH workflow

- [x] Standalone Multi-SSH uses one target-matrix, command-template,
  signed-preview, and credential-entry workflow without Basic/Advanced mode
  selection.
- [x] The target table, Raw Matrix editor, custom variables, Stored Commandlets,
  prompt-aware execution, and result exports remain directly available.
- [x] Fleet execution retains the 5,000-target ceiling, batches of 50, at most
  10 simultaneous SSH connections, and bounded output capture.

## Compact host import and compatibility

- [x] A collapsed, visually understated importer accepts friendly
  `Name = host` entries and inclusive IPv4/IPv6 ranges.
- [x] Imported targets may append to or replace current rows without removing
  custom variable columns.
- [x] Legacy Basic and Advanced mode links redirect to the unified page while
  preserving Commandlet load and duplication parameters.
- [x] Legacy Basic form submissions become signed previews without executing
  SSH or retaining the submitted password.
- [x] v0.14.1 introduces no application-database schema, dependency, profile,
  configuration, command-line, or automation migration and supports direct
  upgrade from v0.14.0.

## Documentation and release gates

- [x] `APP_VERSION`, README, built-in Help, structured release notes, tests,
  and continuity guidance describe the v0.14.1 behavior.
- [x] Build the v0.14.1 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.14.1` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.14.1.zip` and
  `twn-toolkit-v0.14.1.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
