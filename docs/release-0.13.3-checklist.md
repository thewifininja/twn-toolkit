# v0.13.3 release checklist

## SMTP behavior

- [x] SMTP Message-ID generation uses the domain from the validated sender
  address and does not resolve the toolkit host's FQDN.
- [x] The change preserves recipients, sender, authentication, transport
  security, message content, and per-recipient delivery reporting.
- [x] v0.13.3 introduces no application-database, profile, configuration,
  command-line, or dependency migration.

## CI performance

- [x] The managed-certificate route test remains a real generation and signing
  test while using deterministic certificate names instead of the hosted
  runner's transient hostname.
- [x] The fully mocked SMTP transport test does not load the host system trust
  store.
- [x] CI reports its 50 slowest tests for ongoing performance visibility.
- [x] A GitHub-hosted macOS Python 3.13 comparison reduced pytest from 244.96
  seconds to 35.47 seconds and the complete job from 4m 25s to 58 seconds.
- [x] Pull-request CI passed on Ubuntu 3.10, Ubuntu 3.13, macOS 3.13,
  repository checks, and the dependency audit; the PR macOS job took 52
  seconds.

## Release gates

- [x] Build the v0.13.3 bundle from the release-preparation source and verify
  its internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.13.3` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.13.3.zip` and
  `twn-toolkit-v0.13.3.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
