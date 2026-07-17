# v0.11.1 release checklist

## Product and compatibility

- [x] Certificate Automation is labeled Beta in navigation, the tool UI,
  built-in Help, README, and structured release notes.
- [x] Beta guidance requires end-to-end validation of enrollment, pending
  collection, renewal, exports, certificate chains, and target RADIUS behavior.
- [x] Saved PKI credentials and managed private keys remain encrypted locally;
  downloads warn about unencrypted key material and profile backups exclude PKI
  automation data.
- [x] Multi-Ping remains functional without `fping`; accelerated mode is enabled
  only after a real local capability check and installation never invokes a
  package manager or `sudo` automatically.
- [x] v0.11.1 introduces no incompatible migration of existing application
  databases or configuration. Certificate Automation uses a separate owner-only
  local data store.

## Release candidate gates

- [x] Build the v0.11.1 bundle from the release-preparation commit and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass pull-request CI on Ubuntu 3.10, Ubuntu 3.13, macOS 3.13, repository
  checks, and the dependency audit.
- [ ] After approval and squash merge, pass merged-main CI before creating the
  tag.
- [ ] Create and push the exact annotated `v0.11.1` tag only after every
  preceding gate is complete and the project owner explicitly approves it.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the release contains `twn-toolkit-v0.11.1.zip` and
  `twn-toolkit-v0.11.1.zip.sha256` before testing production discovery.
- [ ] From a production v0.11.0 installation, discover and install v0.11.1;
  verify recovery-point creation, web/scheduler/supervisor health, enabled
  services, audit history, and upgrade status after restart.
- [ ] Exercise rollback to the matched v0.11.0 recovery point and confirm the
  prior code and instance data return healthy.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
