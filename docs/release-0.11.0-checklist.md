# v0.11.0 release checklist

## Product and compatibility

- [x] Administration and CLI upgrades use the same request-independent engine.
- [x] Official and manually uploaded release bundles require whole-archive and
  per-file integrity validation.
- [x] Every upgrade creates a matched code-and-instance recovery point before
  application files or instance data change.
- [x] Post-upgrade validation checks the installed version, databases, managed
  processes, and enabled services, then automatically rolls back after failure.
- [x] Upgrade, backup, and rollback operations retain progress across web
  restarts and record secret-safe initiating and terminal audit events.
- [x] Background schedulers, supervisors, and transfer services enforce
  ownership-aware singleton behavior across starts, restarts, and cleanup.
- [x] v0.11.0 introduces no database-schema or configuration incompatibility.
- [x] README, Quick Start, built-in Help, release notes, upgrade guidance, and
  continuity documentation identify v0.11.0 as the first updater-enabled release.

## Release candidate gates

- [x] Build the v0.11.0 bundle and verify its internal manifest and external
  SHA-256 checksum from a clean release-prep checkout.
- [x] Pass the complete local pytest suite and release-specific validation.
- [x] Pass pull-request CI on every required platform and security gate.
- [ ] From a disposable copy of a real v0.10.2 instance with FTP enabled,
  perform the final conventional bootstrap to the exact v0.11.0 candidate.
- [ ] In a separate disposable copy of the candidate, identify it as the
  test-only lower version v0.10.999, then install the exact v0.11.0 candidate
  bundle through the manual bundle path. Verify web, scheduler, supervisor,
  FTP, audit history, and recovery-point visibility.
- [ ] Exercise rollback from the final candidate recovery point and confirm the
  matched prior code and instance data return healthy.
- [ ] After approval and merge, pass merged-main CI before creating the tag.
- [ ] Create and push the exact annotated v0.11.0 tag only after every preceding
  gate is complete.
- [ ] Pass tag CI/version validation and verify the published ZIP and SHA-256
  assets before announcing the release.

Do not tag or publish from this preparation branch. The project owner performs
the final real-instance drill and explicitly approves release publication.
