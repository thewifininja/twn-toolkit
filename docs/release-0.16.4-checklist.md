# v0.16.4 release checklist

## Automation fallback stage routing

- [x] A stage can continue when one or more preceding actions report an error.
- [x] A stage can continue only when every preceding action reports an error.
- [x] Uncaught action execution exceptions participate in failure routing.
- [x] Partial results remain distinct from errors and are accepted only by the
  existing success-or-partial route, not by either failure route.
- [x] Existing always, success-or-partial, and full-success stored policies keep
  their prior behavior.
- [x] The continuation policy is evaluated before a later stage delay, so an
  ineligible fallback does not create a waiting job.

## Runtime and dependency diagnostics

- [x] System Diagnostics distinguishes manual from boot-managed operation and
  reports service-manager state separately from the live managed process set.
- [x] The external command inventory matches supported integrations and no
  longer reports the unused OpenSSL executable.
- [x] Native macOS BPF readiness and effective Linux network capabilities are
  reported separately from command presence without changing host permissions.
- [x] README, Quick Start, built-in Help, automation and autostart documentation,
  and continuity guidance describe the new behavior.

## Compatibility and release gates

- [x] Feature PRs #99 and #100 passed complete Ubuntu and macOS CI before squash
  merge.
- [x] v0.16.4 introduces no Python dependency, database migration,
  profile-format, server-setting, capability, BPF-policy, permission-policy,
  service-lifecycle, or command-line incompatibility.
- [x] Existing automation definitions, delayed jobs, history, retained output,
  service ownership, managed listeners, instance data, and matched recovery
  guarantees remain unchanged.
- [x] Build the v0.16.4 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete pytest suite and release-specific metadata tests: 594
  passed, 6 skipped, and 213 subtests passed locally.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.16.4` tag only after project-owner
  approval of release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.16.4.zip` and
  `twn-toolkit-v0.16.4.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. Release publication follows
the squash-merged release PR and successful merged-main CI.
