# v0.19.2 release checklist

## Scope

- [x] Remove inherited systemd and launchd service-control state from detached
  upgrade workers before they stop the managed process set.
- [x] Preserve an active upgrade pause and external validation process set if
  the OS service supervisor restarts during the handoff.
- [x] Bypass transient launcher-PID rediscovery when the request-scoped
  deferred reload helper is already active.
- [x] Preserve bounded failed-target status and process logs outside the
  replaceable instance before automatic rollback.
- [x] Add regression coverage for worker launch context, handoff ordering,
  restart behavior, and retained rollback diagnostics.

## Incident and compatibility boundary

- [x] Confirm the production v0.19.0 recovery point passed integrity
  verification and automatic rollback restored the complete healthy process
  set after the v0.19.1 target failed validation.
- [x] Confirm systemd logged `KillMode=mixed` terminating the in-app Python
  worker after the old inherited service context skipped the managed pause.
- [x] Document the one-time CLI upgrade required for existing v0.19.0 or
  v0.19.1 systemd installations; their old web updater cannot retroactively
  launch with the v0.19.2 environment fix.
- [x] No dependency, database migration, profile-format, service-definition,
  capability, native-helper, or operating-system configuration change is
  included.

## Validation

- [x] Run shell syntax checks and compile all Python sources.
- [x] Run the complete local test suite from the hotfix source: 766 passed,
  9 skipped, and 296 subtests passed.
- [x] Pass hotfix PR `#127` CI run `31858346148` on Ubuntu Python 3.10/3.13
  and macOS Python 3.13, including repository checks and dependency audit.
- [x] Squash-merge hotfix PR `#127` as commit
  `1470ed4f6b0b695478f437431132d55e9ecd1286` and pass merged-main CI run
  `31858451844`.
- [x] Run the complete test suite from the exact v0.19.2 release-preparation
  source: 766 passed, 9 skipped, and 296 subtests passed; the pinned dependency
  audit found no known vulnerabilities with two documented advisories ignored
  by policy.
- [x] Build and validate the exact v0.19.2 upgrade bundle with 390 manifested
  files and a matching SHA-256 digest.
- [ ] Pass release-preparation PR CI, squash-merge it, and pass merged-main CI.

## Publication gate

- [ ] Create and push the annotated `v0.19.2` tag only after every validation
  item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.19.2.zip` and `twn-toolkit-v0.19.2.zip.sha256` before
  announcing upgrade availability.

Stop before tagging unless every validation item above is complete.
