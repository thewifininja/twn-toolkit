# v0.19.3 release checklist

## Scope

- [x] Serialize Remote Terminal saved-library schema inspection and alteration
  across concurrent web workers.
- [x] Prevent simultaneous first-start workers from both adding the
  `credential_mode` column.
- [x] Preserve idempotent startup for new libraries and already-migrated
  libraries.
- [x] Add a deterministic multi-connection concurrency regression test.

## Incident and compatibility boundary

- [x] Confirm the production v0.19.0 recovery point passed integrity
  verification and automatic rollback restored the complete healthy process
  set after v0.19.2 target validation failed.
- [x] Reproduce the failed target's exact `duplicate column name:
  credential_mode` traceback from two Gunicorn workers initializing the same
  SQLite library.
- [x] Repair the production installation, verify every managed process and
  SQLite database, and record a successful v0.19.2 operation state.
- [x] Document the direct v0.19.0/v0.19.1 systemd CLI transition to v0.19.3;
  no stepped v0.19.2 installation is required.
- [x] Confirm existing v0.19.2, manual, and macOS installations retain the
  normal supported upgrade workflow.
- [x] No dependency, service-definition, profile-format, native-helper,
  capability, or operating-system configuration change is included.

## Validation

- [x] Run the targeted Remote Terminal store and application regression suite:
  66 passed.
- [x] Run the complete local test suite from the hotfix source: 742 tests
  passed.
- [x] Pass hotfix PR `#130` CI run `31862187645` on Ubuntu Python 3.10/3.13
  and macOS Python 3.13, including repository checks and dependency audit.
- [x] Squash-merge hotfix PR `#130` as commit
  `adfc9e0ec8d21721e9f1b5085b36bd0aa1ca560a` and pass merged-main CI run
  `31862455853`.
- [x] Run the complete test suite from the exact v0.19.3 release-preparation
  source: 767 passed, 9 skipped, and 296 subtests passed; the pinned dependency
  audit found no known vulnerabilities with two documented advisories ignored
  by policy.
- [x] Build and validate the exact v0.19.3 upgrade bundle with 391 manifested
  files and a matching SHA-256 digest.
- [ ] Pass release-preparation PR CI, squash-merge it, and pass merged-main CI.

## Publication gate

- [ ] Create and push the annotated `v0.19.3` tag only after every validation
  item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.19.3.zip` and `twn-toolkit-v0.19.3.zip.sha256` before
  announcing upgrade availability.

Stop before tagging unless every validation item above is complete.
