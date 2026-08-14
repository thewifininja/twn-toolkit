# v0.19.0 release checklist

## Scope

- [x] Add durable investigation cases with attributed journals, managed
  evidence, selectable reports, PDF and evidence-package exports, reopening,
  and lifecycle-aware tool capture.
- [x] Allow multiple operators to collaborate in one open case while retaining
  owner-controlled state, membership, and report presentation.
- [x] Export and import complete portable cases and non-destructively merge an
  accessible closed case into the owner's current open case.
- [x] Add persistent interactive Remote Terminal sessions, reusable host
  folders, encrypted credential libraries, Quick Connect, tab/pop-out session
  management, retained scrollback, Datastore saving, and case transcripts.
- [x] Complete the full-width responsive UI and functional sidebar pass across
  investigations, Remote Terminal, administration, and network tools.
- [x] Expand inspect-first configuration backups across every explicitly
  portable durable domain with encrypted manifests, group previews, owner
  mapping, Combine/Replace behavior, and atomic rollback.

## Compatibility

- [x] Numbered transactional migrations preserve existing investigation data
  while adding collaboration, transfer lineage, and merge metadata.
- [x] Configuration backup manifest v2 remains able to import legacy v1
  backups; recovery points, portable cases, and configuration backups retain
  distinct transfer boundaries.
- [x] Existing accounts, profiles, automation definitions and history, terminal
  data, certificates, cases, evidence, datastore files, and service settings
  remain compatible.
- [x] No dependency, installer, service-topology, native-helper, or operating-
  system configuration change is included. A normal verified upgrade and
  process restart are sufficient.

## Validation

- [x] Validate investigation collaboration, portable transfer, chained and
  idempotent case merging, report rendering, lifecycle capture, Remote Terminal,
  configuration-store boundaries, encryption, owner mapping, and transactional
  rollback with focused regression coverage.
- [x] Validate the configuration-backup create, inspect, review, and complete
  24-group Combine flow at desktop, tablet, and phone widths with no horizontal
  document overflow and aligned controls.
- [x] Run the complete local test suite from the release-preparation source:
  737 passed, 8 skipped, and 291 subtests passed.
- [x] Pass shell syntax, Python source compilation, and the CI-pinned dependency
  audit: no known vulnerabilities found, with the two documented advisories
  ignored by policy.
- [x] Build and validate the exact v0.19.0 upgrade bundle and checksum: 386
  manifested files and a matching SHA-256 digest.
- [ ] Pass pull-request CI on Ubuntu Python 3.10/3.13 and macOS Python 3.13,
  including repository checks and the dependency audit.
- [ ] Squash-merge the release-preparation pull request and pass merged-main CI.

## Publication gate

- [ ] Create and push the annotated `v0.19.0` tag only after project-owner
  approval.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.19.0.zip` and `twn-toolkit-v0.19.0.zip.sha256` before
  announcing in-app upgrade availability.

Stop before tagging until every validation item above is complete.
