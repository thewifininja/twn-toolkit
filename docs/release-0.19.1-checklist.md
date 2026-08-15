# v0.19.1 release checklist

## Scope

- [x] Add persistent Telnet Remote Terminal sessions with optional credentials
  sent only through explicit operator controls after the remote prompt.
- [x] Add folder-level credential inheritance, host and folder overrides,
  stop-inheritance boundaries, atomic multi-select editing, and reviewed bulk
  host import.
- [x] Make the connection explorer collapsible and width-resizable and the live
  terminal height-resizable, with bounded responsive layouts and persisted
  browser preferences.
- [x] Capture bounded terminal transcripts automatically only while a case is
  actively recording and leave paused cases unchanged.
- [x] Let Bulk SSH verify and replace a changed saved host key, rerun only that
  host with the signed command plan, retain every other result, wrap long
  errors, and expand or collapse all results.

## Compatibility

- [x] Existing SSH hosts, credentials, folders, sessions, scrollback, cases,
  and configuration backups remain compatible with optional protocol and
  inheritance metadata.
- [x] Configuration backup review, import, and rollback include the expanded
  Remote Terminal library without exposing stored secrets.
- [x] No dependency, database migration, installer, service-topology,
  native-helper, or operating-system configuration change is included. A
  normal verified upgrade and process restart are sufficient.

## Validation

- [x] Complete operator smoke testing of Remote Terminal and Bulk SSH behavior.
- [x] Run the complete local test suite from the release-preparation source:
  764 passed, 9 skipped, and 296 subtests passed.
- [x] Pass shell syntax, Python source compilation, and the CI-pinned dependency
  audit: no known vulnerabilities found, with the two documented advisories
  ignored by policy.
- [x] Build and validate the exact v0.19.1 upgrade bundle and checksum: 389
  manifested files and a matching SHA-256 digest.
- [x] Pass pull-request CI run `31854700109` for PR `#125` on Ubuntu Python
  3.10/3.13 and macOS Python 3.13, including repository checks and the
  dependency audit.
- [x] Squash-merge PR `#125` as commit
  `3951938dc0632b7b3f2e3ca0c82f3f6f28a365c5` and pass merged-main CI run
  `31854835906`.

## Publication gate

- [ ] Create and push the annotated `v0.19.1` tag only after every validation
  item above is complete and the project owner has approved publication.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.19.1.zip` and `twn-toolkit-v0.19.1.zip.sha256` before
  announcing in-app upgrade availability.

Stop before tagging unless every validation item above is complete.
