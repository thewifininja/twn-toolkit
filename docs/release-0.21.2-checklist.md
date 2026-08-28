# v0.21.2 release checklist

## Scope

- [x] Restore active Remote Terminal sessions from an owner-scoped rendered
  checkpoint and exact output cursor before applying only newer live output.
- [x] Keep live output moving independently of the retained transcript and
  virtualize the bounded 100,000-line interactive scrollback.
- [x] Preserve terminal focus through long-running output, return to the live
  cursor when an operator types, and keep historical inspection stationary.
- [x] Move typing state and Jump to live below the terminal so controls cannot
  cover device output or the active prompt on desktop or mobile.
- [x] Measure every unique DHCP Discover-to-Offer response and retain timing in
  results, activity, administrative audit, case journals, and reports.

## Platform and compatibility boundary

- [x] Use a monotonic Discover/Offer interval on Linux and BPF capture
  timestamps on macOS without sending a DHCP Request or accepting a lease.
- [x] Preserve the existing SSH, Telnet, and serial-console protocol backends,
  owner isolation, transcript limits, retention, and case-evidence behavior.
- [x] Add no Python dependency, database migration, profile-format change,
  privileged-helper change, Raspberry Pi broker change, or service-layout
  change.
- [x] Require no service reinstall and keep the normal `v0.9.0` minimum direct
  upgrade boundary so no stepped release is required.

## Local validation

- [x] Pass the complete release-preparation pytest suite: 831 tests, 309
  subtests, and 9 expected skips on a fresh Python 3.13 environment.
- [x] Run `pip-audit==2.10.1` with only the repository's two documented
  advisory exceptions: no known vulnerabilities found.
- [x] Build and validate the 416-file v0.21.2 upgrade bundle with the `v0.9.0`
  minimum upgrade boundary and matching SHA-256 digest
  `ebed3f01d98ff1d66185b99297d52730d95a1f5e7c6a3fb77ea3efc3b6a6ebf7`.
- [x] Validate DHCP Offer timing and the unobstructed terminal status bar from
  a mobile browser against the local macOS instance.

## Pull-request and merged-main gates

- [ ] Pass the release-preparation PR on Ubuntu Python 3.10/3.13 and macOS
  Python 3.13, including repository checks and dependency audit.
- [ ] Squash-merge the release-preparation PR and pass its merged-main CI run.

## Publication gate

- [ ] Create and push the annotated `v0.21.2` tag only after every validation
  item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.21.2.zip` and `twn-toolkit-v0.21.2.zip.sha256` before
  announcing upgrade availability.

Stop before tagging unless every validation item above is complete.
