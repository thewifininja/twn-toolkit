# v0.22.0 release checklist

## Scope

- [x] Ship the themeable, terminal-inspired TWN Toolkit interface with the
  horizontal `>_TWN:~$ toolkit` identity, squared shared geometry, denser
  navigation, and consistent desktop/mobile workspaces.
- [x] Keep diagnostic results primary by collapsing active or completed setup
  into run bars and opening unchanged settings in responsive side sheets.
- [x] Reorganize dense tools around shared tabs, staged forms, profile controls,
  dropdowns, and result layouts while preserving their operational options.
- [x] Make each Bulk SSH host matrix own a compatible CLI-action library and
  require operators to build and order an explicit runbook for every run.
- [x] Support simultaneous hardware-bound Raspberry Pi Ethernet and Wi-Fi
  profiles with provisional apply, reachability confirmation, and rollback.

## Platform and compatibility boundary

- [x] Add no Python dependency or database migration and retain the normal
  `v0.9.0` minimum direct-upgrade boundary; no stepped release is required.
- [x] Migrate v0.21.2 Bulk SSH command sets with embedded targets into host
  matrices and matrix-owned CLI actions without deleting standalone
  compatibility sources.
- [x] Commit JSON profile changes with atomic replacement and verify that an
  interrupted Bulk SSH migration is retryable without data loss or duplicate
  matrices.
- [x] Map the retired compact workspace layout to tiled while preserving saved
  theme, density, navigation-width, and text-scale preferences.
- [x] Require Raspberry Pi service installations to run
  `sudo ./twn service install` once after upgrading so broker protocol v2 is
  installed; preserve `--network-capabilities` when already in use. Other
  platforms require no service reinstall.
- [x] Keep the existing `com.thewifininja.*` macOS service identifiers and the
  `thewifininja/twn-toolkit` repository path so installed services and updater
  URLs continue to work. User-visible identity and documentation use TWN.

## Local validation

- [x] Pass the focused profile, upgrade, Bulk SSH, authentication, backup,
  version, and home-page compatibility tests: 184 tests and 9 subtests.
- [x] Pass the complete release-preparation pytest suite on the local Python
  3.13 environment: 892 tests, 329 subtests, and 9 expected skips.
- [x] Run `pip-audit==2.10.1` with only the repository's two documented
  advisory exceptions: no known vulnerabilities found.
- [x] Build and validate the 424-file v0.22.0 upgrade bundle (423 payload
  manifest entries) with the `v0.9.0` minimum upgrade boundary and a matching
  generated SHA-256 checksum sidecar.
- [x] Validate the README wordmark SVG, exact `>_TWN:~$ toolkit` text,
  current version/help presentation, and absence of the retired user-visible
  product identity and dragon artwork.

## Pull-request and merged-main gates

- [x] Squash-merge the interface and workflow foundation as PR #152 and pass
  merged-main CI run `33334455094`.
- [ ] Pass the v0.22.0 release-preparation PR on Ubuntu Python 3.10/3.13 and
  macOS Python 3.13, including repository checks and dependency audit.
- [ ] Squash-merge the release-preparation PR and pass merged-main CI.

## Publication gate

- [ ] Create and push the annotated `v0.22.0` tag only after every validation
  and merged-main item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both `twn-toolkit-v0.22.0.zip` and
  `twn-toolkit-v0.22.0.zip.sha256` before announcing upgrade availability.

Stop before tagging unless every validation item above is complete.
