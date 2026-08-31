# v0.22.2 release checklist

## Scope

- [x] Add Osaka Jade as a complete saved dark appearance palette using the
  canonical Omarchy color direction and the toolkit's full semantic component
  contract.
- [x] Keep wide touch-capable Chromium and Brave browsers in desktop geometry by
  selecting the responsive layout from viewport width instead of pointer type.
- [x] Preserve phone and narrow-window navigation, Focus expansion, accordion
  state, Favorites state, appearance persistence, and the existing Tokyo Night
  default.

## Platform and compatibility boundary

- [x] Add no Python dependency, database migration, saved-profile change,
  privileged-helper change, or service-layout change.
- [x] Require no service reinstall from v0.22.1 and retain the normal `v0.9.0`
  minimum direct-upgrade boundary.
- [x] Preserve existing appearance settings and render every installation that
  does not select Osaka Jade exactly as before.

## Local validation

- [x] Pass the complete release-preparation pytest suite: 897 passed, 9
  skipped, and 329 subtests passed.
- [x] Run `pip-audit==2.10.1` with only the repository's two documented
  advisory exceptions and no known vulnerabilities.
- [x] Build and validate the v0.22.2 upgrade bundle with 426 archive entries,
  425 manifest payload files, the `v0.9.0` minimum upgrade boundary, and a
  matching SHA-256 checksum sidecar.
- [x] Validate version metadata, built-in Help, README, responsive breakpoint
  behavior, Osaka Jade persistence, palette completeness, and client-side mode
  switching with the focused release suite: 130 passed and 25 subtests passed.

## Pull-request and merged-main gates

- [x] Squash-merge the wide touch-capable browser correction as PR #159 and pass
  merged-main CI run `33345615848`.
- [x] Pass Osaka Jade PR #160 in CI run `33346567282`, squash-merge it as
  `4dd7b7fe86d7f074c8c6169c82c3f809267cfffa`, and pass merged-main CI run
  `33346705675` on Ubuntu Python 3.10/3.13 and macOS Python 3.13, including
  repository checks and dependency audit.
- [ ] Pass the v0.22.2 release-preparation pull request and merged-main CI.

## Publication gate

- [ ] Create and push the annotated `v0.22.2` tag only after every validation
  and merged-main item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both `twn-toolkit-v0.22.2.zip` and
  `twn-toolkit-v0.22.2.zip.sha256` before announcing upgrade availability.

Stop before tagging unless every validation and merged-main item above is
complete.
