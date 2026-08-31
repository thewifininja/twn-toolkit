# v0.22.1 release checklist

## Scope

- [x] Replace paged sidebar categories and Back links with an in-place accordion
  hierarchy that keeps every top-level destination one click away.
- [x] Preserve the active category, one nested subgroup, and the operator's
  Favorites disclosure state across page loads without first-paint flashing.
- [x] Expand Focus navigation as a real workspace tile so it cannot cover or
  clip tools, while preserving accordion state when the rail collapses.
- [x] Revise static asset URLs when interface files change so upgraded CSS and
  JavaScript cannot be combined with stale browser-cached assets.
- [x] Apply shared squared theme geometry to the remaining Raspberry Pi
  networking cards, selectors, summaries, results, and client rows.

## Platform and compatibility boundary

- [x] Add no Python dependency, database migration, profile-format change,
  privileged-helper change, Raspberry Pi broker change, or service-layout
  change.
- [x] Preserve saved appearance settings, navigation width, Favorites and their
  order, profiles, automations, retained results, and platform service
  identifiers.
- [x] Require no service reinstall from v0.22.0 and retain the normal `v0.9.0`
  minimum direct-upgrade boundary; Raspberry Pi installations upgrading from a
  pre-v0.22.0 release still require the inherited protected broker refresh.

## Local validation

- [x] Pass the complete release-preparation pytest suite: 894 passed, 9
  skipped, and 329 subtests passed.
- [x] Run `pip-audit==2.10.1` with only the repository's two documented
  advisory exceptions and no known vulnerabilities.
- [x] Build and validate the v0.22.1 upgrade bundle with 425 archive files,
  424 manifest payload files, the `v0.9.0` minimum upgrade boundary, and
  matching SHA-256 checksum
  `70154885fa2c97dc53eac24b7f860314f0d3633e7e06bf0142457a07609e4f71`.
- [x] Validate version metadata, built-in Help, README, Quick Start, navigation
  state restoration, Focus geometry, asset revision, and Raspberry Pi theme
  geometry with the focused release suite: 111 passed and 25 subtests passed.

## Pull-request and merged-main gates

- [x] Squash-merge the Raspberry Pi geometry cleanup as PR #155 and pass its
  required CI gates.
- [x] Squash-merge the accordion navigation as PR #156 and pass CI run
  `33343316348` on Ubuntu Python 3.10/3.13 and macOS Python 3.13, including
  repository checks and dependency audit.
- [x] Pass v0.22.1 release-preparation PR #157 in CI run `33343796478` on
  Ubuntu Python 3.10/3.13 and macOS Python 3.13, including repository checks
  and dependency audit.
- [x] Squash-merge PR #157 as
  `ddc55d4fcb09c05057e286602ba0118ca50e2cef` and pass merged-main CI run
  `33344059301`.

## Publication gate

- [ ] Create and push the annotated `v0.22.1` tag only after every validation
  and merged-main item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both `twn-toolkit-v0.22.1.zip` and
  `twn-toolkit-v0.22.1.zip.sha256` before announcing upgrade availability.

Stop before tagging unless every validation and merged-main item above is
complete.
