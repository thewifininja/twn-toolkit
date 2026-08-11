# v0.18.0 release checklist

## Scope

- [x] Use one tabs-first workspace chrome for peer views.
- [x] Standardize full-width page layout, section spacing, nested surfaces,
  actions, and responsive behavior across every route.
- [x] Consolidate saved network configuration around one reusable manager and
  align multi-record profile libraries.
- [x] Add collision-safe duplication for supported Fortinet, network,
  certificate, access-profile, and automation records.
- [x] Preserve write-only secret handling and add sanitized duplication audit
  events behind the existing workflow permissions.

## Compatibility

- [x] No database migration or stored-profile conversion is required.
- [x] No dependency, installer, service-topology, or native-helper change is
  included.
- [x] Existing profiles, encrypted automation data, certificate records,
  backups, and routes remain compatible.
- [x] A normal code upgrade and process restart are sufficient.

## Validation

- [x] Validate all application routes at desktop, tablet, phone, and compact
  widths, including light and dark themes, with no unexpected overflow,
  clipping, spacing, tab-order, or touch-target failures.
- [x] Confirm the browser console remains free of errors and warnings during the
  responsive route matrix.
- [x] Run the complete local test suite from the release-preparation source:
  654 passed, 7 skipped, and 241 subtests passed.
- [x] Pass shell syntax, Python source compilation, and the CI-pinned dependency
  audit: no known vulnerabilities found, with the two documented advisories
  ignored by policy.
- [x] Build and validate the exact v0.18.0 upgrade bundle and checksum from the
  completed release-preparation source.
- [ ] Pass pull-request CI on Ubuntu Python 3.10/3.13 and macOS Python 3.13,
  including repository checks and the dependency audit.
- [ ] Merge through the protected `main` workflow and pass merged-main CI.

## Publication gate

- [ ] Create and push the annotated `v0.18.0` tag only after project-owner
  approval.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.18.0.zip` and `twn-toolkit-v0.18.0.zip.sha256` before
  announcing in-app upgrade availability.

Stop before tagging until every validation item above is complete.
