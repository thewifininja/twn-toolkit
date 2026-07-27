# v0.14.3 release checklist

## Personal Favorites ordering

- [x] Two or more visible Favorites always expose restrained drag handles
  without requiring a separate reorder mode or text link.
- [x] Pointer dragging and keyboard up/down arrows update the same personal
  order and save automatically.
- [x] Reordering a permission-filtered subset preserves temporarily hidden
  Favorites, and dashboard Quick launch follows the saved order.
- [x] Sidebar star actions remain vertically centered with their tool labels in
  light and dark themes.

## DNS testing workspace

- [x] Query and resolver cards use matched rows, text areas, guidance, and
  profile-management controls at desktop widths and stack cleanly on narrow
  layouts.
- [x] Comparison mode retains saved profiles, record types, timeouts, detailed
  answers, and per-query latency while adding useful run summaries.
- [x] Load-test mode requires explicit authorization and provides a live
  estimate before running.
- [x] Load tests are capped at 500 QPS per resolver, 30 seconds, five resolvers,
  100 concurrent queries, and 50,000 planned queries.
- [x] Saturated load tests stop submitting new work at the requested deadline
  and report achieved QPS, success, response statuses, and per-resolver average,
  p50, p95, p99, and maximum successful-query latency.
- [x] The redesigned DNS workspace and both modes were browser-verified in
  light and dark themes; desktop card, text-area, and profile-control alignment
  was also measured directly.

## Compatibility and release gates

- [x] v0.14.3 introduces no application-database schema, dependency, profile,
  configuration, command-line, or automation migration and supports direct
  upgrade from v0.14.2.
- [x] Favorites PR #77 and DNS testing PR #78 passed complete feature-branch CI
  before being squash-merged into `main`.
- [x] Combined merged-main CI exposed one stale cross-feature Favorites test
  assertion for the former DNS tool title; release preparation updates that
  assertion to the merged `DNS Tester` title without changing runtime behavior.
- [x] `APP_VERSION`, README, built-in Help, structured release notes, tests,
  and continuity guidance describe the v0.14.3 behavior.
- [x] Build the v0.14.3 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests
  after the cross-feature assertion correction.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.14.3` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.14.3.zip` and
  `twn-toolkit-v0.14.3.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
