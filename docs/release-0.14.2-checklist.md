# v0.14.2 release checklist

## Operator workspace dashboard

- [x] The landing page prioritizes quick launch, workspace status, recent
  activity, and a four-metric snapshot instead of presenting every counter and
  team score at once.
- [x] Quick launch uses permitted personal Favorites first and falls back to
  common diagnostics, while dashboard search uses the same permission-filtered
  tool set as sidebar search.
- [x] Workspace status summarizes the current operator's live sessions and
  administrator-visible automation health, with direct access to the persistent
  live-tools tray.
- [x] Full activity metrics retain existing custom ranges, reset controls, and
  administrator-managed order/visibility in an expandable secondary view.
- [x] Team activity is collapsed and appears only when multiple operators or
  contributors make comparison relevant.
- [x] Light and dark themes, normal desktop width, a narrow pre-mobile width,
  and a phone-sized viewport have been visually verified.

## Compatibility and release gates

- [x] v0.14.2 introduces no application-database schema, dependency, profile,
  configuration, command-line, or automation migration and supports direct
  upgrade from v0.14.1.
- [x] Dashboard feature PR #75 and merged-main CI passed before this separate
  release-preparation branch was created.
- [x] `APP_VERSION`, README, built-in Help, structured release notes, tests,
  and continuity guidance describe the v0.14.2 behavior.
- [x] Build the v0.14.2 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.14.2` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.14.2.zip` and
  `twn-toolkit-v0.14.2.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
