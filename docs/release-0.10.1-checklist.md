# v0.10.1 release checklist

- [x] Reproduced the false cross-origin rejection with a browser-visible origin
  that differs from Flask's backend Host.
- [x] Browser-classified same-origin login succeeds through that topology.
- [x] Browser-classified cross-site mutations remain blocked before route work.
- [x] Origin/Referer fallback behavior remains covered for clients without fetch
  metadata.
- [x] CI installs the pinned development test runner and collects unittest and
  fixture-based tests together.
- [x] Complete local suite passes: 316 tests, 5 intentional skips, and 128
  subtests.
- [x] Version, built-in Help release notes, README, security guidance, and
  continuity documentation agree on v0.10.1 behavior.

After these versioned gates are green, require pull-request and merged-main CI,
create the annotated tag, require tag/version and platform CI, then publish and
verify the GitHub release before handoff.
