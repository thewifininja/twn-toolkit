# v0.15.0 release checklist

## Multicast testing workspace

- [x] Listen mode supports IPv4 ASM and SSM joins on an explicit interface with
  matching group, UDP port, optional source, reusable-port behavior, bounded
  duration, immediate cancellation, and live packet/byte/rate/source/timeline
  telemetry.
- [x] Generic UDP, RTP v2, and TWN sequenced payloads provide the appropriate
  timing, volume, SSRC, payload-type, gap, loss, duplicate, reordering, and
  jitter evidence without retaining packet payloads.
- [x] Authorization-confirmed Send mode bounds duration, payload, rate, packet
  count, TTL, DSCP, source interface, and source port; End-to-end mode requires
  different interfaces and disables multicast loopback before comparing sent
  and matching received sequences.
- [x] Quick setups and built-in guidance document group-and-port matching,
  interface selection, IGMP membership, link-local flooding, snooping, querier,
  PIM, RPF, firewall, TTL, and packet-capture interpretation.
- [x] The separately authorized macOS PF helper status/install/uninstall path
  syntax-checks proposed rules, backs up the original configuration, owns a
  uniquely marked anchor and hook, detects unexpected edits, and never changes
  Cisco, FortiClient, Apple, or manually managed rules.
- [x] Native socket tests, route and authorization tests, bounded report tests,
  macOS PF fixture tests, tool-registry tests, and responsive UI contract tests
  cover the new workflow.

## Durable automation stages and webhooks

- [x] Every stage after the first accepts a normalized zero-to-24-hour delay
  that begins only after the preceding continuation policy allows progress.
- [x] A delay encrypts completed-stage progress, moves the job to `waiting`,
  releases the worker and lease, resumes through normal claims, survives
  restart, and does not replay already persisted stages during ordinary
  recovery.
- [x] The Automations page presents delay duration, waiting job state, due-time
  progress, reordered stages, assigned actions, and compact stage controls
  without exposing internal persistence details.
- [x] Webhook/API actions validate configured success statuses and optionally
  retry network failures or selected HTTP statuses up to five times with
  bounded exponential backoff and retained per-endpoint attempt evidence; one
  attempt remains the default.
- [x] Toolkit migration 2 creates a pre-change SQLite snapshot and prepares the
  encrypted in-progress job column; automation migration 6 records the durable
  delayed-stage schema transactionally and compatibility tests exercise older
  flat and staged definitions.

## Responsive diagnostics and managed-service lifecycle

- [x] Multi-Ping graphs redraw when their workspace width changes, shrink below
  the former canvas floor, and keep statistics, status, close actions, wrappers,
  and canvases inside each card at wide, narrow, and phone widths.
- [x] TFTP, FTP, and SFTP/SCP workers publish readiness only after their socket
  binds, and status/supervision require matching live PID and ready markers.
- [x] Launcher and supervisor paths use instance-scoped locks, coordinate with
  active start/stop operations, reject stale or zombie process state, clean up
  exact orphan daemons, and retain actionable startup errors.
- [x] Independent transfer services start and stop concurrently, while lazy
  Flask application loading avoids unrelated web initialization in worker and
  command-line processes.

## Compatibility and release gates

- [x] v0.15.0 uses native multicast sockets and existing dependencies. The web
  application and general installer never modify the host firewall; only the
  explicit privileged macOS helper can create its independently removable PF
  configuration.
- [x] Existing profiles, flat or staged automations, retained action history,
  transfer settings and history, iPerf3 data, live-tool data, dashboard state,
  and installation configuration remain supported for direct upgrade from
  v0.14.4.
- [x] Multicast PR #82, automation PR #83, and Multi-Ping PR #84 passed their
  complete feature-branch CI before squash merge; the managed-service lifecycle
  fix is included in the release-preparation baseline and release test run.
- [x] `APP_VERSION`, README, Quick Start, built-in Help, structured release
  notes, focused multicast/automation documentation, tests, and continuity
  guidance describe the v0.15.0 behavior.
- [x] Build the v0.15.0 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.15.0` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.15.0.zip` and
  `twn-toolkit-v0.15.0.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
