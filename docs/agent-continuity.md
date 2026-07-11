# Implementation continuity notes

This file preserves the product and architecture decisions that should survive
conversation compaction and future development sessions.

## Product direction

- The home page is an operational dashboard, not a launch grid.
- Tools live in the persistent left navigation. Favorites are user-specific and
  appear there as well.
- Fortinet leaf workflows remain on the FortiGate and FortiAuthenticator pages;
  the sidebar links to those parent areas instead of listing every workflow.
- Navigation and page visibility follow effective access-profile permissions.
- Prefer reusable, systematic UI patterns over tool-specific CSS or markup.
- Slow server-side actions should use the shared loading presentation and a
  task-specific loading message.

## Activity and dashboard rules

- `instance/activity.sqlite3` is the activity source of truth. It stores
  timestamped metric deltas, per-user attribution, and human-readable events.
- Dashboard summaries support last hour, 24 hours, 7 days, 30 days, and
  lifetime presets plus a user-selected custom local start/end range. The
  selected interval applies consistently to metric cards, the scoreboard, and
  recent activity, and must survive scoreboard rank changes.
- Raw metrics represent work performed: probes, replies, API calls, frames,
  queries, and similar units.
- The activity score represents a deliberate user-initiated execution. Helper
  lookups, preview requests, page loads, and background refreshes do not award
  an action point, though they may increment an appropriate raw metric.
- A deliberate execution may receive an activity point even when the remote
  operation fails. Success/failure and completed-work counters must remain
  separate so the score does not imply success.
- Clearing a user score resets only `actions.total`. It does not erase that
  user's raw operational counters.
- Resetting a metric clears that metric globally and for every user while
  leaving action scores and recent history intact.
- Admins can reset metrics and scores. Standard users can view the dashboard but
  cannot reset it.
- Metric widget order and visibility are global and administrator-managed.
  `instance/dashboard_layout.json` stores stable metric IDs rather than titles
  or array positions. Unknown future widgets default to visible and are appended
  before the hidden group. Hidden widgets never render for standard users.
- Dashboard edit mode operates on the real responsive grid. Hidden widgets move
  below a clear divider; Cancel restores the pre-edit DOM order and visibility,
  while Save persists both. Reordering supports mouse drag, touch/pointer drag,
  and arrow keys from the widget drag handle.
- The global dashboard layout is a selectable, non-sensitive backup item.
  Activity counters, scoreboard data, and recent history are not included.
- New metrics should be attributable to the current user whenever the action is
  authenticated.

## Activity instrumentation pattern

When wiring a tool into metrics:

1. Count one activity action for the intentional run/send/export/execute/test.
2. Count raw units using the most meaningful completed or attempted work for
   that tool.
3. Record one concise recent event for the user-visible operation.
4. Do not award extra action points for preview, polling, or supporting API
   requests.
5. Add store-level assertions and a route test covering attribution and counts.

Activity instrumentation now covers every registered diagnostic/workflow tool:
ping, FortiGate/FortiAuthenticator API work, traceroute, SNMP, RADIUS, DNS,
syslog send/receive, packet replay sends, completed speed tests, TCP scans, NTP,
DHCP Discover, certificate inspection, manual API requests, Path MTU, Multi-SSH,
Subnet Excluder, and What's My IP.

Speed-test helper requests are a special case: latency/download/upload endpoints
do not award action points. The browser reports one completion after all phases
finish, with the actual download and upload bytes it observed. A cancelled or
abandoned speed test therefore does not count as completed.

Packet replay previews do not count. Only an actual send records an action and
accepted replay frames.

## Persistence expectations

- Activity updates must be safe with multiple Gunicorn workers.
- SQLite uses WAL mode, a busy timeout, owner-only database permissions, and a
  one-time initialization lock for concurrent fresh-worker startup.
- Metric increments are append-only samples. Dashboard totals are aggregates,
  which makes time-window filtering possible without changing route callers.
- On first use, a valid legacy `activity.json` is imported exactly once. Legacy
  totals are lifetime-only because they have no reliable occurrence time;
  legacy events retain their recorded timestamps.
- A malformed legacy activity file must not prevent SQLite initialization or
  future metric writes.
- Preserve unknown counter categories during legacy normalization so the schema
  can grow without a destructive migration.
- If activity volume becomes substantial, add daily rollups and a documented
  raw-sample retention policy before deleting historical samples.

## UI standards

- Primary/secondary actions belong consistently in a section header's
  `.section-actions` area, normally at the top right on wide screens.
- Card titles and descriptions should occupy separate blocks; short titles must
  not cause descriptions or kickers to run into them.
- Collapsible parent sections and nested record cards use shared patterns.
- Mobile behavior is part of the component standard, not a per-page patch.
- Avoid walls of warning banners and repeated destructive controls.
- Scoreboard user rows are collapsed by default. Their summary shows only the
  username and currently selected ranking metric; expanding reveals activity
  score, all non-zero metric bubbles, and the admin clear-score action.
- The sidebar scrolls independently, keeps Help/version at the actual bottom,
  and automatically opens the section containing the current page.

## Architecture standards

- The internal tool registry drives navigation, favorites, permissions, and
  endpoint ownership.
- Route handlers validate input, call service/helper code, and render/return the
  result. Domain behavior should not accumulate in `app.py`.
- Preserve stable tool IDs and endpoint names unless a migration is intentional.
- New functionality is trusted internal module registration, not runtime
  third-party plugin loading.
- Keep secrets write-only in the UI. Backups containing secrets require
  encryption.

## Automation architecture

- Reusable condition definitions and reusable action definitions are separate
  first-class records. An automation references one condition plus one or more
  actions and adds trigger/recovery/schedule policy. Conditions observe; the automation state
  machine decides when to fire; actions respond.
- Do not run monitoring loops inside Flask or Gunicorn workers. `./twn` manages
  one separate `twn_toolkit.automation_worker` process beside the web service.
- `instance/automations.sqlite3` stores definitions, scheduler state, checks,
  runs, and retained outputs. SSH action definitions are encrypted at rest with
  a key derived from the installation session secret.
- Current states are disabled, healthy, suspect, triggered, recovering, and
  error. A triggered automation fires once and must recover/rearm before it can
  fire again.
- Initial registered types are `manual.trigger`, `ping.multi`, and
  `ssh.collect`. Manual-trigger automations are excluded from due-check claims
  and expose an explicit Run now action. Add future types
  through `automation_registry.py`; do not add type-specific branches to the
  scheduler.
- Automation definitions are a sensitive backup group. History/output is not
  backed up, and imported definitions remain paused.
- Editing a shared definition pauses all dependent automations. Deletion is
  blocked while references remain. Existing embedded definitions are migrated
  automatically into reusable records.
- Check intervals may be as low as one second. The scheduler polls due work
  every 250ms; condition execution time still limits effective cadence.
- Action runs have a ZIP download containing summary metadata and per-host SSH
  text output.
- Collected action runs can be deleted individually or cleared per automation.
- Multi-SSH and `ssh.collect` share the same prompt-aware executor. Connection,
  authentication, and banner timeouts remain 8 seconds. Command ceilings default
  to 300 seconds and support an inline `[timeout=N] command` override from 1 to
  3600 seconds, with a one-hour combined ceiling per host. Completion is the
  return of the device prompt, not a short quiet period. Timeouts retain partial
  output and stop later commands for that host. Gunicorn's worker timeout is
  3700 seconds so synchronous Multi-SSH can honor that bounded SSH budget.
- Both SSH surfaces accept `Friendly Name = hostname-or-IP`. Preserve the
  connection target as `host` and the optional display value as `host_label` in
  execution results. UI output and filenames prefer the label but still expose
  the actual address.
- SSH capture is bounded to 5 MiB per host while reading; prompt detection keeps
  using a small rolling tail after that limit. Automation browser previews are
  shortened to 40,000 characters per host, but ZIP downloads use the complete
  retained capture.
  Clearing runs must not delete condition-check history.
- Automation creation is administrator-only for the initial vertical slice.
  Granular view/arm/edit/output permissions are a planned extension.
- See `docs/automations.md` for operations, security, and planned extensions.

## Verification

Run the full suite before handoff:

```bash
.venv/bin/python -m unittest discover -s tests
```

For dashboard work, also check light/dark themes, a normal desktop width, a
narrow pre-mobile width, and a phone-sized viewport.
