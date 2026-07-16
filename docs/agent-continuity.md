# Implementation continuity notes

This file preserves the product and architecture decisions that should survive
conversation compaction and future development sessions.

## Decision doctrine

Apply this priority order when requirements conflict:

1. Safety and data integrity.
2. Operator clarity.
3. Product consistency.
4. Flexibility and reuse.
5. Implementation speed.

These are strong defaults, not absolute rules. An exception is acceptable when
the concrete benefit outweighs the tradeoff. State the exception and rationale
in the pull request; update this file when the exception establishes a reusable
precedent.

- Extend an existing component, registry, service, schema, or lifecycle before
  creating a parallel implementation. Generalize only around a demonstrated
  current or near-term consumer; do not add speculative abstraction.
- Keep domain behavior request-independent and reusable. Routes authenticate,
  authorize, validate, invoke services, and translate results into HTTP/UI
  responses; background workers and CLI commands should reuse the same services.
- Prefer stable identifiers, additive formats, explicit capability metadata, and
  bounded configuration over hard-coded branches. Flexibility must not permit
  arbitrary filesystem access, unbounded work, unsafe evaluation, or secret
  retention.
- Design for multiple workers, concurrent requests, restart recovery, partial
  completion, timeouts, resource ceilings, and 10x current data volume. Define
  ownership, persistence, retention, cleanup, idempotency, and rollback before
  adding durable or asynchronous state.
- Preserve compatibility unless a deliberate migration says otherwise. Material
  persistence changes require numbered transactional migrations, pre-change
  snapshots, rollback thinking, and representative upgrade tests.
- Treat permissions, secrets, activity metrics, audit events, diagnostics, Help,
  release notes, accessibility, responsive behavior, and tests as parts of the
  feature—not follow-up polish.

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
- Local operational files live beneath owner-only `instance/datastore/` and are
  managed through the grantable `local.datastore` tool. Keep every future
  transfer integration and cross-tool file picker constrained to this root;
  never accept arbitrary server filesystem paths. The managed TFTP worker uses
  this boundary, is disabled by default, and exposes admin-only listener/write/
  CIDR policy. Datastore contents, TFTP settings, and transfer history are not
  profile-backup data.
- Datastore list/grid preference is browser-local. Multi-file moves and deletes
  use server-validated batch endpoints; validate the complete batch before any
  mutation and roll back completed moves after filesystem failure. Internal
  file drags target datastore folders, while external file drops use the normal
  bounded multipart upload route.
- TFTP configuration lives on the separate grantable `local.file_transfers`
  page. It can scope its namespace to any datastore folder or a single
  runtime-only download file. Temporary staging must be cleared whenever the
  service stops. Incoming WRQ naming patterns support only the documented safe
  timestamp/client/filename tokens and resolve inside the selected root.

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
DHCP Discover, certificate inspection, manual API requests, Path MTU, Multi-SSH, Multi-Transfer,
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
- Alert the project owner before a material SQLite schema change. Use the
  existing numbered, transactional migration ledgers and create consistent
  pre-change snapshots through `MigrationManager`. Add upgrade tests using
  representative snapshots from every affected older schema.

## Versioning and release expectations

- `twn_toolkit/version.py` is the single application-version source used by the
  package, sidebar, and Help page.
- Begin intentional pre-1.0 version increments now. Use Semantic Versioning:
  patch releases for compatible fixes/documentation, minor releases for new
  tools or meaningful workflows, and reserve 1.0.0 for the first explicitly
  supported/stable configuration and migration contract.
- Before 1.0, call out configuration/schema incompatibilities in release notes;
  pre-1.0 does not excuse silent destructive changes.
- Current milestone is 0.11.0: live multi-host SNMP interface monitoring,
  route-level audit enrichment, high-impact preview/confirmation flows,
  representative v0.9.1 upgrade fixtures, operator rollback guidance, managed
  installer restarts, bounded external operations, cross-origin mutation
  protection, and dependency-audit release gates are implemented. The audit
  policy has no pending mutating endpoints. This remains a pre-1.0 release;
  broader real-world upgrade history, packaging, and an explicit supported 1.0
  compatibility contract still need deliberate hardening. The 0.10.1 hotfix
  makes browser-verified same-origin mutation metadata authoritative before the
  backend Host fallback, preserving logins through aliases and proxies while
  continuing to reject cross-site mutations. The complete test command is
  pytest; do not replace it with unittest discovery because fixture-based tests
  would be silently skipped.
  The 0.10.2 patch adds explicit, audit-visible legacy SSH compatibility to every
  SSH/SFTP/SCP surface while retaining modern negotiation by default. The 0.11.0
  feature release adds verified user-facing upgrades, matched code-and-instance
  recovery points, automatic rollback, and hardened singleton ownership for
  background services. It introduces no database-schema or configuration
  incompatibility. Installations on v0.10.2 or older need one final conventional
  upgrade to v0.11.0; routine later upgrades must not require Git, the GitHub CLI,
  or manual tag manipulation.
- Keep release notes beside `APP_VERSION` in `twn_toolkit/version.py` as
  structured data. The Help page renders that source as collapsible release
  history; every intentional version bump must add a dated release entry.
- Use short-lived `codex/<feature>` branches and GitHub pull requests for feature
  work. Run the full test suite before pushing the final revision. The project
  owner normally reviews, then squash-merges and deletes the remote branch;
  return the local checkout to an updated `main` before creating the next branch.

## UI design doctrine

The interface uses an adaptive balance: concise operational summaries by default,
with complexity available through progressive disclosure. Dense information is
appropriate when it helps an operator compare or act, but the first view must
make state, risk, and the next action obvious.

- Preserve a clear hierarchy: page purpose, current state, primary action,
  supporting controls, results, then advanced detail. Prefer plain operational
  language over implementation terminology.
- Make interactions predictable across tools. Reuse shared layout, form, action,
  collection, result, loading, and feedback patterns. A local override is an
  exception; prefer improving the shared component when the need is reusable.
- Show one clear primary action per task context. Separate destructive actions,
  require confirmation proportional to impact, and never rely on color alone to
  communicate risk or status.
- Design loading, empty, disabled, validation, failure, partial-success, success,
  stale, and permission-denied states with the main flow. Preserve operator input
  after recoverable errors and explain the next corrective action.
- Mobile, narrow desktop, and wide desktop are one responsive system. Avoid
  clipped actions and accidental page-level horizontal scrolling; allow bounded
  data regions to scroll when comparison requires it.
- Support keyboard operation, visible focus, semantic labels, readable contrast,
  reduced motion, and light/dark themes. Hover-only disclosure is supplemental,
  never the only way to discover or operate a control.
- Keep secrets write-only and sensitive values out of rendered pages, URLs,
  browser storage, exports, logs, and error detail unless explicitly required and
  protected.

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
  automatically opens the section containing the current page, and provides a
  client-side permitted-tool search above Dashboard. Search results de-duplicate
  Favorites, show the canonical category path, and must not mutate section state.
- Repeated saved-record collections use the shared flat collection treatment:
  one softly shaded list surface with individually clickable rows. Avoid nested
  wrapper outlines, colored side rails, doubled rounded corners, and hover-only
  geometry changes. Hover/focus may change background or border color but must
  remain visually consistent in light and dark themes. Apply fixes through the
  shared component selectors rather than per-tool overrides.

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
- Server identity lives in `server_settings.json`: `instance_name` is a
  lowercase single DNS label used for UI identity, while `preferred_fqdn` is an
  optional syntactically validated multi-label DNS name used for launcher URLs.
  Saving never performs DNS resolution. Browser titles retain the product name
  and add page/instance identity. Toolkit-managed certificate regeneration is
  explicit because it changes the certificate fingerprint.

## Upgrade and recovery architecture

- `upgrade_manager.py` is the request-independent source of truth used by the
  admin UI, `upgrade_cli.py`, and detached `upgrade_worker.py`. The dependency-free
  `release_bundle.py` owns the shared archive format so normal runtime code, CI,
  and release publishing use identical validation without booting the web app.
  Routes authorize, select an official release or bounded upload, invoke the
  manager, and translate status into HTTP/UI responses.
- Published stable releases gain `twn-toolkit-vX.Y.Z.zip` and its `.sha256`
  through the release-bundle workflow. The external digest and internal per-file
  manifest are mandatory. Reject drafts, prereleases, same/older versions,
  unsupported minimum versions, traversal, symlinks, duplicates, undeclared
  files, integrity mismatches, and over-limit bundles.
- `.twn-upgrades/` is owner-only ignored runtime state outside `instance/`.
  Before an upgrade, stop every managed process and copy managed code plus the
  complete stopped instance into one recovery point. Write an integrity manifest
  and verify it before every restore. Retain the five newest recovery points;
  never put them inside the instance or profile backups.
- Success requires the target version, web/scheduler/supervisor and every enabled
  transfer worker to be healthy, and all SQLite quick checks to pass. Any failure
  after backup restores code and instance data together and validates the old
  version again. A recovered failed upgrade remains a failed operation in UI,
  CLI exit status, and audit history; successful restoration does not relabel it
  as a successful upgrade. Never implement an in-place database downgrade or
  allow older code to open post-upgrade instance data.
- Serialize operations with the external lock. Bound downloads, expanded bytes,
  file count, network and subprocess timeouts, disk preflight, and retained
  history. Keep status and logs outside the instance so they survive replacement.
  Audit both the initiating administrator and background terminal result without
  secrets or bundle contents.
- Every managed background daemon is a root-scoped singleton guarded by a
  `.twn-*.lock` file outside the replaceable instance. This includes automation,
  the worker supervisor, TFTP, FTP, and SSH transfer. Launcher start/stop paths
  remove legacy duplicates for the exact module and instance before proceeding;
  supervisor cleanup is also scoped to the exact installation root. Never rely
  only on replaceable instance PID files for ownership: an orphan daemon can run
  duplicate automation or relaunch a transfer service during upgrade or rollback.
- Do not capture installer output in an updater pipe. Send it directly to the
  null device: package-manager output can contain repository credentials, and a
  daemon helper inheriting a captured pipe can keep an otherwise successful
  upgrade waiting indefinitely.
- Libraries that create process helpers, synchronization primitives, or event-loop
  descriptors at import time must be imported only after daemonization. This is
  the bootstrap protection for upgrades launched by an older updater that still
  captures installer output. Do not broadly close inherited descriptors: library
  event loops may own non-obvious descriptors such as macOS kqueues.
- The progress page tolerates the expected unavailable interval and resumes after
  restart. CLI recovery remains available when the UI is down. A manually
  supplied official bundle bypasses the release API, but dependency-changing
  releases may still need configured Python package access.

## SNMP interface bandwidth monitor

- The SNMP Tester includes a browser-lived multi-interface monitor built from
  existing saved SNMP credential and host profiles. It is part of the existing
  `network.snmp` tool and does not create another permission or persistence
  surface.
- `snmp_tools.discover_snmp_interfaces()` walks standard IF-MIB name,
  description, alias, status, type, and speed columns. Interface sampling prefers
  64-bit `ifHCInOctets`/`ifHCOutOctets`, falls back to 32-bit counters, preserves
  Counter64 values as decimal strings for JavaScript `BigInt`, and returns
  uptime/discontinuity/error/discard data for safe re-baselining and diagnostics.
- The browser can monitor up to 20 interfaces across multiple saved hosts.
  `/tools/snmp-test/interface-samples` polls the bounded set concurrently and
  isolates per-interface failures. Discovery and sampling increment raw SNMP
  poll metrics but suppress high-frequency audit events. Only explicit monitor
  start/stop lifecycle boundaries are recorded in activity/audit history, with
  the selected targets and interval.
- Graph samples and counter baselines stay in the open browser page and are not
  written to SQLite or backup data. The browser retains at most 10,000 calculated
  points per interface. Polling intervals are 1, 5, 10, 15, 30, or 60 seconds and
  may be changed while running without clearing history.
- Visible windows are 1, 2, 5, 15, 30, or 60 minutes. A shared history slider and
  Older/Live/Newer controls move every interface graph together while collection
  continues. The zero line shifts within a bounded 20–80% vertical range according
  to the visible download/upload peaks, and both directions are filled back to it.
- IF-MIB counters are interface-relative. For the endpoint attached to a switch
  port, `ifHCOutOctets`/interface transmit is **download**, and
  `ifHCInOctets`/interface receive is **upload**. Keep that mapping; the original
  UI inversion was corrected after a real speed-test comparison. Labels always
  include interface TX/RX so uplinks and trunks are not misleading.
- Hovering (or tapping) a graph selects the nearest retained sample, draws a
  vertical guide with colored points, and shows the local timestamp plus both
  formatted rates. Green is download/interface TX above zero; red is
  upload/interface RX below zero. Tooltip positioning accounts for the canvas's
  internal minimum width on narrow displays.
- Relevant implementation files are `snmp_tools.py`, `snmp_routes.py`,
  `templates/tools/snmp_test.html`, `static/snmp-interface-monitor.js`, the shared
  SNMP monitor styles in `static/styles.css`, and `tests/test_snmp_tools.py`.

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
- Registered condition types are `manual.trigger`, `schedule.calendar`,
  `ping.multi`, `dns.lookup`, `tcp.reachability`, `snmp.value`, and
  `certificate.health`. Registered action types are
  `ssh.collect`, `sftp.fetch`, `syslog.send`, and `webhook.send`. Manual-trigger
  automations are excluded from due-check claims and expose an explicit Run now
  action. Calendar schedules are intentionally handled by a small scheduler
  adapter because occurrence consumption differs from monitoring state. Other
  future types should register through `twn_toolkit/automation_types/` without
  adding type-specific branches to routes, persistence, or the scheduler.
- `automation_registry.py` is now a small compatibility/dispatch facade. The
  immutable type contracts live in `automation_types/models.py`; condition and
  action implementations own their validation, execution, form parsing, and
  secret-field metadata. Condition implementations and registrations are
  grouped under `automation_types/condition_types/`; the stable compatibility
  facade is `automation_types/conditions.py`. Actions remain in
  `automation_types/actions.py`. The automation route therefore does not need a
  new `if type_id == ...` branch when another trusted internal type is added.
- The automation page imports condition and action form macros from focused
  partials under `templates/automations/`. Keep new type-specific fields in the
  appropriate partial instead of growing the page-level layout again.
- A `schedule.calendar` condition contains up to 50 reusable sub-rules. It
  supports one-time, daily, selected-weekday, every-N-weeks, monthly-date, and
  ordinal-weekday rules in an explicit IANA timezone. Simultaneous sub-rules
  collapse into one occurrence. Each referencing automation tracks its own next
  occurrence and applies run-late, grace-period, or skip missed-run policy.
- Schedule claims preserve the intended occurrence in `pending_schedule_at`
  and move `next_check_at` to a five-minute lease. This prevents a second
  scheduler from claiming the same occurrence while allowing a crashed worker
  to retry it. After consumption, recurring schedules advance directly to a
  future occurrence rather than replaying downtime backlog.
- `dns.lookup` reuses the regular DNS tool's concurrent query engine. Each
  hostname/resolver pair is one check. An optional global expected-answer set
  can require any or all values; comparisons ignore case and a final DNS dot.
  Availability, answer mismatch, and the configured failed-check threshold are
  represented in the common condition result contract.
- `tcp.reachability` reuses the regular TCP scanner. Targets use
  `Friendly Name = host | ports`, allowing a different port/range list per host.
  Each expanded host/port pair is one check, and ports normalize to stable
  sorted values. Conditions can expect either open or explicitly refused
  connections. A timeout or generic socket error does not satisfy
  expected-closed because it is not definitive. Legacy global host/port configs
  normalize automatically and are persisted in the new form on their next edit.
- `snmp.value` selects saved SNMP hosts once, evaluates an AND group of named
  OID rules independently on each host, then applies a matching-host threshold.
  OID profiles support safe calculated scalar values. SNMP numeric decoding is
  centralized in `snmp_tools.parse_snmp_numeric` for thresholds and formulas.
- `certificate.health` monitors up to 20 TLS targets and can enforce expiration,
  hostname/IP SAN, system trust, chain order, likely missing intermediates, and
  endpoint availability.
- Automation definitions are a sensitive backup group. History/output is not
  backed up, and imported definitions remain paused.
- Automations use ordered action stages. Actions inside a stage run concurrently;
  stages run sequentially. Each stage has a stable ID, display name, and
  continuation policy (`all_completed`, `success_or_partial`, or `all_success`).
  Existing flat action lists migrate to one default parallel stage. Later stages
  receive bounded, non-secret earlier-action context; raw SSH output is never
  injected automatically.
- `automation_schema_migrations` is the numbered migration ledger. Version 1
  adds `action_stages`; version 2 persists first-generation SNMP definitions as
  per-host AND rules and pauses dependents. Use this runner—not new ad-hoc
  column checks—for future material schema changes.
- Editing a shared definition pauses all dependent automations. Deletion is
  blocked while references remain. Existing embedded definitions are migrated
  automatically into reusable records.
- Check intervals may be as low as one second. The scheduler polls due work
  every 250ms; condition execution time still limits effective cadence.
- Action runs have a ZIP download containing summary metadata and per-host SSH
  text output.
- Collected action runs can be deleted individually or cleared per automation.
- `sftp.fetch` can write to a selected datastore folder (optionally one folder
  per host) or stage binary artifacts for the collected run. `record_run()`
  moves staged files into `instance/automation_artifacts/<run-id>/`, removes
  staging, and stores only bounded metadata in SQLite. Run delete, clear, and
  retention pruning must remove matching artifact directories. Download ZIP
  resolves files through `AutomationStore.run_artifact()`; never trust a stored
  artifact path directly.
- Multi-SSH and `ssh.collect` share the same prompt-aware executor. Connection,
  authentication, and banner timeouts remain 8 seconds. Command ceilings default
  to 300 seconds and support an inline `[timeout=N] command` override from 1 to
  3600 seconds, with a one-hour combined ceiling per host. Completion is the
  return of the device prompt, not a short quiet period. Timeouts retain partial
  output and stop later commands for that host. Gunicorn's worker timeout is
  3700 seconds so synchronous Multi-SSH can honor that bounded SSH budget.
- All Paramiko client and server paths must obtain algorithm restrictions from
  `ssh_security.disabled_ssh_algorithms()`; do not add route-local cipher or key
  overrides. The default rejects SHA-1 `ssh-rsa`. A user-visible
  `allow_legacy_algorithms` boolean may explicitly relax negotiation for trusted
  old equipment. Multi-SSH and Multi-Transfer scope it to one run; automation
  actions and the managed SFTP/SCP service persist it visibly until disabled.
  Keep this separate from unknown-host-key acceptance, forward it through the
  shared executor/service boundary, and audit the boolean without credentials,
  commands, remote paths, or returned content. Any new SSH/SFTP/SCP feature must
  expose the same strong-default/explicit-exception model and add tests for both.
- Multi-Transfer uses the request-independent `sftp_tools.fetch_ssh_files` service,
  which writes into a caller-provided output directory and returns structured
  per-host/per-path results with SFTP, SCP, and FTP protocol adapters. Routes either persist through
  `LocalDatastore` or package an ephemeral ZIP. The legacy action type ID remains
  `sftp.fetch`, but its UI label is SSH file collection and its saved `protocol`
  defaults to SFTP for compatibility.
  FTP intentionally uses Python's standard-library client and is visibly marked plaintext.
  New code should import the protocol-neutral aliases from `transfer_tools`; the
  `sftp.fetch` action ID and older imports remain compatibility surfaces.
- `ssh_transfer_worker.py` is the inbound file-transfer-only SSH listener managed
  by `./twn`. It supports SFTP subsystem and regular-file SCP `-f/-t`, denies
  shells/arbitrary exec, checks trusted CIDRs before SSH, and authenticates with
  a password hash. Preserve contained resolution, symlink rejection, atomic
  `.part` uploads, runtime-root cleanup, and managed process/log integration.
- A separate `ftp_worker` process provides contained legacy FTP with configurable
  control/passive ports, hashed authentication, trusted CIDRs, atomic upload
  rewriting, per-protocol bounded transfer history, total/per-client connection
  limits, and datastore/runtime-only roots. FTP and SSH uploads must preserve the
  shared `MAX_UPLOAD_BYTES` ceiling and delete incomplete `.part` files.
- Both SSH surfaces accept `Friendly Name = hostname-or-IP`. Preserve the
  connection target as `host` and the optional display value as `host_label` in
  execution results. UI output and filenames prefer the label but still expose
  the actual address.
- `syslog.send` reuses the regular RFC 5424 sender and accepts up to 20
  `Friendly Name = host | port` destinations under one UDP/TCP protocol. It
  substitutes only documented trigger/timestamp tokens rather than using a
  general template evaluator. Delivery results are retained per destination;
  mixed outcomes produce a partial action result.
- `webhook.send` reuses the bounded manual API-request helper. It supports up
  to 10 named HTTP/HTTPS endpoints with a shared POST/PUT/PATCH template,
  accepted-status expression, timeout, and TLS policy. Headers are encrypted
  and write-only. JSON templates are parsed then recursively substituted so
  exact boolean/evidence tokens remain typed; text templates use explicit token
  replacement. Never retain request headers, and retain at most 4 KiB of each
  response body.
- SSH capture is bounded to 5 MiB per host while reading; prompt detection keeps
  using a small rolling tail after that limit. Automation browser previews are
  shortened to 40,000 characters per host, but ZIP downloads use the complete
  retained capture.
  Clearing runs must not delete condition-check history.
- Automation creation is administrator-only for the initial vertical slice.
  Granular view/arm/edit/output permissions are a planned extension.
- See `docs/automations.md` for operations, security, and planned extensions.
- `OperationalSettingsStore` owns scheduler concurrency/queue/overlap policy and
  datastore/artifact/free-space limits. Preserve quota enforcement at write time.
- `supervisor_worker.py` watches scheduler heartbeats and enabled transfer-worker
  PIDs. The launcher must stop the supervisor before intentionally stopping workers.
  Managed transfer start/stop operations are serialized with per-service lock
  directories so a settings-triggered restart cannot race the supervisor. Workers
  only remove PID files that still contain their own PID; preserve both safeguards.
- `MigrationManager` maintains the toolkit-wide migration ledger and creates
  consistent SQLite snapshots before new numbered migrations. Automation retains
  its existing internal migration ledger, both shown in System Diagnostics.
- `AuditStore` records sanitized, explicitly annotated actions for every authenticated
  operator and system administrator. Audit inclusion is role-neutral and context-only;
  being a system administrator must not make an otherwise noisy request auditable.
  `audit_policy.py` is the route-level coverage contract for every endpoint that
  accepts a mutating HTTP method. New routes must be classified as annotated,
  conditional, suppressed, excluded with a reason, or pending enrichment. Treat
  the pending set as a burn-down list, never as a permanent allowlist; it is empty
  after the initial audit-enrichment pass and should stay empty in ordinary changes.
  Routes use `annotate_audit_event` for resource context and curated
  before/after values. Never pass request bodies wholesale; recursive storage-time
  sanitization is defense in depth for passwords, credentials, tokens, communities,
  API keys, authorization fields, and secret headers. Use `suppress_audit_event`
  for high-frequency telemetry requests; audit user-visible lifecycle boundaries
  instead. Every event adds the actor role and assigned access-profile names.
  Profile routes share the secret-safe lifecycle helpers in `audit.py`; operator
  tools share `annotate_tool_run` and retain only bounded counts, modes, and outcomes.
  Public setup/login/logout routes record directly because they execute without an
  authenticated `g.current_user`; never add submitted passwords to those events.
  Datastore routes use `LocalDatastore.describe()` and bounded item lists
  for consistent path, kind, and size metadata without retaining file contents.

## Feature proposal and pre-merge checklist

Use this checklist while shaping a proposal, not only after implementation.
Record non-applicable items and justified exceptions briefly rather than forcing
irrelevant machinery into a feature.

1. **Fit and reuse:** What existing tool, component, service, registry, store, or
   lifecycle should own this? What likely next consumer should the design support?
2. **Boundaries:** Are route/UI code and domain behavior separated? Are inputs,
   outputs, concurrency, duration, retries, storage, and retention explicitly bounded?
3. **Failure and scale:** What happens with multiple workers, at 10x volume, after
   restart, on timeout, and after partial completion? Is retry safe; can cleanup or
   rollback recover without data loss?
4. **Compatibility:** Are stable IDs and saved formats preserved? If not, is there
   a migration, snapshot, upgrade test, rollback plan, and release-note warning?
5. **Access and privacy:** Who may see and execute it? Are navigation and direct
   endpoints permission-checked? Are secrets write-only and raw payloads/results
   excluded from persistence, logs, errors, and audit details?
6. **Activity and audit:** Is the intentional operator action distinguished from
   polling, preview, and helper traffic? Add meaningful metrics. Classify every
   mutating endpoint in `audit_policy.py`; keep the pending set empty. Explicitly
   design audit behavior for background jobs, CLI commands, scheduled work, and
   sensitive read/export workflows because the route contract cannot infer them.
7. **UI completeness:** Does the adaptive summary/detail hierarchy reuse shared
   patterns and cover loading, empty, validation, failure, partial-success,
   success, stale, disabled, and denied states? Verify keyboard/focus, reduced
   motion, light/dark themes, phone, narrow desktop, and wide desktop.
8. **Operations:** Are health, diagnostics, ownership, quotas, cleanup, backup/
   restore scope, and administrator recovery defined where relevant?
9. **Verification:** Add service/store tests, route and permission tests, secret-
   absence assertions, migration/upgrade tests when needed, and regression tests
   for the user-visible behavior. Run the complete suite.
10. **Continuity and release:** Update built-in Help and this file for durable
    behavior or precedent. At release time, add dated structured release notes
    beside the intentional version bump so the notes appear inside Help.

## Verification

Run the full suite before handoff:

```bash
.venv/bin/python -m pytest -q
```

For dashboard work, also check light/dark themes, a normal desktop width, a
narrow pre-mobile width, and a phone-sized viewport.

For JavaScript-heavy work, validate syntax with the bundled runtime when Node is
not installed globally:

```bash
/Users/nkarrick/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node --check path/to/file.js
```
