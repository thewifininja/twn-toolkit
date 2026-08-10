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

- The home page is an operator workspace, not a launch grid or a gamification
  surface. Its primary hierarchy is quick launch, items needing attention, and
  recent activity. Full metrics and team comparison are secondary expandable
  views.
- Tools live in the persistent left navigation. Favorites are user-specific,
  preserve the operator's saved order, and appear there as well.
- Fortinet leaf workflows remain on the FortiGate and FortiAuthenticator pages;
  the sidebar links to those parent areas instead of listing every workflow.
- Navigation and page visibility follow effective access-profile permissions.
- Prefer reusable, systematic UI patterns over tool-specific CSS or markup.
- Slow server-side actions should use the shared loading presentation and a
  task-specific loading message.
- DNS load testing remains an explicitly authorized, evenly paced diagnostic:
  cap duration, per-resolver QPS, resolver count, concurrency, and total queries;
  retain only aggregate results and latency percentiles rather than every
  response.
- iPerf3 support uses only an already installed `iperf3` binary and never
  installs packages or invokes a shell. Client traffic requires explicit
  authorization and fixed duration/stream/rate caps. Server mode runs in a
  supervised background worker with explicit Start/Stop controls, one active
  listener per user, ports 1024–65535, synchronous port-availability checks,
  toolkit restart recovery, and sequential single-client cycles. Active
  listeners must appear in the owner’s dashboard and Live tools tray. Retain
  only the newest 50 server results per user; expose source address, normalized
  metrics, and bounded raw JSON only to that user, and provide an explicit
  history-clear action.
- Multicast testing uses native IPv4 UDP sockets and never installs packet
  generators. Keep listen, send, and dual-interface path runs explicitly
  authorized and bounded to 300 seconds, 200 Mbps, 50,000 packets/second, and
  one million generated packets. Support ASM and host-available SSM joins on a
  selected interface; analyze generic UDP, RTP v2, and TWN sequenced payloads
  without retaining payload bytes. Treat same-host path evidence carefully:
  disable sender loopback, require different interfaces, disclose local
  routing/filtering effects, and recommend separate toolkit hosts for
  independent endpoint proof. Reports may include aggregate/source/sequence
  metadata and JSON export, but audit records must omit group addresses,
  source addresses, and payloads. The browser-facing run endpoint streams
  bounded NDJSON progress at a coarse interval so packet/byte/source/rate and
  timeline telemetry remains live without per-packet persistence. Client
  cancellation must close the socket promptly. Receivers set reusable address
  and, when host-supported, reusable port options before binding so standard
  listeners such as mDNS on UDP 5353 can coexist with the toolkit.
  On macOS, PF enabled by third-party software may block the Router Alert IP
  option used by IGMP while still accepting the socket membership. Keep the
  workaround optional and CLI-administered: `./twn multicast-pf` owns a
  dedicated, explicitly invoked PF anchor with status/install/uninstall
  commands, backups, syntax validation, drift refusal, interface scoping, and
  restart-based activation. Never mutate PF from the web UI, the general
  installer, or a vendor-owned anchor. The multicast page may inspect readable
  persistent files and warn about missing, incomplete, stale, or insufficient
  interface coverage, but it must not claim active-rule verification without
  privileged `pfctl` access.
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
- Quick launch uses the current user's permitted Favorites first and fills any
  remaining slots from a short list of common diagnostics. Dashboard search
  must use the same permission-filtered destination set as sidebar search.
- Favorite ordering is user-specific and controls both the sidebar list and
  Quick launch. Reordering a currently visible subset must preserve Favorites
  hidden by access-profile changes so later access restoration is non-destructive.
  When two or more Favorites are visible, their sidebar drag handles remain
  available without entering an edit mode; pointer and keyboard moves save
  automatically.
- Workspace status summarizes the current user's live-tool sessions and, for
  administrators, enabled automation health. Team activity stays collapsed and
  is omitted entirely when there is only one operator and contributor.
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
Subnet Excluder, What's My IP, and multicast listen/send/path tests.

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
- Current milestone is 0.16.8: macOS LaunchDaemon mode keeps Gunicorn,
  automation, supervisor, and enabled transfer workers in the launchd-owned
  process tree, scheduled PCAP actions invoke their bounded helper by absolute
  path, and nested Darwin errno 65 SSH failures identify Local Network Privacy
  as a possible cause. Durable automation claims and renewable leases,
  explicit check-interval and schedule run modes, reusable ALL/ANY condition
  groups, Ping Quality and DNS Performance conditions, standalone and automated
  Packet Capture, lightweight live and retained PCAP inspection, datastore PCAP
  saves, metadata-only SMTP email actions, and the reorganized Administration
  interface are implemented. Packet Replay can now select bounded classic PCAP
  files directly from the contained Datastore when the operator has both tool
  permissions, while retaining upload and raw-frame sources. Automation
  condition deadlines now stay anchored to a non-overlapping start cadence,
  avoid claiming and discarding a round while its predecessor is active, and
  timestamp history at observation start. Automation Ping shares Multi-Ping's
  capability-aware timeout validation, including sub-second values through a
  verified `fping` engine. Packet capture retains the host's existing
  permission boundary and never installs software or invokes sudo. Certificate
  Automation now includes a tested, guided Let's Encrypt DNS-01 workflow that
  distinguishes configured-resolver caching from authoritative propagation,
  retains protected Certbot material, and no longer carries a Beta label.
  Microsoft AD CS remains explicitly Beta. CLI operations now include guarded
  Linux/macOS recovery for orphaned or sudo-started Gunicorn processes, with
  installation-specific process verification, conservative port-conflict
  handling, ownership repair, and a return to normal-user operation. SMTP
  Message-ID generation uses the validated sender domain instead of resolving
  the host FQDN, avoiding platform-specific DNS delays. CI reports slow-test
  timings and keeps host-sensitive certificate tests independent of transient
  runner names. Multi-SSH now uses one preview-first workflow with reusable
  Stored Commandlets, spreadsheet-style target matrices, per-host variables,
  signed previews, and bounded fleet execution for up to 5,000 targets. Its
  compact host importer retains the earlier friendly-name and inclusive
  IPv4/IPv6 range syntax without restoring a separate Basic mode; legacy mode
  URLs redirect to the unified page, and legacy Basic submissions are converted
  into previews without executing. SSH collection
  automation actions use the same matrix and rendering model while saving
  independent Commandlet snapshots and retaining compatibility with legacy
  host-list configurations. The dashboard is now a calmer operator workspace:
  permission-aware quick launch and search lead into live-tool and automation
  status, recent work, and a four-metric snapshot. Full metrics and optional
  team comparison remain available as secondary expandable views without
  changing existing activity data or layout persistence. Personal Favorites
  can now be reordered directly through persistent pointer and keyboard drag
  handles, and dashboard Quick launch follows the same user-specific order.
  DNS testing now uses matched query and resolver cards, clearer comparison
  summaries, and an explicitly authorized load-test mode with fixed rate,
  duration, concurrency, resolver-count, and total-query caps plus aggregate
  throughput, status, and latency-percentile reporting. iPerf3 diagnostics use
  only an existing system binary and now include bounded client tests plus an
  authorization-gated, supervised On/Off listener. Enabled listeners resume
  with the toolkit, surface in the owner’s dashboard and Live tools tray, clean
  up exact recorded orphan processes before crash recovery, and retain the
  newest 50 private server results in an owner-only SQLite database. Multicast
  testing now includes explicit-interface IPv4 ASM and SSM listening, bounded
  controlled Send and dual-interface End-to-end modes, Generic UDP, RTP, and
  TWN sequence-aware reporting, live cancelable telemetry, and bounded JSON
  exports. Its optional macOS PF compatibility helper is a separate privileged
  CLI workflow that detects, installs, verifies, updates, and removes only
  TWN-managed IGMP rules; the web application and installer never change the
  host firewall. Automation pipelines now support durable zero-to-24-hour
  delays after eligible stages, persisting encrypted progress in a waiting job
  without occupying a worker and resuming after restart. Stage continuation can
  now route when any action fails or only when every action fails, keeping
  partial work distinct from errors and enabling backup notification paths.
  Webhook/API actions
  validate configured success statuses and may use explicit bounded retries
  for network failures or selected HTTP responses while retaining per-endpoint
  attempt evidence. Multi-Ping graph canvases and card headers remain contained
  through live workspace resizing. Managed TFTP, FTP, and SFTP/SCP services use
  instance-scoped lifecycle locks plus exact readiness markers, concurrent
  launcher operations, stale/zombie detection, and lazy web-app imports so
  supervision reflects bound listeners and routine starts complete faster.
  Cross-platform boot management now uses an opt-in systemd unit on Ubuntu,
  Raspberry Pi OS, and other systemd Linux hosts or a system LaunchDaemon on
  macOS. The OS service definition is privileged to install, but the toolkit
  remains owned and executed by a selected normal account. Linux can opt into a
  unit-scoped set of `CAP_NET_RAW`, `CAP_NET_ADMIN`, and
  `CAP_NET_BIND_SERVICE`; macOS instead relies on administrator-managed BPF
  access for the normal service account. macOS DHCP Discover uses one raw BPF
  Discover/Offer exchange and never binds port 68 or sends a DHCP Request.
  Installed service lifecycle, ordinary launcher commands, upgrades, rollback,
  and recovery coordinate through the same supervisor context. Service removal
  retains toolkit data. System Diagnostics now separates manual or
  boot-managed mode, OS service-manager state, live managed processes, external
  command integrations, and native macOS BPF or effective Linux network
  capabilities without changing host permissions. Its live database and process
  checks are read-only and bounded; SQLite files above 64 MiB are labeled for a
  maintenance-window integrity check rather than scanned inside the web request.
  Diagnostics degrade per section instead of reconciling runtime state or holding
  the entire page behind a long busy timeout. The Automation workspace reads its
  definitions, recent history, and job counters through one consistent read-only
  snapshot rather than re-running schema and migration setup for each card. The
  toolkit now stores an optional IANA timezone override separately from the host
  clock, applies it immediately to explicit localized Webhook, Email, and Syslog
  variables, and uses it as the initial default for new schedules. UTC storage,
  legacy timestamp variables, existing notification templates, and saved
  schedule timezones remain unchanged.
  Boot-managed upgrades now
  keep the original launcher
  paused while a temporary process set is validated, finalize status, audit,
  staged-input cleanup, and the external operation lock before asking systemd
  or launchd to reload, and withhold launcher discovery across matched instance
  restores. This prevents OS cgroup or job cleanup from killing the detached
  updater while preserving exactly one final toolkit-start event. Responsive
  navigation tracks the browser visual
  viewport so Help/release notes, configured instance name, and installed
  version remain reachable under mobile zoom and browser chrome, while direct
  and nested tool rows use consistent indentation. This remains a pre-1.0
  release; broader real-world
  upgrade history, packaging, and an explicit supported 1.0 compatibility
  contract still need deliberate hardening. The
  0.10.1 hotfix
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
  The 0.11.1 field-validation release is the first intended production exercise
  of that built-in upgrade path. Certificate Automation ships explicitly as a
  Beta workflow: its encrypted local storage and guarded enrollment mechanics are
  covered by automated tests, but operators must validate issuance, pending
  collection, renewal, exports, the complete chain, and target RADIUS behavior
  end to end before deployment. The release also adds optional high-capacity
  fping rounds, shared bounded IPv4-range entry, and reusable UI consistency
  improvements without making fping an installation requirement. Production
  validation successfully exercised v0.11.0-to-v0.11.1 discovery and installation,
  recovery-point creation, service and audit/status checks, rollback to the matched
  v0.11.0 state, and the return to v0.11.1.
  The 0.12.0 feature release adds a separate owner-only transient live-session
  store without changing existing application databases, profiles, or
  configuration. Live Ping and SNMP sessions continue through page navigation;
  SNMP session records contain profile references and samples rather than
  credentials. Wake-on-LAN sends are bounded and report local delivery separately
  from optional remote ping confirmation because routed forwarding remains an
  environmental responsibility.
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
- `templates/components/ui.html` is the source of truth for workspace
  introductions, section headers, standalone empty states, profile sections,
  profile create controls, saved profile cards, and action rows. Import those
  macros instead of reproducing their HTML structure in a tool template.
- Show one clear primary action per task context. Separate destructive actions,
  require confirmation proportional to impact, and never rely on color alone to
  communicate risk or status.
- Primary actions use the shared calm-green `--action-primary` tokens. Red is
  reserved for destructive `.danger` actions and error/risk communication; do
  not add page-specific button colors.
- Action labels use sentence case while preserving acronyms and product names.
  Keep field guidance in one place instead of repeating it in both placeholders
  and helper text.
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
  `.section-actions` area, normally at the top right on wide screens. Use the
  `section_header` call block so the wrapper and responsive behavior are shared.
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
- Saved-record actions use `.button-row`. When independent forms require the
  actions to sit outside the edit form, add the shared `.profile-form-actions`
  modifier so padding, spacing, and child-form margins remain consistent. Do not
  create a tool-specific action-row wrapper.

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
- A boot-managed launcher is a long-lived shell and retains the functions it
  parsed before an upgrade. The installer sets
  `TWN_TOOLKIT_RELOAD_SERVICE_LAUNCHER=1`; during an active upgrade it must start
  a validation-only process set without clearing the managed pause. The updater
  writes its terminal status and audit record, removes staged inputs, and
  removes `operation.lock` last. Only then may a deferred helper stop the
  validation set and clear the pause so systemd/launchd reloads the finalized
  on-disk script. Never reload earlier: systemd `KillMode=mixed` and equivalent
  job cleanup can terminate the detached updater before finalization. Suppress
  startup-generation recording for the validation start so the final managed
  start emits exactly one startup event. When rollback restores the launcher's
  original version, restore the launcher PID and let it adopt the validated
  process set. Ordinary `./twn restart` still uses the lighter pause/resume path,
  and a manual installer outside an active upgrade reloads synchronously.
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

- The SNMP Tester includes a persistent multi-interface monitor built from
  existing saved SNMP credential and host profiles. It is part of the existing
  `network.snmp` tool and does not create another permission or persistence
  surface.
- `snmp_tools.discover_snmp_interfaces()` walks standard IF-MIB name,
  description, alias, status, type, and speed columns. Interface sampling prefers
  64-bit `ifHCInOctets`/`ifHCOutOctets`, falls back to 32-bit counters, preserves
  Counter64 values as decimal strings for JavaScript `BigInt`, and returns
  uptime/discontinuity/error/discard data for safe re-baselining and diagnostics.
- The worker can monitor up to 20 interfaces across multiple saved hosts.
  `LiveToolRunner` resolves saved host and credential profiles at poll time,
  polls the bounded set concurrently, and isolates per-interface failures.
  Live-session configuration stores profile names and interface metadata, never
  communities or SNMPv3 keys. Discovery and sampling increment raw SNMP poll
  metrics but suppress high-frequency audit events. Explicit start, interval
  update, and stop boundaries are recorded in activity/audit history.
- Raw counter samples are capped at 100,000 rows per session in
  `live_tools.sqlite3`; the restored browser derives rates and retains at most
  10,000 calculated points per interface. Polling intervals are 1, 5, 10, 15,
  30, or 60 seconds and may be changed while running without clearing history.
  A five-minute browser lease and 24-hour stopped-session cleanup match persistent
  Multi-Host Ping.
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
  `live_tools.py`,
  `templates/tools/snmp_test.html`, `static/snmp-interface-monitor.js`, the shared
  SNMP monitor styles in `static/styles.css`, and `tests/test_snmp_tools.py`.

## Automation architecture

- Reusable schedules, conditions, and actions are separate first-class records.
  An automation chooses a manual, startup, condition, or schedule run mode; condition
  mode combines up to ten definitions with explicit ALL/ANY semantics; every
  mode connects to one or more staged actions and state policy. Conditions
  observe, schedules provide calendar timing, the automation state machine
  decides when to fire, and actions respond.
- Do not run monitoring loops inside Flask or Gunicorn workers. `./twn` manages
  one separate `twn_toolkit.automation_worker` process beside the web service.
- `instance/automations.sqlite3` stores definitions, scheduler state, checks,
  runs, and retained outputs. SSH action definitions are encrypted at rest with
  a key derived from the installation session secret.
- Current states are disabled, healthy, suspect, triggered, recovering, and
  error. A triggered automation fires once and must recover/rearm before it can
  fire again.
- Registered condition types are `ping.multi`, `dns.lookup`,
  `dns.performance`, `tcp.reachability`, `snmp.value`, and
  `certificate.health`; `manual.trigger`, `schedule.calendar`, and
  `system.startup` use the event-source layer. Registered action types
  are `ssh.collect`, `sftp.fetch`, `syslog.send`, `webhook.send`, `email.send`,
  and `packet.capture`. Manual and Startup automations are excluded from
  due-check claims; Manual exposes Run now, while Startup exposes Arm/Pause and
  a baseline-preserving Test now. Reusable Calendar schedules are handled by
  the scheduler adapter because occurrence consumption differs from monitoring state. Future
  types should register through `twn_toolkit/automation_types/` without adding
  type-specific branches to routes, persistence, or the scheduler.
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
- A Calendar schedule contains up to 50 reusable sub-rules. It
  supports one-time, daily, selected-weekday, every-N-weeks, monthly-date, and
  ordinal-weekday rules in an explicit IANA timezone. Simultaneous sub-rules
  collapse into one occurrence. Each referencing automation tracks its own next
  occurrence and applies run-late, grace-period, or skip missed-run policy.
- Condition and schedule claims use durable SQLite rows with renewable leases.
  A competing scheduler cannot run the same claimed work concurrently; an
  abandoned claim becomes recoverable after lease expiry. After consumption,
  recurring schedules advance directly to a future occurrence rather than
  replaying a downtime backlog.
- `system.startup` records either the host boot generation or the complete
  toolkit-start generation in `automation_event_state`. Arming baselines the
  current generation. A new event updates that row and creates its durable job
  in one transaction, so scheduler restarts cannot duplicate it. The launcher
  writes `instance/twn-toolkit-start.json` only after a stopped web service has
  become live and before starting the scheduler; never rewrite it during a
  scheduler-only restart or a redundant `./twn start`. Startup dispatch waits
  up to 120 seconds for a usable non-loopback address, then runs even without
  one. Internal generation IDs must not be exposed in notification evidence.
- `system_identity.py` owns bounded instance name, hostname, version, address,
  access-URL, and resolved-timezone discovery. `time_settings.py` stores an
  optional IANA override separately from the operating-system clock; blank means
  follow the host timezone. Webhook, Email, and Syslog share one explicit
  replacement map for `toolkit.*`, `startup.*`, and timestamp variables.
  Preserve UTC storage and the legacy `{{timestamp}}`/
  `{{startup.occurred_at}}` values. Localized ISO/display variables resolve the
  timezone at action execution so a saved setting applies without rewriting
  definitions or restarting workers. New schedules may default to the toolkit
  timezone, but every saved schedule keeps its own explicit timezone.
- `dns.lookup` reuses the regular DNS tool's concurrent query engine. Each
  hostname/resolver pair is one check. An optional global expected-answer set
  can require any or all values; comparisons ignore case and a final DNS dot.
  Availability, answer mismatch, and the configured failed-check threshold are
  represented in the common condition result contract.
- General host-list fields use `network_tools.parse_ping_targets` (or its DNS
  and SSH aliases) as the shared parsing boundary. In addition to hostnames and
  individual addresses, it accepts inclusive ascending IPv4 and IPv6 ranges
  such as `10.0.0.1-10.0.0.24`. A named range such as
  `Classroom = 10.0.0.1-10.0.0.24` expands to stable labels beginning with
  `Classroom-0001`. Expanded addresses count against the caller's existing
  limit. Keep structured destination formats such as `host | ports` on their
  dedicated parser rather than applying general range expansion implicitly.
- Multi-Host Ping capability is determined by
  `network_tools.ping_engine_capability`, which runs and caches a real localhost
  ICMP probe. A working optional `fping` command enables one bounded batch
  subprocess per round and a 250-target limit. Missing or unusable `fping`
  retains the 20-worker system-`ping` compatibility engine and its 100-target
  limit. Do not auto-install OS packages or invoke privilege escalation from
  the web application or installer. Persistent rounds are claimed and executed
  by `automation_worker` through `LiveToolStore`/`LiveToolRunner`; Gunicorn
  workers only create, inspect, update, and stop user-owned sessions in
  `instance/live_tools.sqlite3`. A five-minute lease is renewed by the global
  Live tools footer dock or a restored Ping/SNMP page, so closing the toolkit
  eventually stops abandoned polling. Per-session raw server history is capped
  at 100,000 samples and stopped sessions are removed after 24 hours. Rounds never overlap;
  the browser reports actual duration when it exceeds the configured cadence.
  Restored browser history keeps
  ten minutes of raw samples and one hour of ten-second buckets before using
  minute buckets; a 500,000-sample global budget is divided across active
  targets so long-running high-capacity sessions remain memory-bounded.
  Multi-Ping keeps round interval separate from probe timeout. Accelerated mode
  accepts 0.1–10 second timeouts; compatibility mode accepts 1–10 seconds because
  portable system `ping` timeout flags do not reliably support sub-second values.
  Existing saved profiles without a timeout load with the one-second default.
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
  continuation policy (`all_completed`, `success_or_partial`, `all_success`,
  `any_failed`, or `all_failed`).
  Every stage after the first may define `delay_seconds` from 0 through 86400.
  Evaluate continuation before scheduling the next delay. A delay must persist
  encrypted progress in `automation_jobs`, move the job to `waiting`, release
  its worker/lease, and resume through normal claiming; do not sleep inside a
  scheduler worker for a stage delay. Waiting progress survives restart.
  Existing flat action lists migrate to one default parallel stage. Later stages
  receive bounded, non-secret earlier-action context; raw SSH output is never
  injected automatically.
- `automation_schema_migrations` is the numbered migration ledger. Version 1
  adds `action_stages`; version 2 persists first-generation SNMP definitions as
  per-host AND rules and pauses dependents; version 3 adds retention; version 4
  adds durable action jobs; version 5 adds ALL/ANY condition groups; version 6
  adds encrypted delayed-stage progress; version 7 adds durable startup-event
  deduplication state. Use this runner—not new ad-hoc column checks—for future
  material schema changes. Toolkit migrations 2 and 3 perform pre-change
  database snapshots and prepare the corresponding automation schema. The
  internal runner remains the fresh-database and compatibility fallback.
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
- Both SSH surfaces accept `Friendly Name = hostname-or-IP` and shared inclusive
  IP ranges. Preserve the connection target as `host` and the optional display
  value as `host_label` in execution results. UI output and filenames prefer the
  label but still expose the actual address.
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
  replacement. Delivery validates success statuses and supports 1–5 attempts
  with bounded exponential backoff for network errors and explicitly selected
  HTTP statuses. Preserve the one-attempt default to avoid surprise duplicate
  notifications, retain per-attempt outcomes, and keep the same job-derived
  `Idempotency-Key` across attempts. Never retain request headers, and retain at
  most 4 KiB of each response body.
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
