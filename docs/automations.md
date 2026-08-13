# Automations

Reusable schedules describe calendar timing, reusable conditions describe
health observations, and reusable actions describe trusted responses.
Automations choose one plain-language run mode—condition, schedule, startup,
or manual—and connect it to an action pipeline with state policy. A single
definition can be referenced by multiple automations. They
continue running without an open browser because
`./twn start` launches a single scheduler process beside the Gunicorn web
service.

The web interface keeps these responsibilities on separate pages under the
**Automation** sidebar group: **Schedules** for reusable calendars,
**Conditions** for health observations and tests, **Actions** for responses,
and **Automations** for run mode, policy, pipelines, scheduler state, checks,
and retained runs. Manual and startup modes are selected directly on an
automation and do not require a user-managed reusable definition. Existing
manual and calendar source IDs remain valid; the storage compatibility layer
does not rewrite saved automations.

Condition-mode automations can select up to 10 reusable conditions and combine
them with one explicit operator:

- **ALL** is met only when every selected condition is met in the same
  automation check.
- **ANY** is met when one or more selected conditions are met.

The scheduler evaluates every selected condition inside one claimed worker
task, persists one combined observation, and applies debounce, recovery, and
cooldown to that combined result. Evidence retains each member's name, type,
status, summary, and complete type-specific evidence. A member evaluation
error fails the whole automation check into the existing error state instead
of silently treating the member as clear. Existing single-condition
automations load as one-member ALL groups without rewriting their saved rows.

## Calendar schedules

A reusable Calendar schedule can contain up to 50 independent rules,
so one schedule can describe an intentionally complicated operating calendar
without creating a matching pile of conditions and automations. Rules support:

- a one-time local date and time;
- every day at a selected time;
- selected weekdays at a selected time;
- every N weeks on a weekday, anchored to a selected date;
- a day of each month; and
- an ordinal weekday of each month, such as the third Wednesday.

Each schedule has an explicit IANA timezone and a missed-run policy: run late,
run only within a configurable grace period, or skip. Daylight-saving gaps move
to the first valid local minute, and repeated fallback times run once. Multiple
rules that resolve to the same instant are collapsed into one occurrence.

Schedules are reusable definitions, but every automation referencing
one consumes occurrences independently. Scheduled automations bypass the
monitoring debounce, recovery, and cooldown state cycle. A claimed occurrence
is leased in SQLite so scheduler restarts can retry it without two scheduler
processes firing it simultaneously. Stale recurring schedules advance directly
to the next future occurrence rather than replaying a backlog.

## Startup events and system identity

Startup mode provides two event scopes:

- **Once per host boot** is recommended for appliances and Raspberry Pis. It
  fires once after a new operating-system boot and ignores ordinary toolkit,
  scheduler, and worker restarts.
- **Every toolkit start** fires after each complete stopped-to-running toolkit
  transition. Restarting only the scheduler does not create a toolkit-start
  event.

Arming stores the current event generation as a baseline; it does not run the
automation immediately. The next generation and its durable execution job are
committed in one SQLite transaction. This prevents two schedulers or a crash
and restart from sending the same startup event twice. **Test now** queues a
normal startup-shaped test job without advancing that baseline.

At event time, the scheduler waits up to 120 seconds for a usable non-loopback
IPv4 or IPv6 address. It dispatches as soon as an address is available and
still dispatches after the bound if networking remains unavailable. This keeps
a DHCP failure from silently suppressing the notification it was meant to
provide.

Startup evidence contains bounded, non-secret toolkit identity. Webhook, Email,
and Syslog templates can use:

- `{{toolkit.instance_name}}`, `{{toolkit.hostname}}`, and
  `{{toolkit.version}}`;
- `{{toolkit.primary_ipv4}}`, `{{toolkit.ipv4_addresses}}`, and
  `{{toolkit.ipv6_addresses}}`;
- `{{toolkit.primary_url}}` and `{{toolkit.urls}}`; and
- `{{startup.reason}}`, `{{startup.mode}}`, and
  `{{startup.occurred_at}}`.

Exact JSON tokens for address and URL lists remain arrays. Text and embedded
JSON substitutions render those lists as compact JSON text. Internal boot and
toolkit generation identifiers are deliberately omitted from action evidence.

## First supported vertical slice

- Condition: multi-host Ping health with reachability plus optional packet
  loss, average latency, and jitter limits. Each evaluation can take 1–10
  probes per target before applying a degraded-target threshold. The working
  accelerated `fping` engine permits 0.1–10 second per-target timeouts; the
  compatibility engine permits 1–10 seconds. Existing `ping.multi` definitions
  remain compatible.
- Condition: DNS lookup health across a hostname-by-resolver matrix. A, AAAA,
  CNAME, MX, NS, PTR, and TXT records can require any successful answer or
  compare returned values against an expected set. Thresholds can trigger when
  one, several, or every query path fails or returns an unexpected answer.
- Condition: DNS performance across the same hostname-by-resolver matrix,
  triggering when one, several, or every query path fails or exceeds a selected
  response-time limit.
- Condition: TCP service state with a custom port list per host. Ports and
  inclusive ranges are supported, and a check can require an open service or a
  definitive connection refusal. Timeouts remain failures rather than being
  mistaken for proof that a port is closed. Legacy definitions with one global
  port list are normalized by applying that list to each saved host.
- Condition: SNMP OID rules evaluated with AND logic independently on every
  selected host, followed by a host-count threshold. OID profiles can expose
  safe calculated scalar values for percentage, remaining percentage,
  difference, and sum operations.
- Condition: multi-target TLS certificate health with expiration, hostname,
  system-trust, chain-order, likely-missing-intermediate, and connectivity
  policy.
- Run mode: Manual for explicitly started, on-demand automations. Manual
  automations are never claimed by the scheduler.
- Run mode: Startup for once-per-host-boot or every-complete-toolkit-start
  execution with durable deduplication and bounded network readiness.
- Check intervals: 1 second through 24 hours. The scheduler polls due work four
  times per second and anchors each next deadline to the prior cadence rather
  than completion time. A condition round never overlaps another round for the
  same automation. If a timeout crosses the next deadline, the waiting round
  starts promptly after completion without being claimed and discarded; long
  pauses resume from the current time instead of replaying a backlog. Check
  history uses the round's observation-start time, so a timeout remains
  attributed to the second in which its probes began.
- Per-condition thresholds: all targets breach policy, or at least a selected
  number breach policy.
- General ping, DNS-name, and SSH-file-collection host lists accept
  inclusive ascending IPv4 and IPv6 ranges. Named ranges use
  `Friendly Name = start-address-end-address` and normalize to numbered labels
  such as `Friendly Name-0001`; every expanded address counts toward the
  condition or action's host limit.
- Debounce: require consecutive met checks before firing.
- Recovery: require consecutive clear checks before rearming.
- Cooldown: minimum interval between incident triggers.
- Action: render a command template against a target matrix of up to 5,000 SSH
  hosts. Fixed Name and Host columns plus operator-defined variable columns use
  the same `{{ variable }}` substitution as Bulk SSH. A Stored Commandlet can
  populate the action editor, but the action saves a snapshot rather than a
  live reference. Fleet execution submits batches of 50 with no more than 10
  simultaneous SSH connections and a bounded aggregate output budget. Commands
  use a 300-second default ceiling and complete as soon as the original device
  prompt returns. Prefix an individual command with `[timeout=600]` when it
  needs a different ceiling; accepted values are 1 through 3600 seconds. The
  combined timeout budget across commands is limited to one hour per host.
- Action: send an RFC 5424 syslog message to up to 20 UDP or TCP collectors.
  Facility, severity, hostname, application name, timeout, and destination ports
  are configurable. Messages support the documented trigger, toolkit, startup,
  and timestamp variables. Each collector records its own success/error result,
  so a partial delivery remains visible.
- Action: send a POST, PUT, or PATCH Webhook/API notification to up to 10
  endpoints. Headers are encrypted/write-only, accepted HTTP statuses and TLS
  verification are explicit, redirects are not followed, and retained response
  previews are capped at 4 KiB per endpoint. Each endpoint records its delivery
  attempts. Optional exponential-backoff retries can cover network errors and
  selected HTTP statuses; one attempt remains the default to avoid surprising
  duplicate notifications. JSON templates preserve typed boolean/object
  substitutions for trigger state and evidence.
- Action: send a plain-text email notification through the installation-wide
  SMTP service configured under Administration → System Settings → Email.
  To, Cc, Bcc, subject, and message templates support trigger and prior-action
  metadata. Messages never include file or PCAP attachments, and retained run
  output contains delivery status, subject, and message ID without retaining
  the rendered body.

Administration → System Settings → System controls the toolkit timezone used by
localized notification variables. Leave it blank to follow the host timezone or
save an IANA name such as `America/New_York`; the setting does not change the
operating-system clock and applies without a restart. `{{timestamp.local}}`
produces an ISO timestamp with the applicable UTC offset,
`{{timestamp.display}}` produces a human-readable value with the timezone
abbreviation, and `{{toolkit.timezone}}` exposes the resolved IANA name. Startup
notifications have matching `{{startup.occurred_at_local}}` and
`{{startup.occurred_at_display}}` variables. Existing `{{timestamp}}` and
`{{startup.occurred_at}}` values remain UTC for compatibility; new webhook and
email templates prefer the localized variables, while saved templates are never
rewritten during upgrade. New calendar schedules default to the toolkit timezone
but retain their own explicit timezone after they are saved.
- Action: fetch regular files concurrently from named hosts over SFTP, SCP, or
  FTP. Results can be written beneath a selected datastore folder (optionally
  grouped per host) or retained as bounded run artifacts for ZIP download.
  Collision-safe token filenames and per-host/per-path outcomes are preserved
  for both successful and partial runs.
- Action: capture a bounded PCAP from a local or SPAN-connected interface using
  the shared Packet Capture engine. Interface, BPF filter, duration, packet
  count, file-size ceiling, snapshot length, and promiscuous mode are explicit.
  The completed PCAP can be retained with the run for ZIP download or saved
  directly beneath a selected Local Datastore folder. Filename patterns support
  `{timestamp}`, `{action}`, and `{interface}` tokens; duplicate names receive
  a numeric suffix and never overwrite an existing capture.
- History: retain condition checks, triggers, per-host command output, and
  action status in `instance/automations.sqlite3`.
- Downloads: each action run can be downloaded as a ZIP containing JSON run
  metadata and one text file per SSH host. Host filenames begin with the run's
  sortable local timestamp, such as `20260710172428-Core-Switch.txt` or
  `20260710172428-10.0.0.12.txt`. Syslog, webhook, and email runs include
  per-target delivery result JSON.
- Capture: retain at most 5 MiB per host. A timed-out command keeps its partial
  output, identifies the command and timeout, and stops later commands on that
  host while other hosts continue. Long browser previews are shortened without
  changing the complete retained ZIP output.
- Cleanup: delete a single collected run or clear all collected action runs for
  an automation without deleting its condition-check history. Global retention
  is managed in Administration → System Settings → Operations. Check history defaults to 7 days;
  collected action runs default to indefinite retention. Setting either policy
  to 0 disables automatic deletion for that record type.

New schedule, condition, and action implementations register through
`automation_registry.py`. The scheduler and state machine do not need
tool-specific branches when a new registered type follows the common result
contracts.

Condition registrations live under `automation_types/condition_types/` and are
grouped into network, SNMP, and certificate domains. Manual and calendar
sources have a distinct internal event-source registry. The compatibility facade
remains `automation_types/conditions.py`. Condition result rendering is
kept in `_condition_evidence.html`, while dynamic SNMP rule editing is isolated
in `automation-snmp.js` instead of expanding the shared automation script.

Every persisted evaluation includes a versioned `evidence.evaluation` envelope
with its source `kind` (`condition`, `schedule`, or `manual`), registered type,
schema version, and observation timestamp. Type-specific evidence remains alongside
that envelope for compatibility and readable diagnostics. Execution and
prior-action metadata are added separately when an action job runs.

## Action pipelines

Each automation contains one or more user-defined stages. Actions within a
stage run concurrently, while stages run sequentially from top to bottom. A
new or legacy automation starts with one default stage containing all selected
actions, preserving the original parallel behavior. Stages have stable IDs,
editable names, ordering controls, and one of five continuation policies:

- continue after every action completes, regardless of result;
- continue only when every result is success or partial;
- continue only when every result is success;
- continue when one or more actions report an error; or
- continue only when every action reports an error.

An action-level `partial` result is distinct from an error: it means the action
completed some of its work, such as delivering to two of three endpoints. The
full-success policy stops on partial results, while the success-or-partial
policy accepts them. Failure routes react to action errors, including uncaught
execution exceptions. A common fallback pipeline tries a Discord webhook in
one stage and sends email in the next stage only if Discord reports an error.

Every stage after the first may also wait from zero seconds through 24 hours
before it starts. The continuation policy is evaluated first, so a stage that
is not eligible does not wait. Delays are durable queue state rather than a
sleeping worker: completed-stage results are encrypted, the worker is released,
and the pipeline resumes after its due time even if the toolkit restarts.

Later actions receive a bounded prior-action context. Webhook templates can use
`{{actions.results}}`, `{{actions.successful}}`, `{{actions.partial}}`, and
`{{actions.failed}}`. The context includes status, summary, stage/action
identity, and small structured target summaries. It deliberately excludes raw
SSH command output, secrets, and unbounded payloads. Full captures remain in
retained runs and ZIP downloads.

Pipeline and startup-source structure participate in encrypted profile
backup/restore. Database schema changes are recorded in
`automation_schema_migrations`; migration 1
adds ordered stages and converts existing action lists into a single default
parallel stage transactionally. Migration 2 converts the first SNMP condition
format into persisted per-host AND rules and pauses dependent automations for
review. Migration 3 adds the global retention policy and daily-pruning ledger.
Migration 4 adds the durable action-execution queue. Migration 5 adds ALL/ANY
condition groups. Migration 6 adds encrypted in-progress pipeline state for
durable delayed stages. Migration 7 adds per-automation startup-event
deduplication state. Toolkit migrations 2 and 3 snapshot existing SQLite
databases before preparing those schema changes.

## Durable execution

When a condition reaches its trigger threshold, the state transition and an
action-execution job are written in one SQLite transaction. Calendar
occurrences similarly advance only when their execution job is safely queued.
Each job contains an encrypted snapshot of the action pipeline, so later edits
cannot silently change work that has already been triggered.

The scheduler claims jobs with time-limited leases and renews those leases
while actions run. If the process exits, another scheduler can reclaim the job
after its lease expires. Infrastructure failures use bounded exponential
backoff and become visibly failed after three attempts; an administrator can
requeue failed jobs from the Automations page. The page also reports queued,
waiting, and running counts and the age of the oldest unfinished job. A job in
the waiting state is intentionally idle until its next stage is due and does
not consume an automation worker.

Execution is deliberately **at least once**. A process can complete an external
action and exit before recording that stage's progress, so actions in that
stage may be repeated after recovery. Once stage progress is recorded, an
ordinary restart resumes at the next eligible stage instead of replaying prior
stages. Every retry retains the same execution job ID in
`trigger.evidence.execution.job_id`; templates can use `{{trigger.job_id}}`.
Webhook actions automatically send that ID in the `Idempotency-Key` header
unless the action defines its own header, allowing compatible receivers to
deduplicate retries. Webhook delivery also validates configured success
statuses and can retry network failures or selected response statuses up to
five times with bounded exponential backoff. Run history retains per-endpoint
attempts plus the scheduled and queued timestamps and execution attempt number.

## State model

An armed automation moves through these states:

1. `healthy`: its trigger condition is clear.
2. `suspect`: the condition is met but has not reached its consecutive-check
   threshold.
3. `triggered`: the threshold was reached and actions were queued once.
4. `recovering`: the condition is clear again but has not reached its recovery
   threshold.
5. `healthy`: recovery completed and the automation can trigger again after
   its cooldown.

An evaluation error produces the separate `error` state; it does not count as
a met network condition.

Automations using Manual or Startup mode do not use this monitoring state cycle.
The Manual card exposes `Run now`, and each explicit execution is
stored as a normal downloadable action run.

Startup cards expose `Arm`/`Pause` plus `Test now`. Arming waits for the next
configured event; testing executes the action immediately with current system
identity and does not consume the next real startup.

## Security and backups

Automation administration is initially system-administrator-only. SSH action configuration
is encrypted at rest with a key derived from the installation's private
`instance/session_secret`. Passwords are never rendered back into the page.

Automation definitions participate in profile backup and restore. Because the
definitions can contain credentials, selecting them makes backup encryption
mandatory. Runtime check history and captured SSH output are intentionally not
included in backups. Imported automations are paused.

The scheduler checks the retention policy hourly and performs pruning at most
once per day. Settings previews the currently eligible check/run counts before
manual pruning. Database optimization is a separate manual operation because
SQLite compaction can briefly pause writers; ordinary pruning does not run
`VACUUM`. Runtime check history, retained output, and the local retention policy
are intentionally not included in profile backups.

Editing a reusable condition or action pauses every automation that references
it. Definitions cannot be deleted while an automation still references them.

The first implementation does not provide an arbitrary local-shell action or
runtime-loaded Python extensions. Conditions and actions are trusted internal
registrations.

## Operations

```bash
./twn start
./twn status
./twn logs
./twn stop
```

`status` reports the web service and scheduler separately. `logs` includes the
scheduler log from `instance/twn-automation.log`.

The current scheduler uses one process with atomic due-check and execution-job
claiming in SQLite. Its heartbeat separates active condition checks from active
action jobs. Web workers only configure and display automations; they do not
run monitoring loops. Manual and startup-test runs are first written to the
same durable queue, then claimed and executed synchronously so the browser
still receives the completed run.

## Planned extensions

- HTTP response health, NTP health, and syslog-pattern condition types.
- Broader per-action retry policies beyond Webhook/API delivery.
- Explicit production and out-of-band source-interface binding.
- Optional repeated collection during a long-lived incident.
- Granular permissions for viewing, arming, editing, and downloading output.
