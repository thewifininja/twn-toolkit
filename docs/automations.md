# Automations

Reusable conditions describe observations, reusable actions describe trusted
responses, and automations connect them with scheduling and state policy. A
single condition or action can be referenced by multiple automations. They
continue running without an open browser because
`./twn start` launches a single scheduler process beside the Gunicorn web
service.

## Calendar schedules

A reusable Calendar schedule condition can contain up to 50 independent rules,
so one condition can describe an intentionally complicated operating calendar
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

Calendar conditions are reusable definitions, but every automation referencing
one consumes occurrences independently. Scheduled automations bypass the
monitoring debounce, recovery, and cooldown state cycle. A claimed occurrence
is leased in SQLite so scheduler restarts can retry it without two scheduler
processes firing it simultaneously. Stale recurring schedules advance directly
to the next future occurrence rather than replaying a backlog.

## First supported vertical slice

- Condition: multi-host ICMP reachability.
- Condition: DNS lookup health across a hostname-by-resolver matrix. A, AAAA,
  CNAME, MX, NS, PTR, and TXT records can require any successful answer or
  compare returned values against an expected set. Thresholds can trigger when
  one, several, or every query path fails or returns an unexpected answer.
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
- Condition: reusable manual trigger for explicitly started, on-demand
  automations. Manual conditions are never claimed by the scheduler.
- Check intervals: 1 second through 24 hours. The scheduler polls due work four
  times per second so one-second checks are not held behind a one-second polling
  boundary; actual duration still includes the condition execution time.
- Trigger modes: all targets fail, or at least a selected number fail.
- Debounce: require consecutive met checks before firing.
- Recovery: require consecutive clear checks before rearming.
- Cooldown: minimum interval between incident triggers.
- Action: run a command set on up to 50 SSH targets concurrently. Commands use
  a 300-second default ceiling and complete as soon as the original device
  prompt returns. Prefix an individual command with `[timeout=600]` when it
  needs a different ceiling; accepted values are 1 through 3600 seconds. The
  combined timeout budget across commands is limited to one hour per host.
  Targets may use `Friendly Name = hostname-or-IP`; the address is retained for
  troubleshooting while the friendly name is used in results and ZIP filenames.
- Action: send an RFC 5424 syslog message to up to 20 UDP or TCP collectors.
  Facility, severity, hostname, application name, timeout, and destination ports
  are configurable. Messages support the explicit variables
  `{{trigger.status}}`, `{{trigger.summary}}`, `{{trigger.met}}`, and
  `{{timestamp}}`. Each collector records its own success/error result, so a
  partial delivery remains visible.
- Action: send a POST, PUT, or PATCH Webhook/API notification to up to 10
  endpoints. Headers are encrypted/write-only, accepted HTTP statuses and TLS
  verification are explicit, redirects are not followed, and retained response
  previews are capped at 4 KiB per endpoint. JSON templates preserve typed
  boolean/object substitutions for trigger state and evidence.
- Action: fetch regular files concurrently from named hosts over SFTP, SCP, or
  FTP. Results can be written beneath a selected datastore folder (optionally
  grouped per host) or retained as bounded run artifacts for ZIP download.
  Collision-safe token filenames and per-host/per-path outcomes are preserved
  for both successful and partial runs.
- History: retain condition checks, triggers, per-host command output, and
  action status in `instance/automations.sqlite3`.
- Downloads: each action run can be downloaded as a ZIP containing JSON run
  metadata and one text file per SSH host. Host filenames begin with the run's
  sortable local timestamp, such as `20260710172428-Core-Switch.txt` or
  `20260710172428-10.0.0.12.txt`. Syslog and webhook runs include per-target
  result JSON.
- Capture: retain at most 5 MiB per host. A timed-out command keeps its partial
  output, identifies the command and timeout, and stops later commands on that
  host while other hosts continue. Long browser previews are shortened without
  changing the complete retained ZIP output.
- Cleanup: delete a single collected run or clear all collected action runs for
  an automation without deleting its condition-check history. Global retention
  is managed in Administration → Settings. Check history defaults to 7 days;
  collected action runs default to indefinite retention. Setting either policy
  to 0 disables automatic deletion for that record type.

New condition and action implementations register through
`automation_registry.py`. The scheduler and state machine do not need
tool-specific branches when a new registered type follows the common result
contracts.

Condition registrations live under `automation_types/condition_types/` and are
grouped into network, trigger, SNMP, and certificate domains. The compatibility
facade remains `automation_types/conditions.py`. Condition result rendering is
kept in `_condition_evidence.html`, while dynamic SNMP rule editing is isolated
in `automation-snmp.js` instead of expanding the shared automation script.

## Action pipelines

Each automation contains one or more user-defined stages. Actions within a
stage run concurrently, while stages run sequentially from top to bottom. A
new or legacy automation starts with one default stage containing all selected
actions, preserving the original parallel behavior. Stages have stable IDs,
editable names, ordering controls, and one of three continuation policies:

- continue after every action completes, regardless of result;
- continue only when every result is success or partial; or
- continue only when every result is success.

Later actions receive a bounded prior-action context. Webhook templates can use
`{{actions.results}}`, `{{actions.successful}}`, `{{actions.partial}}`, and
`{{actions.failed}}`. The context includes status, summary, stage/action
identity, and small structured target summaries. It deliberately excludes raw
SSH command output, secrets, and unbounded payloads. Full captures remain in
retained runs and ZIP downloads.

Pipeline structure participates in encrypted profile backup/restore. Database
schema changes are recorded in `automation_schema_migrations`; migration 1
adds ordered stages and converts existing action lists into a single default
parallel stage transactionally. Migration 2 converts the first SNMP condition
format into persisted per-host AND rules and pauses dependent automations for
review. Migration 3 adds the global retention policy and daily-pruning ledger.

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

Automations that reference a Manual trigger do not use this scheduled state
cycle. Their expanded card exposes `Run now`, and each explicit execution is
stored as a normal downloadable action run.

## Security and backups

Automation administration is initially administrator-only. SSH action configuration
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

The current scheduler uses one process with due-check claiming in SQLite. Web
workers only configure and display automations; they do not run monitoring
loops.

## Planned extensions

- HTTP response health, NTP health, and syslog-pattern condition types.
- Per-action retry policies and optional explicit retry backoff.
- Explicit production and out-of-band source-interface binding.
- Optional repeated collection during a long-lived incident.
- Granular permissions for viewing, arming, editing, and downloading output.
- Multiple conditions with `ALL`/`ANY` grouping after the single-condition
  workflow is proven.
