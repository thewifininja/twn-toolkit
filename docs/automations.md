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
  an automation without deleting its condition-check history.

New condition and action implementations register through
`automation_registry.py`. The scheduler and state machine do not need
tool-specific branches when a new registered type follows the common result
contracts.

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

- HTTP/API, SNMP, certificate, and syslog-pattern
  condition types.
- Explicit action ordering and retry/continue policies for multi-action plans.
- Explicit production and out-of-band source-interface binding.
- Optional repeated collection during a long-lived incident.
- Retention and disk-quota policy for checks and action artifacts.
- Granular permissions for viewing, arming, editing, and downloading output.
- Multiple conditions with `ALL`/`ANY` grouping after the single-condition
  workflow is proven.
