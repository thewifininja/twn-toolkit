# Automations

Reusable conditions describe observations, reusable actions describe trusted
responses, and automations connect them with scheduling and state policy. A
single condition or action can be referenced by multiple automations. They
continue running without an open browser because
`./twn start` launches a single scheduler process beside the Gunicorn web
service.

## First supported vertical slice

- Condition: multi-host ICMP reachability.
- Condition: reusable manual trigger for explicitly started, on-demand
  automations. Manual conditions are never claimed by the scheduler.
- Check intervals: 1 second through 24 hours. The scheduler polls due work four
  times per second so one-second checks are not held behind a one-second polling
  boundary; actual duration still includes the condition execution time.
- Trigger modes: all targets fail, or at least a selected number fail.
- Debounce: require consecutive met checks before firing.
- Recovery: require consecutive clear checks before rearming.
- Cooldown: minimum interval between incident triggers.
- Action: run a command set on up to 50 SSH targets concurrently.
- History: retain condition checks, triggers, per-host command output, and
  action status in `instance/automations.sqlite3`.
- Downloads: each action run can be downloaded as a ZIP containing JSON run
  metadata and one text file per SSH host. Host filenames begin with the run's
  sortable local timestamp, such as `20260710172428-Core-Switch.txt` or
  `20260710172428-10.0.0.12.txt`.
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

- DNS, TCP, HTTP/API, SNMP, certificate, syslog-pattern, schedule, and manual
  condition types.
- Explicit action ordering and retry/continue policies for multi-action plans.
- Explicit production and out-of-band source-interface binding.
- Optional repeated collection during a long-lived incident.
- Retention and disk-quota policy for checks and action artifacts.
- Granular permissions for viewing, arming, editing, and downloading output.
- Multiple conditions with `ALL`/`ANY` grouping after the single-condition
  workflow is proven.
