# Background network diagnostics

TCP scan, DNS comparison, and DNS load-test submissions validate input, persist a run and redirect (HTTP 303) to a
stable result URL. The HTTP request does not perform the network test. The result page
shows queued/running/cancellation-requested and terminal states, refreshes status
with short requests, and works without JavaScript through manual refresh.
Navigation away does not stop a scan or submit another copy. Recent runs and
100-row result pages remain available locally and through an Agent.

## Execution and rollout

The existing automation scheduler supervises finite diagnostic subprocesses.
It maintains a separate bounded diagnostic pool; automation and live-tool
execution pools retain their existing limits. TCP scanning, DNS comparisons and
DNS load tests and [Bulk Transfer](background-transfers.md) use this queue. Other synchronous routes remain separate migration work.

Restart the automation scheduler and web workers on each instance that runs
scans after updating. On an Agent, its local scheduler performs the scan; the
Mainframe tunnel only submits and reads results. No distributed protocol change
is required. If the scheduler is stopped or still running older code, requests
remain queued and the page reports missing heartbeat when applicable. An older
worker may still publish a heartbeat without understanding this queue: complete
the worker restart as part of the update.

The scheduler admits only as many subprocesses as the configured diagnostic
worker count. There is no unbounded executor backlog. Claims are atomic across
processes; the existing automation singleton lock owns scheduling. A token
delivered through the child's standard input identifies each claim. Tokens do
not appear in command arguments or browser responses.

The subprocess has an independent monotonic deadline and parent-death watcher.
The scheduler also enforces deadlines, requests termination for cancellation,
and kills a process that does not exit within two seconds. A queued cancellation
prevents execution. A running cancellation remains requested until exit is
confirmed. Deadlines include subprocess startup and result publication;
incomplete scan results are discarded. These guarantees apply to TCP scanning and DNS comparisons/load tests,
whose processes own their resolution and probe threads; they are not a general
promise of safe cancellation for arbitrary side-effecting tools.

On scheduler shutdown, children are terminated and reaped with one shared
two-second grace period. Unconfirmed work becomes unknown and is not replayed.
On restart, previously running claims are fenced and surfaced as unknown.
Completed results retain ownership until the subprocess exits so retention or
the scheduler cannot interrupt case recording merely because results are ready.
If process creation or the ownership handoff fails, the scheduler reaps any
created child, records the failed run, and releases its retention claim. Failed
starts follow normal history limits without requiring a scheduler restart; they
are not automatically retried.

## Policy

Settings → Operations → Background diagnostic limits applies on the instance
where the diagnostic executes. TCP, DNS, and Bulk Transfer share this queue and its policy. Transfer artifact admission adds headroom for downloaded files and their ZIP/datastore copy.

| Setting | Default | Range |
| --- | --- | --- |
| Concurrent diagnostic runs | 2 | 1–8 |
| Queued diagnostic runs | 32 | 1–200 |
| Active diagnostic runs per user | 4 | 1–200 |
| Diagnostic deadline | 300 seconds | 5–3,600 seconds |
| Retained diagnostic runs | 128 | 1–10,000 |
| Diagnostic retention | 24 hours | 1–720 hours |

New submissions snapshot their deadline. Other policy changes apply on the next
scheduler/admission check. Lowering concurrency lets active children finish.
History is bounded by both age and count; older terminal results may be removed
to admit new work. Active or still-owned runs are not evicted. If they consume
the entire history capacity, submission fails clearly instead.

TCP input limits remain 50 hosts, 200 ports and 5,000 combinations, with at most
200 connection threads per scan. Raising diagnostic concurrency multiplies that
possible connection/thread demand; shared cross-tool/target budgets remain
future work. The internal result envelope is 5,000 rows / 8 MiB serialized data,
and inputs are at most 64 KiB. Results are encrypted per row and read by page.
These internal envelopes are distinct from operator-adjustable policy.

Admission checks configured minimum free disk space with 32 MiB of headroom for
each active diagnostic's input/result/encryption/journal allowance. This
coordinates admission within this queue, not reservations across every toolkit
writer. SQLite file size may retain freed pages after history cleanup.

## Attribution and limits

Status, results and cancellation require the corresponding tool permission and the
submitting user's identity. Configuration captures the user and actively
recording case at submission. Completion records against that case, even if the
user selects another case or pauses recording. Membership/closed-case rules are
still checked at recording time. Successful runs preserve activity counters and
case result details; cancellation/failure/interruption records the outcome.

Audit/activity/case recording spans separate stores and is best effort. A crash
or a case becoming unavailable can leave a durable run result without its
secondary recording; network work is never replayed to repair that. Validation
failures remain request-side audit/case events.

The diagnostic database is private runtime state and uses the instance secret
key to encrypt inputs and results. Back up the key with retained data.
This change does not complete all asynchronous tool migrations, cross-tool
connection/storage budgets, or large artifact transport.

## DNS workflow and rollout

Both DNS modes use the existing automation worker's diagnostic scheduler. Upgrade
and restart executing web and automation workers together before submitting DNS
jobs. Older workers do not support the new DNS job type. Keep Mainframe/Agent
versions aligned; this is not a version-negotiation fix.

Comparison results page in groups of 100, with statistics over the complete
matrix (up to 100 hosts × 20 resolvers). Load tests retain their existing consent,
duration/rate/concurrency/query limits and aggregate resolver metrics. Validation
runs before enqueue and again in the child, without sending preflight queries.
Saved host/resolver profiles remain available; each run captures the submitted
values so later profile edits cannot change queued work. Reloading a result URL
does not submit work; Run again is an explicit new submission.

Queue wait is separate from the captured process deadline. Diagnostic concurrency
limits simultaneous processes, not the combined DNS query rate across runs or
per-target socket admission. A cancelled/timed-out load test may already have
sent queries; it stops further process work and discards incomplete output. It
is never automatically replayed. Completed DNS results, like TCP results, are
subject to configured history retention and input/result envelope limits.

DNS and TCP use the same status panel and polling script. Recent history is
filtered by tool, and job pages/status/cancellation enforce both submitting user
and tool identity. Agent links retain the selected Agent prefix. Larger case
records and artifact transport remain separate audit work; paged HTML does not
claim to fix every large response.
