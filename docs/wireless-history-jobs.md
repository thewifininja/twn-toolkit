# Background FortiGate wireless history

Find Wireless Client History queues a read-only lookup and immediately redirects
to its result link. The automation scheduler runs the appliance requests in an
isolated process. Navigation stays available during log pagination, live-client
lookup, or a stalled appliance. Recent runs, cancellation, and manual refresh
without JavaScript use the same finite-job system as TCP, DNS, and Bulk Transfer.

Settings → Operations controls the shared worker count, queue/per-user limits,
whole-run deadline (default 300 seconds), and retained history (default 24 hours).
The executing Agent applies its own settings; the Mainframe tunnel submits and
reads results. The deadline covers subprocess startup, resolution, HTTP work,
formatting, and publication. Waiting in the queue is separate. A cancelled,
expired, or interrupted worker is not automatically replayed. Restart recovery
marks unconfirmed work unknown. Start another lookup explicitly if needed.

The run snapshots the selected profile, API key, MAC, VDOM, time window, submitting
user, and recording case. Later profile edits do not redirect already queued
requests to a different appliance. Cancel and resubmit to use a changed profile.
Configuration and results are encrypted with the existing instance key; only the
owner with wireless-history tool permission can read or cancel the run. API keys
are never sent to the result page. Preserve the instance key during upgrades.

## Results and limits

Completed requests can have succeeded, incomplete (one source failed), or failed
(both sources failed) lookup outcomes. The result page and case record distinguish
these outcomes; a source error does not prove absence of client activity. The
underlying job is terminal `succeeded` when result collection/publication finished,
even when those published results describe source failures.

The page shows 100 collapsed AP transitions at a time and the AP path for that
page. Counts refer to the full run. Existing diagnostic storage limits allow up
to 5,000 transitions and 8 MiB of serialized results; exceeding either fails the
run with a shorter-time-window suggestion and retains no partial timeline. The
existing FortiGate HTTP request/page/row/byte budgets also remain in effect.

Only display fields are retained, without raw vendor event payloads or internal
datetime objects. Text fields are capped at 512 characters, event details at
2,000, and the live-client summary at 100 matching entries. The page explicitly
reports clipping/omitted live entries. The case keeps the first 500 transitions
with an omitted count and full-run metrics, matching its bounded report purpose;
normal job pages provide the retained timeline until job history expires.

Case attribution stays with the case recording at submission. Reloading results
or changing the user's active case does not rerun the lookup or append another
result. A failure to record activity/audit/case metadata does not replay requests.
As with existing finite diagnostics, crashes during secondary attribution can
leave a completed result without a case notice; this is not an exactly-once
transaction across the separate stores.

## Deployment and acceptance

Update web and automation workers together on each executing instance. Older
workers do not understand this new job type; a heartbeat alone does not establish
version compatibility. No distributed protocol or privileged-helper changes are
needed. Other FortiGate/FortiAuthenticator operations remain separate workflows.

Verify local and Agent-tunnel submission, navigation while an appliance is slow,
status polling/manual refresh, cancellation, paged AP paths, partial-source error
messages, and case attribution. Use a disposable instance for fault injection.
