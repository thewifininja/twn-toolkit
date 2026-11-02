# Bulk Transfer: confirmed results and safe return paths

Scope: queue a fetch, return to its retained outcome, inspect complete/partial/
failed/unconfirmed outputs, and review another fetch. This is a display and
navigation batch, not a transport, trust, receipt or worker-state change.

## Verified source problem

`execute_transfer` can finish the durable job as `succeeded` after processing a
mixture of successful and failed files (including all-file failure). The existing
case/audit recorder already classifies those rows as `succeeded`, `incomplete` or
`failed`. The GUI instead hardcoded “Transfer complete,” the setup bar said “Ready
to fetch” before validation, and history displayed the raw successful worker state.
These descriptions could contradict the actual per-file results and case outcome.

## Resulting behavior

- A shared completed-file classifier preserves the existing case/audit semantics.
  Display outcome is separate from raw execution state; no durable state/receipt
  or transfer permission is changed. Valid successful counts, entire retained rows
  and expected host/file count support a complete claim. Missing or contradictory
  evidence is explicitly unconfirmed.
- Current result headline, run bar, status response, progress copy and history
  project that outcome. A successful worker with failed files is partial/failed,
  not green “Finished.” Pagination uses the whole run for its headline and labels
  the visible page separately.
- Retained published paths remain available after interruption. Cancel, deadline
  and unknown outcomes explain that completed outputs are not rolled back and
  that the destination must be inspected before another Datastore fetch.
- Download ZIP remains gated by the existing completed-job/archive receipt,
  owner, retention and artifact checks. Partial ZIPs remain available with their
  report; all-file failure does not invent a download.
- “Review another fetch” opens the existing settings editor; it does not submit
  the old host/file set. A new queue remains an explicit validated action.
  Setup says “Review transfer settings,” rather than claiming readiness.
- History optionally decrypts only its bounded owned summary projection, never
  stored configurations/passwords. The default history row shape is unchanged.
  Damaged history summaries are unconfirmed without hiding the other runs.
- Shared components accept optional display labels/messages; other diagnostics
  retain their existing behavior. The separate continuity batch owns form dirty-
  state and poller binding. Its active/terminal single-snapshot history SQL must
  be retained when combining the optional summary columns.

## Evidence and limits

**Inspected:** prepare/queue validation, worker fetch/publication/archive lifecycle,
case/audit recording, owner-scoped result/status/cancel/download routes, result
pagination, shared result run bar/history/status poller, existing admission and
storage tests. No live data or actual connections were used.

**Tested:** synthetic outcome matrices (complete/mixed/all-failed/empty/malformed),
row/count/ZIP evidence checks, cancelled/unknown/failed publication, destination
reconciliation advice, raw state preservation, validation without network work,
owned summary-only history, unreadable summary resilience, 200-result pagination,
and real worker execution with mocked fetches proving display/case/audit agreement.
Existing transfer jobs/admission/storage/limits and shared UI regressions are also
run: **135 tests and 37 subtests passed** (35.78 seconds) before candidate
commit. Exact-head repeat and independent/browser review remain parent gates.

**Browser pending parent:** this worker has no browser surface. The separately
verified loopback fixture uses a new temporary instance and only synthetic ZIP/
Datastore outputs. Standalone role, no agents/scheduler/workers, and blocked actual
fetches isolate it from real devices. The parent checks outcome screens, history,
Review another fetch, empty/loading/validation states, keyboard and narrow layouts.

**Unverified:** real SFTP/SCP/FTP devices, remote Agent/offline rendering, all
palette/density combinations, and expired-artifact browser behavior beyond existing
backend retention tests. No live deployment, main merge, public publication,
version/release or security configuration change was performed by this worker.
