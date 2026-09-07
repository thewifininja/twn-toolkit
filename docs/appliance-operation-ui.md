# Appliance mutation results

FortiGate rename and FortiAuthenticator MAC cleanup keep the reviewed preview and
confirmation flow. On submission, the page shows an inline status and blocks
repeat submissions from that form. After 30 seconds without a response, it tells
the operator that the outcome is uncertain. Returning to a submitted preview from
the browser's back/forward cache requires a fresh preview before another run.

Result pages report successful rows and reported errors together. An error,
especially a lost response, does not prove the appliance rejected a change.
Operators should reconcile the appliance state before preparing another preview;
successful changes should not be repeated. Switch ordering keeps its existing
post-apply verification and now displays delayed-response guidance inline.

These mutation requests are still synchronous. The UI guard is not server-side
idempotency or durable job recovery. Closing the page does not cancel appliance
changes, and a browser timeout does not establish the operation's outcome.
Whole-operation supervision, retained partial progress and server-side replay
protection remain audit follow-ups. Read-only appliance jobs are described in
[appliance-read-jobs.md](appliance-read-jobs.md).
