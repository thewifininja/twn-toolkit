# Distributed history reads

Job status, requester history and latest-tool-result lookups use read-only
snapshots while their selected records have current leases and payloads.
Requester history uses an index on requester and descending creation time.
Latest-result lookup uses Agent, requester, capability, version and descending
creation time. These indexes avoid whole-history scans and temporary sorts for
those query shapes.

A read that finds a due lease or payload closes its read connection, acquires
the existing immediate write reservation and reruns the selection. It expires
only due records in that current selection, then returns the updated records.
This recheck respects a lease renewal, completion, deletion or newly inserted
result between the original snapshot and the write reservation. It does not
upgrade a deferred read transaction.

Results remain scoped to the requester where the caller uses a requester-scoped
API. Missing or inaccessible records do not trigger an expiry sweep. History
returns at most 100 records; single-job and latest-result queries return at most
one. Records outside the selected page continue to expire through existing
Mainframe housekeeping and authoritative ownership/claim operations. Reading
one user's history no longer sweeps another user's records.

Claim/start/renew/complete/cancel transitions still reserve the writer and check
ownership atomically. A read-only status snapshot does not authorize execution,
retry or cancellation. Expired unstarted claims become cancelled, expired
started work becomes unknown, and expired sensitive payloads are removed before
returning a record that was due at the snapshot check.

The additional indexes increase database size and insert/update maintenance.
They are created when an application or worker first opens an existing store;
building them takes a write reservation and needs disk space. They do not alter
the configured payload retention period, discard outcome records or resolve
unknown outcomes.

Cross-process wakeups, terminal-history retention policy and sustained fleet
load testing remain separate work. These changes remove unnecessary writer
reservations from fresh reads; they do not remove all queue/database writes.
