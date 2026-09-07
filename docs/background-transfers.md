# Background Bulk Transfer

Bulk Transfer validates and queues SFTP, SCP, and FTP fetches, then redirects to an
owner-scoped result URL. Fetching and ZIP assembly run in a supervised child of
the existing automation worker. Navigating away or refreshing results does not
repeat network work. Status, cancellation, results, and download routes require
both Bulk Transfer permission and the submitting identity.

The existing diagnostic pool, queue/user limits, overall deadline, and history
retention also govern Bulk Transfer. Outgoing transfer worker, per-host deadline,
file/run byte limits are captured when queued; shared connection admission still
reads the instance's current connection policy. These limits remain adjustable
in Operations. Queue waiting is outside the child deadline. A process deadline
covers fetching, metadata, publication, and ZIP assembly; stopped/restarted work
is never automatically replayed. Update/restart web and automation workers
together on executing instances; older workers do not understand transfer jobs.

## Results and cancellation

Completed results are encrypted, paged in groups of 100, and associated with the
user and recording case selected at submission. Activity, audit, and generated
case manifests remain best effort and never cause a transfer replay. Passwords
are encrypted with the retained job configuration and never rendered back into
the form. Protect the instance key and recovery data.

Download mode produces a ZIP on disk, then exposes a separate authenticated,
range-capable download. It does not build a whole archive in Python memory or
require download cookies/polling. ZIPs remain available while the job is retained,
up to the configured retention age; this replaces the previous immediate,
one-shot download. Payload archives use owner-only filesystem permissions rather
than application-level encryption. The scheduler removes expired/orphaned and
unsuccessful-job staging on its cleanup sweep; a stopped scheduler delays physical
cleanup, but the download route rejects archives past their retention age.

Datastore mode publishes files individually through the existing datastore upload
checks. Confirmed published paths appear with job status, including interrupted
runs. Cancellation stops further child work but does not undo published files.
A crash between publication and its progress checkpoint can leave an additional
file that is not in the confirmed list. Inspect/reconcile the destination before
an explicit retry. Partial file-publication errors are retained per result.

## Storage and transport boundaries

Queue admission accounts for the existing 32 MiB result allowance plus twice each
active transfer's configured run-byte ceiling, covering fetched files plus a ZIP
or datastore copy. Retained archives already consume measured disk space. This is
conservative admission coordination within the finite-job queue; it is not a
reservation shared by every filesystem writer or a hard filesystem quota.

During GUI Bulk Transfer execution, SFTP/SCP/FTP private staging and ZIP writes
use the same physical reservations as incoming uploads and case/appliance exports.
Known file sizes reserve their remaining bytes; unknown-length FTP grows its
reservation with received content. The existing protocol confirmation checks and final private filename rename
remain in place; failures remove the partial file. Atomic ZIP publication occurs only after the archive
closes successfully. The ZIP file ceiling is derived from the captured run limit
(twice run bytes plus 32 MiB for archive/report overhead). Private roots and files
use modes700/600. Diagnostic cleanup reclaims staging left by exited processes.
Direct transfer API callers can supply an output store; callers without one retain
their existing local-file behavior. Other writers and external processes remain
outside this reservation guarantee.

Local downloads can stream the retained archive and support byte ranges. The
Agent GUI still has its configured finite response-size limit. Larger archives
must be downloaded directly from the Agent (or through a client making supported
range requests); this change does not introduce unlimited tunnel streaming or
remove that limit. Slow-client file serving, other synchronous tools, and broader
cross-writer storage guarantees remain separate audit items.
