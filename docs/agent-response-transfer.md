# Agent response transfer

GUI protocol 2 adds finite response chunking while keeping operation control
messages small. Upgrade Mainframe and Agent code together, restart their web and
automation/distributed workers, and wait for an authenticated heartbeat. GUI1 and
legacy peers remain approved but cannot be selected for GUI access. No enrollment
reset or certificate replacement is needed.

## Limits

Mainframe administrators can change these under **Settings → Operations**:

| Setting | Default | Allowed range | Applies to |
| --- | --- | --- | --- |
| Maximum Agent response | 16 MiB | 1–256 MiB | Raw body of one response |
| Agent response storage quota | 128 MiB | 16–8192 MiB | Aggregate encrypted chunk payloads |
| Agent response retention | 15 minutes | 1–1440 minutes | Time from first chunk, including upload and browser delivery |

The first limit is sent with each new request; the receiver also checks its
current limit on every new chunk. Lowering a limit can interrupt a response
already uploading. Quota reductions block new chunks until usage falls below the
new limit. Changes do not extend existing retention deadlines. Chunk size is a
protocol framing choice (64 KiB), not an operator concurrency setting.

The quota counts encrypted base64 payloads, which are larger than raw bodies.
SQLite pages, indexes, journals and retained free pages add filesystem overhead;
the quota is not a bound on the database file size. The existing minimum-free-disk
reserve is checked with space for the incoming chunk and journal overhead. Other
writers can consume disk concurrently, so this is admission checking rather than
an instance-wide reservation. Deleted SQLite pages can be reused; deletion does
not shrink the database file automatically.

## Ownership and delivery

Responses up to 160 KiB stay inline in the existing encrypted control output.
Larger responses are read incrementally and uploaded over the existing outbound
mutual-TLS listener. Every chunk is bound to the authenticated Agent, operation,
activation and attempt. The Mainframe accepts only the running owner, enforces
ordered chunks, and accepts an identical repeated chunk without storing it twice.
Conflicting chunks, expired transfers and stale attempts are rejected. Receiving
chunks never executes the original HTTP request.

The final small receipt contains status, allowlisted headers, original request
path, body length and SHA-256. The Mainframe verifies the staged body before
publishing success and before claiming browser delivery. Browser delivery reads
one chunk at a time with short database reads, without holding a database lock
while waiting for the browser. Integrity verification before delivery still
reads the complete staged response under a transaction; larger configured limits
increase that cost. Body length is sent to the browser so a truncated download
cannot appear to have the advertised complete size.

The Mainframe atomically claims a response for one retrieval. Completion of the
stream or closing the response removes staged chunks; a browser disconnect does
not enable replay or resume. A successfully executed operation retains its outcome
metadata after its body is removed. Responses are marked `Cache-Control: no-store`.

When the initial browser wait ends, existing owned-operation status and no-replay
rules apply. A response that finishes later is linked from its status page. The
link redirects to the original Agent tool URL with a reserved `_twn_response`
query parameter, so same-page forms and navigation retain the Agent context.
GET retrieves the retained body once; HEAD does not consume it. Refresh after
consumption returns unavailable and never reruns the original request. A new,
explicit form submission is a new operation and strips the reserved retrieval
parameter. Retrieval requires the original requester to remain an administrator
and select that Agent; it can use a completed response even if the Agent is now
offline. It does not issue any command to that Agent.

Failed, expired and orphaned chunks are removed by periodic payload cleanup
(while the distributed worker is running) and new chunk admission. Successful
job deletion removes its chunks immediately. Original transfer deadlines survive
chunk cleanup so retries cannot open a fresh retention window. The small transfer
deadline record follows the job payload lifetime. If the worker is stopped,
expired data can remain on disk until cleanup resumes; it cannot be retrieved.

## Scope and failure behavior

This avoids whole-response buffering in the transport and retains only a small
prefix before switching from inline to chunks. A route can still allocate a large
HTML string or other data before yielding it; route-level memory and pagination
remain separate work. The entire finite body must reach the Mainframe before
browser delivery. This does not solve indefinitely stalled routes, request uploads
over 160 KiB, live streams, SSE or WebSockets. Range request/response headers are
preserved, but resume after one-time delivery is a new explicit request and only
works if the original route supports ranges.

Size, quota, disk, lease, cancellation, network and retention failures can occur
after the underlying operation has already performed an effect. Execution is not
automatically retried. An unconfirmed result remains unknown and must be reconciled;
an expired or consumed successful body does not erase its successful outcome.
Keep deployment versions aligned and test large populated libraries, downloads,
timeouts and the relevant real devices before treating operator acceptance as done.
