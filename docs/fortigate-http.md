# FortiGate API connection and result policy

Wireless client/history lookups reuse one HTTP session across their pages and
supported endpoint/filter fallbacks. Bulk rename, export/discovery tasks, and
switch-move batches also reuse connections within each operation. Each scope
closes its session on success or failure. Sessions are not global and are not
shared across profiles or workers. Individual calls outside a scope own and close
their own session. Connection reuse depends on appliance keep-alive support.

The following centralized constants in twn_toolkit/fortigate.py can be adjusted
in code; they are not per-profile UI settings:

| Constant | Default | Scope |
| --- | --- | --- |
| MAX_RESPONSE_BYTES | 16 MiB | One decompressed API response, including exports and errors |
| MAX_LOG_BYTES | 64 MiB | Response bodies across a wireless-history lookup |
| MAX_LOG_ROWS | 60,000 | Unique matching history rows retained |
| MAX_LOG_REQUESTS | 120 | Requests across history pages, endpoints, and filters |
| MAX_LOG_PAGES_PER_FILTER | 6 | Pages per history filter, including its terminating page |
| RESPONSE_CHUNK_BYTES | 64 KiB | Response read chunk size |

Responses are read in bounded chunks before JSON decoding. Python objects and
deduplication metadata require additional memory; these are not process RSS
limits. Connection/read timeouts retain their existing meaning and do not bound
system DNS resolution or total operation duration.

A history search that exceeds a budget or reaches the page cap without an empty
or older page fails explicitly. It does not return the rows collected so far.
Narrow the time range or tune the policy when a legitimate search reaches a limit.
Malformed pages and failed later requests also fail the lookup.

Unsupported filters/endpoints (HTTP 400/404) can still select another read
variant before any matching history is collected. Authentication, server,
transport, redirect, and budget errors stop immediately. There are no added
automatic retries for reads or mutations.

HTTP redirects are rejected before reading their bodies. Configure the final
appliance API URL in the profile if it redirects. A mutation is not resent to a
redirect target. Existing task reporting still distinguishes completed mutations
from later failures; connection reuse does not make a batch transactional.
