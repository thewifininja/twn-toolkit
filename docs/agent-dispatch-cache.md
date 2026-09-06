# Agent HTTP dispatch cache

An Agent shares one Flask application for an instance and keeps a separate
cookie-bearing client for each delegated Mainframe user. Request identity and
fabric context come from the current authenticated envelope, never from a cached
user object. Flask's [request contexts](https://flask.palletsprojects.com/en/stable/reqcontext/)
isolate request-local data across worker threads.

**Settings → Operations → Distributed operation limits**, on the Agent:

| Setting | Default | Range |
| --- | --- | --- |
| Cached remote users (`distributed_http_client_limit`) | 32 | 1–256 |
| Remote client idle time (`distributed_http_client_idle_seconds`) | 900 seconds | 1–86,400 seconds |

Limits apply per instance per Agent process. Changes apply on the next request
or cleanup. When idle entries must be removed, the least recently used entry
goes first. An entry is pinned before initialization and while waiting for its
user lock, handling the request, reading the response and closing it. Cleanup
does not interrupt that work. Reducing capacity below the active count blocks
admission for new users until entries become idle; it does not terminate active
requests. Requests for already-pinned users keep their existing entry.

If all slots are pinned, a new user receives HTTP 503 with Retry-After: 1 before
the local HTTP handler runs. There is no automatic retry of a tunneled mutation.
A slow handler can still occupy its worker lane and keep its cache entry pinned;
this cache is not a request deadline or a fleet connection budget.

Ordinary requests for one user remain serialized to preserve cookie/session
updates. Different users can run concurrently. Terminal input, output and resize
requests retain their existing separate, cookie-free client path so a terminal
poll does not wait behind that user's ordinary page request. They still pin the
shared app. Initialization is serialized per instance, outside the registry
lock, so another cached instance can initialize or dispatch independently.

Eviction drops cookie state, including pending flash messages. It does not
delete saved definitions, operations or remote terminal sessions. A later request
creates a fresh client; durable state still comes from the instance stores.
Applications have no permanent cache entry after their clients and idle lifetime
expire. Cyclic Python objects are reclaimed by normal garbage collection;
allocator behavior means RSS need not fall immediately.

Requests perform cleanup, and the Agent worker checks every 60 seconds
(`DISPATCH_CACHE_SWEEP_SECONDS`). A busy worker can delay that periodic check;
active and waiting requests remain protected throughout. An idle timeout starts
when the last request releases its entry. A process-wide code guard,
`MAX_CACHED_INSTANCES = 8`, also bounds apps for embedding callers that use
multiple instance directories. Normal Agent workers serve one instance. This
guard is not a UI setting. A fork starts with a fresh child cache.

The bounds cover cached app/client references. They are not a byte/RSS ceiling
for responses, application-owned data or the toolkit as a whole. Large tunneled
response buffering and broader fleet concurrency remain separate concerns.
