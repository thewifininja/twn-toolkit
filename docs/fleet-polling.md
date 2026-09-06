# Fleet listener capacity and polling

Each updated Agent normally holds at most two idle long-poll connections:
one regular work poll and one interactive poll. Three interactive execution workers
share the interactive poll gate; once a request is delivered, its execution runs
outside that gate so another worker can fetch work. Lease renewal and result
control do not wait for the interactive poll gate.

Mainframe **Settings → Operations → Distributed operation limits** exposes:

| Setting | Default | Range |
| --- | --- | --- |
| Listener connections | 32 | 2–512 |
| Control connection reserve | 8 | 1 to capacity minus 1 |
| Long polls per Agent | 2 | 1–8 |

These settings apply when the distributed worker starts. Each listen address has
its own bounded listener and poll budget. The connection bound applies before
TLS negotiation. The socket backlog uses the configured capacity, subject to
operating-system limits.

At most `connections - reserve` authenticated requests may remain in a long
poll. Each Agent also has a share limit. A poll checks for ready work before
requesting a waiting slot. When no waiting slot is available, updated Agents
receive their acknowledgements and an empty successful response with a
`retry_after_seconds` hint. They remain connected and pace the next poll.
Ready jobs can still be delivered without a waiting slot.

The reserve is headroom protected from **idle long polls**, not a separate
authenticated control-only socket pool. TLS handshakes, request reads and other
short requests also consume it. An untrusted flood or stalled short requests
can still exhaust total capacity until existing timeouts release their slots.
Per-Agent waiting limits do not constitute a universal per-Agent request limit.

## Sizing

A starting model for updated, otherwise idle Agents is
`connections >= 2 × agents + reserve`. This leaves room for control traffic but
is not a throughput, latency or maximum-fleet guarantee. For example:

| Agents | Old idle polls | Updated idle polls | Example connections / reserve |
| --- | --- | --- | --- |
| 1 | 4 | 2 | 32 / 8 |
| 8 | 32 | 16 | 32 / 8 |
| 25 | 100 | 50 | 64 / 8 |
| 100 | 400 | 200 | 256 / 32 |

The default 32/8 budget accommodates 12 updated Agents continuously waiting on
both lanes. Larger fleets still make immediate checks when waiting capacity is
full, but this increases handshake traffic and can add the retry interval to
delivery latency. Tune against measurements on the actual Mainframe. Increasing
limits also increases possible sockets, threads and TLS memory use. Admission
is opportunistic; it does not promise strict FIFO fairness.

## Reconnect and compatibility

Transport failures use exponential backoff with equal jitter: a 1-second initial
ceiling doubles to 30 seconds, and each delay is randomly selected from half the
ceiling to the ceiling. A successful exchange resets it. The interactive gate
holds the delay so another local worker cannot bypass the retry pacing.
Disconnected regular work and control heartbeat retries have independent backoffs. Pending enrollment and
unenrolled status checks wait five seconds. Server capacity hints receive
additional bounded jitter; their base is one second. These are centralized code
policies in `distributed_polling.py`, not extra UI settings.

Retry pauses check shutdown every 100 ms. Existing network timeouts still govern
an in-flight request, and running capability handlers retain their existing
ownership/cancellation behavior. This does not replay a side-effecting handler
after an uncertain result.

The additive `supports_poll_retry` request flag lets old Mainframes ignore the
new pacing feature. Updated Mainframes send HTTP 503 for saturated legacy polls,
because old workers would otherwise spin on an empty successful response.
A legacy worker may report a temporary disconnect when its extra polls are
refused. Results accepted before that response remain committed and can be acknowledged
idempotently on retry. Upgrade Agents too for two idle polls and the new retry
behavior. Job ownership protocol remains version 2.

### Independent status reporting

The Agent's main loop sends a short authenticated `/v1/agent-status` request
independently of the regular executor. It updates presence/capabilities and
acknowledges regular results, but never claims work or waits on a long-poll slot.
Healthy status requests are paced at 5–7.5 seconds, including jitter; failures use
the bounded reconnect backoff. The five-second base is the centralized
`CONTROL_STATUS_SECONDS` code policy. These short requests add control traffic
beyond the two-idle-connection sizing model.

One regular execution thread claims and executes at most one job at a time,
without a local backlog. Three existing interactive execution threads remain.
Result-only followups also use the status endpoint so they cannot accidentally
claim tunnel requests or a second regular job. Only the control loop writes
the local connectivity status file; a delayed job completion cannot overwrite
a newer disconnect report.

**Upgrade and restart the Mainframe worker before upgrading Agents.** The
status endpoint is new; older Mainframes return 404. Updated Agents report a
control connection failure and retry with backoff, without falling back to a
heartbeat that could claim work. Existing regular/interactive delivery may
continue, but independent status is unavailable until the Mainframe is updated.
Older Agents continue to use the existing heartbeat endpoint on new Mainframes.

Shutdown shares a 30-second grace period across execution threads. Polls that
return after stop is requested do not start new handlers. Already-started
handlers retain their ownership/receipt semantics: this is not forced
cancellation, and an interrupted side effect may still have an unknown outcome.
Lease renewal remains independent of the control heartbeat.

## Queue work and remaining limits

Idle polls now perform an indexed, read-only queued-work probe. A positive probe
still goes through the existing atomic claim; it is not ownership permission.
The index starts with Agent and state, so retained history for other Agents and
terminal states does not require a whole-history scan. Probes keep the existing
50 ms interactive and 100 ms heartbeat intervals, avoiding extra typing latency.
Periodic Mainframe housekeeping and normal status reads continue to expire
leases/payloads.

This removes empty claim transactions, not all polling or all database writes:
heartbeat, activation and receipt processing still persist state. Cross-process
wakeups, broader history indexes/retention, asynchronous execution classes for
long HTTP handlers and shared target connection budgets remain separate work.
All three interactive threads can still be occupied by long HTTP requests; the
independent status heartbeat does not guarantee remote page/terminal availability
in that condition.
