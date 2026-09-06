# Shared outgoing transfer admission

Operations → Outgoing transfer limits has two instance-wide controls:

| Setting | Default | Range | Scope |
| --- | --- | --- | --- |
| Outgoing connections across runs | 32 | 1–256 | Concurrent outgoing SFTP, SCP and FTP host transfers |
| Outgoing connections per host | 4 | 1–64 | Those transfers to the same normalized host, across protocols and ports |

These are initial operator policy defaults, not measured device limits. Adjust
both for the capacity of this instance and its targets. The existing worker limit
still controls each run. Multiple manual requests and automation actions now
share the two new limits across web and worker processes using the same instance
directory. An Agent uses its own local instance limits.

A slot covers connection setup, all files requested from that host, and connection
cleanup. Waiting for capacity consumes the existing per-host deadline. If it
expires before admission, each requested file receives a capacity error and no
connection is opened. A waiting transfer holds no other slot. Acquisition is
opportunistic, not FIFO; a busy target can delay other targets within that run's
worker pool. Separate runs for other hosts can use available capacity.

Admission reads the current limits. Lowering a limit lets active transfers finish
and prevents new admission until the remaining active count is below the limit.
Increasing it permits new admissions without restarting workers. Other transfer
settings retain their existing per-run snapshot behavior.

Slots use owner-only files in `.transfer-admission` and kernel file locks on the
local instance filesystem. Process exit releases the lock; no PID timeout or
stale lease cleanup is needed. The slot files are reused and limited by the
largest configured global capacity (at most 256), and hold only hashed normalized
host identifiers. Do not remove or replace this directory while transfers are
running. A lock/storage error fails closed. Local filesystem stalls are not
forcibly interruptible.

Hostnames are case-folded and trailing dots removed; IP literals are normalized.
DNS aliases and a hostname versus its resolved IP remain different host keys.
Admission does not add DNS lookups. This is a per-instance transfer budget, not a
fleet-wide or all-protocol network limit. SSH command execution, remote terminals,
TCP scans and other tools are outside it. Standalone Python calls that omit
`instance_path` keep their historical per-run behavior; application manual and
automation paths always pass their instance.

Upgrade and restart all web and automation processes sharing the instance before
relying on this guarantee: older processes do not acquire these slots. Incoming
file services and shared disk reservations have separate policies.
