# Shared condition host workers

Operations → Shared condition host workers sets a per-instance, per-process
ceiling for host checks in overlapping automation condition batches. Default:
20; range: 1–200. This is adjustable operator policy, not a measured network limit.
It covers TCP reachability, DNS lookup and DNS performance, certificate health,
compatibility/fallback ping, and SNMP conditions. Each SNMP host × rule-profile
poll consumes one worker through event-loop and dispatcher cleanup; OID entries
within that poll remain sequential. Accelerated fping does not consume these slots.

The normal singleton automation daemon shares the pool across its jobs. Engine
condition evaluation uses the engine's instance path; interactive condition tests
use the current application's instance. A condition scope is restored on exit,
including failure, so later unrelated work does not inherit its pool.

Action callbacks use their own pool. Each condition batch submits a bounded
window and retains its existing local concurrency ceiling (TCP's requested
concurrency, DNS/fallback ping 20, certificates 10). The shared ceiling can reduce
that concurrency. SNMP conditions use the shared ceiling for their host ×
rule-profile combinations instead of launching all combinations together.
Default TCP condition concurrency therefore changes from up to 100 per condition to up to 20 across these condition batches. Large checks may
take longer; adjust the setting to match the desired load and cadence.

Result order, DNS resolution caching within each TCP scan, timestamps, per-probe
timeouts and condition policy calculations retain their existing behavior.
There is no deadline while waiting in this pool. A stalled probe/resolver can
occupy a worker; this change is a concurrency bound, not a whole-condition time
budget. There is no FIFO/fairness guarantee between batches.

The final borrower drains work and shuts down/removes the idle pool. Changes to
the configured limit apply after overlapping batches drain and a new pool is
created. Instances and processes remain independent; this is not a global
per-target socket limit. An Agent or another web process has its own pool.
Standalone evaluations without an instance context retain independent pools.

Normal SNMP tools and live interface polling retain their existing async execution.
Normal TCP/DNS/ping tools outside condition evaluation keep their existing
per-call worker counts, now with bounded submission windows instead of eagerly
creating a future for every target.

Upgrade and restart the executing automation/web workers to load this change.
Subsequent settings edits apply after active batches drain. Probe-specific
connection deadlines and remaining protocol-wide admission work are separate.

## Accelerated ping condition rounds

Operations → Concurrent accelerated-ping condition rounds sets a separate
per-instance, per-process pool limit: default 4, range 1–32. Four matches the
default automation concurrency; it is adjustable policy, not a measured safe
packet rate. Each slot runs one complete fping round in one subprocess. It does
not divide the target list or launch a process per host. Conditions retain their
100-target and 10-round validation limits, target order, 2 ms packet pacing,
per-probe timeout and subprocess safety timeout. The capability check remains
separate from round admission.

Overlapping conditions and interactive condition tests in the same process and
instance share the limit. Rounds release their slots before the next round.
Host-check and action pools remain available independently. Manual ping tools,
live ping sessions and standalone calls without condition scope keep their
existing execution. This does not impose a fleet-wide or per-target packet rate.

Waiting happens before a round starts, so its subprocess timeout and reported
probe latency exclude admission wait. Waiting can lengthen total condition time
and the gap between successive samples, affecting which network conditions are
observed. There is no queue-wait deadline or fairness guarantee. Failed or timed
out rounds propagate the existing error and release the slot; subsequent rounds
can run. Pool settings reload after overlapping borrowers (including waiting
rounds) drain. Upgrade/restart executing workers to load the implementation.
