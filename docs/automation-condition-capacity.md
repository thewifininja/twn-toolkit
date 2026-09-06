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
creating a future for every target. Accelerated ping behavior is unchanged.

Upgrade and restart the executing automation/web workers to load this change.
Subsequent settings edits apply after active batches drain. Probe-specific
connection deadlines and remaining protocol-wide admission work are separate.
