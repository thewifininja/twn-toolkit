# Shared automation action workers

Operations → Shared automation action workers controls the number of action
callbacks that can execute concurrently across overlapping stages for one
instance in one process. The default is 20; the allowed range is 1–64. This is an
operator policy default that preserves the former single-stage concurrency while
preventing each overlapping stage from creating its own 20-thread pool.

The normal automation daemon is a singleton per instance, so its manual and
scheduled runs share this budget. Concurrent automation workers still controls
how many runs/conditions the scheduler processes. Action workers are a separate
pool; waiting pipeline jobs do not consume an action worker themselves. Live-tool
workers and scheduler heartbeats keep their separate execution paths.

Each stage submits a window of at most the shared worker count, refilling it as
results finish. With W active stages and A action workers, at most W × A action
futures are submitted at once; only A callbacks execute. The normal scheduler's
run-worker limit bounds W. Results retain definition order, including errors, so
continuation rules and downstream stage context keep their existing meaning.
Admission is not a fairness guarantee between stages.

The pool is shared across engine objects using the same resolved instance path.
It exists only while stages borrow it; the final borrower drains submitted work
and shuts down the pool. There is no permanent cache of idle executors for old
instances. A changed setting takes effect once overlapping active stages drain
and a new pool is created. Existing work is not interrupted to resize the pool.

These are action callbacks, not individual sockets. An action can still create
its own host workers or HTTP child. Outgoing file transfers additionally obey
[shared transfer connection limits](outgoing-transfer-admission.md). Other
protocol connection budgets remain separate work. TCP, DNS, certificate and
fallback-ping condition batches use a [separate shared pool](automation-condition-capacity.md). Distinct
processes or instances have separate action pools; this does not impose a
cross-process or fleet-wide action limit on standalone Python callers.

Upgrade/restart the automation daemon to load the implementation. Saving a new
limit afterward does not require a restart, but a continuously busy pool may not
adopt it until its stages drain. An action that blocks can still occupy capacity;
this change does not add action deadlines, forced cancellation, or replay. On
unexpected interruption, unsubmitted actions are not launched and submitted
running actions are drained before the pool is released.
