# Switch-order review and application

Inventory loading and applying an order run as finite jobs supervised by the
existing automation worker. Their POST endpoints return 202 with job, status and
cancel URLs. The browser polls in place and retains an Open run link; navigation
and other tools remain available. Recent runs are listed on the switch-order page.
Deploy the web and automation workers together when upgrading this contract.

Loading returns a signed binding for the authenticated user, instance, complete
profile configuration, VDOM, original ordered switch IDs and the toolkit's current
operation revision for that origin. Changing the profile or VDOM discards this
state. Late load responses cannot populate a newly selected target.

Checking confirmation validates the loaded binding locally and signs the exact
original and desired orders. Editing the order cancels that confirmation; late
confirmation responses cannot authorize another order. Both bindings expire after
15 minutes. They contain keyed digests, without profile credentials or inventory.
The worker revalidates the profile and expiring confirmation before each move.

Before applying, the worker reloads the inventory and rejects changed membership
or order. A local cross-process origin lock serializes this toolkit's operations,
including explicit/default HTTP port aliases. Every attempted move advances a
persistent origin revision. Older reviews then require a fresh inventory load,
even if an uncertain job has been pruned or the observed order appears unchanged.
Origin revisions survive ordinary diagnostic-history cleanup. Other administrators,
external writers and DNS aliases are outside this local serialization guarantee.

Each remote move requires an encrypted durable intent checkpoint and running
worker ownership. Acknowledged moves are checkpointed before the next attempt.
The final order is read back and must match before success is reported. An
interrupted attempt is unknown, with its last acknowledged and in-flight moves
retained. Cancellation does not roll back changes; reconcile the appliance before
another apply. Workers never replay started operations after interruption/restart.

A repeated admission for the same signed confirmation returns its original job.
Receipts survive pruned history through the confirmation's lifetime; tombstones
reject resubmission when the result has expired. The browser can retry a lost
supervised admission response using the exact same confirmation. This recovers
admission, not a remote mutation. If admission still cannot be confirmed, inspect
recent runs before another apply. Old synchronous pages must be refreshed.

Only the submitting user with current switch-order access can view or cancel a
run. Original actor/profile/case attribution is retained; recording failures leave
a warning on the result. Target and editing controls stay disabled during apply.

Inventory is limited to 500 switches and 128 characters per identifier. Presentation
labels show 256 characters; identifiers are never silently truncated. Admission
also enforces the shared 64 KiB configuration envelope. Retained summaries are
limited to 1 MiB and HTML result sections show 50 rows per page. Worker, queue,
deadline, history and disk settings reuse the existing Operations policy. These
bounds apply to this workflow, not every profile library or appliance operation.
