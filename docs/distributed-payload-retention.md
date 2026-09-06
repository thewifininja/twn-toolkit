# Distributed payload storage and retention

Mainframe queue inputs, outputs and agent-provided error text are encrypted on
disk. Agent result receipts are encrypted too. The bounded control envelopes use
[Fernet authenticated encryption](https://cryptography.io/en/latest/fernet/),
with an instance-specific key derived from the existing session secret and a
separate distributed-payload domain. Each encrypted value is bound to its job ID
and column. A wrong key, altered token or transplanted value fails decoding.

Operation identifiers, owners, agents, capabilities, timestamps, execution state
and ownership tokens remain database metadata. Encryption does not hide these
fields or protect against someone who also possesses the instance secret.
Empty payload markers and coordinator-generated status messages contain no
request data and can remain plaintext.

## Lifetime and settings

**Settings → Operations → Distributed operation limits** exposes payload
retention on Mainframes and Agents. The existing
`distributed_receipt_retention_hours` setting now bounds queued inputs and
completed results as well as acknowledged receipt tombstones. Default: 24 hours;
range: 1–720 hours. Configure each instance independently.

- New queued jobs snapshot this deadline at enqueue. If still unclaimed when
  it expires, they are cancelled and cannot execute with missing inputs.
- Tunnel inputs are removed atomically when claimed, cancelled before execution,
  or fenced by an activation change. Delivery retains its in-memory input.
  Diagnostic inputs remain encrypted for their form/history until expiry.
- Completed results receive a new deadline at completion. Their output, input
  and supplied error details are removed at expiry; state, timestamps and
  ownership survive. An unresolved operation never becomes safe to retry merely
  because its payload expired.
- The web request removes its stored tunnel output copy once it has loaded a
  terminal response into memory, including failed/invalid response handling.
  This does not prove the browser received it, and no request is replayed.
- Agent acknowledgement immediately drops the result body. A result still
  unacknowledged at its deadline becomes a small encrypted summary containing
  the actual execution state and ownership. Its deduplication receipt remains
  until acknowledged; expiration does not admit duplicate execution.
- Existing payload deadlines retain the setting captured when written. Changing
  the setting affects newly queued/completed payloads. Acknowledged tombstone
  removal uses the current setting; capacity pressure may evict these
  acknowledged tombstones earlier, as before.

Queue access enforces expiry, and the Mainframe distributed worker sweeps every
60 seconds (`PAYLOAD_CLEANUP_INTERVAL_SECONDS`). Agent receipt initialization
and pending-result polling enforce receipt expiry, including an already-open
interactive lane. Cleanup requires those processes to run: a stopped instance
does not erase files on a wall-clock deadline, and busy or unavailable workers
can delay physical cleanup. Expired payloads are removed before normal queue or
pending-result reads return them. The encrypted metadata summaries can outlive
the payload window.

## Upgrade, backup and recovery

Upgrade all web and distributed processes sharing an instance together and
restart them together. Startup transactionally migrates existing plaintext rows,
preserving original ages and removing already-expired payloads. The on-disk
format is not readable by older code; do not run an older worker against a
migrated database. The network ownership protocol stays at version 2, so separate
instances can upgrade independently.

Preserve the matching `session_secret`, or the configured
`TWN_TOOLKIT_SECRET_KEY` override, with database backups. Every process on one
instance must use the same secret. Changing or losing it prevents decrypting
existing payloads; automatic key rotation is not implemented. Do not delete
ownership records to work around decryption errors, because operations may have
already run. Restore the matching key and reconcile unresolved operations before
retrying them. A rollback requires a compatible database backup and matching
key, with reconciliation of work performed since that backup.

Connections enable
[SQLite secure_delete](https://www.sqlite.org/pragma.html#pragma_secure_delete)
to overwrite deleted database content. Migration and cleanup cannot erase old
backups, filesystem snapshots or historic journal copies. Apply the deployment's
retention policy to those copies separately. No whole-disk forensic-erasure
guarantee is made. Payload encryption also does not remove sensitive data from
other application stores, subprocess arguments or external targets.
