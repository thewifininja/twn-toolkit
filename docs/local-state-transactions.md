# Local state transactions

The toolkit stores small configuration records in JSON and relational/runtime state in SQLite. JSON filenames and portable backup formats remain compatible with existing instances.

## Mutating JSON state

Use `file_transaction(path)` from `twn_toolkit.file_transactions` around the complete read, validation, mutation, and publication sequence. Locking only the final write does not prevent lost updates. The same rule applies to deletion, duplication, restoration, and checks such as “only the first administrator may be created.”

The helper locks an owner-only sidecar named `.<filename>.lock`. The sidecar stays in place after release because deleting it could let two writers lock different inodes. Do not lock the data file itself: atomic replacement changes its inode. Existing stores continue publishing complete files with temporary-file replacement, so normal readers do not need to wait for a writer.

Transactions serialize separate threads and processes on the supported Linux and macOS deployments. They are reentrant within a thread, allowing a compound store operation to call other protected methods. Keep them limited to local state work; do not hold a transaction across device I/O or launch a child process from within one. Lock behavior on network/shared filesystems is not a supported multi-host coordination mechanism.

An explicit replacement remains a replacement. This mechanism preserves concurrent field updates and serializes whole-record replacement, but does not provide an editor revision/conflict UI or merge arbitrary stale caller-supplied records.

## Configuration import

JSON-backed backup adapters expose `transaction_path` for their underlying file. The import coordinator acquires all participating paths in canonical sorted order before reading snapshots and retains them through success or rollback. Adapter writes may reenter those locks. A new JSON adapter must expose the same path its normal mutation methods protect.

This prevents rollback from restoring a snapshot over a concurrent JSON edit. It does not turn several files into a crash-atomic database transaction. Existing SQLite adapters still own their database transaction and rollback behavior. Recovery snapshots remain the mechanism for broader interrupted-maintenance recovery.

## Validation

`tests/test_file_transactions.py` exercises independent processes and threads, an interrupted writer, nested transactions, password revocation, failed import rollback, and concurrent initial setup. Existing auth, access-profile, profile, and configuration-backup tests protect schema and behavior compatibility. Run the full suite before merging changes to this boundary.
