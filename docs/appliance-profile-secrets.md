# Saved integration profile secrets

FortiGate API keys, FortiAuthenticator passwords, RADIUS shared secrets and test passwords, and SNMP communities/authentication/privacy keys are now encrypted in their existing profile JSON files. Public profile fields remain readable. Store callers still receive strings, so device requests, profile edits, duplication, previews, and configuration backup workflows keep their existing interfaces.

Secret fields use a versioned Fernet envelope with a domain-separated key derived from the toolkit instance secret. The authenticated payload includes filename, profile name and field name, so moving ciphertext between profiles or fields is rejected. Empty values remain empty. Files retain atomic replacement and mode 0600. Failed decryption prevents normal read/modify/write operations from replacing the original file with empty credentials.

## Existing installations

Legacy plaintext profiles remain readable without a migration write on read. Saving any profile in one of these files protects all secret fields in that file. To protect untouched files explicitly, stop all toolkit writers first and run from the checkout:

```sh
.venv/bin/python -m twn_toolkit.profile_secrets --instance /absolute/path/to/instance
```

Restart all readers/writers on the updated version afterward. The command handles the five existing appliance/RADIUS/SNMP credential files; absent files are not created. It is repeatable and reports filenames, never secret values. Each file is replaced atomically, but the multi-file migration is not a single transaction. A failure may leave some files migrated and others unchanged; correct the error and rerun.

Preserve `session_secret` with full-instance recovery data. If `TWN_TOOLKIT_SECRET_KEY` is configured, every process and migration command must receive that same override. Losing or changing the original key makes saved ciphertext unreadable. Do not fix decryption errors by deleting keys or saving blank credentials. Restore the matching key and data, or intentionally restore from a portable configuration backup.

Old toolkit versions cannot read the new secret envelopes. For rollback use a matching pre-upgrade recovery point, or export portable configuration while running the new version and import it through the destination's supported configuration workflow. Do not copy encrypted profile JSON alone to another instance; portable export decrypts through the store and import re-encrypts with the destination key. Existing export sensitivity and optional backup-password protection remain unchanged.

## Scope and limits

This protects secret contents in these saved profile files from exposure when those files alone are copied or inspected. It does not protect against a host administrator or another process that can access the instance key, live process memory, or authorized exports. It does not erase plaintext from old backups, snapshots, historical filesystem blocks, or legacy files that have not yet been rewritten.

Arbitrary RADIUS attribute values, automation secrets, other integrations, and RADIUS EAP subprocess arguments remain separate audit work. No live migration, password rotation, appliance call, or enrollment change is performed by merely shipping this implementation.
