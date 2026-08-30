# Configuration backups

Configuration backups move reusable toolkit settings between installations.
They are intentionally narrower than recovery points and portable case files.

| Artifact | Purpose | Includes | Does not include |
| --- | --- | --- | --- |
| Configuration backup | Move selected reusable settings | Selected profiles, reusable definitions, portable preferences, and selected credentials | Runtime/history, instance identity, cases, issued keys, datastore content, or code |
| Recovery point | Restore one installation as a unit | Matched toolkit code and the complete durable instance | A selective cross-instance merge workflow |
| Portable case | Transfer an investigation | Case journal, attribution, selected evidence, and case metadata | General toolkit configuration |

Do not use a configuration backup as disaster recovery. Use a recovery point
when code, users, operational state, and the instance must be restored together.

## Portable groups

The v2 catalog currently registers:

- FortiGate and FortiAuthenticator connection profiles;
- ping, DNS host/resolver, RADIUS server/credential/attribute, SNMP
  credential/host/OID, TCP scan host/port, NTP, traceroute, Wake-on-LAN, and
  Bulk SSH host matrices with their CLI actions, plus pre-v0.22 command-set
  compatibility records;
- automation definitions without execution history or output;
- dashboard layout without counters or activity;
- user-owned Remote Terminal folders, saved hosts, and credentials without
  active sessions or scrollback;
- Certificate Automation AD CS credentials, servers, templates, and managed
  certificate definitions without issued certificates, private keys, or
  request history;
- custom access-profile definitions without users, passwords, or assignments;
- SMTP delivery settings and credentials; and
- the explicit toolkit timezone.

Secrets are decrypted only while constructing or applying the backup. A
secret-bearing selection forces password encryption on export. On import,
secrets are validated and encrypted again with the destination installation's
key; source ciphertext is never copied into the destination store.

## Recovery-only and case data

The following remain outside portable configuration backups:

- users, password hashes, access assignments, sessions, and installation
  signing secrets;
- listener identity, bind address, client allowlists, operational limits, and
  transfer-service settings;
- TLS identity, issued certificates, private keys, and certificate history;
- cases and their evidence, which use the portable-case workflow;
- datastore files; and
- audit/activity history, automation jobs and output, terminal sessions and
  scrollback, captures, reports, retained tool results, and live state.

This boundary prevents an import from silently changing access to the
destination host, replacing its identity, or mixing operational evidence with
configuration.

## Export format and compatibility

New files use `twn-toolkit-configuration-backup` format version 2. The manifest
records the source toolkit version, creation time, group identity, category,
sensitivity, and record count. Group counts are validated against the payload
before inspection or import.

Encrypted v2 files use the
`twn-toolkit-encrypted-configuration-backup` envelope with PBKDF2-HMAC-SHA256
and Fernet authenticated encryption. The toolkit continues to accept legacy
plain and encrypted v1 profile backups. New exports are always v2.

## Inspect-first import

Import is a two-step operation:

1. Upload the file, provide its password when needed, and choose Combine or
   Replace. The toolkit validates and holds the decoded payload in a
   short-lived, installation-key-encrypted local staging file.
2. Review available/unavailable groups and the number of new, matching, and
   (for Replace) local-only records. Select the groups, resolve Remote Terminal
   owner mappings, and explicitly confirm the import.

**Combine** preserves local-only names, adds new names, and updates matching
names. **Replace** makes supported selected groups match the backup. A group
that cannot replace safely is disabled in Replace mode; Certificate Automation
is Combine-only so existing issued material is never deleted by configuration
import.

Remote Terminal libraries are keyed by source username. An exact local match is
suggested, but the administrator must be able to assign each library to a local
operator or exclude it. Import never creates users or grants access.
Saved console records include their stable adapter identity and line settings.
An imported adapter may remain marked detached until the corresponding physical
device is attached to the destination toolkit host.

Stores validate their complete incoming records before or within their write
transaction. Generic groups are snapshotted and rolled back in reverse order if
a later group fails. Complex groups use atomic local database transactions and
run last when their rollback contract is intentionally narrower.

## Extending the catalog

Every new durable domain must be classified as `portable`, `recovery`, or
`case`. Portable groups register a stable ID, label, category, description,
sensitivity flag, store adapter, and supported import modes. A store adapter
must:

1. return a list of named, JSON-serializable records;
2. validate bounds and references before accepting data;
3. avoid exporting histories, live state, or unrelated secrets;
4. re-encrypt credentials through the destination store; and
5. provide an exact replacement snapshot contract or an atomic custom import.

Catalog order and IDs, v1 compatibility, manifest validation, secret
re-encryption, excluded key material, import preview, route behavior, and the
full application suite are covered by tests.
