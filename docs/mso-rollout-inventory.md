# MSO rollout inventory

Inventory of current saved models, checked against the profile stores, portable
backup registrations, Remote Terminal libraries, and automation/certificate
stores. The saved-list section is implemented in development v0.25.4. Later sections
remain a rollout plan, not a claim that those models already sync.

Every participating object remains local by default, with one fleet-wide MSO
toggle. Authorized edits are bidirectional; origin is informational. No per-Agent
destination lists. Preserve the approved compact switch and keep operational MSO
controls out of standalone mode.

## Saved lists and profiles

| Model | Current state / proposed order |
| --- | --- |
| Ping profiles | Implemented pilot |
| DNS query/hostname lists | Implemented |
| DNS server lists | Implemented |
| NTP target lists | Implemented |
| Traceroute target lists | Implemented |
| TCP scanner host lists | Implemented |
| TCP scanner port lists | Implemented |
| Wake-on-LAN device groups | Implemented |
| SNMP host profiles | Implemented; automatically shares the selected credential by UUID |
| SNMP credentials | Implemented; protected secret fields and dependency guards |
| SNMP OID profiles | Implemented |
| RADIUS request-attribute sets | Implemented; validate attribute payloads and sensitivity |
| LLDP personas, including MED policies/custom TLVs | Implemented; receiving never starts transmission or selects a local interface |

Sources: `twn_toolkit/profiles.py` and `twn_toolkit/tool_modules/network.py`.
Saved profile arrival must never start a diagnostic or change an active run.

## Libraries, references, and credentials

| Model | Additional work before rollout |
| --- | --- |
| Remote Terminal folders/full paths | Stable folder IDs, bidirectional moves/renames and parent dependencies |
| Remote Terminal SSH/Telnet definitions | Folder/credential references, user ownership and visibility |
| Remote Terminal credentials | Secret distribution and ownership rules; host-scoped references |
| Bulk SSH host matrices and per-host variables | Matrix identity, dependencies, ownership and potentially sensitive values |
| Matrix-owned CLI actions | Preserve association with the correct matrix; commands may contain secrets |
| Legacy SSH command sets | Compatibility/import handling; avoid creating a second competing library |
| FortiGate connection profiles | Include connection metadata and deliberate API credential handling |
| FortiAuthenticator connection profiles | Include connection metadata and deliberate credential handling |
| RADIUS server profiles/shared secrets | Secret distribution rules |
| RADIUS test credentials | Secret distribution rules |
| Other credential stores | Apply the SNMP UUID dependency pattern with their own ownership and validation rules |

Sources: `remote_connections.py`, `ssh_commandlets.py`, `profiles.py`, and their
portable backup adapters. Same-named local users are not automatically the same
owner. References must resolve by stable identity, never silently by display name.

Previously discussed folder behavior: carry the shared object's full path;
required ancestors must be represented in sync. A shared folder can also contain
local-only objects. Handle parent removal and concurrent moves explicitly.

## Automations and certificate definitions

| Model | Additional work before rollout |
| --- | --- |
| Automation conditions | Stable references to supporting profiles/credentials |
| Automation actions | Referenced objects, secrets, and instance-specific resources |
| Automation schedules | Separate portable timing definitions from local activation/timezone context |
| Automation definitions/workflows | Dependency consistency and explicit execution placement/activation |
| PKI server profiles | Referenced credentials and trust configuration |
| Certificate templates | Stable server/template references |
| PKI credentials | Secret distribution rules |
| Managed certificate enrollment/renewal definitions | Separate definition sharing from execution and machine-specific destinations |

Sources: `automation.py`, `certificate_automation.py`, and
`configuration_backup_stores.py`. Recommendation: receiving a definition must not
enable execution on every replica. Issued certificates/private keys and job state
are not ordinary configuration objects.

## Stored data that needs a separate scope decision

| Area | Recommendation |
| --- | --- |
| Cases, notes, evidence and attachments | Separate replication rules for ownership, append-only evidence, sizes and retention |
| Datastore files, scripts and artifacts | Explicit file replication with quotas and transfer handling |
| Access profiles | Potential future central policy; do not implicitly replicate users/passwords/assignments |
| SMTP delivery settings | Fleet policy decision, with secret handling |
| Toolkit timezone | Fleet policy decision; affects scheduling |
| Dashboard layout and personal appearance/navigation preferences | Preference portability rather than ordinary tool MSOs |

Keep runtime and device identity local: job queues/results/history, live sessions,
terminal scrollback, logs/audit history, locks/PIDs, enrollment identities,
pairing tokens, CA/private installation keys, listeners/service configuration,
network interfaces, serial-device paths, and OS/hardware-specific settings.
They may have backup or future management features without becoming MSOs.

## Delivery sequence and acceptance

1. Expand the central MSO page to list shared objects and filter conflicts/status
   across supported types. Keep per-tool controls compact. A future manual network
   sync control belongs here; existing **Refresh profiles** only reloads editor data.
2. Add the simple profile/list adapters, beginning with DNS, then the remaining
   first-table models. Reuse the Ping protocol and withdrawal behavior.
3. Add folders, libraries and referenced definitions with stable dependency handling.
4. Add credential-bearing objects and automation/certificate definitions after
   deciding ownership, secret delivery, and activation behavior.
5. Treat evidence/files and global settings as separate decisions rather than
   silently including everything persisted on disk.

For each model: inventory the whole payload and references; register validation,
permissions, migration, status and readable conflict comparison; verify create,
edit, rename, duplicate, offline conflict, withdrawal and deletion in both
directions; verify recovery/import identities and that receiving never executes
work. Preserve existing local data and any private visibility. Test the UI locally
before building and distributing the next pilot bundle.
