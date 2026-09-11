# MSO rollout inventory

Inventory of current saved models, checked against the profile stores, portable
backup registrations, Remote Terminal libraries, and automation/certificate
stores. Development v0.25.5 implements the saved lists and tool libraries below,
including credentials. Automations and Certificates/PKI are deferred.

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

| Model | Implementation |
| --- | --- |
| Remote Terminal folders/full paths | UUIDs, bidirectional moves/renames, complete ancestor dependencies |
| Remote Terminal SSH/Telnet definitions | Global/Admins Only; private objects and serial consoles stay local |
| Remote Terminal credentials | Protected secrets, stable references, host-scoped withdrawal |
| Bulk SSH matrices and per-host variables | One protected shared matrix object |
| Matrix-owned CLI actions | Included in the matrix revision and conflict comparison |
| Legacy SSH command sets | Compatible local source for copying actions into matrices |
| FortiGate profiles/API keys | Implemented; default selection remains local |
| FortiAuthenticator profiles/credentials | Implemented; default selection remains local |
| RADIUS servers/shared secrets | Implemented |
| RADIUS test credentials | Implemented |

Sources: `remote_connections.py`, `ssh_commandlets.py`, `profiles.py`, and their
portable backup adapters. Same-named local users are not automatically the same
owner. References must resolve by stable identity, never silently by display name.

Remote Terminal visibility policy is decided: only Global and Admins Only objects
are eligible for MSO. Private objects remain local, including private folders and
credentials referenced by otherwise shareable hosts. The user must explicitly
change those dependencies' visibility before sharing; MSO never broadens it
implicitly. Inherited visibility is resolved through the full folder path. A
shared folder can contain private, local-only children. No cross-machine user
identity mapping or username matching is included in this rollout.

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

## Outside the current rollout

| Area | Recommendation |
| --- | --- |
| Cases, notes, evidence and attachments | Excluded by the release owner |
| Datastore files, scripts and artifacts | Excluded by the release owner |
| Access profiles | Potential future central policy; do not implicitly replicate users/passwords/assignments |
| SMTP delivery settings | Excluded by the release owner |
| Toolkit timezone | Fleet policy decision; affects scheduling |
| Dashboard layout and personal appearance/navigation preferences | Excluded by the release owner |

Keep runtime and device identity local: job queues/results/history, live sessions,
terminal scrollback, logs/audit history, locks/PIDs, enrollment identities,
pairing tokens, CA/private installation keys, listeners/service configuration,
network interfaces, serial-device paths, and OS/hardware-specific settings.
They may have backup or future management features without becoming MSOs.

## Remaining work and acceptance

The authorized tool-library rollout is implemented. A central inventory/manual-sync
pane remains future work; central conflict review already covers all supported
kinds. Automations and PKI require their own activation and dependency design.
Other excluded data remains outside MSO.

For acceptance, use disposable objects in each tool, verify both directions,
rename and edit, then test offline conflict review and withdrawal. Remote Terminal
checks should include full folder paths, inherited credentials, private-dependency
rejection and an administrator editing a received library. Bulk SSH should include
an action edit without executing it. See [MSO behavior](mainframe-synced-objects.md)
for visibility, credential, conflict, migration and backup details.
