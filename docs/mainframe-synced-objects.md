# Mainframe Synced Objects — Ping pilot

The v0.25.1 development build introduces MSO for saved **Ping profiles**. Other
saved lists, terminal folders and definitions, credentials, automations, cases,
and files do not sync in this pilot. v0.25.0 remains the published stable release.

## Using it

Connect an Agent to a Mainframe, or use the Mainframe itself. In Ping, select or
create a saved profile, enable **MSO · Sync with Mainframe**, and save. The profile
is shared with the whole enrolled fleet; there are no destination selectors.
Existing and newly created profiles remain local unless MSO is enabled.

Create, rename, edit, disable MSO, or delete from any participating instance using
its existing Ping permission. Origin identifies where an object began; it does
not restrict editing. Receiving a profile never starts Ping or changes an active
run. The receiving machine's installed Ping engine still determines which target
counts and timeouts it can execute.

The compact status shows Local, Pending, Synced, or Conflict. Pending changes
remain on disk while offline and retry through the enrollment worker. Synced
means the Mainframe accepted this revision; it does not assert every offline
Agent has received it. Use **Refresh profiles** to discover newly received items
or explicitly load a changed saved version. Background status checks preserve
unsaved editor contents.

![Compact MSO controls in the Ping profile manager](images/mso-ping-controls.png)

## Conflicts in one place

**Review conflicts** opens the shared **MSO conflicts** page. It is also available
under the Ping profile's More actions menu. Resolution controls live there,
not in each tool's editor. The pilot page shows conflicts on the instance you
are currently using, including through a Mainframe agent tab. It cannot inspect
an offline Agent's unsent draft.

Compare the saved local and fleet versions, then choose **Use fleet version** or
**Keep saved local version**. These choices use saved data, not an unsaved editor
buffer. Duplicate first in Ping if you want an independent local copy. A deleted
shared object cannot be resurrected by a stale offline edit: accept the removal
or retain a local duplicate. If another change arrives while reviewing, refresh
the conflict before choosing again.

Different UUIDs with the same name are never silently merged. An incoming
collision appears with an identifying suffix and a conflict. Rename the existing
local profile, then use the fleet version, or explicitly keep the suffixed name.

![Central MSO conflict comparison](images/mso-conflicts.png)

## Removing or leaving

- **Disable MSO:** keep an independent local copy on the acting instance and
  remove the shared replicas from the Mainframe and other Agents as they sync.
  The local copy gets a fresh UUID. The confirmation states this fleet-wide effect.
- **Delete an MSO:** remove the shared profile everywhere as peers sync, without
  retaining a new local copy. Concurrent offline changes remain explicit conflicts.
- **Duplicate:** always create a fresh local object, even when the source is MSO.
- **Leave/change coordination role:** preserve available profiles as independent
  local objects with new UUIDs and discard their MSO membership. Late replies
  from the old membership cannot reattach them.
- **Revoke an Agent:** existing certificate approval checks stop further sync.
  This pilot does not remotely erase saved data already held by that Agent.

## Compatibility and recovery

Upgrade Mainframe and participating Agents to a build supporting the pilot and
restart their enrollment workers. Older peers can remain enrolled but do not
sync MSOs. The Mainframe advertises MSO protocol support before an Agent attempts
sync. Sync errors are separate from an otherwise healthy Agent connection.

Ping profiles migrate once from `ping_profiles.json` to the owner-readable
`mso.sqlite3` database. The legacy JSON file is retained but is no longer the
active Ping store. Do not edit it to change profiles after migration. Other
profile stores keep their existing formats.

Portable configuration exports contain profile values, without fleet identity
or membership. Imported profiles are independent local objects. Replacing or
merging a Ping library with active, pending, or conflicted MSOs is rejected:
resolve/withdraw those objects first. A failed multi-group import restores the
original UUIDs and pending operations. Recovery points include the SQLite store
and its matching code. Restoring an older Mainframe may require explicit
reconciliation if an Agent has a cursor beyond the restored history; this pilot
does not silently reset that cursor or support moving Agents between Mainframes.

## Framework boundaries

The shared store, authenticated exchange, revision checks, durable proposals,
acknowledgements, tombstones and membership epoch are independent of Ping data.
Types are registered with explicit payload validators; adding a new type also
requires a permission-aware UI/storage adapter and its own migration/tests.
There is no arbitrary file or secret replication.

Each exchange carries at most four proposals and four changed records. A shared
object is limited to 64 KiB; Ping accepts up to 250 targets. The pilot retains up
to 5,000 shared identities, including deletion tombstones, and 10,000 recent
operation receipts. Tombstones prevent stale resurrection. Reaching the identity
limit produces an explicit error; automatic tombstone retirement and fleet-wide
conflict aggregation are outside this pilot.

## Two-instance acceptance

1. On Mainframe, enable MSO on a disposable Ping profile and save. On the Agent,
   refresh profiles and verify targets/timing, then edit its name or targets and
   save. Refresh on Mainframe and verify the change without starting Ping.
2. Disconnect the Agent; save a profile edit there and another edit to the same
   profile on Mainframe. Reconnect, open Review conflicts on the Agent, compare
   both versions and resolve. Confirm the chosen version on both instances.
3. Disable MSO on the Agent for a Mainframe-created profile. Confirm it becomes
   local there and disappears on Mainframe. Repeat with shared Delete and verify
   both copies disappear. Duplicate an MSO and verify the duplicate stays local.
