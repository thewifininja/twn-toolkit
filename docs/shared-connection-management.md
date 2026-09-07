# Shared Remote Terminal management

The same authenticated permissions apply locally and through a Mainframe GUI
tunnel. A local account and a delegated Mainframe account remain distinct
identities, even if their usernames match.

| Item availability | Owner | Another administrator | Another ordinary user |
| --- | --- | --- | --- |
| Private | Use and manage | No access | No access |
| Admins Only | Use and manage | Use and manage | No access |
| Global | Use and manage | Use and manage | Use only |

Management includes editing and deleting hosts, empty folders, and unused
credentials, and bulk editing items within one owner's library. Stored passwords
remain write-only: a blank password preserves the existing secret; supplying a
replacement changes it. Normal host-scoped and credential-availability checks
still apply when connecting.

Editing preserves the object's owner. The audit event records the actual local
or delegated editor separately from the object owner. Only the owner can make a
shared item Private. An administrator may change shared availability between
Global and Admins Only, or use inheritance when the parent policy permits it.

Private dependencies are protected too. Shared management cannot select another
owner's locations or credentials, modify a hidden credential through its host,
or change a shared folder's inherited policies when doing so would affect private
descendants. A shared credential used by a private item cannot be changed through
shared management. Folder deletion still requires an empty folder; credential
deletion still requires removing its assignments first. Rejected edits roll back
all parts of the request, including associated visibility and credential updates.

Creating and importing items, adding children, and duplicating remain operations
within the creator's own library. Cross-owner moves, ownership transfer, shared
creation namespaces, and cross-instance synchronization are separate features;
shared editing does not implicitly perform them. The dialogs offer locations and
credentials from the existing object's library and hide duplication for shared
items the editor does not own.

Upgrade and restart the Agent web/distributed workers together with the Mainframe
web code when testing this feature through a tunnel. Older peers can still show
shared items without the new management controls or reject a shared edit. No
re-enrollment or ownership migration is necessary.
