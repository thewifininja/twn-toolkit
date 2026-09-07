# MAC cleanup previews

FortiAuthenticator MAC cleanup requires a preview before either removing group memberships or deleting devices globally. The preview retains the selected profile, group and action and displays the profile alongside the group. Select any subset of its candidates and type the confirmation for that selected count.

Two opaque signatures use the shared 15-minute preview policy:

- The target signature binds the user, toolkit instance, full profile configuration, group URI and action. Execute validates it before constructing an appliance client.
- The candidate signature also binds the reviewed device IDs, MAC addresses, names, membership identities and other groups. Execute reloads current memberships and devices and validates this snapshot before any deletion. Collection ordering alone does not invalidate it.

Changes to any reviewed candidate, including unselected candidates or group identities with unchanged display names, require a fresh preview. Existing eligibility checks and typed confirmation still apply. Tokens contain keyed digests, not profile credentials or candidate records. Pages opened before this change require a fresh preview.

These signatures expire but are not one-time execution receipts or appliance locks. An external change after validation can still race execution. Partial or uncertain operations must be reconciled against current appliance state before rebuilding a preview and retrying. Global deletion retains its existing cross-group warning and per-target results. Device operations remain synchronous; this change does not close the separate operation deadline and scaling findings.
