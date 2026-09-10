# Beta release versioning

Choose the intended GA version before assigning versions to beta installations.
Every beta must have a supported upgrade path to that GA. Installing an ordinary
numeric development version consumes its place in the upgrade ordering, even
when no public release or tag exists. The normal updater requires a strictly
newer version; a GitHub prerelease label does not change that comparison.

## Current updater limitations

The bundle parser currently accepts only three numeric components (`X.Y.Z`).
Versions such as `0.26.0-beta.1` are **not supported yet**. Normal release discovery
also excludes GitHub drafts and prereleases. Verified local bundles can deliver
numeric development builds through the normal updater and recovery workflow.

Until prerelease support is implemented, keep numeric pilot versions below the
intended GA version. Do not install the intended GA number as a beta: a later
bundle with that same number will not qualify as a normal upgrade. If a pilot
has already reached or exceeded the intended GA number, choose a higher GA
version or restore a suitable recovery point first. Do not bypass version checks
or relabel an installed build to conceal a downgrade.

Recovery restores code and saved instance data together. Preserve newer data
before rolling back; for shared objects, consider changes already synchronized
to other peers. A recovery point is not an automatic fleet-wide rollback.

## Future prerelease support

Before deploying suffix-based beta versions, implement and verify the complete
path through version parsing, comparison, bundle names and manifests, installation,
release discovery, tag CI, and release publication. Define explicit beta opt-in
without offering prereleases to users on the stable channel.

Regression coverage must prove ordering such as
`0.26.0-beta.2 < 0.26.0-beta.10 < 0.26.0-rc.1 < 0.26.0`, successful beta-to-beta
and beta-to-GA upgrades, rejection of equal versions and downgrades, and recovery
with matching code and data. Include a verified upgrade from an existing numeric
installation; updating only the candidate parser does not make an older updater
understand prerelease bundle versions.

## Current MSO planning

The MSO pilot has used numeric development versions through **v0.25.3**.
**v0.26.0 is the likely next GA target**, subject to the release owner's final
scope decision. It sorts above those pilot versions, so they can upgrade normally
once a verified GA bundle is available. This planning note does not change the
installed version or authorize publication.
