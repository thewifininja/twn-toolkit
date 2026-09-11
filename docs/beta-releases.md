# Beta release versioning

Choose the intended GA version before assigning versions to beta installations.
Every beta must have a supported upgrade path to that GA. Installing an ordinary
numeric development version consumes its place in the upgrade ordering, even
when no public release or tag exists. The normal updater requires a strictly
newer version; a GitHub prerelease label does not change that comparison.

## Required policy for future betas

Future beta builds must use explicit prerelease versions and matching annotated
tags, such as `v0.27.0-beta.1`, published as GitHub prereleases. Choose and record
the intended GA target and beta sequence before packaging or installing a pilot.
Do not assume that the next ordinary patch number is available for development,
and do not silently substitute numeric patch versions when prerelease support is
missing. Implement the supported prerelease upgrade path below before the next
beta deployment; any numeric exception requires an explicit release-owner decision.

The v0.25.1–v0.25.6 MSO pilot consumed those installed version positions even
without public tags. The owner accepted that exception because v0.26.0 was the
next GA. It is historical context, not permission to repeat the practice.

## Current updater limitations

The bundle parser currently accepts only three numeric components (`X.Y.Z`).
Versions such as `0.27.0-beta.1` are **not supported yet**. Normal release discovery
also excludes GitHub drafts and prereleases. Verified local bundles can deliver
numeric development builds through the normal updater and recovery workflow.

If the release owner explicitly approves a numeric exception, keep its pilot
versions below the intended GA version. Do not install the intended GA number as
a beta: a later bundle with that same number will not qualify as a normal upgrade. If a pilot
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
`0.27.0-beta.2 < 0.27.0-beta.10 < 0.27.0-rc.1 < 0.27.0`, successful beta-to-beta
and beta-to-GA upgrades, rejection of equal versions and downgrades, and recovery
with matching code and data. Include a verified upgrade from an existing numeric
installation; updating only the candidate parser does not make an older updater
understand prerelease bundle versions.

## v0.26.0 transition

The MSO pilot used numeric development versions **v0.25.1–v0.25.6**. The release
owner selected **v0.26.0** as GA; it sorts above every pilot version, so those
installations can use the normal updater once the verified stable bundle is
published. Do not retrospectively rename installed pilots or move existing tags.
