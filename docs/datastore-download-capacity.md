# Datastore ZIP download capacity

Download selected builds a private, temporary ZIP in the instance's shared upload staging area. Its writes acquire the same cross-process free-space reservations as uploads, transfer staging and diagnostic exports. The lease remains held while the response streams, and response close removes the ZIP and releases capacity. An exited worker's staging is reclaimed by the existing abandoned-upload cleanup.

The completed ZIP must fit the configured maximum upload size, including compression and ZIP metadata. A selection can contain at most 500 selected roots and 10,000 expanded files and folders. Nested duplicate selections retain their existing behavior. The toolbar shows the ZIP size and entry limits. Archive construction remains synchronous; this change does not add a background download job.

Temporary downloads do not consume the logical datastore publication quota, since no file is published there. They do consume physical space and respect the configured minimum free-disk reserve. Build failures and failed response setup clean staging immediately; an interrupted or completed response releases it on close. Existing source files are preserved. These guarantees cover cooperating reservation users; databases, logs and other OS writers do not share a universal disk quota.
