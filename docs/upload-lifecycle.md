# Upload lifecycle

Web Datastore uploads and incoming TFTP, SFTP, SCP, and FTP transfers use the
same `LocalDatastore.begin_upload()` lifecycle. `write()` accepts sequential
bytes, `commit()` publishes the completed file, and `abort()` discards it.
Closing the stream or leaving its context without committing always aborts.

## Storage and concurrency

Unfinished files live under the owner-only `instance/.upload-reservations/`
directory, outside the folders served to clients. The instance staging area and
upload destination must share a filesystem; an upload to a separately mounted
destination is rejected before receiving content. Files are published with
owner-only permissions. An existing destination remains available during a
replacement upload. No-overwrite publication uses an atomic hard link, so a
last-moment competing creation cannot be overwritten. Replacements reject
changes to the destination or its parent directory detected during the transfer.

A stable registry lock coordinates independent worker processes on supported
local Unix filesystems. It covers filesystem operations and accounting, never
network reads. Each active upload holds a separate owner lock. The next upload
operation reclaims staging from processes that have exited. This also applies
to stale staging restored from a recovery point: uploads are never resumed.
Private staging is excluded from portable configuration backups.

Reservations account for the Datastore quota and the configured free-disk
reserve across transfer roots. A replacement's old bytes are credited only to
that replacement; other uploads cannot spend a hoped-for reduction before it
commits. Known SCP lengths are reserved up front. Unknown lengths reserve
capacity in growing windows, up to 64 MiB per extension. Buffers are bounded at
256 KiB per upload. Directory scans occur at reservation changes and commit,
rather than once per packet. Every buffer flush checks current disk space.

These guarantees coordinate uploads using this API. Other toolkit writers and
manual filesystem changes can still consume space independently; reservation
extensions and commit recheck actual usage. Filesystem allocation overhead and
external writers prevent an absolute free-space guarantee. Multi-host shared
filesystems are not certified for this locking model.

## Protocol completion

- SFTP commits on an explicit file CLOSE. Session teardown first aborts its
  unclosed upload handles. Invalid offsets and write failures invalidate the
  upload, preventing a later CLOSE from publishing a prefix.
- SCP checks the declared length and the client's final status before commit.
- TFTP writes accepted blocks through the shared lifecycle and commits before
  acknowledging the final block. Existing destinations can be rejected before
  the initial acknowledgement.
- FTP commits before sending its final successful completion response. Storage
  and publication failures return an error; partial transfers are discarded.
  Append and restart uploads are unsupported.

An interrupted connection after publication but before the final response can
leave a completed file whose client did not receive confirmation. Check the
stored destination before retrying. Atomic publication does not provide
exactly-once delivery or a power-loss durability guarantee for the directory
entry. No database or configuration migration is required.
