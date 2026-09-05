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

## Administrator controls

**Settings → Operations → Maximum incoming file size** applies to new web,
TFTP, SFTP, SCP, and FTP uploads. The default remains 1024 MiB; the supported
range is 1–65536 MiB. Each upload snapshots this limit when it begins. A smaller
explicit caller limit still applies, so this setting cannot bypass narrower
case/import policies. Web upload requests allow the configured total plus
1 MiB of multipart overhead. Other web endpoints retain their existing request
limits. Saving this setting does not require a service restart.

**Local Tools → File Transfers → SFTP / SCP → Connection and resource limits**
controls the SSH listener. Saving these settings restarts it and disconnects
active clients. Older settings files receive the following defaults without a
migration. These are adjustable starting policies, not protocol requirements.

| Setting | Default | Supported range | Purpose |
| --- | ---: | ---: | --- |
| Connections | 32 | 1–256 | Bound accepted clients, including authentication and cleanup. |
| Connections per client IP | 4 | 1–256, no more than total | Limit one client; NAT clients share an allowance. |
| Channels per connection | 4 | 1–32 | Permit several transfers while bounding subsystem/command workers. |
| Open handles per SFTP channel | 16 | 1–256 | Bound file and directory handles; closing releases capacity. |
| Directory listing entries | 10000 | 100–100000 | Bound materialized listings; oversized listings fail without truncation. |
| Authentication deadline | 30 seconds | 1–300 | Includes handshake and authentication; keepalives cannot extend it. |
| Idle timeout | 30 seconds | 1–3600 | Expire idle channels and unused authenticated connections. |

The connection/channel defaults accommodate several devices and sessions while
putting a finite ceiling on work. The idle default preserves the previous SCP
idle allowance; the authentication and listing defaults are conservative
starting choices to tune for host capacity and device behavior. Maximum values
are validation bounds, not a claim that every supported host can sustain all
of them simultaneously. Lower connection/channel/handle counts on smaller
hosts. Temporary file-descriptor exhaustion pauses admission instead of
terminating the listener.

Idle activity means completed SFTP requests or SCP network progress. Slow
trickles that never complete an SFTP packet do not keep a session alive.
Active transfers may run longer than the idle timeout. Repeated subsystem or
exec requests on a channel cannot create extra workers. Shutdown and disconnect
hold the connection allowance until owned workers finish cleanup.

Internal tuning stays centralized in code: upload buffers/reservation windows
are in `uploads.py`; SFTP packets are bounded to 1 MiB and reads to 64 KiB in
`ssh_transfer_worker.py`. These are implementation bounds rather than operator
policy. Atomic publication and abort-on-interruption remain mandatory.

SFTP CLOSE now returns publication failures on the wire. Some clients,
including Paramiko's `SFTPFile.close()`, suppress these errors; operators should
also consult transfer history. Download history starts at completion/abort,
counts bytes actually read, and marks success only after an explicit CLOSE
with complete sequential coverage. Arbitrary out-of-order reads can be recorded
as incomplete when full coverage cannot be confirmed.
