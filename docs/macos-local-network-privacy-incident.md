# macOS local-network privacy incident and service follow-up

Status: root-retained bounded network flow passed CIDR-free manual and scheduled production acceptance; cold-boot gate remains for v0.17.0 GA
Priority: high before the next macOS service-lifecycle change
Observed: 2026-08-07 through 2026-08-10 on production v0.16.6-v0.16.9 candidates; final controlled probes on macOS 15.1.1 (24B91)

## Summary

The production macOS instance abruptly stopped reaching five switches over SSH.
Every automation SSH action failed with a Paramiko error similar to:

```text
NoValidConnectionsError: [Errno None] Unable to connect to port 22 on 192.168.1.101
```

Interactive SSH from Terminal continued to work. A packet-capture action added
around the same time completed successfully, which initially made concurrent
capture the leading suspect. The capture did not cause the failure. The toolkit
web and automation processes were being denied local-network connections by
macOS before an SSH handshake began.

The operational mitigation was to add the directly connected Ethernet subnet
to macOS's system-wide local-network exception and restart the Mac:

```bash
sudo defaults write com.apple.network.local-network \
  AllowedEthernetLocalNetworkAddresses -array "192.168.1.0/24"
```

This command was safe in this incident because the preference domain did not
previously exist. Any product helper must read and merge existing values rather
than overwrite them. Apple documents that this setting applies to every program
on the Mac for the specified network and requires a restart:

- <https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy>

## Evidence

- Manual OpenSSH connected to the switch successfully.
- A Python socket connection launched from Terminal received the switch's SSH
  banner.
- Paramiko launched from Terminal completed its client handshake.
- The toolkit TCP Port Scanner, running in the web worker, failed immediately
  with `[Errno 65] No route to host` for `192.168.1.101:22`.
- The host had a valid direct route to `192.168.1.101` through active Ethernet
  interface `en6`; the Mac's address on that link was `192.168.1.254/24`.
- All five switches failed together, ruling against an individual switch SSH
  configuration or credential problem.
- No `tcpdump` or packet-capture worker was left running after the capture.
- Retained automation history contained an SSH-only failure immediately before
  the SSH-plus-PCAP failure. PCAP concurrency was therefore not required to
  reproduce the problem.
- Toggling the visible Python entry under System Settings > Privacy & Security >
  Local Network off and on did not restore toolkit access.
- Starting the toolkit through the interactive Terminal context did not change
  the result because its long-lived workers subsequently daemonized and
  detached.
- After the CIDR exception and reboot, the toolkit worker reported port 22 open
  in 3.4 ms.
- The final simultaneous validation completed successfully: PCAP captured 228
  packets in 30.1 seconds and SSH collection succeeded on all 5 of 5 switches.
- Production was upgraded to v0.16.8 and its calendar scheduler then completed
  a parallel 30.3-second PCAP containing 12,377 packets plus SSH collection on
  all 5 of 5 switches while the Ethernet CIDR exception remained present.
- The exception was subsequently removed and the Mac restarted. A manual
  parallel PCAP and SSH automation then reproduced the split result: PCAP
  succeeded, while SSH returned Darwin errno 65 for the first switch. This
  proves that the v0.16.8 foreground-child design did not independently restore
  local-network access.
- The first v0.16.9 candidate installed all seven direct jobs successfully.
  Gunicorn, automation, and supervisor were UID 501 processes with PPID 1, but
  the toolkit TCP scanner still returned errno 65 in 1.2 ms while the exact
  virtualenv Python executable connected from Terminal.
- Every application property list contained `UserName=admin` and
  `GroupName=staff`. Apple Developer Technical Support specifically excludes a
  LaunchDaemon using `UserName` for a role account from the automatic daemon
  allowance discussed in TN3179.
- A temporary root LaunchDaemon parent that spawned the same Python probe as
  UID 501 still returned errno 65. This disproved the idea that retaining a
  privileged ancestor was sufficient; macOS attributed the operation to the
  unprivileged Python child.
- A temporary root LaunchDaemon running `/usr/bin/nc` as the connecting process
  reached `192.168.1.101:22` successfully. Both temporary jobs were unloaded
  after their result was captured.

## Cause assessment

The proven failure mechanism was macOS Local Network Privacy returning
`EHOSTUNREACH` to a background toolkit process. The exact privacy-state event
that changed cannot be proven from retained macOS or toolkit history.

The original service layout had a fragile responsibility boundary. Its
LaunchDaemon started `twn service-run`, but the managed processes detached from
that launchd-owned process tree:

- Gunicorn is started with `--daemon` in `twn`.
- The automation scheduler is started with `--daemon` in `twn`.
- Automation, supervisor, and transfer workers use a POSIX double-fork and
  `setsid()` implementation.

Direct jobs removed that lifecycle defect but did not remove the privacy denial.
Apple exempts root processes and qualifying launchd daemons, but separately
tracks the responsible code performing the operation. Apple DTS guidance adds
the critical qualification that a LaunchDaemon using `UserName` for a role
account is not in the automatic system-daemon case. Production matched that
condition exactly: direct Homebrew Python processes were UID 501 and failed,
regardless of whether their parent was PID 1 or a retained root shell. Only the
process that actually called `connect()` while root received the exemption.

A service reload associated with deploying or configuring the new PCAP
workflow likely exposed the pre-existing privacy fragility; the PCAP operation
itself did not alter routes, SSH, or persistent privacy configuration.

The Python binary dated to 2026-03-02 and the retained OS installation history
did not show a same-day system update, so neither was a direct same-day trigger.

## Engineering response

### 1. Keep long-lived workers under direct launchd supervision

Do not self-daemonize when the toolkit is already running under a service
manager. Required macOS design:

1. Install separate LaunchDaemons for the web process, automation scheduler,
   supervisor, and enabled transfer services.
2. Run each service in the foreground and let launchd own restart behavior,
   standard streams, and process lifetime.

The v0.16.8 intermediate design kept `twn service-run` in the foreground on
macOS and launched Gunicorn, the automation scheduler, supervisor, and enabled
transfer services as non-daemonizing children. Foreground workers wrote the
same PID files as daemon mode, and shutdown snapped the web PID before stopping
sibling workers so Gunicorn cleanup could not race the launcher. The
CIDR-removal test proved that this process ancestry was not equivalent to being
started by launchd.

The v0.16.9 candidate retained the coordinator only for lifecycle and upgrade
handoffs and installs separate system LaunchDaemons for web, automation,
supervisor, TFTP, SFTP/SCP, and FTP. Each job invokes `twn launchd-run ROLE`,
performs bounded setup, and then `exec`s the final foreground process without a
fork. Thus Gunicorn and every Python worker retain launchd as their actual
parent. This remains the correct lifecycle model, but the production CIDR-free
test proved it is not by itself a Local Network Privacy fix when `UserName`
selects the non-root service account. Owner-only pause, boot-generation,
web-generation, and listener-enable markers preserve non-root start, stop,
restart, settings, upgrade, rollback, and cold-boot behavior.

Manual launches and Linux service mode retain their existing daemon behavior.
Existing macOS installations require one administrator-approved
`sudo ./twn service install` after the code upgrade because only root can create
the additional files in `/Library/LaunchDaemons`.

Relevant code:

- `twn`: `start_automation`, Gunicorn construction, `start_supervisor`, and
  `service_run`
- `twn_toolkit/service_cli.py`: `render_launchd_plists`
- `twn_toolkit/automation_worker.py`: `_daemonize`
- `twn_toolkit/supervisor_worker.py`: `_daemonize`
- `twn_toolkit/tftp_worker.py`, `ftp_worker.py`, and
  `ssh_transfer_worker.py`: worker daemonization

### 2. Use a bounded root TCP connector

Do not run Gunicorn, automation, Paramiko, or the complete toolkit as root.
Install one native root LaunchDaemon whose authority is limited to outbound TCP
connection setup and a fixed opaque relay:

1. Listen on a mode-0600 Unix socket owned by the configured service account.
2. Verify every client with the kernel-provided peer UID.
3. Accept only bounded TCP host, port, address-family, and timeout fields.
4. Perform `connect()` as root, create a local socket pair, clear supplemental
   groups, and return the caller's local endpoint with `SCM_RIGHTS`.
5. Keep the remote socket in the bounded root child for the complete flow and
   blindly copy bytes between it and the local endpoint. Never parse, log,
   persist, authenticate, or execute relay traffic.
6. Keep SSH credentials, host-key policy, authentication, commands, protocol
   parsing, transfer handling, and output storage in the normal caller.

The helper is a small universal native executable installed root-owned beneath
`/Library/PrivilegedHelperTools`; it never executes toolkit code as root.
Managed Python workers opt in through an absolute Unix-socket environment
variable and a process-wide socket subclass. Manual launches and Linux never
install the shim.

The first v0.16.10 production automation exposed a separate handoff edge case
after the privacy failure was resolved. System Diagnostics reported the
connector ready and the toolkit TCP scanner opened switch port 22, but Paramiko
reported `Error reading SSH protocol banner`. Controlled probes showed:

- a direct Terminal socket received `SSH-2.0-OpenSSH_9.9`;
- the raw descriptor returned through `SCM_RIGHTS` received the same banner;
- duplicating that descriptor over the Python placeholder socket produced an
  immediate EOF; and
- detaching the placeholder and initializing the socket object with the
  returned descriptor received the banner normally.

The v0.16.11 shim therefore adopted the returned descriptor directly and closed
only the unused placeholder.

The final production acceptance run exposed a deeper limitation in that model.
With the CIDR exception still absent, a simultaneous PCAP captured 7,711
packets, but the scheduler reported `Error reading SSH protocol banner` for all
five switches. Controlled probes established that:

- raw connector, adopted-socket, bare Paramiko, and five-way concurrent
  Paramiko handshakes all received `SSH-2.0-OpenSSH_9.9` when launched from
  Terminal;
- the exact saved SSH action, run from Terminal with its encrypted production
  configuration, succeeded on three switches and lost two banners; and
- the same action in the background automation scheduler lost all five
  banners, even though its LaunchDaemon had the connector environment and the
  connector socket was ready.

That evidence invalidated Terminal-side descriptor probes as proof of the
background data path. Apple documents that macOS tracks the responsible code
performing a local-network operation, automatically exempts root and proper
system LaunchDaemons, and treats user-context agents differently. Direct jobs
using `UserName=admin` remain in the problematic role-account context. See
[TN3179: Understanding local network privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).

v0.17.0 therefore keeps remote socket creation in the root LaunchDaemon but no
longer hands that remote descriptor to Python. The helper creates a local socket
pair, returns one local endpoint, and relays opaque bytes through the other
endpoint for a bounded lifetime. An intermediate candidate dropped UID before
starting the copy loop; a manual run happened to pass 5 of 5 switches, but two
calendar runs succeeded on only 4 of 5 and then 2 of 5 because banner arrival
remained timing-dependent. Every failed banner left one matching relay child
and TCP session alive because the child inherited a termination handler and
waited for the silent remote half indefinitely.

The final helper retains root only in the small per-connection copy loop, clears
supplemental groups, restores default termination signals, and closes an idle
half-closed connection after five seconds. It necessarily copies the raw stream
through bounded memory, but does not interpret, log, persist, authenticate, or
execute it; application authentication, commands, protocol state, and stored
output remain in the unprivileged toolkit. For SSH and TLS, post-handshake
credentials and commands remain encrypted on that stream. Plaintext protocols
may exist transiently in the fixed relay buffers and receive no additional
parsing or storage from the helper.

The first run with that final helper captured 15,078 packets in 30.3 seconds
and completed SSH collection on four switches, but SW2 exceeded Paramiko's
eight-second banner timeout. The root relay itself was healthy: three
concurrent five-switch raw-banner rounds and three concurrent five-switch bare
Paramiko rounds all succeeded (15 of 15 in each test family), including SW2.
The failed automation nevertheless left exactly one root relay child alive.

Inspection of Paramiko 4.0 identified the cleanup gap: `Transport.close()`
returns without closing its socket when banner negotiation has already marked
the transport inactive. The toolkit's `SSHClient.close()` call therefore could
not half-close the local relay endpoint, so the helper's five-second
half-close timer never began. The shared client path now closes the captured
transport socket explicitly, allows 15 seconds for the server banner, and
retries one banner failure with a fresh pre-authentication connection. SSH
collection, SFTP, and SCP all use that path. This is bounded to one retry and
does not replay an authenticated command or file operation.

The final production candidate (SHA-256
`99c3e5275a7b27c7d7283df8208ad3bc3494e238980e6761412498082c5aa289`)
then passed both acceptance paths without the CIDR fallback. A manual
simultaneous run captured 12,021 packets and collected SSH from all five
switches. A real calendar-triggered service run captured 5,949 packets in 30.0
seconds and also collected SSH from all five. All relay children created by
those final runs exited; only the known child from the earlier pre-fix timeout
was still present during the immediate post-run process check. It exited at the
helper's 3,700-second lifetime cap, leaving only the root listener. The
temporary calendar rule was restored to its original daily 09:43 AM time and
the automation was re-armed.

The first cold-boot functional pass also succeeded before any interactive
Terminal launch: launchd restored every managed component, diagnostics showed
the connector Ready and BPF access Ready, the toolkit scanner opened SSH port
22 on all five switches, and a simultaneous automation captured 8,264 packets
while collecting SSH from all five. The required post-run process audit then
found six retained root relay children consuming roughly 42% CPU each. Five
had been created together during the earlier scanner check and one began later.

The children were not blocked on network traffic. Once one side had closed,
macOS continued returning `POLLHUP` for a descriptor whose relay direction was
already complete. Because `poll()` returned immediately instead of timing out,
the original five-second timeout never fired and the root child spun until its
3,700-second hard cap. The corrected helper removes descriptors with no
requested events from the poll set and maintains a monotonic deadline measured
from actual reads, writes, EOF transitions, and half-closes. Repeated readiness
without progress therefore cannot extend the deadline. A native harness now
holds the application endpoint open after the remote closes and requires the
relay to exit normally within the shortened test deadline. The corrected
helper must pass a second production cold-boot and cleanup check before GA.

This boundary also covers other TCP-based actions that use the shared Python
socket layer, including the TCP scanner, certificate probes, FTP/SFTP clients,
and Requests/urllib3 integrations. UDP, BPF packet capture/replay, and listener
permissions remain separate concerns.

### 3. Diagnose errno 65 explicitly

SSH error formatting now unwraps nested Paramiko connection errors. When one
contains Darwin `errno.EHOSTUNREACH` (65), it identifies macOS Local Network
Privacy as a possible cause, directs the operator to the toolkit TCP Port
Scanner, and explains that a successful Terminal connection is a different
privacy context.

Future diagnostic work should also:

- report the selected route and interface without claiming that a valid route
  disproves the privacy denial; and
- include the service/worker PID, parent PID, executable, macOS version, and
  configured CIDR exceptions in the diagnostics bundle.

Diagnostics should offer probes from both the web worker and automation worker.
A Terminal-originated probe is not equivalent on macOS because Terminal and its
children receive special treatment.

### 4. Provide an explicit administrator fallback

Consider a helper such as:

```text
sudo ./twn local-network allow-ethernet 192.168.1.0/24
```

Requirements:

- validate and normalize IPv4 or IPv6 CIDR input;
- select Ethernet or Wi-Fi explicitly;
- read, preserve, and merge existing array values;
- show that the exception applies system-wide to every program on that network;
- require explicit administrator confirmation;
- explain that a Mac restart is required;
- provide a matching command that removes only the selected CIDR; and
- never apply the exception silently during install or upgrade.

Keep this as a supported fallback even after fixing process ownership because
Apple privacy behavior and unsigned/interpreted responsible-code identity can
change between macOS releases.

### 5. Add regression coverage

Maintain a physical or virtual macOS 15.5+ service test that covers:

- a LaunchDaemon running as a non-root service user;
- the root connector property list without `UserName`, root-owned helper,
  mode-0600 UID-owned Unix socket, peer-UID rejection, root-retained network
  flow, cleared supplemental groups, opaque bidirectional relay, idle
  half-close cleanup, and default child termination behavior;
- a cold boot with no prior interactive Terminal launch;
- toolkit restart, upgrade handoff, rollback, and recovery;
- replacement of the Homebrew Python runtime;
- outbound TCP and Paramiko SSH to a directly connected Ethernet address;
- direct ownership of the `SCM_RIGHTS` local relay endpoint without overlaying
  it on a placeholder, including bidirectional traffic over a real TCP stream;
- the same SSH collection while a bounded PCAP runs in parallel; and
- explicit inactive-transport socket cleanup plus one bounded banner retry
  across SSH collection, SFTP, and SCP; and
- actionable diagnostics for a deliberately denied local-network process.

Unit tests should also verify error unwrapping, CIDR merging/removal, platform
gating, broker protocol bounds and errno propagation, direct-job property lists
and marker conditions, foreground PID files, aggregate launchd health, and
pause/resume behavior across boot generations.

## Upgrade rollback incident and recovery hardening

The first production attempt to install the descriptor-adoption candidate
failed during its installer validation. Automatic rollback then restored a raw
filesystem copy of `automations.sqlite3` whose main file and WAL state had not
been captured atomically. The restored database reported a one-page freelist
mismatch, and the automation worker failed with `database disk image is
malformed`. The updater's hash manifest could prove that the malformed bytes
matched the backup, but not that those bytes formed a valid database.

Both automatically preserved, displaced pre-rollback instances contained
healthy automation databases. Production was stopped, the newest healthy copy
was consolidated through `sqlite3.Connection.backup()`, and every live
top-level database passed `PRAGMA quick_check` before the service restarted.
The malformed live file remains in an owner-only manual recovery directory for
forensics and can be restored if later analysis requires it.

The v0.17.0 recovery path now:

1. omits top-level SQLite main, WAL, and shared-memory files from `copytree`;
2. verifies each live source through SQLite;
3. creates a consistent online backup and switches the snapshot to a
   consolidated delete journal;
4. verifies every snapshot before writing the integrity manifest; and
5. repeats SQLite verification after manifest validation before any restore.

Regression tests keep committed rows that exist only in a live WAL and prove
the recovery point contains them without depending on copied sidecars. They
also reject malformed live sources and hash-matched malformed recovery files.

This database failure was a recovery-point implementation defect discovered
while testing the networking fix; it was not caused by Paramiko, packet capture,
the root connector, or a schema migration.

The successful v0.17.0 production upgrade then exposed a separate handoff race.
The direct automation process and heartbeat were healthy, but its PID marker was
absent, so CLI status and System Diagnostics correctly reported the managed
process set as incomplete. The automation log's malformed-database traceback
was historical; its modification time predated the upgrade by approximately 45
minutes. `launchctl` showed the scheduler running with exit code 0.

An ordinary restart reproduced the recovery gap: cleanup searched only for
legacy `--daemon` workers, so it could not stop a direct launchd scheduler when
the marker needed to identify its PID was already missing. Terminating the
verified admin-owned scheduler let launchd recreate it with a PID marker and
returned diagnostics to Active. v0.17.0 now scopes process matching by module
and exact instance while including both daemonized and direct workers. Restart
and the deferred upgrade handoff use that path, and the handoff performs a
bounded final readiness wait with one exact-instance repair cycle.

## Release and support notes

Suggested release-note text:

> Keeps macOS web and worker processes unprivileged while a bounded native root
> LaunchDaemon performs TCP connection setup and blindly relays each stream
> over a UID-restricted Unix socket. Production
> proved that direct UID 501
> launchd jobs and unprivileged children of a root parent still received Local
> Network Privacy errno 65; only the connecting root process was exempt.

Support guidance for affected existing versions:

1. Confirm the target has a valid route and that Terminal can connect.
2. Reproduce from the toolkit TCP Port Scanner with closed/error results shown.
3. Treat immediate `[Errno 65] No route to host` on macOS as a possible Local
   Network Privacy denial, not proof of a routing failure.
4. Inspect existing `com.apple.network.local-network` defaults before changing
   them.
5. If approved by the administrator, add only the required wired or Wi-Fi CIDR
   and restart the Mac.
6. Re-test from the toolkit worker and then run an end-to-end automation.

After installing v0.16.10 or newer code on a host that predates the connector,
run `sudo ./twn service install` once to install the direct-job set and
protected TCP connector before testing without a CIDR exception. A host that
already completed that installation for v0.16.10 does not repeat it when
upgrading to v0.16.11. It must run the service install again for the final
v0.17.0 build because that release replaces the descriptor-only helper with the
root-retained bounded relay.

Do not recommend running the complete toolkit as root to bypass this policy.

## Separate PCAP configuration observation

The production action was named `en0-pcap-30`, but its successful run captured
on `lo0`. The switch network routed through `en6`. This did not cause the SSH
failure, but future UI work should show interface name, addresses, status, and
loopback classification prominently so an action name cannot obscure the saved
capture interface. Do not automatically change an interface because SPAN and
capture interfaces may intentionally differ from the management route.

## Related scheduled-PCAP import failure

Follow-up testing found a separate service-only failure for PCAP actions started
by ping, calendar, and other scheduler-driven automations:

```text
packet.capture failed: ToolInputError: .../.venv/bin/python: Error while
finding module specification for 'twn_toolkit.packet_capture_exec'
(ModuleNotFoundError: No module named 'twn_toolkit')
```

Manual **Run now** automation executions worked because the web process had the
checkout root as its working directory. The detached automation scheduler calls
`os.chdir("/")`; its PCAP action then started
`python -m twn_toolkit.packet_capture_exec`, so the child interpreter could not
discover the source package from `/`.

The code fix does not rely only on the macOS foreground-worker change. It
invokes `packet_capture_exec.py` by its absolute path so scheduled captures also
work in manual daemon mode and on Linux. Regression coverage executes that
wrapper from an unrelated working directory.

An audit of the other registered automation actions found no equivalent package
import dependency: SSH, remote transfer, syslog, webhook, email, and their
condition evaluators use imported libraries, absolute instance paths, temporary
directories, or executables resolved from the service PATH. Other background
`python -m twn_toolkit...` launches currently provide the checkout root as an
explicit `cwd`: standalone packet-capture workers, managed iPerf server workers,
and upgrade workers. Their launch tests now assert that working-directory
invariant.
