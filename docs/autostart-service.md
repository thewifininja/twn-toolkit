# Autostart service

The toolkit can install an operating-system service that starts at boot, remains
available without an interactive shell, and restarts after an unexpected web
process failure.

```bash
./twn service install
./twn service status
```

Installation requests administrator authorization because it writes an OS
service definition. The toolkit itself runs as the account that invoked `sudo`,
not as root. Pass `--user NAME` when installing from a root shell or when a
different dedicated account should own the service. A root-owned service is
refused unless `--allow-root` is explicitly supplied; normal-user ownership is
the recommended production configuration.

## Before installation

1. Complete a normal `./install.sh` and confirm `./twn status` reports the web
   process, automation scheduler, and worker supervisor running.
2. Choose the account that will own `instance/`, Datastore files, certificates,
   captures, and service logs. The helper refuses an account that does not own
   existing runtime data instead of silently changing ownership.
3. Decide whether the host actually needs packet capture, replay, DHCP Discover,
   promiscuous mode, or ports below 1024. Most toolkit functions do not need
   additional OS network permission.
4. On macOS, confirm the checkout location is service-compatible and provision
   BPF access before expecting packet tools to work.

The service definition stores the installation's absolute path. Move the
toolkit by uninstalling the service first, moving the directory, and installing
the service again. Python virtual environments also contain absolute paths, so
rebuild `.venv` with `./install.sh` after moving an existing checkout.

## Linux, Ubuntu, and Raspberry Pi OS

Linux installation requires systemd. This covers supported Ubuntu releases and
the official Raspberry Pi OS images. The helper installs and enables
`/etc/systemd/system/twn-toolkit.service`:

```bash
./twn service install
./twn service status
```

The default unit is deliberately unprivileged. On a dedicated diagnostic host,
the optional form grants only `CAP_NET_RAW`, `CAP_NET_ADMIN`, and
`CAP_NET_BIND_SERVICE` to the managed service process tree:

```bash
./twn service install --network-capabilities
```

Those capabilities support Linux raw packet replay, packet capture/promiscuous
mode, DHCP client-port access, and listeners below port 1024 without granting
full root access. They are still powerful network privileges; enable them only
on a host and network where toolkit users are trusted. The unit bounds the
capability set and does not modify the virtual environment's Python executable,
so rebuilding `.venv` does not silently remove or spread the grant.

Service-manager output is available through:

```bash
./twn service logs
sudo journalctl -u twn-toolkit.service
```

After installation, verify the application as well as systemd:

```bash
./twn service status
./twn status
```

`service status` proves the unit is enabled and active. `./twn status` proves
the managed web process, scheduler, supervisor, and configured listeners are
healthy and prints the usable URLs. Reboot validation is intentionally simple:
reboot the host, sign back in, and run both commands without manually launching
the toolkit. Raspberry Pi OS uses this same systemd path.

The authenticated **Administration → System Diagnostics** page combines these
views without conflating them. It identifies manual versus boot-managed mode,
shows whether the definition belongs to the checkout currently serving the
page, and reports installed/enabled/active service state alongside the live
launcher, web process, scheduler, and supervisor.

Linux distributions without systemd are detected and left unchanged. A future
adapter can add another init system without weakening the systemd path.

## macOS

macOS installation creates
`/Library/LaunchDaemons/com.thewifininja.toolkit.plist`. A LaunchDaemon starts at
boot even when nobody has logged in; its `UserName` and `GroupName` keep the
toolkit process and instance data owned by the installing account.

Install the toolkit outside macOS privacy-protected user folders. System
LaunchDaemons cannot reliably execute programs beneath `Desktop`, `Documents`,
`Downloads`, iCloud Drive, or `~/Library/CloudStorage`, even when the configured
service user owns those files. A suitable location is `~/twn-toolkit`. The
helper detects protected locations before stopping the current toolkit or
writing a service definition. For a relocated existing checkout, rebuild its
`.venv`; a fresh clone followed by `./install.sh` does this automatically.

```bash
./twn service install
./twn service status
./twn service logs
```

macOS has no direct equivalent to systemd's scoped ambient capabilities. The
service therefore remains unprivileged. Packet capture, packet replay, and DHCP
Discover require an administrator-managed BPF access policy when normal-user
BPF access is not already available. The macOS DHCP backend constructs one
Ethernet/IPv4/UDP Discover through BPF, listens for matching Offers, and never
binds privileged UDP port 68 or sends a DHCP Request.

The Wireshark macOS package's optional ChmodBPF service is one established way
to pre-create BPF devices, grant its `access_bpf` group read/write access, and
preserve that access after reboot. Confirm the account used by the toolkit
service appears in that group and can read/write the devices:

```bash
id -Gn
ls -l /dev/bpf0
```

Restart the toolkit service after changing group membership so launchd applies
the updated supplementary groups. The toolkit reports a focused permission
error when BPF is unavailable and never changes BPF ownership or permissions
automatically. Multicast IGMP compatibility remains separately managed by the
narrow `./twn multicast-pf` helper. Do not run the entire web toolkit as root
merely to obtain BPF access. Low numbered managed-listener ports, such as TFTP
69 or FTP 21, remain unavailable to the normal-user macOS service; use the
toolkit's default high ports.

System Diagnostics reports BPF under **Platform capabilities**, not command
dependencies: BPF is a native macOS kernel facility, while Wireshark's
ChmodBPF package is one permission policy for it. The readiness check uses the
effective account and groups of the running toolkit process. Restart the
service after changing group membership before relying on that result.

`./twn service install` waits for launchd to report the job active and for the
web process, scheduler, and supervisor to become ready. If the job exits or the
managed processes never become ready, installation removes the failed property
list and points to `./twn service logs`; it does not leave a repeatedly failing
LaunchDaemon installed.

## Lifecycle commands

```text
./twn service install      Install, enable, and start boot-time service
./twn service status       Show installed and active/loaded state
./twn service logs         Show systemd or launchd wrapper logs
./twn service start        Start the installed OS service
./twn service stop         Stop it until manually started or the next boot
./twn service restart      Restart the installed OS service
./twn service uninstall    Disable and remove it; retain toolkit data
```

Once the OS service is running, the familiar commands remain useful without
administrator access:

- `./twn stop` pauses the toolkit processes while leaving the boot supervisor
  loaded;
- `./twn start` asks that supervisor to resume them with the service's original
  security context; and
- `./twn restart` uses the same pause/resume handshake; and
- an installer, upgrade, rollback, or recovery that replaces application code
  starts and validates the replacement process set before asking the OS manager
  to reload the launcher itself from the finalized files on disk.

The pause is intentionally cleared by a service-manager restart or reboot, so
an installed autostart service always returns after the host starts.

Uninstallation removes only the systemd unit or launchd property list. It does
not delete `instance/`, logs, profiles, certificates, captures, or Datastore
files.

## Managed listeners and crash recovery

The OS service supervises the toolkit launcher. The launcher in turn supervises
the web process, automation scheduler, worker supervisor, and enabled managed
listeners such as TFTP, FTP, SFTP/SCP, and iPerf3. Installing the OS service does
not enable any listener that was disabled in the web application.

On systemd, `Restart=on-failure` returns the launcher after an unexpected exit.
On macOS, launchd keeps the job alive after an unsuccessful exit. Deliberately
using `./twn stop` creates a managed pause rather than fighting the OS
supervisor; `./twn start` clears that pause. A reboot or explicit
`./twn service restart` clears it as well.

## Upgrade, relocation, and uninstall

Supported `./twn upgrade`, in-app upgrades, rollback, and recovery temporarily
pause the loaded service and update or restore the matched code-and-instance
pair. The installer starts a validation-only process set directly through the
same service account and security context while the original launcher remains
paused. The updater verifies the version, managed processes, enabled listeners,
and databases, records its terminal result, cleans the request, and removes the
operation lock last. A small deferred handoff then stops the temporary process
set and lets systemd or launchd load the finalized `twn` from disk. The final
OS-managed start records the normal toolkit-start automation event exactly once.

If automatic rollback restores the version that the original in-memory launcher
already represents, that launcher adopts the validated restored process set
instead of forcing another restart. If the handoff cannot observe updater
finalization within its bounded wait, it restores the original launcher and
retains the healthy validated process set rather than leaving the service
stranded. Handoff diagnostics are written to
`.twn-upgrades/service-reload.log`. This does not need another administrator
prompt. The service definition is not part of the release bundle and remains
installed. Running `./install.sh` outside an active supported upgrade still uses
the normal synchronous service reload.

To relocate an installation:

1. Run `./twn service uninstall` from the old checkout.
2. Move or freshly clone the toolkit to the final location.
3. Run `./install.sh` there so `.venv` matches the new absolute path.
4. Confirm normal startup, then run `./twn service install` again with the
   intended user and Linux capability option.

To remove only boot-time management:

```bash
./twn service uninstall
./twn service status
```

The second command should report that autostart is not installed. The checkout,
virtual environment, `instance/`, Datastore, certificates, captures, and service
log files remain recoverable and can still be started manually with
`./twn start`.

## Troubleshooting

- **Service is active but the toolkit is not:** run `./twn service logs`, then
  `./twn status` and `./twn logs`. On macOS, a `spawn scheduled` state with an
  exit code is not considered active.
- **macOS reports `EX_CONFIG` or will not stay running:** confirm the checkout
  is outside protected user folders, the service account owns `instance/`, and
  `.venv` was created at the checkout's current path.
- **Capture, replay, or DHCP fails although the web UI works:** the service is
  correctly unprivileged. Reinstall the Linux unit with
  `--network-capabilities`, or provision persistent BPF read/write access for
  the macOS service account and restart the service.
- **A low listener port fails on macOS:** use the toolkit's default high port.
  macOS does not provide the systemd-style scoped bind capability.
- **The wrong account owns runtime files:** uninstall the service, repair the
  intended normal-user ownership with `./twn recover` or
  `./twn fix-permissions`, verify normal startup, and reinstall for that user.
