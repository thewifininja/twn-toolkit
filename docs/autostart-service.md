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
different dedicated account should own the service.

The service definition stores the installation's absolute path. Move the
toolkit by uninstalling the service first, moving the directory, and installing
the service again.

## Linux, Ubuntu, and Raspberry Pi OS

Linux installation requires systemd. This covers supported Ubuntu releases and
the official Raspberry Pi OS images. The helper installs and enables
`/etc/systemd/system/twn-toolkit.service`:

```bash
./twn service install
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
- `./twn restart`, upgrades, rollback, and recovery use the same handshake.

The pause is intentionally cleared by a service-manager restart or reboot, so
an installed autostart service always returns after the host starts.

Uninstallation removes only the systemd unit or launchd property list. It does
not delete `instance/`, logs, profiles, certificates, captures, or Datastore
files.
