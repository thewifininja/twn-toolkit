# Guided installation

On a fresh checkout in an interactive terminal, run `./install.sh`. The full-screen
installer detects the OS, asks **service or manual mode before location**, then
lets you select tools, hostname, timezone, permissions and the final installation
plan. Use arrows to navigate, Enter to select/edit, Tab for buttons, and M to stop
the banner animation. Back retains your choices. Nothing is installed until you
accept **Install** on the review page.

For an existing checkout, use `./twn setup`. Use `./twn setup --plain` for text
prompts, or `--no-motion` for a still banner. Python 3.10 or newer must already be
available to start setup. On Debian/Ubuntu, virtual-environment support may also
require `python3-venv`; it appears as a prerequisite in the dependency inventory.

## What setup changes

- Manual mode starts this installation when setup finishes, but adds no boot
  service. Use `./twn start` and `./twn stop` afterward.
- Service mode uses the existing systemd or launchd installer and the current
  regular account. The native OS authorization prompt appears only for selected
  privileged operations. Do not launch the entire wizard with sudo. No password
  is collected, recorded or stored by the wizard.
- A fresh installation can be copied into a new or empty destination. Only release
  source is copied: no `.venv`, runtime data, Git metadata or private review files.
  The source remains intact and the new environment is built in its final path.
  An existing instance must stay in place during setup. To relocate it, stop its
  service and follow the offline [relocation procedure](autostart-service.md#upgrade-relocation-and-uninstall).
- On macOS, service paths are resolved before validation. Desktop, Documents,
  Downloads, iCloud Drive and `~/Library/CloudStorage` are unsuitable. A local
  `~/twn-toolkit` checkout is appropriate. A link into a protected folder is still
  protected. An existing service for another checkout is never replaced by setup.
- The **preferred hostname** is the GUI's preferred FQDN, not the OS hostname or
  short instance name. Blank retains automatic address-based URLs. You must arrange
  DNS/name resolution. A new installation generates its HTTPS certificate after
  saving the hostname. Changing an existing hostname does not replace an existing
  certificate; install a matching certificate through the existing HTTPS workflow.
- The timezone picker searches city/region names. **Follow host** stores no override.
  Existing listen addresses, network allowlists, instance names, TLS choices,
  profiles and other settings are preserved.

## Dependency inventory and individual choices

`./twn setup --dependencies` reports the complete shared external-command inventory.
It is also used by Settings diagnostics. Presence is checked on the toolkit/service
search path, including both Homebrew prefixes and their `sbin` directories. A found
binary is not proof that its version, daemon or effective permissions are usable.

| Dependency | Ubuntu/Debian | Arch | macOS | Purpose / qualification |
|---|---|---|---|---|
| Python / venv | python3, python3-venv | python | Python prerequisite | Runtime; Python must exist before setup starts |
| Timezone database | tzdata | tzdata | OS-provided | City/region selection; if missing, install and revisit the picker |
| Native build support | build-essential, python3-dev, libffi-dev, libssl-dev, pkg-config, cargo | base-devel, rust | Apple Command Line Tools / Rust, provision separately | Only needed when no compatible Python wheels are available |
| ping | iputils-ping | iputils | OS-provided | Ping / Path MTU |
| traceroute | traceroute | traceroute | OS-provided | Route diagnostics; traceroute6 also checked on macOS |
| tcpdump | tcpdump | tcpdump | tcpdump / OS tool | Packet capture; permissions are separate |
| iperf3 | iperf3 | iperf3 | iperf3 | Toolkit manages its own listeners; avoid another iPerf daemon |
| fping | fping | fping | fping | Accelerated Ping; needs effective packet privileges |
| lsof | lsof | lsof | lsof / OS tool | Listener recovery fallback |
| lldpd + lldpcli | lldpd | lldpd | lldpd | Daemon and control-socket access are verified separately |
| ip / ifconfig | iproute2 | iproute2 | OS-provided | Interface/address discovery and changes |
| NetworkManager / nmcli | network-manager | networkmanager | Not applicable | Pi management; installing can affect host networking; setup never enables or reconfigures it |
| iw | iw | iw | Not applicable | Pi radio inspection |
| ethtool | ethtool | ethtool | Not applicable | Pi permanent-MAC fallback |
| ps / sysctl | procps | procps-ng | OS-provided | Process/boot identity and recovery |
| sudo | sudo | sudo | OS-provided | Only for selected privileged actions |
| systemctl / launchctl | Existing systemd host | Existing systemd host | OS-provided launchd | Setup does not replace the init system |
| shasum / sha256sum | coreutils | coreutils | OS-provided | Python hashing fallback is available |
| Wireshark ChmodBPF | Not applicable | Not applicable | Optional wireshark-chmodbpf cask | BPF access; login/restart may be needed |
| Certbot | Locked Python environment | Locked Python environment | Locked Python environment | Do not install a duplicate system package |
| eapol_test | Disabled | Disabled | Disabled | EAP remains disabled; no package offered |

The Python dependency set is the complete hash-locked `requirements.txt`, with
input declarations in `requirements.in`: Flask, Gunicorn, Certbot, Paramiko,
pyserial, pyftpdlib, requests/NTLM, ReportLab, cryptography, dnspython, pyrad,
pysnmp and Scapy, plus their locked transitive dependencies. `pip check` runs after
installation. OpenSSL, SSH, SNMP, DNS and RADIUS command-line clients are not silently
installed as duplicates of the Python implementations. Standard POSIX shell/core
utilities are bootstrap OS prerequisites; Git and uv are development tools, not
runtime dependencies of a release-bundle installation.

The wizard checks apt-get, pacman or Homebrew before proposing commands. If a
manager or mapping is unavailable, skip the optional tool or follow the platform's
manual instructions. Homebrew is never bootstrapped with a downloaded shell script
and never runs as root. The review shows the selected packages and exact command;
interactive package-manager transaction/authorization prompts remain enabled.
Package scripts can start system services. Arch uses `pacman -S --needed`, never
an isolated `-Sy`; refresh/upgrade the host through its normal administration process
if repositories are stale. A failed transaction stops setup; completed package
changes are not automatically undone.

Linux has a separate opt-in to enable/start `lldpd` through systemd. On macOS,
installing the formula does not mean a privileged LLDP daemon is running. Configure
that daemon through your normal launchd administration, then use the final
control-socket check; the wizard does not run `sudo brew services`. Existing LLDP
state is preserved unless its explicit Linux daemon option is selected.

Linux network capabilities use the existing bounded service option. The running
service's capability bits are checked after setup. On macOS, ChmodBPF is an
independent package/permission choice. Current-account diagnostics are labeled as
such, and service-user readiness remains visible in Settings diagnostics. Serial
access continues through the existing scoped service group setup.

## Optional macOS multicast compatibility

The network page offers an independent opt-in with explicit interface selection.
It delegates to the existing `multicast-pf` helper, which preserves the dedicated
anchor, backups, syntax validation, idempotency and uninstall behavior. Setup does
not modify vendor anchors or reload the live PF ruleset. Restart macOS before
relying on new rules; inspect with `sudo ./twn multicast-pf status` and remove with
`sudo ./twn multicast-pf uninstall`. See [multicast](multicast.md).

## Automation, upgrades and recovery

`./install.sh --non-interactive` retains the established installer behavior and
stage/status contract. Upgrades and rollbacks never open the wizard, even on a TTY.
`./twn setup --dry-run` prints the proposed defaults without changes. For explicit
unattended onboarding, create a JSON configuration:

```json
{
  "location": "/home/operator/twn-toolkit",
  "service": false,
  "packages": [],
  "hostname": "",
  "timezone": "",
  "network": false,
  "lldpd": false,
  "pf_interfaces": []
}
```

Review with `./twn setup --config setup.json --dry-run`, then apply with
`./twn setup --config setup.json --yes`. Unknown fields and invalid selections fail
before execution. Unattended mode uses noninteractive package options, closed input
and `sudo -n`: arrange narrowly scoped authorization externally or the command will
fail rather than wait for credentials. Interactive setup is preferred when native
package/cask prompts require a human. No passwords belong in configuration files.

Setup refuses active jobs/terminals, nonempty relocation destinations, incompatible
service paths, and conflicting setup/upgrade operations. It checks free space but
does not reserve it. Failures stop at the failed stage and show native output;
completed changes are not represented as rolled back. Rerun after resolving the
reported issue. If interrupted after processes were stopped, inspect `./twn status`
and restart the existing checkout as appropriate. Instance data is not deleted.

Package mappings follow the official [Homebrew formula catalog](https://formulae.brew.sh/formula/), [Ubuntu packages](https://packages.ubuntu.com/), and [Arch packages](https://archlinux.org/packages/). Homebrew’s keg-only lsof paths are included in setup and service discovery; the macOS system copy remains usable.
