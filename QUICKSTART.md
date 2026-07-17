# The WiFi Ninja’s Toolkit Quick Start

This guide takes a new installation from first launch through a useful network
test, saved device profiles, a working automation, local file services, and
basic administration. The searchable **Help** page inside the toolkit contains
the full field guide and release notes.

## Requirements

- Python 3.10 or newer
- macOS, Linux, or Raspberry Pi OS
- Network access from the toolkit host to the systems being tested
- A modern browser

Optional workflows need their own remote permissions:

- FortiGate workflows use a REST API administrator and token.
- FortiAuthenticator workflows use an administrator with **Web service
  access** and its Web Service API Access Key.
- PEAP/MSCHAPv2 and EAP-TLS tests require `eapol_test`.
- DHCP Discover and Packet Replay may require elevated network permissions.

## Install or upgrade

From the project directory:

```bash
./install.sh
```

The installer checks system commands, creates `.venv`, installs Python
dependencies, generates a self-signed certificate for a fresh installation,
and starts the toolkit. Running it again refreshes dependencies while
preserving `instance/` data and an existing HTTP/HTTPS choice. If an existing
toolkit is active, the installer restarts its managed processes after refreshing
dependencies so the service cannot continue on stale code or libraries.

After the initial installation, use **Administration → Updates & Recovery** or
`./twn upgrade`. Routine upgrades do not require Git, the GitHub CLI, or manual
tags. The toolkit stops its services, creates a matched code and complete
instance recovery point, verifies the release, restarts, checks processes and
databases, and restores the previous pair automatically on failure. See
[Upgrade and Recovery](docs/upgrade-recovery.md).

An installation running v0.10.2 or older needs one final conventional upgrade
to v0.11.0, the first updater-enabled release. All later upgrades can use the
built-in workflow.

For a manual Python setup:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
./twn start
```

Open one of the HTTPS URLs printed by the launcher—normally
<https://127.0.0.1:5050> is available locally. A fresh installation uses a
self-signed certificate, so the browser will display a certificate warning.

## First launch

There is no default account.

1. Create the first administrator.
2. Sign in and open **Administration → Settings**.
3. Review the short instance name, preferred FQDN, client allowlist, password
   policy, idle timeout, operational limits, and retention settings.
4. Open **Administration → System Diagnostics** and confirm that the web,
   scheduler, supervisor, databases, and required dependencies are healthy.

The persistent sidebar is the primary navigation:

- Use **Find a tool** above Dashboard to filter permitted destinations by tool
  name or category path without changing which menu sections are expanded.
- **Fortinet Tools** contains FortiGate and FortiAuthenticator profiles and
  workflows.
- **Network Tools** is divided into Addressing & Reachability, Multi-Host
  Tools, Services & Protocols, and Traffic & Interfaces.
- **Local Tools** contains the Datastore and managed File Transfers.
- **Automation** contains reusable Conditions, Actions, and Automations.
- **Administration** contains server-wide configuration and diagnostics.

Hover or focus a tool in the sidebar and select its star to add or remove a
personal Favorite.

## Run a first network test

**Multi-Host Ping** is a useful first test because it needs no saved
credentials:

1. Open **Network Tools → Multi-Host Tools → Multi-Host Ping**.
2. Enter one target per line. Optional friendly names use
   `Friendly Name = hostname-or-IP`.
3. Select **Start**.
4. Review live reachability, current/minimum/average/maximum latency, loss, and
   response-time history.
5. Edit the target box and select **Update targets** when the active run should
   change. Unchanged targets keep their history; removed targets remain visible
   as removed.

Invalid entries are reported without preventing valid targets from running.
The active run uses a validated snapshot, so typing does not create partial
hosts in the charts. Ping chart history exists in the browser session unless
exported.

The other Network Tools follow the same category layout shown in the sidebar:

- **Addressing & Reachability:** IP information, subnet exclusion, DNS, NTP,
  Path MTU, and Traceroute
- **Multi-Host Tools:** Ping, Multi-SSH, Multi-Transfer, and TCP Port Scanner
- **Services & Protocols:** RADIUS, certificate inspection and AD CS enrollment,
  SNMP, Webhook/API, and Syslog
- **Traffic & Interfaces:** Wi-Fi/LAN Speed Test, DHCP Discover, and Packet
  Replay

SNMP Tester can also discover the standard IF-MIB interfaces across saved SNMP
hosts and build a monitor set of up to 20 interfaces. Each interface gets an
adaptive mirrored graph with endpoint download (interface transmit) above zero
and endpoint upload (interface receive) below zero. Hover a graph to inspect
both rates at the nearest retained sample. The monitor prefers 64-bit
high-capacity counters and supports 1, 5, 10, 15, 30, or 60-second polling
intervals. Change that interval while a monitor is running without losing
history. Choose a visible time range and use the shared history navigator to
inspect older windows while live samples keep collecting. Graphs are temporary
browser-session data and stop when you leave the page.

## Add Fortinet profiles

### FortiGate

1. Open **Fortinet Tools → FortiGate**.
2. Create a profile with a descriptive name and the complete appliance URL,
   including a custom port when needed, such as
   `https://192.0.2.10:8443`.
3. Enter the REST API token and default VDOM (usually `root`).
4. Leave TLS verification enabled when the FortiGate uses a trusted
   certificate.
5. Save the profile and select **Test**.

A read-only FortiGate administrator is sufficient for inventory exports.
Rename and reorder workflows require write permission for the corresponding
wireless-controller or switch-controller resources. A successful profile test
proves connectivity and authentication; a later HTTP 403 usually means the
remote administrator profile does not permit that specific operation.

FortiGate workflow pages provide in-browser preview and selection. CSV import
or export is available where useful, but it is not required for normal rename
or inventory workflows.

### FortiAuthenticator

1. Open **Fortinet Tools → FortiAuthenticator**.
2. Create a profile with the appliance URL and administrator username.
3. Enter the Web Service API Access Key—not the interactive login password.
4. Save the profile and select **Test**.

Cleanup workflows require remote permission to modify Users and Devices.
Always build and review the cleanup preview before removing memberships or
deleting a MAC device globally.

## Build a first automation

Automation uses reusable definitions. A condition or action can be shared by
multiple automations without being rebuilt.

### 1. Create and test a condition

Open **Automation → Conditions**, expand **New condition**, and choose a type.

For a simple outage condition:

1. Choose **Multi-host ICMP reachability**.
2. Give it a descriptive name.
3. Enter one or more named targets.
4. Choose whether all targets or a selected number must fail.
5. Save it, expand the saved condition, and select **Test**.

Testing a condition is read-only. It reports current evidence without running
an action or arming an automation.

Other reusable conditions include DNS lookup health, per-host TCP services,
SNMP value rules and calculations, certificate health, calendar schedules, and
a Manual trigger.

### 2. Create an action

Open **Automation → Actions** and expand **New action**. A practical first action is **SSH command collection**:

1. Add friendly-named SSH targets.
2. Enter the username and password.
3. Add the command sequence.
4. Save the action.

Commands normally use prompt-aware completion with a default ceiling. Override
one long-running command by prefixing it, for example:

```text
[timeout=600] diag debug report
```

Other actions can collect files over SFTP/SCP/FTP, send RFC 5424 Syslog, or
send templated Webhook/API notifications. Saved action credentials are
write-only in the UI and encrypted at rest.

### 3. Connect them

Open **Automation → Automations** and expand **New automation**:

1. Name the automation.
2. Select the reusable condition.
3. Select one or more actions in Stage 1.
4. For a monitored condition, set **Check every**, **Trigger after**,
   **Recover after**, and **Cooldown**.
5. Add stages when later actions should wait for earlier ones. Actions in one
   stage run in parallel; stages run sequentially.
6. Save the automation.

New monitored or calendar automations remain paused until you select **Arm**.
Use **Test condition** before arming. Editing a referenced condition or action
pauses dependent automations so changes can be reviewed safely.

### Manual and calendar automations

- A **Manual trigger** produces an on-demand automation with a **Run now**
  button and no polling interval.
- A **Calendar schedule** can contain multiple one-time, daily, weekday,
  alternating-week, monthly-date, or ordinal-weekday rules in one reusable
  condition. Set an IANA timezone and missed-occurrence policy, then use
  **Refresh next run times** to preview without arming or executing anything.

### Review output

Expand an automation to see recent condition checks and collected action runs.
Each run shows stage/action identity and per-target success, partial, or error
details. Download the ZIP for complete SSH output, collected files, and run
metadata. Retained output can be deleted per run or cleared without removing
condition-check history.

The scheduler continues when the browser is closed. If the page reports that
the scheduler is stopped, run `./twn restart` and confirm with `./twn status`.

## Use the Datastore and File Transfers

### Datastore

Open **Local Tools → Datastore** to upload, download, rename, move, or delete
contained files and folders. List/grid views, drag-and-drop uploads, selection,
folder drop targets, bulk ZIP downloads, and a read-only plain-text file preview
from each file's three-dot menu are supported.

Files live beneath `instance/datastore/`. They are excluded from Git and from
profile backup/restore, so back up that directory separately when its contents
matter.

### Managed transfer services

Open **Local Tools → File Transfers** to configure TFTP, SFTP/SCP, or FTP.
Every listener is disabled by default.

For each service:

1. Choose the bind address and non-privileged or standard port.
2. Restrict trusted IPv4/IPv6 client networks.
3. Select a Datastore folder, or upload one runtime-only file.
4. Configure read/write and incoming filename behavior.
5. Save and enable the service.
6. Confirm its worker in `./twn status` and review transfer history in the UI.

Runtime-only files disappear when their service stops. SFTP/SCP provides no
interactive shell and stores its service password as a one-way hash. TFTP has
no authentication or encryption; FTP authentication and content are plaintext.
Prefer SFTP/SCP whenever the client supports it.

## Add users and access profiles

Open **Administration → Settings**:

1. Create one or more custom access profiles.
2. Select exactly which individual tools each profile may use.
3. Create or edit users and assign one or more profiles.

Effective access is the union of assigned profiles. These accounts are operators:
they can fully use the tools granted to them without receiving unrestricted system
control. The built-in System administrator profile is protected and grants full
toolkit, account, service, and audit access. Unauthorized links are removed from
navigation, and direct requests remain blocked by the server.

## Back up and restore profiles

Open **Administration → Updates & Recovery → Profile backups**. The
**Profile backup and restore** page exports selected configuration groups.

- Selecting any credentials or secrets makes backup encryption mandatory.
- Non-secret selections may be encrypted optionally.
- **Combine** keeps existing entries and adds imported definitions.
- **Replace** replaces the selected stored groups.
- Imported automations remain paused until reviewed.

The backup does not contain activity metrics, runtime automation history,
collected output, transfer history, or Datastore files.

## Service operations

```text
./twn start             Start the toolkit
./twn stop              Stop the toolkit
./twn restart           Restart the toolkit
./twn status            Show process state and access URLs
./twn logs              Show recent errors
./twn enable-https ...  Generate or regenerate managed HTTPS
./twn disable-https     Return an existing installation to HTTP
./twn upgrade           Install the latest verified stable release
./twn backup            Create a matched recovery point
./twn rollback ID       Restore a matched recovery point
./twn fix-permissions   Repair instance ownership after sudo mode
```

Use another port for one launch:

```bash
TWN_TOOLKIT_PORT=8443 ./twn start
```

If a privileged run leaves root-owned instance files, stop the toolkit and run
`./twn fix-permissions` before returning to a normal user account.

## Privileged tools

- **DHCP Discover** binds UDP client port 68 and may require root or equivalent
  Linux capabilities.
- **Packet Replay** requires raw Ethernet/BPF access. Linux normally needs root
  or `CAP_NET_RAW`; macOS may require BPF permission.
- Standard TFTP/FTP listener ports may need privileged bind permission. The
  default high ports avoid that requirement.

See [Packet Replay setup](docs/packet-replay.md) for detailed platform steps.

## Recovery and reset

If every administrator is locked out:

```bash
./twn stop
./twn adminreset
./twn start
```

This resets users without deleting saved device profiles or API keys.

To remove saved profiles and credentials before sharing a clean source copy:

```bash
./twn stop
./twn reset-data
```

Review the prompt carefully. Datastore files and other operational instance
data are managed separately.

## Security reminder

The default private-network allowlist, authentication, and HTTPS are defense in
depth for a trusted internal deployment; they do not make the toolkit safe for
unrestricted internet exposure. Protect the host and `instance/`, restrict
listeners to necessary clients, prefer encrypted protocols, and use least-
privileged remote accounts.

For complete feature guidance, open **Help** in the toolkit or continue with:

- [README](README.md)
- [Automation architecture and operations](docs/automations.md)
- [Packet Replay setup](docs/packet-replay.md)
