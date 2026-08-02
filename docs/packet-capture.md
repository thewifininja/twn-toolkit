# Packet Capture

Packet Capture records bounded classic PCAP files with the host system's
`tcpdump` command. It is available as a standalone Network Tool and as an
automation action.

## Intended deployment

The most useful deployment gives the toolkit server two interfaces:

1. a management interface used for the web application and active condition
   checks; and
2. a capture interface connected to a switch SPAN or mirror destination.

The capture interface does not need an IP address. The switch determines which
traffic is copied to it.

## Capture controls

- interface selected from the host's current interface list;
- optional tcpdump/BPF capture filter;
- duration from 5 through 300 seconds;
- optional packet limit up to 1,000,000 packets;
- maximum retained file size from 1 through 512 MiB;
- full-packet capture or a 64–65535-byte snapshot length; and
- promiscuous mode on or off.

The first reached limit stops a capture. Only one capture may own an interface
at a time, including across standalone and automation captures. Standalone
captures run in a dedicated process and continue through browser navigation.

## Packet viewer

Open the viewer on a running or completed capture to review a bounded table of
capture time, source and destination MAC/IP/port, protocol, VLAN identifiers,
and captured/wire length. The floating window can be moved or minimized and
restores across toolkit navigation. Running viewers poll for new complete
packet records and auto-scroll by default; scrolling upward or turning off the
toggle pauses that behavior. The viewer retains at most 1,000 rendered rows
while its packet count continues forward. It deliberately does not render
payload contents or attempt full protocol dissection.

Local Datastore places **Inspect PCAP** in the file actions for `.pcap`,
`.pcapng`, and `.cap` files. Datastore users can invoke the same floating viewer without
navigating to Packet Capture. Save to datastore from capture history still
requires access to both tools. Large files are read in bounded pages; use
Wireshark or another dedicated analyzer for filtering, streams, payloads, and
deep decoding.

## Permissions

`tcpdump` must be installed and available on the toolkit service `PATH`. The
service account also needs platform capture access:

- Linux commonly uses root or the `CAP_NET_RAW` and `CAP_NET_ADMIN`
  capabilities on `tcpdump`.
- macOS uses BPF devices and may require an administrator-managed BPF access
  policy.

The toolkit does not invoke a package manager, run `sudo`, or change capture
permissions automatically.

For an autostarting Linux toolkit, the recommended scoped approach is
`./twn service install --network-capabilities`. The systemd unit grants the
managed service process tree `CAP_NET_RAW`, `CAP_NET_ADMIN`, and
`CAP_NET_BIND_SERVICE` without changing the Python or tcpdump executable.
macOS LaunchDaemons remain unprivileged and still require an
administrator-managed BPF access policy when normal-user access is unavailable.
Wireshark's optional ChmodBPF service is one established way to grant persistent
read/write access through its `access_bpf` group. Confirm the toolkit service
account appears in that group, verify `/dev/bpf0` is group-readable and
group-writable, and restart the service after changing membership. The toolkit
does not change BPF ownership or permissions automatically.

See [Autostart Service](autostart-service.md) for complete Linux capability,
macOS service placement, verification, and troubleshooting guidance.

## Storage and security

Standalone PCAPs live beneath `instance/packet_captures/`. Automation PCAPs
can move into the existing `instance/automation_artifacts/` run directory or
be saved directly to a selected datastore folder. Standalone and run-retained
captures use the automation-artifact quota and minimum free-disk reserve;
datastore captures use the datastore quota. Neither form is included in profile
backups.

**Save to datastore** copies a completed standalone PCAP into the selected
datastore folder using an editable filename. Automation capture names support
`{timestamp}`, `{action}`, and `{interface}` pattern tokens. The `.pcap`
extension is added when omitted, and duplicate names receive a numeric suffix
instead of overwriting. Datastore copies follow the datastore quota and
lifecycle and are independent of capture-history deletion.

Recent standalone captures are collapsed by default to keep longer histories
compact. Their summaries retain the interface, timestamp, size, packet count,
and status; active or explicitly focused captures open automatically.

Packet captures can contain credentials, session tokens, personal data, and
application payloads. Grant the tool only to authorized operators and delete
captures when they are no longer required.

Automation capture begins after its condition reaches the configured trigger
threshold. It cannot recover packets from before detection. Automation action
delivery is at least once, so a reclaimed execution job may create another
capture.
