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

## Permissions

`tcpdump` must be installed and available on the toolkit service `PATH`. The
service account also needs platform capture access:

- Linux commonly uses root or the `CAP_NET_RAW` and `CAP_NET_ADMIN`
  capabilities on `tcpdump`.
- macOS uses BPF devices and may require an administrator-managed BPF access
  policy.

The toolkit does not invoke a package manager, run `sudo`, or change capture
permissions automatically.

## Storage and security

Standalone PCAPs live beneath `instance/packet_captures/`. Automation PCAPs
move into the existing `instance/automation_artifacts/` run directory.
Together they use the automation-artifact quota and minimum free-disk reserve.
Neither form is included in profile backups.

Packet captures can contain credentials, session tokens, personal data, and
application payloads. Grant the tool only to authorized operators and delete
captures when they are no longer required.

Automation capture begins after its condition reaches the configured trigger
threshold. It cannot recover packets from before detection. Automation action
delivery is at least once, so a reclaimed execution job may create another
capture.
