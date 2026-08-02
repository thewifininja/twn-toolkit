# DHCP Discover

DHCP Discover tests whether the toolkit host can reach DHCP servers from one
selected local interface and shows every matching Offer that arrives before a
bounded timeout. It is a diagnostic probe, not a DHCP client.

## Safety boundary

Each run creates a new transaction identifier and sends exactly one DHCP
Discover. The packet requests a broadcast reply and uses the selected client MAC
address, optional host name, optional vendor class, and ordered Parameter
Request List. The toolkit:

- never sends a DHCP Request;
- never accepts an Offer or configures the offered address;
- never changes interface addressing, routes, or DNS;
- listens only for Offers matching that run's transaction identifier; and
- deduplicates repeated copies of the same server/address Offer.

The probe still appears to DHCP infrastructure as a real client discovery. Use
an authorized test MAC and avoid creating unnecessary load on production DHCP
servers.

## Running a probe

1. Open **Network Tools → Traffic & Interfaces → DHCP Discover**.
2. Select the local interface attached to the broadcast domain under test.
3. Keep the interface MAC or enter another authorized unicast client MAC.
4. Set a 0.2–15 second listen timeout. Three seconds is a practical first test.
5. Choose requested options by number or by the names shown on the page. Order
   is preserved and duplicates are removed.
6. Optionally set a host name and vendor-class identifier when testing a client
   policy.
7. Select **Send discover** and review every returned Offer.

The result identifies the offered address, DHCP server identifier, packet source,
relay-agent address when present, next-server field, and all returned options.
The **Requested** column distinguishes solicited options from additional policy
the server supplied.

## Linux permissions

Linux sends the DHCP payload through a UDP socket bound to client port 68 and,
where supported, binds that socket to the selected interface. A normal service
without network capabilities will usually be denied that operation.

For an autostarting toolkit on a dedicated Ubuntu or Raspberry Pi diagnostic
host, use the bounded service capability set:

```bash
./twn service install --network-capabilities
./twn service status
```

The systemd unit grants `CAP_NET_RAW`, `CAP_NET_ADMIN`, and
`CAP_NET_BIND_SERVICE` only to the managed service process tree. It does not
modify the virtual environment's Python executable or run the full toolkit as
root. See [Autostart Service](autostart-service.md) for the security tradeoff and
lifecycle procedure.

## macOS permissions

macOS does not bind UDP port 68. The backend opens the receive listener first,
constructs one Ethernet/IPv4/UDP Discover, transmits it through Scapy/libpcap/BPF
on the selected interface, and captures matching UDP 67-to-68 Offers through
BPF. This works for a normal-user LaunchDaemon when that service account can
read and write `/dev/bpf` devices.

Wireshark's optional ChmodBPF service is one established way to create a
persistent `access_bpf` permission policy. Verify the account and device access,
then restart the toolkit service after group membership changes:

```bash
id -Gn
ls -l /dev/bpf0
./twn service restart
```

The toolkit reports a focused BPF permission error and never changes device
ownership or permissions automatically. Do not run the complete web toolkit as
root merely to make DHCP Discover work.

## Interpreting no response

**No matching Offers arrived** means only that this host captured no matching
Offer before the deadline. Check the following before concluding DHCP is down:

- the selected interface is connected to the intended VLAN and is operational;
- the test MAC and optional vendor class are permitted by server policy;
- a local firewall, endpoint-security product, hypervisor, Wi-Fi access point,
  or switch is not blocking broadcasts or replies;
- a relay is configured when the DHCP server is outside the local broadcast
  domain;
- the timeout is long enough for the environment; and
- the service account has the Linux port/interface or macOS BPF permission
  described above.

A simultaneous packet capture on the selected segment is the best next step.
Seeing the Discover leave but no Offer return points beyond the toolkit host;
seeing an Offer on wire but not in the page points toward host capture access,
interface selection, or transaction mismatch.

## Records and privacy

A completed run records activity counts for Discovers and Offers. The
administrative audit event retains the requested-option count, Offer count, and
outcome rather than the entered MAC, host name, vendor class, or returned option
payloads. Results are rendered for the current request and are not saved as a
DHCP lease or reusable profile.
