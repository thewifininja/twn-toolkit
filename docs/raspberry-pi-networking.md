# Raspberry Pi networking

On Raspberry Pi hardware, **Administration → System Settings → Raspberry Pi
networking** can manage the Pi's network adapters and simultaneous network
roles through NetworkManager. The page is
not shown on other platforms. Detection uses the device-tree compatibility
identifier rather than assuming every ARM Linux host is a Raspberry Pi.

## Adapters and profiles

The workspace discovers built-in and USB Ethernet and Wi-Fi adapters. Profiles
are bound to a permanent hardware address, not only the current Linux interface
name. This is important for field kits: removing a USB NIC, booting without it,
or having udev assign it a different name does not delete the profile or prevent
unrelated profiles from operating. The profile is shown as **Missing hardware**
and remains dormant until that adapter returns. The protected broker watches
the kernel's interface inventory: it deactivates a role whose required adapter
disappears, re-resolves returning hardware by permanent MAC, and asks
NetworkManager to restore the saved role. This same reconciliation runs after
a cold boot, including when optional USB adapters are still absent.

Each physical Wi-Fi radio can run one active role at a time. A Pi with multiple
Wi-Fi adapters can therefore expose multiple SSIDs simultaneously—for example,
a bridged service SSID on the built-in radio and a private NAT SSID on a USB
radio. The toolkit does not assume that a driver supports reliable virtual
multi-BSSID operation on one radio.

## Supported wireless modes

- **NAT access point** creates a private IPv4 wireless network. NetworkManager
  provides DHCP, DNS forwarding, and NAT through the selected Ethernet uplink.
- **Bridged access point** joins Wi-Fi clients directly to an Ethernet network.
  The wired side can be untagged or backed by an optional 802.1Q VLAN. A
  tagged bridge is Layer-2-only and leaves toolkit management on the parent
  Ethernet interface; an untagged bridge requests its management address on
  the bridge itself.
- **Wi-Fi client** joins an existing open, WPA2 Personal, WPA2/WPA3 transition,
  WPA3 Personal, PEAP-MSCHAPv2, or EAP-TLS network.

Access-point modes require both an AP-capable Wi-Fi adapter and a wired
Ethernet interface. Adapter firmware, regulatory country, and NetworkManager
still determine which bands, channels, and WPA3 combinations can be used.

## Wired interface modes

Every detected built-in or USB Ethernet adapter can have an independent
profile:

- **DHCP client** obtains IPv4 addressing from the connected network.
- **Static IPv4** sets an address/prefix and optional gateway and DNS servers.
- **Private DHCP + NAT** makes the Pi a DHCP/DNS gateway on that interface and
  routes clients through its active default uplink.
- **Disable IPv4** leaves the link available without IPv4 configuration.

Profiles also expose IPv6 automatic/disabled behavior, MTU, route metric, DNS
overrides, boot autoconnect, and enabled/disabled state. Enabled private DHCP
networks must not overlap one another, including networks used by NAT access
points; validation blocks both exact duplicates and partially nested subnets
before any system configuration changes.

## Live visibility

The adapter inventory reports link state, current addresses, gateway, driver,
bus, active Wi-Fi channel, frequency, signal, and radio capabilities. Managed
access points report observed clients by combining association data, DHCP
leases, and neighbor entries. Installing the operating system's `iw` utility
adds per-client signal, traffic, and rate details; the rest of the page remains
functional if `iw` is unavailable. Private DHCP + NAT Ethernet profiles use the
same client workspace to report downstream lease identity, address, hardware
address, and current or recent neighbor reachability.

## Enterprise Wi-Fi

PEAP-MSCHAPv2 accepts a username and write-only password. Server-certificate
validation is enabled by default and requires an expected authentication-server
domain. Trust can come from the operating-system CA store or an uploaded CA
certificate. Administrators may explicitly disable validation for a network
that cannot yet supply a usable server certificate, but the page labels the
credential-interception risk.

EAP-TLS requires server validation plus a client identity. Upload either a
PKCS#12 bundle or a matching client certificate and private key, with an
optional write-only key password. PEM, DER, and PKCS#12 content is parsed and
validated before it reaches NetworkManager. Private keys, Wi-Fi passphrases,
and enterprise passwords are encrypted in the toolkit instance and are never
rendered back into the browser. Staged material and generated NetworkManager
profiles use owner-only permissions.

## Protected system service

Network changes are not made by the web process. On Raspberry Pi hardware,
`./twn service install` also installs a small root-owned NetworkManager broker.
It accepts requests only from the configured toolkit service UID over a
mode-0600 Unix socket, validates the request again against real interfaces, and
can modify only toolkit-prefixed NetworkManager profiles plus its private state.
The application, workers, credentials, and Datastore remain unprivileged.

Install or refresh the service from the same checkout that serves the page:

```bash
sudo ./twn service install
```

If the service was installed with scoped Linux network capabilities, preserve
that choice while refreshing it:

```bash
sudo ./twn service install --network-capabilities
```

An ordinary code upgrade cannot create or replace this root-owned helper. The
page reports an unavailable or outdated broker until an administrator refreshes
the service once. Confirm readiness with `./twn service status` and return to
System Settings.

## Safe apply and recovery

Apply and Disable are provisional. Before changing networking, the broker
stages the complete profile collection, creates a NetworkManager checkpoint,
and records the prior active connections,
wireless-country setting, Wi-Fi radio state, toolkit profile files, and managed
state. The page then starts a two-minute confirmation timer.

- Select **Keep configuration** only after proving that the toolkit remains
  reachable through the intended management path.
- Select **Roll back now**, or simply allow the timer to expire, to restore the
  prior state.
- Untagged bridged mode can move the Pi to an address supplied by the bridged
  network. Tagged bridges carry client traffic without requesting an address
  on the client VLAN and retain the parent Ethernet management path. Keep a
  wired or local-console recovery path during initial testing.

The broker owns the rollback timer, so closing the browser or interrupting the
web application does not cancel recovery. Raspberry Pi networking is local
machine state: complete recovery points retain it, but portable configuration
backups intentionally exclude it.
