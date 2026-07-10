# Packet Replay setup

Packet Replay sends raw Ethernet frames from the host running The WiFi Ninja's
Toolkit. Treat it like a lab tool: use only a wired test interface on networks
where you are authorized to transmit crafted traffic.

## Host requirements

- A wired Ethernet interface selected in the Packet Replay page.
- One raw Ethernet frame pasted as hex, or a full-packet classic Ethernet PCAP
  containing one or more packets.
- Access to the Packet Replay tool through an assigned toolkit access profile,
  or administrator access.
- OS permission to open raw packet transmit facilities.

Wireless frame injection is not supported. Sending an Ethernet frame through a
normal Wi-Fi client interface will not create arbitrary 802.11 management or
control frames.

## Linux

Linux uses the toolkit's native `AF_PACKET` sender. Start the toolkit with root
privileges on a dedicated diagnostic host:

```bash
./twn stop
sudo ./twn start
```

Alternatively, grant raw-socket capability to the Python interpreter used by the
toolkit. This is powerful; use it only on a controlled diagnostic host:

```bash
sudo setcap cap_net_raw+ep "$(readlink -f .venv/bin/python)"
./twn restart
```

If the virtual environment is rebuilt or Python is upgraded, reapply the
capability.

## macOS

macOS uses Scapy for raw packet transmit. Untagged frames use the libpcap send
path; VLAN-tagged frames use Scapy's BPF/raw-device path. Some systems allow
this from a normal user session, while others require permission to open BPF
packet devices. If the page reports a permission error, stop the normal service
and start it with `sudo` for lab testing:

```bash
./twn stop
sudo ./twn start
```

After changing packet replay code or updating the toolkit, restart the service
before testing. The page should show **Send requested** after pressing **Send
Packet Replay**; if it does not, the browser did not submit the send action or
the running service is stale.

If the page reports that Scapy is missing, rerun the installer or refresh
requirements:

```bash
./install.sh
```

## Using the page

1. Select the wired interface.
2. Paste one raw Ethernet frame as hex or upload a classic Ethernet PCAP with
   one or more packets.
3. Optionally rewrite source/destination MAC addresses.
4. Optionally add, replace, or remove VLAN tags.
5. Preview the plan and review warnings.
6. Select **Send Packet Replay** from the preview card.

A successful send reports the number of replay frames, interface, elapsed time,
and sender backend, such as `linux raw socket` or `scapy`.

After previewing an uploaded PCAP, the toolkit preserves the decoded packets for
the follow-up send action. You do not need to reselect the file before
pressing **Send Packet Replay**. Repeat count and VLAN fanout apply to every
source packet in the capture.

VLAN fanout accepts individual IDs, ranges, and the `untagged` keyword. For
example, `untagged,10-12,20` sends one untagged copy plus VLAN 10, 11, 12, and
20 copies for each source packet and repeat. VLAN ID `0` is allowed as an
802.1Q priority-tagged frame; it is not the same thing as untagged.

On macOS, Scapy does not return a reliable on-wire byte counter. The toolkit
reports that the backend accepted the replay bytes; verify actual egress with
Wireshark/tcpdump on the selected interface or from another host on the same
Layer 2 segment.

When checking VLAN-tagged replay traffic, use a VLAN-aware capture filter. For
example:

```bash
sudo tcpdump -i en0 -e -nn -vvv 'vlan or ether proto 0x8100'
sudo tcpdump -i en0 -e -nn -vvv 'vlan and port 514'
```

## Common failures

- **Permission denied:** restart the toolkit with root privileges or Linux
  `CAP_NET_RAW`.
- **No such device / interface not found:** select the OS interface name shown
  on the page, not a switchport name or VLAN label from another system.
- **VLAN tag not visible:** check the preview's **First replay header bytes**.
  If it contains `81 00` followed by the expected VLAN ID, the toolkit built an
  802.1Q-tagged frame. Use a VLAN-aware capture filter such as `vlan`,
  `ether proto 0x8100`, or `vlan and port 514`; a plain inner-protocol filter
  may miss tagged traffic depending on the capture tool and interface.
- **No effect on the network:** verify the frame is valid for the selected
  interface and VLAN, and confirm the switchport allows that traffic.
- **Wireless testing:** use a wired adapter. This tool does not perform Wi-Fi
  injection.
