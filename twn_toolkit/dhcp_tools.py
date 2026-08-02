from __future__ import annotations

import errno
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import time
from typing import Any

from .network_tools import ToolInputError


DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
_ETHERTYPE_IPV4 = 0x0800
_VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}

DHCP_OPTIONS = {
    1: "Subnet Mask",
    2: "Time Offset",
    3: "Router",
    4: "Time Server",
    6: "Domain Name Server",
    12: "Host Name",
    15: "Domain Name",
    26: "Interface MTU",
    28: "Broadcast Address",
    42: "NTP Servers",
    43: "Vendor Specific Information",
    44: "NetBIOS Name Server",
    46: "NetBIOS Node Type",
    47: "NetBIOS Scope",
    51: "IP Address Lease Time",
    53: "DHCP Message Type",
    54: "Server Identifier",
    58: "Renewal Time",
    59: "Rebinding Time",
    60: "Vendor Class Identifier",
    66: "TFTP Server Name",
    67: "Bootfile Name",
    81: "Client FQDN",
    119: "Domain Search",
    121: "Classless Static Route",
    125: "Vendor-Identifying Vendor Options",
    138: "CAPWAP Access Controller IPv4 Address",
    150: "TFTP Server Address",
    252: "WPAD",
}

DEFAULT_PARAMETER_REQUEST_LIST = (1, 3, 6, 15, 26, 28, 42, 51, 54, 58, 59, 119, 121)
_NORMALIZED_NAMES = {
    re.sub(r"[^a-z0-9]", "", name.lower()): code for code, name in DHCP_OPTIONS.items()
}
_IP_LIST_OPTIONS = {3, 4, 6, 28, 42, 44, 54, 138, 150}
_SECONDS_OPTIONS = {51, 58, 59}
_TEXT_OPTIONS = {12, 15, 60, 66, 67, 252}


def available_interfaces() -> list[dict[str, str]]:
    interfaces = []
    for _index, name in socket.if_nameindex():
        try:
            mac = interface_mac(name)
        except ToolInputError:
            continue
        if mac != "00:00:00:00:00:00":
            interfaces.append({"name": name, "mac": mac})
    return interfaces


def interface_mac(interface: str) -> str:
    if not interface or interface not in {name for _index, name in socket.if_nameindex()}:
        raise ToolInputError("Select a valid network interface.")
    path = f"/sys/class/net/{interface}/address"
    try:
        with open(path, encoding="ascii") as handle:
            return normalize_mac(handle.read().strip())
    except OSError:
        pass

    if sys.platform == "darwin":
        try:
            completed = subprocess.run(
                ["ifconfig", interface],
                capture_output=True,
                text=True,
                timeout=2,
                check=True,
            )
            match = re.search(r"\bether\s+([0-9a-fA-F:]{17})\b", completed.stdout)
            if match:
                return normalize_mac(match.group(1))
        except (OSError, subprocess.SubprocessError):
            pass

    # SIOCGIFHWADDR is supported by Linux even when sysfs is unavailable.
    try:
        import fcntl

        request = struct.pack("256s", interface.encode("ascii")[:15])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
            response = fcntl.ioctl(control, 0x8927, request)
        return ":".join(f"{byte:02x}" for byte in response[18:24])
    except (ImportError, OSError, UnicodeEncodeError):
        raise ToolInputError(f"Could not determine the MAC address for {interface}.")


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(compact) != 12 or not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        raise ToolInputError("Enter a client MAC address as six hexadecimal octets.")
    octets = [compact[index : index + 2].lower() for index in range(0, 12, 2)]
    if int(octets[0], 16) & 1:
        raise ToolInputError("The client MAC address must be a unicast address.")
    return ":".join(octets)


def parse_parameter_request_list(value: str) -> list[int]:
    tokens = [token.strip() for token in re.split(r"[,\n]", value) if token.strip()]
    if not tokens:
        raise ToolInputError("Request at least one DHCP option.")
    result = []
    for token in tokens:
        if token.isdigit():
            code = int(token)
        else:
            code = _NORMALIZED_NAMES.get(re.sub(r"[^a-z0-9]", "", token.lower()), -1)
        if not 1 <= code <= 254:
            raise ToolInputError(f"Unknown DHCP option {token!r}; use a name shown below or 1–254.")
        if code not in result:
            result.append(code)
    if len(result) > 64:
        raise ToolInputError("Request no more than 64 DHCP options.")
    return result


def format_parameter_request_list(codes: list[int] | tuple[int, ...]) -> str:
    return ", ".join(str(code) for code in codes)


def build_discover(
    transaction_id: int,
    mac: str,
    parameter_request_list: list[int],
    *,
    hostname: str = "",
    vendor_class: str = "",
) -> bytes:
    mac_bytes = bytes.fromhex(normalize_mac(mac).replace(":", ""))
    chaddr = mac_bytes + (b"\x00" * 10)
    packet = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,  # BOOTREQUEST
        1,  # Ethernet
        6,
        0,
        transaction_id,
        0,
        0x8000,  # Require a broadcast reply; the offered address is not configured locally.
        b"\x00" * 4,
        b"\x00" * 4,
        b"\x00" * 4,
        b"\x00" * 4,
        chaddr,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    options = bytearray(DHCP_MAGIC_COOKIE)
    _append_option(options, 53, b"\x01")  # DHCPDISCOVER
    _append_option(options, 61, b"\x01" + mac_bytes)
    _append_option(options, 55, bytes(parameter_request_list))
    if hostname:
        _append_option(options, 12, _ascii_option(hostname, "Host name"))
    if vendor_class:
        _append_option(options, 60, _ascii_option(vendor_class, "Vendor class"))
    options.append(255)
    return packet + bytes(options)


def parse_offer(packet: bytes, transaction_id: int, source: tuple[str, int]) -> dict[str, Any] | None:
    if len(packet) < 240 or packet[0] != 2:
        return None
    xid = struct.unpack_from("!I", packet, 4)[0]
    if xid != transaction_id or packet[236:240] != DHCP_MAGIC_COOKIE:
        return None
    raw_options = _parse_options(packet[240:])
    if raw_options.get(53, [b""])[0] != b"\x02":
        return None

    offered_address = socket.inet_ntoa(packet[16:20])
    server_address = socket.inet_ntoa(packet[20:24])
    decoded = []
    for code, values in raw_options.items():
        for raw in values:
            decoded.append(
                {
                    "code": code,
                    "name": DHCP_OPTIONS.get(code, f"Option {code}"),
                    "value": _decode_option(code, raw),
                    "hex": raw.hex(" "),
                }
            )
    server_identifier = next(
        (option["value"] for option in decoded if option["code"] == 54),
        source[0],
    )
    return {
        "offered_address": offered_address,
        "server_address": server_identifier,
        "source_address": source[0],
        "relay_address": socket.inet_ntoa(packet[24:28]),
        "next_server": server_address if server_address != "0.0.0.0" else "",
        "options": decoded,
    }


def discover_offers(
    interface: str,
    mac: str,
    parameter_request_list: list[int],
    *,
    timeout: float = 3.0,
    hostname: str = "",
    vendor_class: str = "",
) -> list[dict[str, Any]]:
    if not 0.2 <= timeout <= 15:
        raise ToolInputError("Timeout must be between 0.2 and 15 seconds.")
    if interface not in {name for _index, name in socket.if_nameindex()}:
        raise ToolInputError("Select a valid network interface.")
    mac = normalize_mac(mac)
    if not parameter_request_list or any(not 1 <= code <= 254 for code in parameter_request_list):
        raise ToolInputError("DHCP option numbers must be between 1 and 254.")

    transaction_id = int.from_bytes(os.urandom(4), "big")
    packet = build_discover(
        transaction_id,
        mac,
        parameter_request_list,
        hostname=hostname.strip(),
        vendor_class=vendor_class.strip(),
    )
    if sys.platform == "darwin":
        return _discover_offers_macos_bpf(
            interface,
            packet,
            transaction_id,
            timeout=timeout,
        )
    return _discover_offers_udp(
        interface,
        packet,
        transaction_id,
        timeout=timeout,
    )


def _discover_offers_udp(
    interface: str,
    packet: bytes,
    transaction_id: int,
    *,
    timeout: float,
) -> list[dict[str, Any]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        elif sys.platform == "darwin":
            # IP_BOUND_IF is 25 in Darwin's netinet/in.h but is not exported by Python.
            interface_index = socket.if_nametoindex(interface)
            sock.setsockopt(socket.IPPROTO_IP, 25, interface_index)
        sock.bind(("", DHCP_CLIENT_PORT))
        sock.sendto(packet, ("255.255.255.255", DHCP_SERVER_PORT))

        deadline = time.monotonic() + timeout
        offers = []
        seen = set()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                response, source = sock.recvfrom(65535)
            except socket.timeout:
                break
            offer = parse_offer(response, transaction_id, source)
            if offer:
                key = (offer["server_address"], offer["offered_address"])
                if key not in seen:
                    seen.add(key)
                    offers.append(offer)
        return offers
    except PermissionError as exc:
        raise ToolInputError(
            "DHCP probing requires permission to bind UDP port 68 and select the interface. "
            "Run the toolkit with the required network capabilities."
        ) from exc
    except OSError as exc:
        raise ToolInputError(f"DHCP probe failed: {exc}") from exc
    finally:
        sock.close()


def _discover_offers_macos_bpf(
    interface: str,
    packet: bytes,
    transaction_id: int,
    *,
    timeout: float,
) -> list[dict[str, Any]]:
    try:
        from scapy.all import conf, sniff  # type: ignore[import-not-found]
        from scapy.error import Scapy_Exception  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ToolInputError(
            "macOS DHCP discovery requires Scapy. Run the installer again or install requirements."
        ) from exc

    listener = None
    sender = None
    try:
        conf.use_pcap = True
        listener = conf.L2listen(
            iface=interface,
            filter=f"udp and src port {DHCP_SERVER_PORT} and dst port {DHCP_CLIENT_PORT}",
        )
        sender = conf.L2socket(iface=interface)
        frame = _build_dhcp_discover_frame(packet, interface_mac(interface))
        sent = sender.send(frame)
        if isinstance(sent, int) and sent != len(frame):
            raise ToolInputError(
                f"DHCP discovery handed only {sent} of {len(frame)} bytes to BPF on {interface}."
            )
        captured = sniff(opened_socket=listener, timeout=timeout, store=True)
    except PermissionError as exc:
        raise ToolInputError(_macos_bpf_permission_message()) from exc
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM}:
            raise ToolInputError(_macos_bpf_permission_message()) from exc
        raise ToolInputError(f"DHCP BPF probe failed on interface {interface}: {exc}") from exc
    except (Scapy_Exception, ValueError) as exc:
        detail = str(exc).strip()
        if any(token in detail.lower() for token in ("permission", "permitted", "/dev/bpf")):
            raise ToolInputError(_macos_bpf_permission_message()) from exc
        raise ToolInputError(
            f"DHCP BPF probe failed on interface {interface}: {detail or 'Scapy rejected the request.'}"
        ) from exc
    finally:
        for raw_socket in (sender, listener):
            if raw_socket is None:
                continue
            try:
                raw_socket.close()
            except (AttributeError, OSError, Scapy_Exception):
                pass

    offers = []
    seen = set()
    for captured_packet in captured:
        extracted = _extract_dhcp_udp_payload(bytes(captured_packet))
        if extracted is None:
            continue
        response, source = extracted
        offer = parse_offer(response, transaction_id, source)
        if offer:
            key = (offer["server_address"], offer["offered_address"])
            if key not in seen:
                seen.add(key)
                offers.append(offer)
    return offers


def _macos_bpf_permission_message() -> str:
    return (
        "macOS DHCP discovery needs BPF capture and transmit access. Install Wireshark's "
        "ChmodBPF service or otherwise grant the toolkit service user read/write access to "
        "/dev/bpf devices; do not run the whole toolkit as root."
    )


def _build_dhcp_discover_frame(packet: bytes, source_mac: str) -> bytes:
    return _build_ipv4_udp_frame(
        packet,
        source_mac=source_mac,
        destination_mac="ff:ff:ff:ff:ff:ff",
        source_address="0.0.0.0",
        destination_address="255.255.255.255",
        source_port=DHCP_CLIENT_PORT,
        destination_port=DHCP_SERVER_PORT,
        packet_id=struct.unpack_from("!I", packet, 4)[0] & 0xFFFF,
    )


def _build_ipv4_udp_frame(
    payload: bytes,
    *,
    source_mac: str,
    destination_mac: str,
    source_address: str,
    destination_address: str,
    source_port: int,
    destination_port: int,
    packet_id: int = 0,
) -> bytes:
    source_mac_bytes = bytes.fromhex(normalize_mac(source_mac).replace(":", ""))
    destination_mac_compact = re.sub(r"[^0-9a-fA-F]", "", destination_mac)
    if len(destination_mac_compact) != 12:
        raise ToolInputError("Destination MAC address must contain six hexadecimal octets.")
    destination_mac_bytes = bytes.fromhex(destination_mac_compact)
    source_ip = socket.inet_aton(source_address)
    destination_ip = socket.inet_aton(destination_address)
    udp_length = 8 + len(payload)
    ip_length = 20 + udp_length
    if ip_length > 65535:
        raise ToolInputError("DHCP packet is too large for IPv4.")
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_length,
        packet_id & 0xFFFF,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        source_ip,
        destination_ip,
    )
    checksum = _internet_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", checksum) + ip_header[12:]
    udp_header = struct.pack(
        "!HHHH",
        source_port,
        destination_port,
        udp_length,
        0,  # An IPv4 UDP checksum of zero explicitly means no checksum.
    )
    ethernet_header = destination_mac_bytes + source_mac_bytes + struct.pack("!H", _ETHERTYPE_IPV4)
    return ethernet_header + ip_header + udp_header + payload


def _extract_dhcp_udp_payload(frame: bytes) -> tuple[bytes, tuple[str, int]] | None:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    ip_offset = 14
    while ethertype in _VLAN_ETHERTYPES:
        if len(frame) < ip_offset + 4:
            return None
        ethertype = struct.unpack_from("!H", frame, ip_offset + 2)[0]
        ip_offset += 4
    if ethertype != _ETHERTYPE_IPV4 or len(frame) < ip_offset + 20:
        return None
    version_ihl = frame[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(frame) < ip_offset + ip_header_length + 8:
        return None
    if frame[ip_offset + 9] != socket.IPPROTO_UDP:
        return None
    fragment = struct.unpack_from("!H", frame, ip_offset + 6)[0]
    if fragment & 0x3FFF:
        return None
    ip_total_length = struct.unpack_from("!H", frame, ip_offset + 2)[0]
    if ip_total_length < ip_header_length + 8:
        return None
    udp_offset = ip_offset + ip_header_length
    source_port, destination_port, udp_length = struct.unpack_from("!HHH", frame, udp_offset)
    if source_port != DHCP_SERVER_PORT or destination_port != DHCP_CLIENT_PORT or udp_length < 8:
        return None
    payload_end = min(ip_offset + ip_total_length, udp_offset + udp_length, len(frame))
    if payload_end < udp_offset + 8:
        return None
    source_address = socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16])
    return frame[udp_offset + 8 : payload_end], (source_address, source_port)


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _append_option(options: bytearray, code: int, value: bytes) -> None:
    if len(value) > 255:
        raise ToolInputError(f"DHCP option {code} is too long.")
    options.extend((code, len(value)))
    options.extend(value)


def _ascii_option(value: str, label: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ToolInputError(f"{label} must contain ASCII characters only.") from exc
    if not encoded or len(encoded) > 255:
        raise ToolInputError(f"{label} must be between 1 and 255 characters.")
    return encoded


def _parse_options(data: bytes) -> dict[int, list[bytes]]:
    result: dict[int, list[bytes]] = {}
    index = 0
    while index < len(data):
        code = data[index]
        index += 1
        if code == 0:
            continue
        if code == 255:
            break
        if index >= len(data):
            break
        length = data[index]
        index += 1
        if index + length > len(data):
            break
        result.setdefault(code, []).append(data[index : index + length])
        index += length
    return result


def _decode_option(code: int, raw: bytes) -> str:
    if code == 53 and raw:
        return {1: "Discover", 2: "Offer", 3: "Request", 5: "ACK", 6: "NAK"}.get(
            raw[0], str(raw[0])
        )
    if code in _IP_LIST_OPTIONS and raw and len(raw) % 4 == 0:
        return ", ".join(str(ipaddress.ip_address(raw[index : index + 4])) for index in range(0, len(raw), 4))
    if code == 1 and len(raw) == 4:
        return str(ipaddress.ip_address(raw))
    if code in _SECONDS_OPTIONS and len(raw) == 4:
        seconds = int.from_bytes(raw, "big")
        return f"{seconds} seconds"
    if code == 26 and len(raw) == 2:
        return str(int.from_bytes(raw, "big"))
    if code == 119:
        decoded = _decode_domain_search(raw)
        return ", ".join(decoded) if decoded else raw.hex(" ")
    if code == 121:
        decoded = _decode_classless_routes(raw)
        return "; ".join(decoded) if decoded else raw.hex(" ")
    if code in _TEXT_OPTIONS:
        return raw.decode("utf-8", errors="replace")
    return raw.hex(" ")


def _decode_domain_search(raw: bytes) -> list[str]:
    names = []
    offset = 0
    try:
        while offset < len(raw):
            labels = []
            cursor = offset
            jumped = False
            visited = set()
            while True:
                if cursor >= len(raw) or cursor in visited:
                    raise ValueError
                visited.add(cursor)
                length = raw[cursor]
                if length == 0:
                    if not jumped:
                        offset = cursor + 1
                    break
                if length & 0xC0 == 0xC0:
                    if cursor + 1 >= len(raw):
                        raise ValueError
                    pointer = ((length & 0x3F) << 8) | raw[cursor + 1]
                    if not jumped:
                        offset = cursor + 2
                        jumped = True
                    cursor = pointer
                    continue
                if length > 63 or cursor + 1 + length > len(raw):
                    raise ValueError
                labels.append(raw[cursor + 1 : cursor + 1 + length].decode("ascii"))
                cursor += length + 1
                if not jumped:
                    offset = cursor
            names.append(".".join(labels))
    except (UnicodeDecodeError, ValueError):
        return []
    return names


def _decode_classless_routes(raw: bytes) -> list[str]:
    routes = []
    offset = 0
    try:
        while offset < len(raw):
            prefix = raw[offset]
            offset += 1
            if prefix > 32:
                raise ValueError
            destination_length = (prefix + 7) // 8
            if offset + destination_length + 4 > len(raw):
                raise ValueError
            destination = raw[offset : offset + destination_length] + b"\0" * (4 - destination_length)
            offset += destination_length
            router = raw[offset : offset + 4]
            offset += 4
            network = ipaddress.ip_network((ipaddress.ip_address(destination), prefix), strict=False)
            routes.append(f"{network} via {ipaddress.ip_address(router)}")
    except ValueError:
        return []
    return routes
