from __future__ import annotations

import ipaddress
import hashlib
import platform
import re
import socket
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


RFC1918_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)
PING_TIME_PATTERN = re.compile(r"time[=<]([\d.]+)\s*ms", re.IGNORECASE)
SSH_TIMEOUT_PREFIX = re.compile(r"^\[timeout=(\d+)\]\s+(.+)$", re.IGNORECASE)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SSH_DEFAULT_COMMAND_TIMEOUT = 300
SSH_MAX_COMMAND_TIMEOUT = 3600
SSH_MAX_RUN_TIMEOUT = 3600
SSH_OUTPUT_LIMIT = 5 * 1024 * 1024


class ToolInputError(ValueError):
    pass


def split_values(value: str) -> list[str]:
    values = re.split(r"[\s,]+", value.strip())
    return list(dict.fromkeys(item for item in values if item))


def subtract_subnets(supernets_text: str, exclusions_text: str) -> list[str]:
    supernet_values = (
        list(RFC1918_NETWORKS)
        if supernets_text.strip().lower() == "rfc1918"
        else split_values(supernets_text)
    )
    exclusion_values = split_values(exclusions_text)
    if not supernet_values:
        raise ToolInputError("Enter at least one supernet or use rfc1918.")
    if not exclusion_values:
        raise ToolInputError("Enter at least one network to exclude.")
    if len(supernet_values) > 100 or len(exclusion_values) > 100:
        raise ToolInputError("A maximum of 100 parent networks and 100 exclusions is allowed.")

    supernets = _parse_networks(supernet_values, "supernet")
    exclusions = _parse_networks(exclusion_values, "exclusion")
    remaining = _collapse_networks(supernets)

    for exclusion in exclusions:
        updated: list[ipaddress._BaseNetwork] = []
        for network in remaining:
            if network.version != exclusion.version or not network.overlaps(exclusion):
                updated.append(network)
            elif network.subnet_of(exclusion):
                continue
            elif exclusion.subnet_of(network):
                updated.extend(network.address_exclude(exclusion))
        remaining = _collapse_networks(updated)

    return [str(network) for network in sorted(remaining, key=_network_sort_key)]


def validate_hosts(hosts_text: str, limit: int = 100) -> list[str]:
    hosts = split_values(hosts_text)
    if not hosts:
        raise ToolInputError("Enter at least one IP address or hostname.")
    if len(hosts) > limit:
        raise ToolInputError(f"A maximum of {limit} hosts is allowed per run.")
    invalid = [host for host in hosts if not _valid_host(host)]
    if invalid:
        raise ToolInputError(f"Invalid host value(s): {', '.join(invalid[:5])}")
    return hosts


def parse_tcp_ports(value: str, limit: int = 200) -> list[int]:
    tokens = [token for token in re.split(r"[\s,]+", value.strip()) if token]
    if not tokens:
        raise ToolInputError("Enter at least one TCP port.")
    ports: set[int] = set()
    for token in tokens:
        if "-" in token:
            if token.count("-") != 1:
                raise ToolInputError(f"Invalid port range: {token}")
            start_text, end_text = token.split("-", 1)
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ToolInputError(f"Invalid port range: {token}") from exc
            if start > end:
                raise ToolInputError(f"Port range must be ascending: {token}")
            if end - start + 1 > limit:
                raise ToolInputError(f"Port range '{token}' exceeds the {limit}-port limit.")
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(token))
            except ValueError as exc:
                raise ToolInputError(f"Invalid TCP port: {token}") from exc
        if len(ports) > limit:
            raise ToolInputError(f"A maximum of {limit} unique TCP ports is allowed.")
    invalid = [port for port in ports if not 1 <= port <= 65535]
    if invalid:
        raise ToolInputError("TCP ports must be between 1 and 65535.")
    return sorted(ports)


def scan_tcp_ports(
    targets: list[dict[str, str]],
    ports: list[int],
    timeout: float = 1.0,
    max_workers: int = 100,
) -> list[dict[str, Any]]:
    if not targets or not ports:
        raise ToolInputError("Select at least one host and TCP port.")
    if len(targets) * len(ports) > 5000:
        raise ToolInputError("A scan is limited to 5,000 host/port combinations.")
    if not 0.1 <= timeout <= 10:
        raise ToolInputError("Connection timeout must be between 0.1 and 10 seconds.")
    if not 1 <= max_workers <= 200:
        raise ToolInputError("Concurrency must be between 1 and 200.")

    jobs = [(target, port) for target in targets for port in ports]
    return scan_tcp_checks(jobs, timeout=timeout, max_workers=max_workers)


def scan_tcp_checks(
    checks: list[tuple[dict[str, str], int]],
    timeout: float = 1.0,
    max_workers: int = 100,
) -> list[dict[str, Any]]:
    if not checks:
        raise ToolInputError("Select at least one TCP host/port check.")
    if len(checks) > 5000:
        raise ToolInputError("A scan is limited to 5,000 host/port combinations.")
    if not 0.1 <= timeout <= 10:
        raise ToolInputError("Connection timeout must be between 0.1 and 10 seconds.")
    if not 1 <= max_workers <= 200:
        raise ToolInputError("Concurrency must be between 1 and 200.")
    workers = min(max_workers, len(checks))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_tcp_port, target, port, timeout): index
            for index, (target, port) in enumerate(checks)
        }
        indexed_results = [(futures[future], future.result()) for future in as_completed(futures)]
    return [result for _index, result in sorted(indexed_results)]


def _scan_tcp_port(target: dict[str, str], port: int, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    status = "error"
    detail = ""
    try:
        with socket.create_connection((target["host"], port), timeout=timeout):
            status = "open"
    except ConnectionRefusedError:
        status = "closed"
        detail = "Connection refused"
    except (TimeoutError, socket.timeout):
        status = "timeout"
        detail = "No response before timeout"
    except socket.gaierror as exc:
        detail = f"DNS resolution failed: {exc}"
    except OSError as exc:
        detail = str(exc)
    try:
        service = socket.getservbyport(port, "tcp")
    except OSError:
        service = ""
    return {
        "host": target["host"],
        "label": target.get("label", ""),
        "port": port,
        "service": service,
        "status": status,
        "detail": detail,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


def parse_ping_targets(hosts_text: str, limit: int = 100) -> list[dict[str, str]]:
    targets, invalid = parse_ping_targets_with_errors(hosts_text, limit=limit)
    if invalid:
        values = ", ".join(item["value"] for item in invalid[:5])
        raise ToolInputError(f"Invalid host value(s): {values}")
    return targets


def parse_ping_targets_with_errors(
    hosts_text: str, limit: int = 100
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    targets: list[dict[str, str]] = []
    invalid: list[dict[str, str]] = []
    candidate_count = 0
    for raw_line in hosts_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=" in line:
            label, host = (part.strip() for part in line.split("=", 1))
            if not label:
                invalid.append({"value": line, "error": "Friendly name cannot be empty."})
                candidate_count += 1
                continue
            if len(label) > 100:
                invalid.append({"value": line, "error": "Friendly name exceeds 100 characters."})
                candidate_count += 1
                continue
            candidates = [(label, host)]
        else:
            candidates = [("", host) for host in split_values(line)]
        for label, host in candidates:
            candidate_count += 1
            if _valid_host(host):
                targets.append({"label": label, "host": host})
            else:
                invalid.append({"value": host or line, "error": "Invalid IP address or hostname."})

    if not candidate_count:
        raise ToolInputError("Enter at least one IP address or hostname.")
    if candidate_count > limit:
        raise ToolInputError(f"A maximum of {limit} hosts is allowed per run.")
    return targets, invalid


def parse_ssh_targets(hosts_text: str, limit: int = 50) -> list[dict[str, str]]:
    """Parse SSH targets using the shared `Friendly Name = host` syntax."""
    return parse_ping_targets(hosts_text, limit=limit)


def parse_dns_hosts(hosts_text: str, limit: int = 100) -> list[dict[str, str]]:
    return parse_ping_targets(hosts_text, limit=limit)


def parse_dns_servers(servers_text: str, limit: int = 20) -> list[dict[str, str]]:
    servers: list[dict[str, str]] = []
    for raw_line in servers_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=" in line:
            label, address = (part.strip() for part in line.split("=", 1))
            if not label:
                raise ToolInputError("DNS server friendly names cannot be empty.")
        else:
            label, address = "", line
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise ToolInputError(f"DNS server '{address}' must be an IPv4 or IPv6 address.") from exc
        servers.append({"label": label, "address": address})
    if not servers:
        raise ToolInputError("Enter at least one DNS server.")
    if len(servers) > limit:
        raise ToolInputError(f"A maximum of {limit} DNS servers is allowed per run.")
    return servers


def dns_lookup_matrix(
    hosts: list[dict[str, str]],
    servers: list[dict[str, str]],
    record_type: str = "A",
    timeout: float = 3.0,
) -> list[dict[str, Any]]:
    allowed_types = {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"}
    record_type = record_type.upper()
    if record_type not in allowed_types:
        raise ToolInputError("Select a supported DNS record type.")
    if not 0.2 <= timeout <= 30:
        raise ToolInputError("DNS timeout must be between 0.2 and 30 seconds.")

    jobs = [(host, server) for host in hosts for server in servers]
    workers = min(20, len(jobs))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_dns_lookup, host, server, record_type, timeout): index
            for index, (host, server) in enumerate(jobs)
        }
        indexed_results = [(futures[future], future.result()) for future in as_completed(futures)]
    return [result for _index, result in sorted(indexed_results)]


def radius_authenticate(
    servers: list[dict[str, Any]],
    credentials: dict[str, Any],
    protocol: str = "pap",
    timeout: float = 3.0,
    retries: int = 1,
    attributes: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    protocol = protocol.lower()
    if protocol not in {"pap", "chap"}:
        raise ToolInputError("Authentication protocol must be PAP or CHAP.")
    if not 0.2 <= timeout <= 30:
        raise ToolInputError("RADIUS timeout must be between 0.2 and 30 seconds.")
    if not 1 <= retries <= 5:
        raise ToolInputError("RADIUS attempts must be between 1 and 5.")
    workers = min(10, len(servers))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _radius_authenticate_one,
                server,
                credentials,
                protocol,
                timeout,
                retries,
                attributes or [],
            ): index
            for index, server in enumerate(servers)
        }
        indexed_results = [(futures[future], future.result()) for future in as_completed(futures)]
    return [result for _index, result in sorted(indexed_results)]


def _radius_authenticate_one(
    server: dict[str, Any],
    credentials: dict[str, Any],
    protocol: str,
    timeout: float,
    retries: int,
    attributes: list[dict[str, Any]],
) -> dict[str, Any]:
    from pathlib import Path

    from pyrad.client import Client
    from pyrad.dictionary import Dictionary
    from pyrad.packet import AccessAccept, AccessChallenge, AccessReject, AccessRequest

    client = Client(
        server=server["host"],
        authport=server["port"],
        secret=server["secret"].encode("utf-8"),
        dict=Dictionary(str(Path(__file__).with_name("radius_dictionary"))),
        timeout=timeout,
        retries=retries,
    )
    request_packet = client.CreateAuthPacket(
        code=AccessRequest,
        **{"User-Name": credentials["username"]},
    )
    for attribute in attributes:
        key: Any = attribute["name"]
        value: Any = attribute["value"]
        if attribute.get("raw"):
            codes = [int(part) for part in key.split(":")]
            key = codes[0] if len(codes) == 1 else tuple(codes)
            value = bytes.fromhex(value)
        request_packet.AddAttribute(key, value)
    if protocol == "pap":
        request_packet["User-Password"] = request_packet.PwCrypt(credentials["password"])
    else:
        if request_packet.authenticator is None:
            request_packet.authenticator = request_packet.CreateAuthenticator()
        chap_id = bytes([request_packet.id])
        digest = hashlib.md5(
            chap_id + credentials["password"].encode("utf-8") + request_packet.authenticator
        ).digest()
        request_packet["CHAP-Password"] = chap_id + digest

    started = time.monotonic()
    try:
        reply = client.SendPacket(request_packet)
        statuses = {
            AccessAccept: "Access-Accept",
            AccessReject: "Access-Reject",
            AccessChallenge: "Access-Challenge",
        }
        attributes = []
        for name in reply.keys():
            for value in reply[name]:
                attributes.append(
                    {
                        "name": str(name),
                        "value": _radius_value(value),
                        "raw_hex": value.hex() if isinstance(value, bytes) else "",
                    }
                )
        return {
            "server_name": server["name"],
            "server": server["host"],
            "port": server["port"],
            "status": statuses.get(reply.code, f"Response code {reply.code}"),
            "response_ms": round((time.monotonic() - started) * 1000, 1),
            "attributes": attributes,
        }
    except Exception as exc:
        return {
            "server_name": server["name"],
            "server": server["host"],
            "port": server["port"],
            "status": "error",
            "response_ms": round((time.monotonic() - started) * 1000, 1),
            "attributes": [],
            "error": f"{type(exc).__name__}: {exc}",
        }


def _radius_value(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
            if decoded.isprintable():
                return decoded
        except UnicodeDecodeError:
            pass
        return f"{len(value)} bytes"
    return str(value)


def parse_radius_attributes(value: str, limit: int = 50) -> list[dict[str, Any]]:
    from pathlib import Path

    from pyrad.dictionary import Dictionary

    dictionary = Dictionary(str(Path(__file__).with_name("radius_dictionary")))
    attributes: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(value.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("# "):
            continue
        if "=" not in line:
            raise ToolInputError(f"RADIUS attribute line {line_number} must use Name = value.")
        name, item_value = (part.strip() for part in line.split("=", 1))
        if not name or not item_value:
            raise ToolInputError(f"RADIUS attribute line {line_number} is incomplete.")
        raw_match = re.fullmatch(r"#(\d+)(?::(\d+))?", name)
        if raw_match:
            try:
                bytes.fromhex(item_value)
            except ValueError as exc:
                raise ToolInputError(
                    f"Raw attribute line {line_number} must contain an even-length hexadecimal value."
                ) from exc
            code = raw_match.group(1)
            if raw_match.group(2):
                code += f":{raw_match.group(2)}"
            attributes.append({"name": code, "value": item_value, "raw": True})
        else:
            if name not in dictionary.attributes:
                raise ToolInputError(
                    f"Unknown RADIUS attribute '{name}' on line {line_number}. "
                    "Use #type = hex, or #vendor:type = hex for an unknown attribute."
                )
            attribute = dictionary.attributes[name]
            converted: Any = item_value
            if attribute.type in {"integer", "signed", "short", "byte", "integer64"}:
                try:
                    converted = int(item_value)
                except ValueError as exc:
                    raise ToolInputError(
                        f"RADIUS attribute '{name}' requires a whole number."
                    ) from exc
            elif attribute.type == "octets":
                if item_value.lower().startswith("hex:"):
                    try:
                        converted = bytes.fromhex(item_value[4:].strip())
                    except ValueError as exc:
                        raise ToolInputError(f"Invalid hexadecimal value for '{name}'.") from exc
                else:
                    converted = item_value.encode("utf-8")
            attributes.append({"name": name, "value": converted, "raw": False})
    if len(attributes) > limit:
        raise ToolInputError(f"A maximum of {limit} additional RADIUS attributes is allowed.")
    return attributes


def _dns_lookup(
    host: dict[str, str],
    server: dict[str, str],
    record_type: str,
    timeout: float,
) -> dict[str, Any]:
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server["address"]]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    started = time.monotonic()
    try:
        answer = resolver.resolve(host["host"], record_type, search=False)
        return {
            "host": host["host"],
            "host_label": host["label"],
            "server": server["address"],
            "server_label": server["label"],
            "record_type": record_type,
            "status": "success",
            "answers": [item.to_text() for item in answer],
            "response_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout) as exc:
        return {
            "host": host["host"],
            "host_label": host["label"],
            "server": server["address"],
            "server_label": server["label"],
            "record_type": record_type,
            "status": type(exc).__name__,
            "answers": [],
            "response_ms": round((time.monotonic() - started) * 1000, 1),
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "host": host["host"],
            "host_label": host["label"],
            "server": server["address"],
            "server_label": server["label"],
            "record_type": record_type,
            "status": "error",
            "answers": [],
            "response_ms": round((time.monotonic() - started) * 1000, 1),
            "error": str(exc),
        }


def ping_hosts(hosts: list[str], timeout: int = 1) -> list[dict[str, Any]]:
    workers = min(20, len(hosts))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_ping_host, host, timeout): index for index, host in enumerate(hosts)}
        indexed_results = [(futures[future], future.result()) for future in as_completed(futures)]
    return [result for _index, result in sorted(indexed_results)]


def run_ssh_hosts(
    hosts: list[str] | list[dict[str, str]],
    username: str,
    password: str,
    commands: list[str],
    port: int = 22,
    allow_unknown_hosts: bool = False,
    send_ctrl_y: bool = False,
    command_delay: float = 1.0,
    default_command_timeout: int = SSH_DEFAULT_COMMAND_TIMEOUT,
) -> list[dict[str, Any]]:
    if not username:
        raise ToolInputError("Enter an SSH username.")
    if not password:
        raise ToolInputError("Enter an SSH password.")
    command_specs = parse_ssh_commands(commands, default_command_timeout)
    targets = []
    for item in hosts:
        if isinstance(item, dict):
            host = str(item.get("host", "")).strip()
            label = str(item.get("label", "")).strip()
        else:
            host = str(item).strip()
            label = ""
        if not _valid_host(host):
            raise ToolInputError(f"Invalid host value: {host}")
        if len(label) > 100:
            raise ToolInputError("Friendly names must be 100 characters or fewer.")
        targets.append({"host": host, "label": label})
    if not targets:
        raise ToolInputError("Enter at least one IP address or hostname.")
    if not 1 <= port <= 65535:
        raise ToolInputError("SSH port must be between 1 and 65535.")

    workers = min(10, len(targets))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _ssh_host,
                target["host"],
                username,
                password,
                command_specs,
                port,
                allow_unknown_hosts,
                send_ctrl_y,
                command_delay,
                target["label"],
            ): index
            for index, target in enumerate(targets)
        }
        indexed_results = [(futures[future], future.result()) for future in as_completed(futures)]
    return [result for _index, result in sorted(indexed_results)]


def parse_ssh_commands(
    commands: list[str], default_timeout: int = SSH_DEFAULT_COMMAND_TIMEOUT
) -> list[dict[str, Any]]:
    try:
        normalized_default = int(default_timeout)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Default command timeout must be a whole number.") from exc
    if not 1 <= normalized_default <= SSH_MAX_COMMAND_TIMEOUT:
        raise ToolInputError(
            f"Default command timeout must be between 1 and {SSH_MAX_COMMAND_TIMEOUT} seconds."
        )
    normalized = [str(command).strip() for command in commands if str(command).strip()]
    if not normalized:
        raise ToolInputError("Enter at least one command.")
    if len(normalized) > 50:
        raise ToolInputError("A maximum of 50 SSH commands is allowed per run.")
    parsed: list[dict[str, Any]] = []
    for raw_command in normalized:
        timeout = normalized_default
        command = raw_command
        match = SSH_TIMEOUT_PREFIX.fullmatch(raw_command)
        if match:
            timeout = int(match.group(1))
            command = match.group(2).strip()
            if not 1 <= timeout <= SSH_MAX_COMMAND_TIMEOUT:
                raise ToolInputError(
                    f"Command timeout must be between 1 and {SSH_MAX_COMMAND_TIMEOUT} seconds."
                )
        if not command:
            raise ToolInputError("A timeout override must be followed by a command.")
        if len(command) > 500:
            raise ToolInputError("Each SSH command must be 500 characters or fewer.")
        parsed.append({"command": command, "timeout": timeout})
    if sum(item["timeout"] for item in parsed) > SSH_MAX_RUN_TIMEOUT:
        raise ToolInputError(
            f"Combined command timeout budget cannot exceed {SSH_MAX_RUN_TIMEOUT} seconds per host."
        )
    return parsed


def _parse_networks(values: list[str], label: str) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=True))
        except ValueError as exc:
            raise ToolInputError(f"Invalid {label} '{value}': {exc}") from exc
    return networks


def _network_sort_key(network: ipaddress._BaseNetwork) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def _collapse_networks(
    networks: list[ipaddress._BaseNetwork],
) -> list[ipaddress._BaseNetwork]:
    ipv4 = [network for network in networks if network.version == 4]
    ipv6 = [network for network in networks if network.version == 6]
    return [*ipaddress.collapse_addresses(ipv4), *ipaddress.collapse_addresses(ipv6)]


def _valid_host(host: str) -> bool:
    candidate = host.split("%", 1)[0]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        # Values that are shaped like IPv4 addresses must be valid IPv4
        # addresses; do not reinterpret an out-of-range address as a numeric
        # DNS hostname (for example, 192.0.2.999).
        if "." in candidate and re.fullmatch(r"[0-9.]+", candidate):
            return False
        return bool(HOSTNAME_PATTERN.fullmatch(host))


def _ping_host(host: str, timeout: int) -> dict[str, Any]:
    is_ipv6 = False
    try:
        is_ipv6 = ipaddress.ip_address(host.split("%", 1)[0]).version == 6
    except ValueError:
        pass

    system = platform.system()
    if is_ipv6 and system == "Darwin":
        binary = shutil.which("ping6") or "/sbin/ping6"
        command = [binary, "-c", "1", "-W", str(timeout * 1000), host]
    else:
        binary = shutil.which("ping") or "/sbin/ping"
        command = [binary]
        if is_ipv6:
            command.append("-6")
        command.extend(["-c", "1", "-W", str(timeout * 1000 if system == "Darwin" else timeout), host])

    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 0.25,
            check=False,
        )
        output = f"{completed.stdout}\n{completed.stderr}"
        match = PING_TIME_PATTERN.search(output)
        return {
            "host": host,
            "reachable": completed.returncode == 0,
            "latency_ms": float(match.group(1)) if match else None,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except subprocess.TimeoutExpired:
        return {
            "host": host,
            "reachable": False,
            "latency_ms": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except OSError as exc:
        return {
            "host": host,
            "reachable": False,
            "latency_ms": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": f"Unable to run the local ping command: {exc.strerror or exc}",
        }


def _ssh_host(
    host: str,
    username: str,
    password: str,
    commands: list[dict[str, Any]],
    port: int,
    allow_unknown_hosts: bool,
    send_ctrl_y: bool,
    command_delay: float,
    host_label: str = "",
) -> dict[str, Any]:
    import paramiko

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy() if allow_unknown_hosts else paramiko.RejectPolicy()
    )
    output: list[str] = []
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=8,
            auth_timeout=8,
            banner_timeout=8,
        )
        channel = client.invoke_shell(width=200, height=1000)
        channel.settimeout(0.2)
        initial_output = _read_channel(channel, max_wait=5.0, quiet_after=0.5)
        output.append(initial_output)
        prompt = _extract_ssh_prompt(initial_output)
        if send_ctrl_y:
            channel.send("\x19")
        for command_spec in commands:
            command = str(command_spec["command"])
            command_timeout = int(command_spec["timeout"])
            channel.send(f"{command}\n")
            if command_delay > 0:
                time.sleep(min(command_delay, 0.25))
            command_output, completed = _read_ssh_command(
                channel,
                command_timeout,
                prompt,
                capture_limit=max(0, SSH_OUTPUT_LIMIT - sum(len(item) for item in output)),
            )
            output.append(command_output)
            if not completed:
                return {
                    "host": host,
                    "host_label": host_label,
                    "status": "timeout",
                    "output": _bounded_output("".join(output)),
                    "error": (
                        f"Command exceeded its {command_timeout}-second timeout: {command}"
                    ),
                    "timed_out_command": command,
                    "command_timeout": command_timeout,
                }
        return {
            "host": host,
            "host_label": host_label,
            "status": "success",
            "output": _bounded_output("".join(output)),
        }
    except Exception as exc:
        return {
            "host": host,
            "host_label": host_label,
            "status": "error",
            "output": _bounded_output("".join(output)),
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        client.close()


def _read_channel(channel: Any, max_wait: float, quiet_after: float = 0.35) -> str:
    chunks: list[str] = []
    deadline = time.monotonic() + max_wait
    quiet_since = time.monotonic()
    while time.monotonic() < deadline:
        if channel.recv_ready():
            chunks.append(channel.recv(65535).decode("utf-8", errors="replace"))
            quiet_since = time.monotonic()
        elif time.monotonic() - quiet_since >= quiet_after:
            break
        else:
            time.sleep(0.05)
    return "".join(chunks)


def _extract_ssh_prompt(value: str) -> str:
    lines = [
        line.strip()
        for line in ANSI_ESCAPE_PATTERN.sub("", value).replace("\r", "").splitlines()
        if line.strip()
    ]
    if not lines:
        return ""
    candidate = lines[-1]
    return candidate if _looks_like_prompt(candidate) else ""


def _looks_like_prompt(value: str) -> bool:
    return bool(value) and len(value) <= 200 and value.rstrip().endswith(("#", ">", "$"))


def _prompt_returned(value: str, prompt: str) -> bool:
    lines = [
        line.strip()
        for line in ANSI_ESCAPE_PATTERN.sub("", value).replace("\r", "").splitlines()
        if line.strip()
    ]
    if not lines:
        return False
    candidate = lines[-1]
    if candidate == prompt:
        return True
    prompt_host = prompt.split(" ", 1)[0] if prompt else ""
    return bool(prompt_host) and candidate.startswith(prompt_host) and _looks_like_prompt(candidate)


def _read_ssh_command(
    channel: Any,
    max_wait: int,
    prompt: str,
    capture_limit: int = SSH_OUTPUT_LIMIT,
) -> tuple[str, bool]:
    chunks: list[str] = []
    captured = 0
    truncated = False
    detection_tail = ""
    deadline = time.monotonic() + max_wait
    quiet_since = time.monotonic()
    received_output = False
    while time.monotonic() < deadline:
        if channel.recv_ready():
            value = channel.recv(65535).decode("utf-8", errors="replace")
            detection_tail = (detection_tail + value)[-4096:]
            remaining = max(0, capture_limit - captured)
            if remaining:
                kept = value[:remaining]
                chunks.append(kept)
                captured += len(kept)
            if len(value) > remaining:
                truncated = True
            received_output = True
            quiet_since = time.monotonic()
            if prompt and _prompt_returned(detection_tail, prompt):
                return _captured_ssh_output(chunks, truncated), True
        elif not prompt and received_output and time.monotonic() - quiet_since >= 2.0:
            return _captured_ssh_output(chunks, truncated), True
        else:
            time.sleep(0.05)
    return _captured_ssh_output(chunks, truncated), False


def _captured_ssh_output(chunks: list[str], truncated: bool) -> str:
    value = "".join(chunks)
    if not truncated:
        return value
    return f"{value}\n\n[Additional command output omitted after reaching the per-host capture limit.]"


def _bounded_output(value: str, limit: int = SSH_OUTPUT_LIMIT) -> str:
    cleaned = value.strip()
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[:limit]}\n\n[Output truncated by The WiFi Ninja's Toolkit]"
