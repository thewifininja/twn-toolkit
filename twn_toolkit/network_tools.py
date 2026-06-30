from __future__ import annotations

import ipaddress
import platform
import re
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


def parse_ping_targets(hosts_text: str, limit: int = 100) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    for raw_line in hosts_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=" in line:
            label, host = (part.strip() for part in line.split("=", 1))
            if not label:
                raise ToolInputError("Friendly names cannot be empty.")
            if len(label) > 100:
                raise ToolInputError("Friendly names must be 100 characters or fewer.")
            candidates = [(label, host)]
        else:
            candidates = [("", host) for host in split_values(line)]
        for label, host in candidates:
            targets.append({"label": label, "host": host})

    if not targets:
        raise ToolInputError("Enter at least one IP address or hostname.")
    if len(targets) > limit:
        raise ToolInputError(f"A maximum of {limit} hosts is allowed per run.")
    invalid = [target["host"] for target in targets if not _valid_host(target["host"])]
    if invalid:
        raise ToolInputError(f"Invalid host value(s): {', '.join(invalid[:5])}")
    return targets


def ping_hosts(hosts: list[str], timeout: int = 1) -> list[dict[str, Any]]:
    workers = min(20, len(hosts))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_ping_host, host, timeout): index for index, host in enumerate(hosts)}
        indexed_results = [(futures[future], future.result()) for future in as_completed(futures)]
    return [result for _index, result in sorted(indexed_results)]


def run_ssh_hosts(
    hosts: list[str],
    username: str,
    password: str,
    commands: list[str],
    port: int = 22,
    allow_unknown_hosts: bool = False,
    send_ctrl_y: bool = False,
    command_delay: float = 1.0,
) -> list[dict[str, Any]]:
    if not username:
        raise ToolInputError("Enter an SSH username.")
    if not password:
        raise ToolInputError("Enter an SSH password.")
    if not commands:
        raise ToolInputError("Enter at least one command.")
    if len(commands) > 50:
        raise ToolInputError("A maximum of 50 SSH commands is allowed per run.")
    if any(len(command) > 500 for command in commands):
        raise ToolInputError("Each SSH command must be 500 characters or fewer.")
    if not 1 <= port <= 65535:
        raise ToolInputError("SSH port must be between 1 and 65535.")

    workers = min(10, len(hosts))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _ssh_host,
                host,
                username,
                password,
                commands,
                port,
                allow_unknown_hosts,
                send_ctrl_y,
                command_delay,
            ): index
            for index, host in enumerate(hosts)
        }
        indexed_results = [(futures[future], future.result()) for future in as_completed(futures)]
    return [result for _index, result in sorted(indexed_results)]


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
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "host": host,
            "reachable": False,
            "latency_ms": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": str(exc),
        }


def _ssh_host(
    host: str,
    username: str,
    password: str,
    commands: list[str],
    port: int,
    allow_unknown_hosts: bool,
    send_ctrl_y: bool,
    command_delay: float,
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
        output.append(_read_channel(channel, max_wait=1.0))
        if send_ctrl_y:
            channel.send("\x19")
        for command in commands:
            channel.send(f"{command}\n")
            time.sleep(command_delay)
            output.append(_read_channel(channel, max_wait=3.0))
        return {
            "host": host,
            "status": "success",
            "output": _bounded_output("".join(output)),
        }
    except Exception as exc:
        return {
            "host": host,
            "status": "error",
            "output": _bounded_output("".join(output)),
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        client.close()


def _read_channel(channel: Any, max_wait: float) -> str:
    chunks: list[str] = []
    deadline = time.monotonic() + max_wait
    quiet_since = time.monotonic()
    while time.monotonic() < deadline:
        if channel.recv_ready():
            chunks.append(channel.recv(65535).decode("utf-8", errors="replace"))
            quiet_since = time.monotonic()
        elif time.monotonic() - quiet_since >= 0.35:
            break
        else:
            time.sleep(0.05)
    return "".join(chunks)


def _bounded_output(value: str, limit: int = 500_000) -> str:
    cleaned = value.strip()
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[:limit]}\n\n[Output truncated by The WiFi Ninja's Toolkit]"
