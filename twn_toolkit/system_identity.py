from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

from .server_settings import ServerSettingsStore
from .time_settings import TimeSettingsStore
from .version import APP_VERSION


TOOLKIT_START_MARKER = "twn-toolkit-start.json"


def write_toolkit_start_marker(instance_path: str | Path) -> dict[str, Any]:
    """Record one complete toolkit start, independently of scheduler restarts."""
    instance = Path(instance_path)
    instance.mkdir(parents=True, exist_ok=True)
    marker = {
        "id": secrets.token_hex(16),
        "occurred_at": time.time(),
    }
    path = instance / TOOLKIT_START_MARKER
    temporary = instance / f".{TOOLKIT_START_MARKER}.{os.getpid()}"
    try:
        temporary.write_text(
            json.dumps(marker, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return marker


def collect_system_identity(instance_path: str | Path) -> dict[str, Any]:
    """Return bounded, non-secret identity and current startup generations."""
    instance = Path(instance_path)
    settings = ServerSettingsStore(str(instance)).get()
    addresses, route_primary = _local_addresses()
    ipv4_addresses = [
        item["address"] for item in addresses if item["family"] == "ipv4"
    ]
    ipv6_addresses = [
        item["address"] for item in addresses if item["family"] == "ipv6"
    ]
    primary_ipv4 = (
        route_primary
        if route_primary in ipv4_addresses
        else ipv4_addresses[0]
        if ipv4_addresses
        else ""
    )
    scheme = _runtime_value(instance / "twn-toolkit.scheme", "http")
    if scheme not in {"http", "https"}:
        scheme = "http"
    port_text = _runtime_value(instance / "twn-toolkit.port", "5050")
    try:
        port = int(port_text)
    except ValueError:
        port = 5050
    if not 1 <= port <= 65535:
        port = 5050
    listen_host = _runtime_value(
        instance / "twn-toolkit.host", str(settings["listen_host"])
    )
    urls = _access_urls(
        scheme=scheme,
        port=port,
        listen_host=listen_host,
        preferred_fqdn=str(settings["preferred_fqdn"]),
        ipv4_addresses=ipv4_addresses,
        ipv6_addresses=ipv6_addresses,
    )
    startup = collect_startup_state(instance)
    hostname = socket.gethostname().strip() or "unknown"
    return {
        "toolkit": {
            "instance_name": str(settings["instance_name"]),
            "hostname": hostname,
            "version": APP_VERSION,
            "primary_ipv4": primary_ipv4,
            "ipv4_addresses": ipv4_addresses,
            "ipv6_addresses": ipv6_addresses,
            "addresses": addresses,
            "primary_url": urls[0] if urls else "",
            "urls": urls,
            "timezone": TimeSettingsStore(instance).resolved_timezone(),
        },
        "startup": startup,
    }


def collect_startup_state(instance_path: str | Path) -> dict[str, Any]:
    """Read only stable event generations; this is safe to poll cheaply."""
    instance = Path(instance_path)
    boot = _boot_identity()
    toolkit_start = _toolkit_start_identity(instance)
    return {
        "boot_id": boot["id"],
        "boot_started_at": boot["occurred_at"],
        "toolkit_start_id": toolkit_start["id"],
        "toolkit_started_at": toolkit_start["occurred_at"],
    }


def startup_event(identity: dict[str, Any], mode: str) -> dict[str, Any]:
    startup = identity.get("startup", {})
    if mode == "toolkit_start":
        return {
            "key": str(startup.get("toolkit_start_id", "")),
            "occurred_at": float(startup.get("toolkit_started_at", 0) or 0),
            "reason": "Toolkit service started",
        }
    return {
        "key": str(startup.get("boot_id", "")),
        "occurred_at": float(startup.get("boot_started_at", 0) or 0),
        "reason": "Host started",
    }


def _runtime_value(path: Path, default: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return default
    return value or default


def _toolkit_start_identity(instance: Path) -> dict[str, Any]:
    path = instance / TOOLKIT_START_MARKER
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        marker_id = str(payload.get("id", "")).strip()
        occurred_at = float(payload.get("occurred_at", 0))
        if marker_id and occurred_at > 0:
            return {"id": marker_id, "occurred_at": occurred_at}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return {"id": "", "occurred_at": 0.0}


@lru_cache(maxsize=1)
def _boot_identity() -> dict[str, Any]:
    proc_boot_id = Path("/proc/sys/kernel/random/boot_id")
    try:
        boot_id = proc_boot_id.read_text(encoding="ascii").strip()
    except OSError:
        boot_id = ""
    boot_started_at = _linux_boot_time()
    if boot_id:
        return {"id": f"linux:{boot_id}", "occurred_at": boot_started_at}

    try:
        output = subprocess.run(
            ("sysctl", "-n", "kern.boottime"),
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        output = ""
    match = re.search(r"sec\s*=\s*(\d+)", output)
    if match:
        seconds = float(match.group(1))
        return {
            "id": f"macos:{int(seconds)}",
            "occurred_at": seconds,
        }

    try:
        fallback = subprocess.run(
            ("ps", "-o", "lstart=", "-p", "1"),
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        fallback = ""
    if fallback:
        digest = hashlib.sha256(fallback.encode("utf-8")).hexdigest()[:24]
        return {"id": f"pid1:{digest}", "occurred_at": 0.0}
    # Python's monotonic clock is system-wide on supported macOS and Linux
    # versions. This fallback remains stable across process restarts even in a
    # constrained service sandbox where sysctl and ps are unavailable.
    approximate_boot = max(0, int((time.time() - time.monotonic()) // 10) * 10)
    return {
        "id": f"monotonic:{approximate_boot}",
        "occurred_at": float(approximate_boot),
    }


def _linux_boot_time() -> float:
    try:
        for line in Path("/proc/stat").read_text(encoding="ascii").splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def _local_addresses() -> tuple[list[dict[str, str]], str]:
    discovered: dict[str, str] = {}
    route_primary = _route_primary_ipv4()
    if route_primary:
        discovered[route_primary] = "default route"

    for command in (
        ("ip", "-o", "-4", "addr", "show", "up"),
        ("ip", "-o", "-6", "addr", "show", "up"),
    ):
        try:
            output = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3,
                check=True,
            ).stdout
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            continue
        for line in output.splitlines():
            match = re.search(
                r"^\d+:\s+([^\s:]+)(?:@[^\s]+)?\s+inet6?\s+([^/\s]+)", line
            )
            if match:
                _add_address(discovered, match.group(2), match.group(1))

    try:
        output = subprocess.run(
            ("ifconfig",),
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        ).stdout
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        output = ""
    current_interface = ""
    for line in output.splitlines():
        if line and not line[0].isspace() and ":" in line:
            current_interface = line.split(":", 1)[0]
            continue
        match = re.match(r"\s+inet6?\s+([^\s%]+)(?:%[^\s]+)?", line)
        if match:
            _add_address(discovered, match.group(1), current_interface)

    try:
        answers = socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        answers = []
    for answer in answers:
        _add_address(discovered, str(answer[4][0]).split("%", 1)[0], "hostname")

    ordered = sorted(
        discovered,
        key=lambda value: (
            0 if value == route_primary else 1,
            ipaddress.ip_address(value).version,
            int(ipaddress.ip_address(value)),
        ),
    )
    return [
        {
            "address": value,
            "family": "ipv4" if ipaddress.ip_address(value).version == 4 else "ipv6",
            "interface": discovered[value],
        }
        for value in ordered
    ], route_primary


def _route_primary_ipv4() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            candidate = str(probe.getsockname()[0])
    except OSError:
        return ""
    return candidate if _usable_address(candidate) else ""


def _add_address(target: dict[str, str], value: str, interface: str) -> None:
    value = value.strip().split("%", 1)[0]
    if _usable_address(value):
        target.setdefault(value, interface or "unknown")


def _usable_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
    )


def _access_urls(
    *,
    scheme: str,
    port: int,
    listen_host: str,
    preferred_fqdn: str,
    ipv4_addresses: Iterable[str],
    ipv6_addresses: Iterable[str],
) -> list[str]:
    hosts: list[str] = []
    if listen_host == "0.0.0.0":
        if preferred_fqdn:
            hosts.append(preferred_fqdn)
        hosts.extend(ipv4_addresses)
        hosts.extend(f"[{value}]" for value in ipv6_addresses)
        hosts.append("127.0.0.1")
    elif listen_host == "127.0.0.1":
        hosts.append("127.0.0.1")
    else:
        try:
            address = ipaddress.ip_address(listen_host)
        except ValueError:
            hosts.append(listen_host)
        else:
            hosts.append(f"[{address}]" if address.version == 6 else str(address))
    return list(dict.fromkeys(f"{scheme}://{host}:{port}" for host in hosts))


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage toolkit startup identity.")
    parser.add_argument("command", choices=("mark-start", "show"))
    parser.add_argument("--instance", required=True)
    args = parser.parse_args()
    payload = (
        write_toolkit_start_marker(args.instance)
        if args.command == "mark-start"
        else collect_system_identity(args.instance)
    )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
