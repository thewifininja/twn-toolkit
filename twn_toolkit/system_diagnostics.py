from __future__ import annotations

import grp
import os
import platform
import pwd
import shutil
import sys
from pathlib import Path
from typing import Any

from .network_tools import ping_engine_capability


CHMOD_BPF_PLIST = Path("/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist")
LINUX_NETWORK_CAPABILITY_BITS = {
    "CAP_NET_BIND_SERVICE": 10,
    "CAP_NET_ADMIN": 12,
    "CAP_NET_RAW": 13,
}


def _command_entry(
    name: str,
    workflow: str,
    *,
    alternatives: tuple[str, ...] | None = None,
    optional: bool = False,
    detail: str = "",
) -> dict[str, Any]:
    candidates = alternatives or (name,)
    executable = None
    for candidate in candidates:
        executable = shutil.which(candidate)
        if executable:
            break
    return {
        "name": name,
        "workflow": workflow,
        "available": bool(executable),
        "optional": optional,
        "detail": detail
        or (
            f"Available at {executable}."
            if executable
            else "Not found on the toolkit service PATH."
        ),
    }


def command_dependencies(*, system: str | None = None) -> list[dict[str, Any]]:
    """Inventory external executables used by toolkit workflows on this platform."""
    detected_system = system or platform.system()
    dependencies = [
        _command_entry("ping", "Ping, Path MTU, and automation fallback"),
        _command_entry("traceroute", "Traceroute"),
        _command_entry("tcpdump", "Packet Capture", optional=True),
        _command_entry("iperf3", "iPerf3 client and managed server", optional=True),
        _command_entry("eapol_test", "RADIUS PEAP and EAP-TLS", optional=True),
        _command_entry("certbot", "ACME DNS-01 certificates", optional=True),
        _command_entry(
            "sudo",
            "Privileged service, recovery, and narrow PF helper operations",
            optional=True,
        ),
    ]

    ping_capability = ping_engine_capability()
    dependencies.append(
        {
            "name": "fping",
            "workflow": "Accelerated Multi-Ping and Ping automations",
            "available": bool(ping_capability["accelerated"]),
            "optional": True,
            "detail": str(ping_capability["detail"]),
        }
    )

    if detected_system == "Darwin":
        dependencies.extend(
            (
                _command_entry("ping6", "IPv6 Ping and Path MTU"),
                _command_entry("traceroute6", "IPv6 Traceroute"),
                _command_entry("ifconfig", "Interface discovery and Wake-on-LAN"),
                _command_entry(
                    "pfctl", "Optional macOS multicast compatibility", optional=True
                ),
                _command_entry("launchctl", "Autostart service management"),
                _command_entry(
                    "sysctl", "Operating-system boot identity fallback", optional=True
                ),
            )
        )
    elif detected_system == "Linux":
        dependencies.extend(
            (
                _command_entry(
                    "ip or ifconfig",
                    "Interface and address discovery",
                    alternatives=("ip", "ifconfig"),
                ),
                _command_entry("systemctl", "Autostart service management"),
            )
        )

    dependencies.extend(
        (
            _command_entry("ps", "Process discovery and recovery"),
            _command_entry("lsof", "Listener recovery fallback", optional=True),
            {
                **_command_entry(
                    "shasum or sha256sum",
                    "Requirements change detection",
                    alternatives=("shasum", "sha256sum"),
                    optional=True,
                ),
                "detail": "A Python hashing fallback is always available.",
            },
        )
    )
    return dependencies


def _current_account() -> tuple[str, list[str]]:
    try:
        username = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        username = str(os.geteuid())
    groups = []
    for group_id in os.getgroups():
        try:
            groups.append(grp.getgrgid(group_id).gr_name)
        except KeyError:
            groups.append(str(group_id))
    return username, sorted(set(groups))


def _macos_bpf_capability() -> dict[str, Any]:
    username, groups = _current_account()
    devices = sorted(Path("/dev").glob("bpf[0-9]*"))
    writable_device = next(
        (
            path
            for path in devices
            if os.access(path, os.R_OK | os.W_OK, effective_ids=True)
        ),
        None,
    )
    chmod_bpf = CHMOD_BPF_PLIST.is_file()
    policy = (
        "Wireshark ChmodBPF is installed"
        if chmod_bpf
        else "Wireshark ChmodBPF was not detected"
    )
    group_detail = (
        "access_bpf membership is active"
        if "access_bpf" in groups
        else "access_bpf membership is not active"
    )
    if writable_device:
        detail = (
            f"{username} can read and write {writable_device}; {policy}, and {group_detail}."
        )
    elif devices:
        detail = (
            f"{len(devices)} BPF device(s) exist, but {username} cannot read and write them; "
            f"{policy}, and {group_detail}."
        )
    else:
        detail = f"No /dev/bpf devices were found; {policy}."
    return {
        "name": "macOS BPF packet access",
        "available": writable_device is not None,
        "status": "Ready" if writable_device else "Permission needed",
        "detail": detail,
    }


def _linux_effective_capabilities() -> set[str]:
    try:
        lines = Path("/proc/self/status").read_text(encoding="ascii").splitlines()
        encoded = next(
            line.split(":", 1)[1].strip()
            for line in lines
            if line.startswith("CapEff:")
        )
        value = int(encoded, 16)
    except (OSError, StopIteration, ValueError):
        return set()
    return {
        name
        for name, bit in LINUX_NETWORK_CAPABILITY_BITS.items()
        if value & (1 << bit)
    }


def _linux_network_capability() -> dict[str, Any]:
    effective = _linux_effective_capabilities()
    expected = set(LINUX_NETWORK_CAPABILITY_BITS)
    missing = sorted(expected - effective)
    if not missing:
        status = "Enabled"
        detail = (
            "The current toolkit process has CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, "
            "and CAP_NET_RAW."
        )
        available = True
    elif effective:
        status = "Partial"
        detail = (
            f"Effective: {', '.join(sorted(effective))}. Missing: {', '.join(missing)}."
        )
        available = False
    else:
        status = "Not enabled"
        detail = (
            "The current toolkit process has no scoped Linux network capabilities. "
            "Most workflows still work; raw capture/replay, promiscuous mode, DHCP client-port access, "
            "and low-numbered listeners may not."
        )
        available = False
    return {
        "name": "Linux scoped network capabilities",
        "available": available,
        "status": status,
        "detail": detail,
    }


def platform_capabilities(*, system: str | None = None) -> list[dict[str, Any]]:
    detected_system = system or platform.system()
    capabilities = [
        {
            "name": "Python runtime",
            "available": sys.version_info >= (3, 10),
            "status": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "detail": sys.executable,
        }
    ]
    if detected_system == "Darwin":
        capabilities.append(_macos_bpf_capability())
    elif detected_system == "Linux":
        capabilities.append(_linux_network_capability())
    return capabilities
