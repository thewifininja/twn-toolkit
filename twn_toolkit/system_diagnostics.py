from __future__ import annotations

import grp
import os
import platform
import pwd
import shutil
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .setup_dependencies import DEPENDENCIES
from .network_tools import ping_engine_capability
from .serial_diagnostics import linux_serial_capability


CHMOD_BPF_PLIST = Path("/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist")
LINUX_NETWORK_CAPABILITY_BITS = {
    "CAP_NET_BIND_SERVICE": 10,
    "CAP_NET_ADMIN": 12,
    "CAP_NET_RAW": 13,
}


@contextmanager
def readonly_sqlite_connection(
    path: str | Path,
    *,
    timeout_seconds: float = 0.2,
) -> Iterator[sqlite3.Connection]:
    """Open an existing SQLite database without schema or data mutations.

    Diagnostics must remain observational. A short busy timeout prevents one
    active writer from holding the entire diagnostics page for SQLite's normal
    ten-second application timeout.
    """
    database = Path(path).resolve()
    connection = sqlite3.connect(
        f"{database.as_uri()}?mode=ro",
        uri=True,
        timeout=max(0.0, float(timeout_seconds)),
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            f"PRAGMA busy_timeout = {max(0, int(timeout_seconds * 1000))}"
        )
        connection.execute("PRAGMA query_only = ON")
        yield connection
    finally:
        connection.close()


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
    dependencies = []
    for spec in DEPENDENCIES:
        if detected_system not in spec.systems or not spec.commands:
            continue
        optional = spec.category not in {'system', 'bootstrap'}
        if spec.id == 'fping':
            ping = ping_engine_capability()
            dependencies.append({'name':'fping','workflow':spec.purpose,'available':bool(ping['accelerated']),
                                 'optional':True,'detail':str(ping['detail'])})
        elif spec.all_commands:
            dependencies.extend(_command_entry(name, spec.purpose, optional=optional, detail=spec.note)
                                for name in spec.commands)
        else:
            name = ' or '.join(spec.commands)
            dependencies.append(_command_entry(name, spec.purpose, alternatives=spec.commands,
                                               optional=optional, detail=spec.note))
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
        capabilities.append(linux_serial_capability())
    return capabilities
