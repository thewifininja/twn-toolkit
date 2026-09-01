from __future__ import annotations

import grp
import os
import pwd
import stat
import sys
from pathlib import Path
from typing import Iterable


SERIAL_DEVICE_PATTERNS = (
    "/dev/ttyUSB*",
    "/dev/ttyACM*",
    "/dev/ttyAMA*",
    "/dev/rfcomm*",
    "/dev/cuaU*",
)


def serial_permission_status(path_value: str | Path) -> dict[str, object]:
    path = Path(path_value)
    try:
        metadata = path.stat()
    except OSError:
        return {
            "path": str(path),
            "present": False,
            "accessible": False,
            "owner": "",
            "group": "",
            "mode": "",
            "service_user": _effective_user(),
            "missing_groups": [],
        }
    owner = _user_name(metadata.st_uid)
    group = _group_name(metadata.st_gid)
    effective_groups = {os.getegid(), *os.getgroups()}
    group_can_access = bool(
        metadata.st_mode & stat.S_IRGRP and metadata.st_mode & stat.S_IWGRP
    )
    missing_groups = (
        [group]
        if group
        and metadata.st_gid not in effective_groups
        and metadata.st_gid != 0
        and group_can_access
        else []
    )
    return {
        "path": str(path),
        "present": True,
        "accessible": os.access(path, os.R_OK | os.W_OK),
        "owner": owner,
        "group": group,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "service_user": _effective_user(),
        "missing_groups": missing_groups,
    }


def serial_permission_message(path_value: str | Path) -> str:
    status = serial_permission_status(path_value)
    path = str(status["path"])
    if not status["present"]:
        return f"The console device {path} is no longer attached to this toolkit host."
    if sys.platform.startswith("linux"):
        identity = (
            f"{status['owner']}:{status['group']} with mode {status['mode']}"
            if status["owner"] and status["group"]
            else f"mode {status['mode']}"
        )
        missing = list(status["missing_groups"])
        if missing:
            group = str(missing[0])
            return (
                f"The toolkit service cannot open {path}. The device is {identity}, "
                f"but service account {status['service_user']} does not have the "
                f"{group} supplementary group. Grant that group to the toolkit "
                "service, then restart the toolkit service."
            )
        return (
            f"The toolkit service cannot read and write {path}. The device is "
            f"{identity}. Grant service account {status['service_user']} explicit "
            "read/write access through its device group, ACL, or udev rule, then "
            "restart the toolkit service."
        )
    return (
        f"The toolkit service cannot read and write {path}. Grant the service "
        "account access to that serial device, then restart the toolkit service."
    )


def linux_serial_service_groups(
    device_paths: Iterable[Path] | None = None,
    *,
    os_release_path: Path = Path("/etc/os-release"),
) -> tuple[str, ...]:
    """Return bounded serial groups for a Linux systemd service.

    Live device ownership is authoritative. When no adapter is attached during
    service installation, use the platform's conventional group only when that
    local group actually exists.
    """
    if not sys.platform.startswith("linux"):
        return ()
    paths = list(device_paths) if device_paths is not None else _serial_paths()
    groups: list[str] = []
    for path in paths:
        try:
            metadata = path.stat()
        except OSError:
            continue
        if not stat.S_ISCHR(metadata.st_mode) or metadata.st_gid == 0:
            continue
        if not (
            metadata.st_mode & stat.S_IRGRP and metadata.st_mode & stat.S_IWGRP
        ):
            continue
        name = _group_name(metadata.st_gid)
        if name:
            groups.append(name)
    if groups:
        return tuple(dict.fromkeys(groups))
    identifiers = _linux_distribution_ids(os_release_path)
    candidates = ("uucp", "dialout") if "arch" in identifiers else ("dialout", "uucp")
    for candidate in candidates:
        try:
            grp.getgrnam(candidate)
        except KeyError:
            continue
        return (candidate,)
    return ()


def _serial_paths() -> list[Path]:
    paths: list[Path] = []
    for pattern in SERIAL_DEVICE_PATTERNS:
        paths.extend(Path("/dev").glob(Path(pattern).name))
    return sorted(set(paths))


def _linux_distribution_ids(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    values: set[str] = set()
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key in {"ID", "ID_LIKE"}:
            values.update(value.strip().strip('"').casefold().split())
    return values


def _effective_user() -> str:
    return _user_name(os.geteuid()) or str(os.geteuid())


def _user_name(user_id: int) -> str:
    try:
        return pwd.getpwuid(user_id).pw_name
    except KeyError:
        return str(user_id)


def _group_name(group_id: int) -> str:
    try:
        name = grp.getgrgid(group_id).gr_name
    except KeyError:
        return ""
    return name if name and not any(character.isspace() for character in name) else ""


__all__ = [
    "linux_serial_service_groups",
    "serial_permission_message",
    "serial_permission_status",
]
