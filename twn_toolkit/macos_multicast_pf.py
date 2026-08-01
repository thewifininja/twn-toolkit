from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence


PF_ANCHOR_NAME = "twn_toolkit"
PF_CONF_PATH = Path("/etc/pf.conf")
PF_ANCHOR_PATH = Path("/etc/pf.anchors/twn_toolkit")
PF_BEGIN_MARKER = "# BEGIN TWN TOOLKIT MULTICAST"
PF_END_MARKER = "# END TWN TOOLKIT MULTICAST"
PF_MANAGED_BLOCK = (
    f'{PF_BEGIN_MARKER}\n'
    f'anchor "{PF_ANCHOR_NAME}"\n'
    f'load anchor "{PF_ANCHOR_NAME}" from "{PF_ANCHOR_PATH}"\n'
    f"{PF_END_MARKER}\n"
)
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
RULE_PATTERN = re.compile(
    r"^pass quick on (?:(?P<single>[A-Za-z0-9_.:-]+)|\{ (?P<many>[A-Za-z0-9_.: -]+) \}) "
    r"inet proto igmp from any to 224\.0\.0\.0/4 no state allow-opts$"
)


class MulticastPfError(RuntimeError):
    pass


def multicast_pf_status(
    interfaces: Sequence[str] = (),
    *,
    system: str | None = None,
    pf_conf_path: Path = PF_CONF_PATH,
    anchor_path: Path = PF_ANCHOR_PATH,
    boot_time: float | None = None,
    check_active: bool = False,
    effective_uid: int | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    host_system = system or platform.system()
    requested_interfaces = _normalize_interfaces(interfaces, allow_empty=True)
    if host_system != "Darwin":
        return {
            "applicable": False,
            "state": "not_applicable",
            "ready": True,
            "attention": False,
            "detail": "The macOS PF compatibility rule is not required on this host.",
            "configured_interfaces": [],
            "missing_interfaces": [],
            "restart_required": False,
            "active": None,
        }

    try:
        pf_conf = pf_conf_path.read_text(encoding="utf-8")
    except OSError as exc:
        return _status_result(
            state="unknown",
            detail=f"The PF configuration could not be inspected: {exc.strerror or exc}",
            requested_interfaces=requested_interfaces,
        )

    block_state = _managed_block_state(pf_conf)
    try:
        anchor_text = anchor_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        anchor_text = ""
    except OSError as exc:
        return _status_result(
            state="unknown",
            detail=f"The TWN PF anchor could not be inspected: {exc.strerror or exc}",
            requested_interfaces=requested_interfaces,
        )

    configured_interfaces = parse_anchor_interfaces(anchor_text) if anchor_text else []
    if block_state == "malformed" or (anchor_text and configured_interfaces is None):
        return _status_result(
            state="drifted",
            detail="The macOS multicast PF configuration differs from the format managed by TWN Toolkit.",
            requested_interfaces=requested_interfaces,
            configured_interfaces=configured_interfaces or [],
        )
    if block_state == "absent" and not anchor_text:
        return _status_result(
            state="missing",
            detail="The optional macOS PF compatibility rule is not installed.",
            requested_interfaces=requested_interfaces,
        )
    if block_state != "present" or not anchor_text:
        return _status_result(
            state="drifted",
            detail="The TWN PF anchor and its main PF configuration hook are incomplete.",
            requested_interfaces=requested_interfaces,
            configured_interfaces=configured_interfaces or [],
        )

    configured_interfaces = configured_interfaces or []
    missing_interfaces = [
        interface
        for interface in requested_interfaces
        if interface not in configured_interfaces
    ]
    if missing_interfaces:
        return _status_result(
            state="interfaces_missing",
            detail="The PF compatibility rule does not cover every current multicast interface.",
            requested_interfaces=requested_interfaces,
            configured_interfaces=configured_interfaces,
            missing_interfaces=missing_interfaces,
        )

    observed_boot_time = boot_time if boot_time is not None else _darwin_boot_time(runner)
    restart_required = bool(
        observed_boot_time is not None
        and max(pf_conf_path.stat().st_mtime, anchor_path.stat().st_mtime)
        > observed_boot_time
    )
    active: bool | None = None
    uid = os.geteuid() if effective_uid is None else effective_uid
    if check_active and uid == 0:
        active = _active_rule_loaded(anchor_path, runner)
        restart_required = not active

    if restart_required:
        return _status_result(
            state="restart_required",
            detail="The PF compatibility files are installed, but macOS should be restarted before relying on them.",
            requested_interfaces=requested_interfaces,
            configured_interfaces=configured_interfaces,
            restart_required=True,
            active=active,
        )
    if active is False:
        return _status_result(
            state="not_loaded",
            detail="The PF compatibility files are installed, but the active ruleset does not contain the TWN rule.",
            requested_interfaces=requested_interfaces,
            configured_interfaces=configured_interfaces,
            restart_required=True,
            active=False,
        )
    return _status_result(
        state="configured",
        detail="The macOS PF compatibility rule is configured for the current multicast interfaces.",
        requested_interfaces=requested_interfaces,
        configured_interfaces=configured_interfaces,
        active=active,
    )


def install_multicast_pf(
    interfaces: Sequence[str],
    *,
    system: str | None = None,
    pf_conf_path: Path = PF_CONF_PATH,
    anchor_path: Path = PF_ANCHOR_PATH,
    effective_uid: int | None = None,
    validator: Callable[[Path, Path], None] | None = None,
) -> dict[str, object]:
    _require_darwin_and_root(system=system, effective_uid=effective_uid)
    normalized = _normalize_interfaces(interfaces)
    try:
        original_conf = pf_conf_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MulticastPfError(
            f"Unable to read {pf_conf_path}: {exc.strerror or exc}"
        ) from exc

    block_state = _managed_block_state(original_conf)
    if block_state == "malformed":
        raise MulticastPfError(
            f"The TWN-managed block in {pf_conf_path} is incomplete or duplicated. No changes were made."
        )
    original_anchor: str | None
    try:
        original_anchor = anchor_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        original_anchor = None
    except OSError as exc:
        raise MulticastPfError(
            f"Unable to read {anchor_path}: {exc.strerror or exc}"
        ) from exc
    if original_anchor and parse_anchor_interfaces(original_anchor) is None:
        raise MulticastPfError(
            f"{anchor_path} exists but is not a TWN-managed multicast rule. No changes were made."
        )

    proposed_conf = _install_managed_block(original_conf)
    proposed_anchor = render_anchor_rule(normalized)
    if original_conf == proposed_conf and original_anchor == proposed_anchor:
        return {
            "changed": False,
            "interfaces": normalized,
            "backup": "",
            "detail": "The macOS multicast PF compatibility rule is already installed.",
        }

    validate = validator or _validate_pf_files
    _validate_proposed_files(
        proposed_conf,
        proposed_anchor,
        anchor_path=anchor_path,
        validator=validate,
    )
    backup = _backup_file(pf_conf_path)
    anchor_backup = _backup_file(anchor_path) if original_anchor is not None else None
    try:
        _atomic_write(
            anchor_path,
            proposed_anchor,
            template=anchor_path.parent,
            mode=0o644,
        )
        _atomic_write(pf_conf_path, proposed_conf, template=pf_conf_path)
    except Exception:
        _restore_file(pf_conf_path, backup)
        if anchor_backup is not None:
            _restore_file(anchor_path, anchor_backup)
        else:
            anchor_path.unlink(missing_ok=True)
        raise
    return {
        "changed": True,
        "interfaces": normalized,
        "backup": str(backup),
        "detail": "Installed the macOS multicast PF compatibility rule. Restart macOS to load it safely.",
    }


def uninstall_multicast_pf(
    *,
    system: str | None = None,
    pf_conf_path: Path = PF_CONF_PATH,
    anchor_path: Path = PF_ANCHOR_PATH,
    effective_uid: int | None = None,
    validator: Callable[[Path, Path], None] | None = None,
) -> dict[str, object]:
    _require_darwin_and_root(system=system, effective_uid=effective_uid)
    try:
        original_conf = pf_conf_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MulticastPfError(
            f"Unable to read {pf_conf_path}: {exc.strerror or exc}"
        ) from exc
    block_state = _managed_block_state(original_conf)
    if block_state == "malformed":
        raise MulticastPfError(
            f"The TWN-managed block in {pf_conf_path} is incomplete or duplicated. No changes were made."
        )
    try:
        anchor_text = anchor_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        anchor_text = None
    except OSError as exc:
        raise MulticastPfError(
            f"Unable to read {anchor_path}: {exc.strerror or exc}"
        ) from exc
    if anchor_text and parse_anchor_interfaces(anchor_text) is None:
        raise MulticastPfError(
            f"{anchor_path} is not a TWN-managed multicast rule. No changes were made."
        )
    if block_state == "absent" and anchor_text is None:
        return {
            "changed": False,
            "backup": "",
            "detail": "The macOS multicast PF compatibility rule is not installed.",
        }

    proposed_conf = _remove_managed_block(original_conf)
    validate = validator or _validate_pf_files
    _validate_proposed_files(
        proposed_conf,
        "",
        anchor_path=anchor_path,
        validator=validate,
    )
    backup = _backup_file(pf_conf_path) if proposed_conf != original_conf else None
    try:
        if proposed_conf != original_conf:
            _atomic_write(pf_conf_path, proposed_conf, template=pf_conf_path)
        if anchor_text is not None:
            anchor_path.unlink()
    except Exception:
        if backup is not None:
            _restore_file(pf_conf_path, backup)
        raise
    return {
        "changed": True,
        "backup": str(backup or ""),
        "detail": "Removed the macOS multicast PF compatibility files. Restart macOS to unload the rule safely.",
    }


def render_anchor_rule(interfaces: Sequence[str]) -> str:
    normalized = _normalize_interfaces(interfaces)
    interface_expression = (
        normalized[0]
        if len(normalized) == 1
        else "{ " + " ".join(normalized) + " }"
    )
    return (
        f"pass quick on {interface_expression} inet proto igmp "
        "from any to 224.0.0.0/4 no state allow-opts\n"
    )


def parse_anchor_interfaces(value: str) -> list[str] | None:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    match = RULE_PATTERN.fullmatch(lines[0])
    if not match:
        return None
    if match.group("single"):
        return [match.group("single")]
    return _normalize_interfaces((match.group("many") or "").split())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="./twn multicast-pf",
        description="Manage the optional macOS PF rule required for reliable IGMP membership traffic.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("status", "install"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument(
            "--interfaces",
            nargs="+",
            metavar="INTERFACE",
            help="macOS interface names to cover; defaults to current non-point-to-point multicast interfaces",
        )
    subparsers.add_parser("uninstall")
    args = parser.parse_args(argv)
    try:
        interfaces = []
        if args.command != "uninstall":
            interfaces = args.interfaces or _detected_interfaces()
        if args.command == "status":
            status = multicast_pf_status(
                interfaces,
                check_active=True,
            )
            _print_status(status)
            return 0 if status["ready"] else 1
        if args.command == "install":
            result = install_multicast_pf(interfaces)
        else:
            result = uninstall_multicast_pf()
    except (MulticastPfError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(result["detail"])
    if result.get("interfaces"):
        print("Interfaces: " + ", ".join(result["interfaces"]))
    if result.get("backup"):
        print(f"Backup: {result['backup']}")
    return 0


def _status_result(
    *,
    state: str,
    detail: str,
    requested_interfaces: Sequence[str],
    configured_interfaces: Sequence[str] = (),
    missing_interfaces: Sequence[str] = (),
    restart_required: bool = False,
    active: bool | None = None,
) -> dict[str, object]:
    ready = state in {"configured", "not_applicable"}
    return {
        "applicable": True,
        "state": state,
        "ready": ready,
        "attention": not ready,
        "detail": detail,
        "configured_interfaces": list(configured_interfaces),
        "missing_interfaces": list(missing_interfaces),
        "requested_interfaces": list(requested_interfaces),
        "restart_required": restart_required,
        "active": active,
        "install_command": _install_command(requested_interfaces),
        "status_command": "sudo ./twn multicast-pf status",
        "uninstall_command": "sudo ./twn multicast-pf uninstall",
    }


def _install_command(interfaces: Sequence[str]) -> str:
    suffix = " --interfaces " + " ".join(interfaces) if interfaces else ""
    return f"sudo ./twn multicast-pf install{suffix}"


def _normalize_interfaces(
    interfaces: Sequence[str], *, allow_empty: bool = False
) -> list[str]:
    normalized = list(dict.fromkeys(str(interface).strip() for interface in interfaces))
    if not allow_empty and not normalized:
        raise ValueError("At least one multicast interface is required.")
    for interface in normalized:
        if not INTERFACE_PATTERN.fullmatch(interface):
            raise ValueError(f"Invalid network interface name: {interface or '(empty)'}")
    return sorted(normalized)


def _managed_block_state(value: str) -> str:
    begin_count = value.count(PF_BEGIN_MARKER)
    end_count = value.count(PF_END_MARKER)
    if begin_count == 0 and end_count == 0:
        return "absent"
    if begin_count != 1 or end_count != 1:
        return "malformed"
    start = value.index(PF_BEGIN_MARKER)
    end = value.index(PF_END_MARKER, start) + len(PF_END_MARKER)
    if value[start:end].strip() != PF_MANAGED_BLOCK.strip():
        return "malformed"
    return "present"


def _install_managed_block(value: str) -> str:
    if _managed_block_state(value) == "present":
        return value
    insertion = re.search(r'^anchor "com\.apple/\*"\s*$', value, flags=re.MULTILINE)
    if insertion is None:
        return value.rstrip() + "\n\n" + PF_MANAGED_BLOCK
    index = insertion.start()
    return value[:index] + PF_MANAGED_BLOCK + value[index:]


def _remove_managed_block(value: str) -> str:
    if _managed_block_state(value) == "absent":
        return value
    start = value.index(PF_BEGIN_MARKER)
    end = value.index(PF_END_MARKER, start) + len(PF_END_MARKER)
    if end < len(value) and value[end] == "\n":
        end += 1
    return value[:start] + value[end:]


def _require_darwin_and_root(
    *, system: str | None,
    effective_uid: int | None,
) -> None:
    if (system or platform.system()) != "Darwin":
        raise MulticastPfError("This PF compatibility helper is available only on macOS.")
    uid = os.geteuid() if effective_uid is None else effective_uid
    if uid != 0:
        raise MulticastPfError("Run this command with sudo.")


def _detected_interfaces() -> list[str]:
    from .multicast_tools import available_multicast_interfaces

    return [
        str(interface["name"])
        for interface in available_multicast_interfaces()
        if not interface.get("point_to_point")
    ]


def _validate_proposed_files(
    proposed_conf: str,
    proposed_anchor: str,
    *,
    anchor_path: Path,
    validator: Callable[[Path, Path], None],
) -> None:
    temp_root = Path(tempfile.mkdtemp(prefix="twn-pf-"))
    try:
        temp_anchor = temp_root / "twn_toolkit"
        temp_conf = temp_root / "pf.conf"
        temp_anchor.write_text(proposed_anchor, encoding="utf-8")
        validation_conf = proposed_conf.replace(
            str(anchor_path),
            str(temp_anchor),
        )
        temp_conf.write_text(validation_conf, encoding="utf-8")
        validator(temp_conf, temp_anchor)
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def _validate_pf_files(pf_conf_path: Path, anchor_path: Path) -> None:
    pfctl = shutil.which("pfctl") or "/sbin/pfctl"
    for command in (
        [pfctl, "-n", "-a", PF_ANCHOR_NAME, "-f", str(anchor_path)],
        [pfctl, "-n", "-f", str(pf_conf_path)],
    ):
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise MulticastPfError(
                f"PF rejected the proposed configuration: {detail or 'validation failed'}"
            )


def _backup_file(path: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.twn-toolkit-{stamp}.bak")
    counter = 1
    while backup.exists():
        backup = path.with_name(
            f"{path.name}.twn-toolkit-{stamp}-{counter}.bak"
        )
        counter += 1
    shutil.copy2(path, backup)
    return backup


def _atomic_write(
    path: Path,
    value: str,
    *,
    template: Path,
    mode: int | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    template_stat = template.stat()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode if mode is not None else template_stat.st_mode & 0o777)
        os.chown(temporary, template_stat.st_uid, template_stat.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _restore_file(path: Path, backup: Path) -> None:
    shutil.copy2(backup, path)


def _darwin_boot_time(
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> float | None:
    try:
        completed = runner(
            ["/usr/sbin/sysctl", "-n", "kern.boottime"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"sec\s*=\s*(\d+)", completed.stdout)
    return float(match.group(1)) if match else None


def _active_rule_loaded(
    anchor_path: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> bool:
    expected_interfaces = parse_anchor_interfaces(
        anchor_path.read_text(encoding="utf-8")
    )
    pfctl = shutil.which("pfctl") or "/sbin/pfctl"
    try:
        completed = runner(
            [pfctl, "-a", PF_ANCHOR_NAME, "-sr"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    output = completed.stdout
    return bool(
        completed.returncode == 0
        and "proto igmp" in output
        and "allow-opts" in output
        and expected_interfaces
        and all(interface in output for interface in expected_interfaces)
    )


def _print_status(status: dict[str, object]) -> None:
    print(f"macOS multicast PF status: {status['state']}")
    print(status["detail"])
    configured = status.get("configured_interfaces") or []
    if configured:
        print("Configured interfaces: " + ", ".join(configured))
    missing = status.get("missing_interfaces") or []
    if missing:
        print("Missing interfaces: " + ", ".join(missing))
    if (
        status.get("active") is None
        and status.get("state") in {"configured", "restart_required", "not_loaded"}
    ):
        print("Run with sudo to verify the active PF ruleset.")


if __name__ == "__main__":
    raise SystemExit(main())
