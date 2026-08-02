from __future__ import annotations

import argparse
import getpass
import grp
import os
import platform
import plistlib
import pwd
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import Sequence


SYSTEMD_UNIT_NAME = "twn-toolkit.service"
SYSTEMD_UNIT_PATH = Path("/etc/systemd/system") / SYSTEMD_UNIT_NAME
LAUNCHD_LABEL = "com.thewifininja.toolkit"
LAUNCHD_PLIST_PATH = Path("/Library/LaunchDaemons") / f"{LAUNCHD_LABEL}.plist"
NETWORK_CAPABILITIES = ("CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW")


class ServiceError(RuntimeError):
    pass


@dataclass(frozen=True)
class ServiceUser:
    name: str
    group: str
    uid: int
    gid: int
    home: str


def service_user(name: str | None, *, allow_root: bool = False) -> ServiceUser:
    requested = name or os.environ.get("SUDO_USER")
    if not requested:
        requested = getpass.getuser()
    try:
        account = pwd.getpwnam(requested)
        group_name = grp.getgrgid(account.pw_gid).gr_name
    except KeyError as exc:
        raise ServiceError(f"Service user {requested!r} does not exist.") from exc
    if account.pw_uid == 0 and not allow_root:
        raise ServiceError(
            "Refusing to run the whole toolkit as root. Invoke this through sudo from "
            "the intended account, pass --user NAME, or explicitly add --allow-root."
        )
    return ServiceUser(
        requested,
        group_name,
        account.pw_uid,
        account.pw_gid,
        account.pw_dir,
    )


def _unit_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def _unit_path(value: str) -> str:
    if value != value.strip() or any(character in value for character in "\0\r\n"):
        raise ServiceError(f"Unsupported systemd path: {value!r}")
    return value.replace("%", "%%")


def _service_path(root: Path) -> str:
    return os.pathsep.join(
        (
            str(root / ".venv" / "bin"),
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
        )
    )


def render_systemd_unit(
    root: Path,
    user: ServiceUser,
    *,
    network_capabilities: bool = False,
) -> str:
    capabilities = ""
    if network_capabilities:
        joined = " ".join(NETWORK_CAPABILITIES)
        capabilities = (
            f"CapabilityBoundingSet={joined}\n"
            f"AmbientCapabilities={joined}\n"
            "NoNewPrivileges=true\n"
        )
    return (
        "[Unit]\n"
        "Description=The WiFi Ninja's Toolkit\n"
        "Wants=network-online.target\n"
        "After=network-online.target\n"
        "StartLimitIntervalSec=120\n"
        "StartLimitBurst=5\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"User={user.name}\n"
        f"Group={user.group}\n"
        f"WorkingDirectory={_unit_path(str(root))}\n"
        f"ExecStart={_unit_quote(str(root / 'twn'))} service-run\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "TimeoutStartSec=180\n"
        "TimeoutStopSec=45\n"
        "KillMode=mixed\n"
        "UMask=0077\n"
        f"Environment={_unit_quote('PATH=' + _service_path(root))}\n"
        f"Environment={_unit_quote('HOME=' + user.home)}\n"
        f"Environment={_unit_quote('USER=' + user.name)}\n"
        f"Environment={_unit_quote('LOGNAME=' + user.name)}\n"
        f"{capabilities}"
        "PrivateTmp=true\n"
        "ProtectSystem=full\n"
        "ProtectControlGroups=true\n"
        "ProtectKernelModules=true\n"
        "ProtectKernelTunables=true\n"
        "RestrictRealtime=true\n"
        "LockPersonality=true\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def render_launchd_plist(root: Path, user: ServiceUser) -> bytes:
    instance = root / "instance"
    payload = {
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": [str(root / "twn"), "service-run"],
        "WorkingDirectory": str(root),
        "UserName": user.name,
        "GroupName": user.group,
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 5,
        "ProcessType": "Background",
        "Umask": 0o077,
        "EnvironmentVariables": {
            "PATH": _service_path(root),
            "HOME": user.home,
            "USER": user.name,
            "LOGNAME": user.name,
        },
        "StandardOutPath": str(instance / "twn-service.log"),
        "StandardErrorPath": str(instance / "twn-service-error.log"),
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False)


def _run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True)


def _run_quiet(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _write_system_file(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _require_root() -> None:
    if os.geteuid() != 0:
        raise ServiceError("This service-manager operation requires sudo.")


def _validate_installation(root: Path) -> None:
    if not root.is_absolute():
        raise ServiceError("The toolkit installation path must be absolute.")
    if not (root / "twn").is_file() or not os.access(root / "twn", os.X_OK):
        raise ServiceError(f"Toolkit launcher is missing or not executable: {root / 'twn'}")
    if not (root / ".venv" / "bin" / "python").is_file():
        raise ServiceError("Python virtual environment is missing. Run ./install.sh first.")


def _validate_macos_service_location(root: Path, user: ServiceUser) -> None:
    resolved_root = root.resolve()
    home = Path(user.home).resolve()
    protected_roots = (
        home / "Desktop",
        home / "Documents",
        home / "Downloads",
        home / "Library" / "CloudStorage",
        home / "Library" / "Mobile Documents",
    )
    protected = next(
        (
            candidate
            for candidate in protected_roots
            if resolved_root == candidate or resolved_root.is_relative_to(candidate)
        ),
        None,
    )
    if protected is not None:
        recommended = home / "twn-toolkit"
        raise ServiceError(
            "macOS privacy controls prevent a system LaunchDaemon from executing "
            f"the toolkit beneath {protected}. Use a fresh clone at an unprotected "
            f"path such as {recommended}, then run ./install.sh and install the "
            "service there. If relocating this checkout instead, rebuild its .venv. "
            "No service changes were made."
        )


def _validate_install_request(
    root: Path,
    user: ServiceUser,
    *,
    system: str,
    network_capabilities: bool,
) -> None:
    _validate_installation(root)
    if system == "Darwin" and network_capabilities:
        raise ServiceError(
            "--network-capabilities is available only for systemd-based Linux. "
            "Provision macOS BPF access separately."
        )
    if system == "Darwin":
        _validate_macos_service_location(root, user)


def _ensure_instance_directory(root: Path, user: ServiceUser) -> Path:
    instance = root / "instance"
    if not instance.exists():
        instance.mkdir(mode=0o700)
        os.chown(instance, user.uid, user.gid)
    if user.uid != 0:
        mismatched = next(
            (
                path
                for path in chain((instance,), instance.rglob("*"))
                if path.lstat().st_uid != user.uid
            ),
            None,
        )
        if mismatched is not None:
            raise ServiceError(
                f"Runtime data is not owned by service user {user.name!r}: {mismatched}. "
                f"Repair it first with: sudo chown -R {user.name}:{user.group} {instance}"
            )
    return instance


def _platform_name(override: str | None = None) -> str:
    name = override or platform.system()
    if name not in {"Darwin", "Linux"}:
        raise ServiceError(f"Automatic service installation is not supported on {name}.")
    return name


def _launchd_details() -> tuple[subprocess.CompletedProcess[str], str, str]:
    result = subprocess.run(
        ("launchctl", "print", f"system/{LAUNCHD_LABEL}"),
        check=False,
        text=True,
        capture_output=True,
    )
    state = "unknown"
    last_exit = ""
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("state = "):
            state = stripped.removeprefix("state = ").strip()
        elif stripped.startswith("last exit code = "):
            last_exit = stripped.removeprefix("last exit code = ").strip()
    return result, state, last_exit


def _launchd_state_is_active(state: str) -> bool:
    return state in {"active", "running"}


def _pid_file_is_running(path: Path) -> bool:
    try:
        process_id = int(path.read_text(encoding="utf-8").strip())
        if process_id <= 1:
            return False
        os.kill(process_id, 0)
    except (OSError, ValueError):
        return False
    return True


def _managed_toolkit_is_ready(root: Path) -> bool:
    instance = root / "instance"
    process_files = (
        "twn-service-launcher.pid",
        "twn-toolkit.pid",
        "twn-automation.pid",
        "twn-supervisor.pid",
    )
    endpoint_files = (
        "twn-toolkit.scheme",
        "twn-toolkit.host",
        "twn-toolkit.port",
    )
    return all(_pid_file_is_running(instance / name) for name in process_files) and all(
        (instance / name).is_file() for name in endpoint_files
    )


def _wait_for_managed_toolkit(root: Path, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _managed_toolkit_is_ready(root):
            return True
        time.sleep(0.25)
    return _managed_toolkit_is_ready(root)


def _wait_for_launchd_running(timeout: float = 10.0) -> tuple[bool, str, str]:
    deadline = time.monotonic() + timeout
    state = "unknown"
    last_exit = ""
    while time.monotonic() < deadline:
        result, state, last_exit = _launchd_details()
        if result.returncode == 0 and _launchd_state_is_active(state):
            return True, state, last_exit
        time.sleep(0.25)
    return False, state, last_exit


def install_service(
    root: Path,
    user: ServiceUser,
    *,
    system: str,
    network_capabilities: bool,
) -> None:
    _validate_install_request(
        root,
        user,
        system=system,
        network_capabilities=network_capabilities,
    )
    _require_root()
    instance = _ensure_instance_directory(root, user)
    if system == "Linux":
        if not shutil.which("systemctl"):
            raise ServiceError("systemctl is unavailable; this Linux installation is not systemd-managed.")
        unit = render_systemd_unit(
            root,
            user,
            network_capabilities=network_capabilities,
        ).encode()
        _write_system_file(SYSTEMD_UNIT_PATH, unit)
        _run(("systemctl", "daemon-reload"))
        _run(("systemctl", "enable", SYSTEMD_UNIT_NAME))
        _run(("systemctl", "restart", SYSTEMD_UNIT_NAME))
        print(f"Installed and started {SYSTEMD_UNIT_NAME} as {user.name}:{user.group}.")
        if network_capabilities:
            print("Enabled scoped Linux network capabilities for capture, replay, and privileged ports.")
        else:
            print("Raw capture/replay and ports below 1024 may need: ./twn service install --network-capabilities")
        return

    if not shutil.which("launchctl"):
        raise ServiceError("launchctl is unavailable on this macOS installation.")
    for log_name in ("twn-service.log", "twn-service-error.log"):
        log_path = instance / log_name
        log_path.touch(exist_ok=True)
        os.chown(log_path, user.uid, user.gid)
        os.chmod(log_path, 0o600)
    _run_quiet(("launchctl", "bootout", f"system/{LAUNCHD_LABEL}"))
    _write_system_file(LAUNCHD_PLIST_PATH, render_launchd_plist(root, user))
    os.chown(LAUNCHD_PLIST_PATH, 0, 0)
    _run(("launchctl", "bootstrap", "system", str(LAUNCHD_PLIST_PATH)))
    _run(("launchctl", "enable", f"system/{LAUNCHD_LABEL}"))
    _run(("launchctl", "kickstart", "-k", f"system/{LAUNCHD_LABEL}"))
    running, state, last_exit = _wait_for_launchd_running()
    if not running:
        _run_quiet(("launchctl", "bootout", f"system/{LAUNCHD_LABEL}"))
        LAUNCHD_PLIST_PATH.unlink(missing_ok=True)
        detail = f"state {state!r}"
        if last_exit:
            detail += f", last exit {last_exit}"
        raise ServiceError(
            f"The macOS LaunchDaemon did not remain running ({detail}). "
            "The failed service definition was removed; inspect ./twn service logs."
        )
    if not _wait_for_managed_toolkit(root):
        _run_quiet(("launchctl", "bootout", f"system/{LAUNCHD_LABEL}"))
        LAUNCHD_PLIST_PATH.unlink(missing_ok=True)
        raise ServiceError(
            "The macOS LaunchDaemon started, but the managed toolkit processes did not "
            "become ready. The failed service definition was removed; inspect "
            "./twn service logs."
        )
    print(f"Installed and started {LAUNCHD_LABEL} as {user.name}:{user.group}.")
    print("macOS does not provide systemd-style scoped network capabilities.")
    print("Packet capture/replay still requires administrator-managed BPF access; multicast PF remains separately installed.")


def uninstall_service(*, system: str) -> None:
    _require_root()
    if system == "Linux":
        _run(("systemctl", "disable", "--now", SYSTEMD_UNIT_NAME), check=False)
        _run(("systemctl", "reset-failed", SYSTEMD_UNIT_NAME), check=False)
        SYSTEMD_UNIT_PATH.unlink(missing_ok=True)
        _run(("systemctl", "daemon-reload"))
        print(f"Removed {SYSTEMD_UNIT_NAME}. Toolkit data was retained.")
        return
    _run_quiet(("launchctl", "bootout", f"system/{LAUNCHD_LABEL}"))
    LAUNCHD_PLIST_PATH.unlink(missing_ok=True)
    print(f"Removed {LAUNCHD_LABEL}. Toolkit data and service logs were retained.")


def manage_service(action: str, *, system: str) -> None:
    _require_root()
    if system == "Linux":
        _run(("systemctl", action, SYSTEMD_UNIT_NAME))
        return
    target = f"system/{LAUNCHD_LABEL}"
    if action == "start":
        _run(("launchctl", "kickstart", "-k", target))
    elif action == "restart":
        _run(("launchctl", "kickstart", "-k", target))
    else:
        _run(("launchctl", "kill", "SIGTERM", target))


def service_status(*, system: str) -> int:
    if system == "Linux":
        if not SYSTEMD_UNIT_PATH.exists():
            print(f"Autostart service is not installed ({SYSTEMD_UNIT_PATH}).")
            return 1
        enabled = _run(("systemctl", "is-enabled", SYSTEMD_UNIT_NAME), check=False).returncode == 0
        active = _run(("systemctl", "is-active", SYSTEMD_UNIT_NAME), check=False).returncode == 0
        print(f"Autostart service: {'enabled' if enabled else 'disabled'}, {'active' if active else 'inactive'}")
        print(f"Unit: {SYSTEMD_UNIT_PATH}")
        return 0 if enabled and active else 1
    if not LAUNCHD_PLIST_PATH.exists():
        print(f"Autostart service is not installed ({LAUNCHD_PLIST_PATH}).")
        return 1
    result, state, last_exit = _launchd_details()
    if result.returncode != 0:
        print("Autostart service: installed but not loaded")
    elif _launchd_state_is_active(state):
        print("Autostart service: loaded, active")
    else:
        detail = f"loaded but not running (state: {state}"
        if last_exit:
            detail += f", last exit: {last_exit}"
        print(f"Autostart service: {detail})")
    print(f"Property list: {LAUNCHD_PLIST_PATH}")
    return 0 if result.returncode == 0 and _launchd_state_is_active(state) else 1


def service_logs(root: Path, *, system: str) -> int:
    if system == "Linux":
        return _run(
            ("journalctl", "-u", SYSTEMD_UNIT_NAME, "-n", "100", "--no-pager"),
            check=False,
        ).returncode
    found = False
    for name in ("twn-service.log", "twn-service-error.log"):
        path = root / "instance" / name
        if not path.exists():
            continue
        found = True
        print(f"{name}:")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        print("\n".join(lines[-100:]))
    if not found:
        print("No launchd service log exists yet.")
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="./twn service")
    parser.add_argument("--root", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--platform", choices=("Darwin", "Linux"), help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="action", required=True)
    install = subparsers.add_parser("install", help="install, enable, and start autostart")
    install.add_argument("--user")
    install.add_argument("--allow-root", action="store_true")
    install.add_argument("--network-capabilities", action="store_true")
    install.add_argument("--validate-only", action="store_true", help=argparse.SUPPRESS)
    for action in ("uninstall", "start", "stop", "restart", "status", "logs"):
        subparsers.add_parser(action)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        system = _platform_name(args.platform)
        if args.action == "install":
            user = service_user(args.user, allow_root=args.allow_root)
            if args.validate_only:
                _validate_install_request(
                    root,
                    user,
                    system=system,
                    network_capabilities=args.network_capabilities,
                )
                return 0
            install_service(
                root,
                user,
                system=system,
                network_capabilities=args.network_capabilities,
            )
        elif args.action == "uninstall":
            uninstall_service(system=system)
        elif args.action in {"start", "stop", "restart"}:
            manage_service(args.action, system=system)
        elif args.action == "status":
            return service_status(system=system)
        else:
            return service_logs(root, system=system)
    except (OSError, ServiceError, subprocess.CalledProcessError) as exc:
        print(f"Service operation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
