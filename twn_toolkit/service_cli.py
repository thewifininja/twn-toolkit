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
LAUNCHD_NETWORK_BROKER_LABEL = f"{LAUNCHD_LABEL}.network-broker"
LAUNCHD_NETWORK_BROKER_PLIST_PATH = (
    Path("/Library/LaunchDaemons") / f"{LAUNCHD_NETWORK_BROKER_LABEL}.plist"
)
MACOS_NETWORK_BROKER_SOURCE = Path(__file__).resolve().parent / "bin" / "twn-network-broker"
MACOS_NETWORK_BROKER_HELPER_PATH = (
    Path("/Library/PrivilegedHelperTools") / "com.thewifininja.toolkit-network-broker"
)
MACOS_NETWORK_BROKER_SOCKET = "/var/run/twn-toolkit-network-broker.sock"
LAUNCHD_JOB_ROLES = (
    "web",
    "automation",
    "supervisor",
    "tftp",
    "ssh-transfer",
    "ftp",
)
LAUNCHD_CORE_ROLES = ("web", "automation", "supervisor")
LAUNCHD_CORE_MARKER = "twn-launchd-direct-enabled"
LAUNCHD_TRANSFER_MARKERS = {
    "tftp": "twn-tftp.launchd-enabled",
    "ssh-transfer": "twn-ssh-transfer.launchd-enabled",
    "ftp": "twn-ftp.launchd-enabled",
}
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


def _launchd_job_label(role: str) -> str:
    return f"{LAUNCHD_LABEL}.{role}"


def _launchd_job_path(role: str) -> Path:
    return LAUNCHD_PLIST_PATH.with_name(f"{_launchd_job_label(role)}.plist")


def _launchd_labels(*, include_coordinator: bool = True) -> tuple[str, ...]:
    workers = tuple(_launchd_job_label(role) for role in LAUNCHD_JOB_ROLES)
    base = (LAUNCHD_NETWORK_BROKER_LABEL,)
    return (base + (LAUNCHD_LABEL,) + workers) if include_coordinator else (base + workers)


def _launchd_paths(*, include_coordinator: bool = True) -> tuple[Path, ...]:
    workers = tuple(_launchd_job_path(role) for role in LAUNCHD_JOB_ROLES)
    base = (LAUNCHD_NETWORK_BROKER_PLIST_PATH,)
    return (base + (LAUNCHD_PLIST_PATH,) + workers) if include_coordinator else (base + workers)


def _render_launchd_payload(
    root: Path,
    user: ServiceUser,
    *,
    label: str,
    arguments: list[str],
    stdout_name: str,
    stderr_name: str,
    keep_alive: dict[str, object],
    run_at_load: bool,
    role: str,
) -> bytes:
    instance = root / "instance"
    payload = {
        "Label": label,
        "ProgramArguments": arguments,
        "WorkingDirectory": str(root),
        "UserName": user.name,
        "GroupName": user.group,
        "RunAtLoad": run_at_load,
        "KeepAlive": keep_alive,
        "ThrottleInterval": 5,
        "ProcessType": "Background",
        "Umask": 0o077,
        "EnvironmentVariables": {
            "PATH": _service_path(root),
            "HOME": user.home,
            "USER": user.name,
            "LOGNAME": user.name,
            "TWN_TOOLKIT_LAUNCHD_DIRECT": "1",
            "TWN_TOOLKIT_LAUNCHD_ROLE": role,
            "TWN_TOOLKIT_NETWORK_BROKER": MACOS_NETWORK_BROKER_SOCKET,
        },
        "StandardOutPath": str(instance / stdout_name),
        "StandardErrorPath": str(instance / stderr_name),
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False)


def render_launchd_plist(root: Path, user: ServiceUser) -> bytes:
    """Render the stable coordinator job retained for upgrade compatibility."""
    return _render_launchd_payload(
        root,
        user,
        label=LAUNCHD_LABEL,
        arguments=[str(root / "twn"), "service-run"],
        stdout_name="twn-service.log",
        stderr_name="twn-service-error.log",
        keep_alive={"SuccessfulExit": False},
        run_at_load=True,
        role="coordinator",
    )


def render_launchd_network_broker_plist(root: Path, user: ServiceUser) -> bytes:
    """Render the root-only TCP connector used by unprivileged macOS workers."""
    instance = root / "instance"
    payload = {
        "Label": LAUNCHD_NETWORK_BROKER_LABEL,
        "ProgramArguments": [
            str(MACOS_NETWORK_BROKER_HELPER_PATH),
            "--socket",
            MACOS_NETWORK_BROKER_SOCKET,
            "--uid",
            str(user.uid),
            "--gid",
            str(user.gid),
        ],
        "WorkingDirectory": "/",
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 5,
        "ProcessType": "Background",
        "Umask": 0o077,
        "StandardOutPath": str(instance / "twn-network-broker.log"),
        "StandardErrorPath": str(instance / "twn-network-broker.log"),
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False)


def render_launchd_plists(root: Path, user: ServiceUser) -> dict[Path, bytes]:
    """Render direct launchd jobs so network workers are actual daemons."""
    instance = root / "instance"
    core_marker = str(instance / LAUNCHD_CORE_MARKER)
    logs = {
        "web": ("twn-service-web.log", "twn-service-web-error.log"),
        "automation": ("twn-automation.log", "twn-automation.log"),
        "supervisor": ("twn-supervisor.log", "twn-supervisor.log"),
        "tftp": ("twn-tftp.log", "twn-tftp.log"),
        "ssh-transfer": ("twn-ssh-transfer.log", "twn-ssh-transfer.log"),
        "ftp": ("twn-ftp.log", "twn-ftp.log"),
    }
    rendered = {
        LAUNCHD_NETWORK_BROKER_PLIST_PATH: render_launchd_network_broker_plist(root, user),
        LAUNCHD_PLIST_PATH: render_launchd_plist(root, user),
    }
    for role in LAUNCHD_JOB_ROLES:
        if role in LAUNCHD_TRANSFER_MARKERS:
            keep_alive: dict[str, object] = {
                "PathState": {
                    str(instance / LAUNCHD_TRANSFER_MARKERS[role]): True,
                },
            }
            run_at_load = False
        else:
            keep_alive = {
                "PathState": {core_marker: True},
            }
            run_at_load = False
        stdout_name, stderr_name = logs[role]
        rendered[_launchd_job_path(role)] = _render_launchd_payload(
            root,
            user,
            label=_launchd_job_label(role),
            arguments=[str(root / "twn"), "launchd-run", role],
            stdout_name=stdout_name,
            stderr_name=stderr_name,
            keep_alive=keep_alive,
            run_at_load=run_at_load,
            role=role,
        )
    return rendered


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


def _run_quiet_bounded(
    command: Sequence[str], timeout_seconds: float | None
) -> subprocess.CompletedProcess[str] | None:
    if timeout_seconds is None:
        return _run_quiet(command)
    try:
        return subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(0.05, float(timeout_seconds)),
        )
    except subprocess.TimeoutExpired:
        return None


def _boot_generation() -> str:
    """Return a token stable within one boot without requiring macOS APIs."""
    return str(max(0, int((time.time() - time.monotonic()) // 10) * 10))


def _write_pause_marker(path: Path, user: ServiceUser | None = None) -> None:
    path.write_text(_boot_generation() + "\n", encoding="ascii")
    os.chmod(path, 0o600)
    if user is not None:
        os.chown(path, user.uid, user.gid)


def _remove_launchd_activation_markers(instance: Path) -> None:
    (instance / LAUNCHD_CORE_MARKER).unlink(missing_ok=True)
    for marker in LAUNCHD_TRANSFER_MARKERS.values():
        (instance / marker).unlink(missing_ok=True)


def _remove_launchd_runtime_artifacts(instance: Path) -> None:
    """Remove state owned by the LaunchDaemon layout while retaining user data and logs."""
    _remove_launchd_activation_markers(instance)
    for name in (
        "twn-service-paused",
        "twn-service-resume",
        "twn-service-web-generation",
        "twn-service-web-generation-marked",
    ):
        (instance / name).unlink(missing_ok=True)


def _remove_macos_network_broker() -> None:
    MACOS_NETWORK_BROKER_HELPER_PATH.unlink(missing_ok=True)
    Path(MACOS_NETWORK_BROKER_SOCKET).unlink(missing_ok=True)


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
        if not MACOS_NETWORK_BROKER_SOURCE.is_file() or not os.access(
            MACOS_NETWORK_BROKER_SOURCE,
            os.X_OK,
        ):
            raise ServiceError(
                "The macOS network broker is missing or not executable in this release bundle."
            )


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


def _launchd_details(
    label: str = LAUNCHD_LABEL,
    *,
    timeout_seconds: float | None = None,
) -> tuple[subprocess.CompletedProcess[str], str, str]:
    command = ("launchctl", "print", f"system/{label}")
    try:
        result = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=(
                max(0.05, float(timeout_seconds))
                if timeout_seconds is not None
                else None
            ),
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", ""), "timed out", ""
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


def _launchd_plist_is_direct(path: Path | None = None) -> bool:
    path = path or LAUNCHD_PLIST_PATH
    try:
        payload = plistlib.loads(path.read_bytes())
        environment = payload.get("EnvironmentVariables", {})
        return (
            isinstance(environment, dict)
            and environment.get("TWN_TOOLKIT_LAUNCHD_DIRECT") == "1"
        )
    except (OSError, plistlib.InvalidFileException, ValueError):
        return False


def _launchd_required_labels(*, direct: bool) -> tuple[str, ...]:
    if not direct:
        return (LAUNCHD_LABEL,)
    return (LAUNCHD_NETWORK_BROKER_LABEL, LAUNCHD_LABEL) + tuple(
        _launchd_job_label(role) for role in LAUNCHD_CORE_ROLES
    )


def _launchd_aggregate_details(
    *,
    direct: bool,
    timeout_seconds: float | None = None,
) -> tuple[bool, str, str]:
    if not direct:
        result, state, last_exit = _launchd_details(
            LAUNCHD_LABEL,
            timeout_seconds=timeout_seconds,
        )
        return (
            result.returncode == 0 and _launchd_state_is_active(state),
            state,
            last_exit,
        )
    inactive: list[str] = []
    exits: list[str] = []
    for label in _launchd_required_labels(direct=direct):
        result, state, last_exit = _launchd_details(
            label,
            timeout_seconds=timeout_seconds,
        )
        if result.returncode != 0 or not _launchd_state_is_active(state):
            inactive.append(f"{label}={state}")
        if last_exit:
            exits.append(f"{label}={last_exit}")
    if inactive:
        return False, "degraded (" + ", ".join(inactive) + ")", "; ".join(exits)
    return True, "active", "; ".join(exits)


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


def _service_definition_details(
    path: Path, *, system: str
) -> tuple[str, str, str]:
    """Return the configured service user, group, and root without elevation."""
    if system == "Darwin":
        try:
            payload = plistlib.loads(path.read_bytes())
        except (OSError, plistlib.InvalidFileException, ValueError):
            return "", "", ""
        return (
            str(payload.get("UserName", "")),
            str(payload.get("GroupName", "")),
            str(payload.get("WorkingDirectory", "")),
        )

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return "", "", ""
    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key in {"User", "Group", "WorkingDirectory"}:
            values[key] = value.strip().strip('"')
    return (
        values.get("User", ""),
        values.get("Group", ""),
        values.get("WorkingDirectory", "").replace("%%", "%"),
    )


def service_runtime_status(
    root: Path,
    *,
    system: str | None = None,
    manager_timeout_seconds: float | None = None,
) -> dict[str, object]:
    """Describe how this checkout is running using the same facts as the CLI."""
    detected_system = system or platform.system()
    instance = root / "instance"
    paused = (instance / "twn-service-paused").is_file()
    launcher_running = _pid_file_is_running(instance / "twn-service-launcher.pid")
    web_running = _pid_file_is_running(instance / "twn-toolkit.pid")
    scheduler_running = _pid_file_is_running(instance / "twn-automation.pid")
    supervisor_running = _pid_file_is_running(instance / "twn-supervisor.pid")
    process_set_ready = web_running and scheduler_running and supervisor_running
    any_process_running = any(
        (launcher_running, web_running, scheduler_running, supervisor_running)
    )

    installed = False
    manager_enabled = False
    manager_active = False
    manager_state = "unsupported"
    last_exit = ""
    definition_path = ""
    service_user_name = ""
    service_group_name = ""
    service_root = ""
    direct_launchd = False
    network_broker_installed = False
    network_broker_socket_ready = False
    platform_supported = detected_system in {"Darwin", "Linux"}

    if detected_system == "Linux":
        definition_path = str(SYSTEMD_UNIT_PATH)
        installed = SYSTEMD_UNIT_PATH.is_file()
        if installed and shutil.which("systemctl"):
            enabled_result = _run_quiet_bounded(
                ("systemctl", "is-enabled", SYSTEMD_UNIT_NAME),
                manager_timeout_seconds,
            )
            active_result = _run_quiet_bounded(
                ("systemctl", "is-active", SYSTEMD_UNIT_NAME),
                manager_timeout_seconds,
            )
            if enabled_result is None or active_result is None:
                manager_state = "timed out"
            else:
                manager_enabled = enabled_result.returncode == 0
                manager_active = active_result.returncode == 0
                manager_state = "active" if manager_active else "inactive"
        elif installed:
            manager_state = "systemctl unavailable"
        else:
            manager_state = "not installed"
        (
            service_user_name,
            service_group_name,
            service_root,
        ) = _service_definition_details(SYSTEMD_UNIT_PATH, system=detected_system)
    elif detected_system == "Darwin":
        definition_path = str(LAUNCHD_PLIST_PATH)
        installed = LAUNCHD_PLIST_PATH.is_file()
        if installed and shutil.which("launchctl"):
            direct_launchd = _launchd_plist_is_direct()
            network_broker_installed = (
                LAUNCHD_NETWORK_BROKER_PLIST_PATH.is_file()
                and MACOS_NETWORK_BROKER_HELPER_PATH.is_file()
            )
            network_broker_socket_ready = Path(MACOS_NETWORK_BROKER_SOCKET).exists()
            manager_active, manager_state, last_exit = _launchd_aggregate_details(
                direct=direct_launchd,
                timeout_seconds=manager_timeout_seconds
            )
            manager_enabled = manager_active
        elif installed:
            manager_state = "launchctl unavailable"
        else:
            manager_state = "not installed"
        (
            service_user_name,
            service_group_name,
            service_root,
        ) = _service_definition_details(LAUNCHD_PLIST_PATH, system=detected_system)

    definition_matches = not service_root or Path(service_root).resolve() == root.resolve()
    manages_this_checkout = installed and definition_matches

    if manages_this_checkout and paused and launcher_running:
        mode = "Boot-managed service"
        state = "Paused"
        healthy = True
    elif manages_this_checkout and manager_active:
        mode = "Boot-managed service"
        if launcher_running and process_set_ready:
            state = "Active"
            healthy = True
        else:
            state = "Degraded"
            healthy = False
    elif process_set_ready:
        mode = "Manual process"
        state = "Running"
        healthy = True
    elif any_process_running:
        mode = "Manual process"
        state = "Degraded"
        healthy = False
    elif manages_this_checkout:
        mode = "Boot service installed"
        state = "Inactive"
        healthy = False
    else:
        mode = "Manual process"
        state = "Stopped"
        healthy = False

    return {
        "platform": detected_system,
        "platform_supported": platform_supported,
        "mode": mode,
        "state": state,
        "healthy": healthy,
        "installed": installed,
        "definition_matches": definition_matches,
        "manages_this_checkout": manages_this_checkout,
        "manager_enabled": manager_enabled,
        "manager_active": manager_active,
        "manager_state": manager_state,
        "last_exit": last_exit,
        "definition_path": definition_path,
        "service_user": service_user_name,
        "service_group": service_group_name,
        "service_root": service_root,
        "direct_launchd": direct_launchd,
        "network_broker_installed": network_broker_installed,
        "network_broker_socket_ready": network_broker_socket_ready,
        "paused": paused,
        "launcher_running": launcher_running,
        "process_set_ready": process_set_ready,
        "web_running": web_running,
        "scheduler_running": scheduler_running,
        "supervisor_running": supervisor_running,
    }


def _wait_for_managed_toolkit(root: Path, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _managed_toolkit_is_ready(root):
            return True
        time.sleep(0.25)
    return _managed_toolkit_is_ready(root)


def _wait_for_launchd_running(
    timeout: float = 10.0,
    *,
    direct: bool = False,
) -> tuple[bool, str, str]:
    deadline = time.monotonic() + timeout
    state = "unknown"
    last_exit = ""
    while time.monotonic() < deadline:
        running, state, last_exit = _launchd_aggregate_details(direct=direct)
        if running:
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
    for log_name in (
        "twn-service.log",
        "twn-service-error.log",
        "twn-service-web.log",
        "twn-service-web-error.log",
        "twn-automation.log",
        "twn-supervisor.log",
        "twn-tftp.log",
        "twn-ssh-transfer.log",
        "twn-ftp.log",
        "twn-network-broker.log",
    ):
        log_path = instance / log_name
        log_path.touch(exist_ok=True)
        os.chown(log_path, user.uid, user.gid)
        os.chmod(log_path, 0o600)

    pause_path = instance / "twn-service-paused"
    resume_path = instance / "twn-service-resume"
    core_marker_path = instance / LAUNCHD_CORE_MARKER
    rendered = render_launchd_plists(root, user)
    for label in reversed(_launchd_labels()):
        _run_quiet(("launchctl", "bootout", f"system/{label}"))
    Path(MACOS_NETWORK_BROKER_SOCKET).unlink(missing_ok=True)
    _write_pause_marker(pause_path, user)
    _remove_launchd_activation_markers(instance)
    resume_path.unlink(missing_ok=True)
    try:
        _write_system_file(
            MACOS_NETWORK_BROKER_HELPER_PATH,
            MACOS_NETWORK_BROKER_SOURCE.read_bytes(),
            mode=0o755,
        )
        os.chown(MACOS_NETWORK_BROKER_HELPER_PATH, 0, 0)
        for path, content in rendered.items():
            _write_system_file(path, content)
            os.chown(path, 0, 0)
        for path in rendered:
            _run(("launchctl", "bootstrap", "system", str(path)))
        for label in _launchd_labels():
            _run(("launchctl", "enable", f"system/{label}"))
        resume_path.touch(mode=0o600, exist_ok=True)
        os.chown(resume_path, user.uid, user.gid)
        pause_path.unlink(missing_ok=True)
        core_marker_path.touch(mode=0o600, exist_ok=True)
        os.chown(core_marker_path, user.uid, user.gid)
        for label in _launchd_required_labels(direct=True):
            _run(("launchctl", "kickstart", "-k", f"system/{label}"))
    except Exception:
        for label in reversed(_launchd_labels()):
            _run_quiet(("launchctl", "bootout", f"system/{label}"))
        for path in _launchd_paths():
            path.unlink(missing_ok=True)
        _remove_macos_network_broker()
        pause_path.unlink(missing_ok=True)
        resume_path.unlink(missing_ok=True)
        _remove_launchd_activation_markers(instance)
        raise

    running, state, last_exit = _wait_for_launchd_running(direct=True)
    if not running:
        for label in reversed(_launchd_labels()):
            _run_quiet(("launchctl", "bootout", f"system/{label}"))
        for path in _launchd_paths():
            path.unlink(missing_ok=True)
        _remove_macos_network_broker()
        pause_path.unlink(missing_ok=True)
        resume_path.unlink(missing_ok=True)
        _remove_launchd_activation_markers(instance)
        detail = f"state {state!r}"
        if last_exit:
            detail += f", last exit {last_exit}"
        raise ServiceError(
            f"The macOS LaunchDaemon set did not remain running ({detail}). "
            "The failed service definitions were removed; inspect ./twn service logs."
        )
    if not _wait_for_managed_toolkit(root):
        for label in reversed(_launchd_labels()):
            _run_quiet(("launchctl", "bootout", f"system/{label}"))
        for path in _launchd_paths():
            path.unlink(missing_ok=True)
        _remove_macos_network_broker()
        pause_path.unlink(missing_ok=True)
        resume_path.unlink(missing_ok=True)
        _remove_launchd_activation_markers(instance)
        raise ServiceError(
            "The macOS LaunchDaemon set started, but the managed toolkit processes did not "
            "become ready. The failed service definitions were removed; inspect "
            "./twn service logs."
        )
    print(
        f"Installed and started the root TCP connector plus {len(rendered) - 1} "
        f"unprivileged LaunchDaemons as {user.name}:{user.group}."
    )
    print("macOS does not provide systemd-style scoped network capabilities.")
    print(
        "Packet capture/replay and DHCP Discover require administrator-managed BPF access; "
        "multicast PF remains separately installed."
    )


def uninstall_service(*, system: str) -> None:
    _require_root()
    if system == "Linux":
        _run(("systemctl", "disable", "--now", SYSTEMD_UNIT_NAME), check=False)
        _run(("systemctl", "reset-failed", SYSTEMD_UNIT_NAME), check=False)
        SYSTEMD_UNIT_PATH.unlink(missing_ok=True)
        _run(("systemctl", "daemon-reload"))
        print(f"Removed {SYSTEMD_UNIT_NAME}. Toolkit data was retained.")
        return
    service_roots = {
        Path(service_root)
        for path in _launchd_paths()
        if path != LAUNCHD_NETWORK_BROKER_PLIST_PATH
        for service_root in (_service_definition_details(path, system="Darwin")[2],)
        if service_root and service_root != "/"
    }
    for label in reversed(_launchd_labels()):
        _run_quiet(("launchctl", "bootout", f"system/{label}"))
    for path in _launchd_paths():
        path.unlink(missing_ok=True)
    _remove_macos_network_broker()
    for service_root in service_roots:
        _remove_launchd_runtime_artifacts(service_root / "instance")
    print("Removed the toolkit LaunchDaemons. Toolkit data and service logs were retained.")


def manage_service(action: str, *, system: str) -> None:
    _require_root()
    if system == "Linux":
        _run(("systemctl", action, SYSTEMD_UNIT_NAME))
        return
    if not _launchd_plist_is_direct():
        target = f"system/{LAUNCHD_LABEL}"
        if action in {"start", "restart"}:
            _run(("launchctl", "kickstart", "-k", target))
        else:
            _run(("launchctl", "kill", "SIGTERM", target))
        return

    instance = _service_definition_details(
        LAUNCHD_PLIST_PATH,
        system="Darwin",
    )[2]
    if not instance:
        raise ServiceError("The direct LaunchDaemon working directory is unavailable.")
    runtime = Path(instance) / "instance"
    pause_path = runtime / "twn-service-paused"
    resume_path = runtime / "twn-service-resume"
    core_marker_path = runtime / LAUNCHD_CORE_MARKER
    if action in {"stop", "restart"}:
        _write_pause_marker(pause_path)
        resume_path.unlink(missing_ok=True)
        _remove_launchd_activation_markers(runtime)
        for label in reversed(_launchd_labels()):
            _run_quiet(("launchctl", "kill", "SIGTERM", f"system/{label}"))
    if action in {"start", "restart"}:
        resume_path.touch(mode=0o600, exist_ok=True)
        pause_path.unlink(missing_ok=True)
        core_marker_path.touch(mode=0o600, exist_ok=True)
        os.chmod(core_marker_path, 0o600)
        for label in _launchd_required_labels(direct=True):
            _run(("launchctl", "kickstart", "-k", f"system/{label}"))


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
    direct = _launchd_plist_is_direct()
    running, state, last_exit = _launchd_aggregate_details(direct=direct)
    if running:
        suffix = " direct jobs" if direct else ""
        print(f"Autostart service: loaded, active{suffix}")
    elif not direct:
        detail = f"loaded but not running (state: {state}"
        if last_exit:
            detail += f", last exit: {last_exit}"
        print(f"Autostart service: {detail})")
    else:
        detail = state
        if last_exit:
            detail += f", last exit: {last_exit}"
        print(f"Autostart service: {detail}")
    print(f"Property list: {LAUNCHD_PLIST_PATH}")
    return 0 if running else 1


def service_logs(root: Path, *, system: str) -> int:
    if system == "Linux":
        return _run(
            ("journalctl", "-u", SYSTEMD_UNIT_NAME, "-n", "100", "--no-pager"),
            check=False,
        ).returncode
    found = False
    for name in (
        "twn-service.log",
        "twn-service-error.log",
        "twn-service-web.log",
        "twn-service-web-error.log",
        "twn-automation.log",
        "twn-supervisor.log",
        "twn-tftp.log",
        "twn-ssh-transfer.log",
        "twn-ftp.log",
        "twn-network-broker.log",
    ):
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
