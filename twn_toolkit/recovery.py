from __future__ import annotations

import argparse
import os
import platform
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Sequence


_APP_MARKER = "twn_toolkit:create_app()"


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def parse_ss_listener_pids(output: str) -> list[int]:
    return sorted({int(value) for value in re.findall(r"\bpid=(\d+)", output)})


def parse_pid_lines(output: str) -> list[int]:
    pids: set[int] = set()
    for value in output.split():
        try:
            pids.add(int(value))
        except ValueError:
            continue
    return sorted(pids)


def parse_linux_listener_inodes(output: str, port: int) -> set[str]:
    inodes = set()
    expected_port = f"{port:04X}"
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or fields[3] != "0A":
            continue
        local_address = fields[1].rsplit(":", 1)
        if len(local_address) == 2 and local_address[1].upper() == expected_port:
            inodes.add(fields[9])
    return inodes


def _linux_proc_listener_pids(
    port: int, *, proc_root: Path = Path("/proc"),
) -> list[int]:
    inodes: set[str] = set()
    for table_name in ("tcp", "tcp6"):
        try:
            output = (proc_root / "net" / table_name).read_text(encoding="ascii")
        except OSError:
            continue
        inodes.update(parse_linux_listener_inodes(output, port))
    if not inodes:
        return []

    pids = set()
    for process_dir in proc_root.iterdir():
        if not process_dir.name.isdigit():
            continue
        try:
            descriptors = (process_dir / "fd").iterdir()
            for descriptor in descriptors:
                try:
                    target = os.readlink(descriptor)
                except OSError:
                    continue
                if target.startswith("socket:[") and target[8:-1] in inodes:
                    pids.add(int(process_dir.name))
        except OSError:
            continue
    return sorted(pids)


def listener_pids(port: int, *, system: str | None = None) -> list[int]:
    """Return listener PIDs using the native tools available on the host."""
    host_system = system or platform.system()
    commands: list[list[str]] = []
    if host_system == "Linux":
        commands.append(["ss", "-H", "-ltnp", f"sport = :{port}"])
    commands.append([
        "lsof", "-nP", "-t", f"-iTCP:{port}", "-sTCP:LISTEN",
    ])
    if host_system == "Linux":
        commands.append(["fuser", "-n", "tcp", str(port)])

    for command in commands:
        result = _run(command)
        if result is None:
            continue
        if command[0] == "ss":
            pids = parse_ss_listener_pids(result.stdout)
        else:
            pids = parse_pid_lines(result.stdout)
        if pids:
            return pids
    if host_system == "Linux":
        return _linux_proc_listener_pids(port)
    return []


def matching_process_table_pids(output: str, gunicorn: Path) -> list[int]:
    """Find toolkit servers whose command retains the installation path."""
    gunicorn_marker = str(gunicorn.resolve())
    matches = []
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=1)
        if (
            len(parts) != 2
            or gunicorn_marker not in parts[1]
            or _APP_MARKER not in parts[1]
        ):
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid != os.getpid():
            matches.append(pid)
    return matches


def _process_table_pids(gunicorn: Path) -> list[int]:
    result = _run(["ps", "-ww", "-axo", "pid=,command="])
    if result is None:
        return []
    return matching_process_table_pids(result.stdout, gunicorn)


def _process_command(pid: int) -> str:
    result = _run(["ps", "-ww", "-p", str(pid), "-o", "command="])
    return result.stdout.strip() if result is not None else ""


def _process_name(pid: int) -> str:
    result = _run(["ps", "-p", str(pid), "-o", "comm="])
    return result.stdout.strip() if result is not None else ""


def _process_cwd(pid: int, *, system: str) -> Path | None:
    if system == "Linux":
        try:
            return Path(os.readlink(f"/proc/{pid}/cwd")).resolve()
        except OSError:
            pass
    result = _run(["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"])
    if result is None:
        return None
    for line in result.stdout.splitlines():
        if line.startswith("n"):
            return Path(line[1:]).resolve()
    return None


def is_toolkit_server_process(
    pid: int,
    root: Path,
    gunicorn: Path,
    *,
    system: str | None = None,
) -> bool:
    host_system = system or platform.system()
    command = _process_command(pid)
    if "gunicorn" not in command or _APP_MARKER not in command:
        return False
    if str(gunicorn.resolve()) in command:
        return True
    return _process_cwd(pid, system=host_system) == root.resolve()


def toolkit_server_pids(
    port: int,
    root: Path,
    gunicorn: Path,
    *,
    system: str | None = None,
) -> list[int]:
    """Find all running Gunicorn servers that belong to this installation."""
    host_system = system or platform.system()
    candidates = set(toolkit_listener_pids(
        port, root, gunicorn, system=host_system,
    ))
    candidates.update(_process_table_pids(gunicorn))
    return sorted(
        pid for pid in candidates
        if is_toolkit_server_process(
            pid, root, gunicorn, system=host_system,
        )
    )


def toolkit_listener_pids(
    port: int,
    root: Path,
    gunicorn: Path,
    *,
    system: str | None = None,
) -> list[int]:
    """Find configured-port listeners that belong to this installation."""
    host_system = system or platform.system()
    return sorted(
        pid for pid in listener_pids(port, system=host_system)
        if is_toolkit_server_process(
            pid, root, gunicorn, system=host_system,
        )
    )


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stop_toolkit_servers(
    port: int,
    root: Path,
    gunicorn: Path,
    *,
    timeout: float = 10.0,
    system: str | None = None,
) -> tuple[list[int], list[int]]:
    matched = toolkit_server_pids(
        port, root, gunicorn, system=system,
    )
    for pid in matched:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass

    deadline = time.monotonic() + timeout
    remaining = {pid for pid in matched if _pid_exists(pid)}
    while remaining and time.monotonic() < deadline:
        time.sleep(0.1)
        remaining = {pid for pid in remaining if _pid_exists(pid)}

    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    if remaining:
        time.sleep(0.1)
    return matched, sorted(pid for pid in remaining if _pid_exists(pid))


def describe_listeners(port: int, *, system: str | None = None) -> list[str]:
    host_system = system or platform.system()
    descriptions = []
    for pid in listener_pids(port, system=host_system):
        name = _process_name(pid)
        descriptions.append(f"  PID {pid}" + (f" ({name})" if name else ""))
    return descriptions


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", choices=("find", "find-listener", "stop", "describe"),
    )
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--gunicorn", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    host_system = platform.system()
    if args.action == "describe":
        print(f"Host OS: {host_system or 'unknown'}")
        descriptions = describe_listeners(args.port, system=host_system)
        if descriptions:
            print(f"Processes listening on TCP port {args.port}:")
            print("\n".join(descriptions))
        else:
            print(f"Listener details for TCP port {args.port} are unavailable.")
        return 0

    if args.root is None or args.gunicorn is None:
        raise SystemExit(
            "--root and --gunicorn are required for process recovery actions"
        )
    if args.action in {"find", "find-listener"}:
        finder = (
            toolkit_listener_pids
            if args.action == "find-listener"
            else toolkit_server_pids
        )
        print(" ".join(
            str(pid) for pid in finder(
                args.port, args.root, args.gunicorn, system=host_system,
            )
        ))
        return 0

    matched, remaining = stop_toolkit_servers(
        args.port, args.root, args.gunicorn, system=host_system,
    )
    if matched:
        print(
            "Stopped orphaned toolkit server process"
            f"{'es' if len(matched) != 1 else ''}: "
            + ", ".join(str(pid) for pid in matched)
            + "."
        )
    if remaining:
        print(
            "Could not stop toolkit server process"
            f"{'es' if len(remaining) != 1 else ''}: "
            + ", ".join(str(pid) for pid in remaining)
            + ".",
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
