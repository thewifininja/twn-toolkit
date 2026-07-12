from __future__ import annotations

import os
import posixpath
import re
import shlex
import ftplib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from string import Formatter
from typing import Any

from .network_tools import ToolInputError


SFTP_MAX_HOSTS = 50
SFTP_MAX_REMOTE_PATHS = 50
SFTP_MAX_TRANSFERS = 200
SFTP_MAX_FILE_BYTES = 256 * 1024 * 1024
SFTP_MAX_RUN_BYTES = 1024 * 1024 * 1024
SFTP_WORKERS = 8
SFTP_FILENAME_TOKENS = {
    "timestamp", "host", "label", "identity", "filename", "stem", "suffix"
}
SFTP_DEFAULT_FILENAME_PATTERN = "{timestamp}-{identity}-{filename}"


def parse_sftp_paths(value: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for raw in str(value or "").splitlines():
        path = raw.strip()
        if not path:
            continue
        if "\x00" in path:
            raise ToolInputError("Remote paths cannot contain null characters.")
        if len(path) > 4096:
            raise ToolInputError("Remote paths may not exceed 4096 characters.")
        if path not in seen:
            seen.add(path)
            paths.append(path)
    if not paths:
        raise ToolInputError("Enter at least one remote file path.")
    if len(paths) > SFTP_MAX_REMOTE_PATHS:
        raise ToolInputError(f"Enter no more than {SFTP_MAX_REMOTE_PATHS} remote paths.")
    return paths


def validate_sftp_filename_pattern(value: str) -> str:
    pattern = str(value or "").strip() or SFTP_DEFAULT_FILENAME_PATTERN
    if len(pattern) > 240 or "/" in pattern or "\\" in pattern or "\x00" in pattern:
        raise ToolInputError("Filename patterns must be 240 characters or fewer without slashes.")
    try:
        parsed = list(Formatter().parse(pattern))
        fields = {
            field_name for _literal, field_name, format_spec, conversion in parsed
            if field_name and not format_spec and not conversion
        }
        if any(field not in SFTP_FILENAME_TOKENS for field in fields):
            raise ValueError
        if any(format_spec or conversion for _literal, _field, format_spec, conversion in parsed):
            raise ValueError
        format_sftp_filename(
            pattern, timestamp="20260712153000", host="192.0.2.10",
            label="Core Switch", remote_path="/data/config.cfg",
        )
    except (KeyError, ValueError):
        raise ToolInputError(
            "Filename pattern tokens are {timestamp}, {host}, {label}, {identity}, "
            "{filename}, {stem}, and {suffix}."
        ) from None
    return pattern


def format_sftp_filename(
    pattern: str,
    *,
    timestamp: str,
    host: str,
    label: str,
    remote_path: str,
) -> str:
    basename = posixpath.basename(remote_path.rstrip("/")) or "download"
    path = Path(basename)
    values = {
        "timestamp": _safe_component(timestamp, "timestamp"),
        "host": _safe_component(host, "host"),
        "label": _safe_component(label, "") if label else "",
        "identity": _safe_component(label or host, "host"),
        "filename": _safe_component(basename, "download"),
        "stem": _safe_component(path.stem, "download"),
        "suffix": _safe_suffix(path.suffix),
    }
    rendered = pattern.format(**values).strip()
    if not rendered or rendered in {".", ".."} or len(rendered) > 255:
        raise ToolInputError("The filename pattern produced an invalid or overly long name.")
    return rendered


class _TransferBudget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self.lock = threading.Lock()

    def reserve(self, size: int) -> None:
        with self.lock:
            if self.used + size > self.limit:
                raise ToolInputError("The combined file-transfer download exceeds the 1 GiB run limit.")
            self.used += size

    def release(self, size: int) -> None:
        with self.lock:
            self.used = max(0, self.used - size)


def fetch_ssh_files(
    *,
    hosts: list[dict[str, str]],
    remote_paths: list[str],
    username: str,
    password: str,
    port: int,
    allow_unknown_hosts: bool,
    output_dir: Path,
    timestamp: str | None = None,
    filename_pattern: str = SFTP_DEFAULT_FILENAME_PATTERN,
    protocol: str = "sftp",
) -> list[dict[str, Any]]:
    protocol = str(protocol).lower()
    if protocol not in {"sftp", "scp", "ftp"}:
        raise ToolInputError("Transfer protocol must be SFTP, SCP, or FTP.")
    if not username.strip():
        raise ToolInputError("Enter a transfer username.")
    if not password:
        raise ToolInputError("Enter a transfer password.")
    if not 1 <= int(port) <= 65535:
        raise ToolInputError("Transfer port must be between 1 and 65535.")
    if not hosts or len(hosts) > SFTP_MAX_HOSTS:
        raise ToolInputError(f"Enter between 1 and {SFTP_MAX_HOSTS} hosts.")
    if len(hosts) * len(remote_paths) > SFTP_MAX_TRANSFERS:
        raise ToolInputError(
            f"A run may contain no more than {SFTP_MAX_TRANSFERS} host/file transfers."
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = timestamp or datetime.now().astimezone().strftime("%Y%m%d%H%M%S")
    pattern = validate_sftp_filename_pattern(filename_pattern)
    budget = _TransferBudget(SFTP_MAX_RUN_BYTES)
    name_lock = threading.Lock()
    used_names: set[str] = set()

    def run_host(host: dict[str, str]) -> list[dict[str, Any]]:
        fetcher = {"sftp": _fetch_sftp_host, "scp": _fetch_scp_host, "ftp": _fetch_ftp_host}[protocol]
        return fetcher(
            host=host,
            remote_paths=remote_paths,
            username=username,
            password=password,
            port=int(port),
            allow_unknown_hosts=allow_unknown_hosts,
            output_dir=output_dir,
            timestamp=stamp,
            filename_pattern=pattern,
            budget=budget,
            used_names=used_names,
            name_lock=name_lock,
        )

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(SFTP_WORKERS, len(hosts))) as executor:
        futures = {executor.submit(run_host, host): index for index, host in enumerate(hosts)}
        ordered: dict[int, list[dict[str, Any]]] = {}
        for future in as_completed(futures):
            ordered[futures[future]] = future.result()
    for index in range(len(hosts)):
        results.extend(ordered[index])
    return results


def fetch_sftp_files(**kwargs: Any) -> list[dict[str, Any]]:
    """Compatibility wrapper for callers created before Multi-Transfer."""
    return fetch_ssh_files(protocol="sftp", **kwargs)


def _fetch_sftp_host(
    *,
    host: dict[str, str],
    remote_paths: list[str],
    username: str,
    password: str,
    port: int,
    allow_unknown_hosts: bool,
    output_dir: Path,
    timestamp: str,
    filename_pattern: str,
    budget: _TransferBudget,
    used_names: set[str],
    name_lock: threading.Lock,
) -> list[dict[str, Any]]:
    import paramiko

    address = host["host"]
    label = host.get("label", "")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy() if allow_unknown_hosts else paramiko.RejectPolicy()
    )
    try:
        client.connect(
            hostname=address,
            port=port,
            username=username,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10,
        )
        sftp = client.open_sftp()
    except Exception as exc:
        client.close()
        return [
            _result(address, label, path, "error", error=f"Connection failed: {type(exc).__name__}: {exc}")
            for path in remote_paths
        ]

    results: list[dict[str, Any]] = []
    try:
        for remote_path in remote_paths:
            reserved = 0
            temporary: Path | None = None
            try:
                attributes = sftp.stat(remote_path)
                size = int(attributes.st_size)
                if size < 0 or size > SFTP_MAX_FILE_BYTES:
                    raise ToolInputError("Remote file exceeds the 256 MiB per-file limit.")
                budget.reserve(size)
                reserved = size
                filename = _unique_output_name(
                    filename_pattern, timestamp, address, label, remote_path,
                    used_names, name_lock
                )
                destination = output_dir / filename
                temporary = output_dir / f".{filename}.part"
                written = 0
                with sftp.open(remote_path, "rb") as source, temporary.open("wb") as target:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > SFTP_MAX_FILE_BYTES or written > size + 1024 * 1024:
                            raise ToolInputError("Remote file changed size or exceeded its transfer limit.")
                        target.write(chunk)
                os.chmod(temporary, 0o600)
                temporary.replace(destination)
                results.append(
                    _result(address, label, remote_path, "success", filename=filename, size=written)
                )
            except Exception as exc:
                if temporary and temporary.exists():
                    temporary.unlink()
                if reserved:
                    budget.release(reserved)
                results.append(
                    _result(address, label, remote_path, "error", error=f"{type(exc).__name__}: {exc}")
                )
    finally:
        try:
            sftp.close()
        finally:
            client.close()
    return results


def _fetch_scp_host(
    *, host: dict[str, str], remote_paths: list[str], username: str, password: str,
    port: int, allow_unknown_hosts: bool, output_dir: Path, timestamp: str,
    filename_pattern: str, budget: _TransferBudget, used_names: set[str],
    name_lock: threading.Lock,
) -> list[dict[str, Any]]:
    import paramiko

    address, label = host["host"], host.get("label", "")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy() if allow_unknown_hosts else paramiko.RejectPolicy()
    )
    try:
        client.connect(
            hostname=address, port=port, username=username, password=password,
            allow_agent=False, look_for_keys=False, timeout=10, auth_timeout=10,
            banner_timeout=10,
        )
    except Exception as exc:
        client.close()
        return [_result(address, label, path, "error", error=f"Connection failed: {type(exc).__name__}: {exc}") for path in remote_paths]

    results: list[dict[str, Any]] = []
    try:
        for remote_path in remote_paths:
            reserved = 0
            temporary: Path | None = None
            channel = None
            try:
                if remote_path.lstrip().startswith("-"):
                    raise ToolInputError("SCP remote paths cannot begin with a dash.")
                transport = client.get_transport()
                if transport is None or not transport.is_active():
                    raise OSError("SSH transport is not active.")
                channel = transport.open_session(timeout=10)
                channel.settimeout(15)
                channel.exec_command(f"scp -f {shlex.quote(remote_path)}")
                channel.sendall(b"\x00")
                header = _scp_read_line(channel)
                while header.startswith(b"T"):
                    channel.sendall(b"\x00")
                    header = _scp_read_line(channel)
                if header[:1] in {b"\x01", b"\x02"}:
                    raise OSError(header[1:].decode("utf-8", errors="replace").strip())
                if not header.startswith(b"C"):
                    raise OSError("Remote SCP server did not return a regular file.")
                parts = header.decode("utf-8", errors="replace").rstrip("\n").split(" ", 2)
                if len(parts) != 3:
                    raise OSError("Remote SCP file header is invalid.")
                size = int(parts[1])
                if size < 0 or size > SFTP_MAX_FILE_BYTES:
                    raise ToolInputError("Remote file exceeds the 256 MiB per-file limit.")
                budget.reserve(size)
                reserved = size
                filename = _unique_output_name(
                    filename_pattern, timestamp, address, label, remote_path,
                    used_names, name_lock,
                )
                destination = output_dir / filename
                temporary = output_dir / f".{filename}.part"
                channel.sendall(b"\x00")
                with temporary.open("wb") as target:
                    remaining = size
                    while remaining:
                        chunk = channel.recv(min(1024 * 1024, remaining))
                        if not chunk:
                            raise OSError("SCP connection closed before the file completed.")
                        target.write(chunk)
                        remaining -= len(chunk)
                status = _scp_recv_exact(channel, 1)
                if status != b"\x00":
                    message = _scp_read_line(channel).decode("utf-8", errors="replace").strip()
                    raise OSError(message or "Remote SCP transfer failed.")
                channel.sendall(b"\x00")
                os.chmod(temporary, 0o600)
                temporary.replace(destination)
                results.append(_result(address, label, remote_path, "success", filename=filename, size=size))
            except Exception as exc:
                if temporary and temporary.exists():
                    temporary.unlink()
                if reserved:
                    budget.release(reserved)
                results.append(_result(address, label, remote_path, "error", error=f"{type(exc).__name__}: {exc}"))
            finally:
                if channel is not None:
                    channel.close()
    finally:
        client.close()
    return results


def _fetch_ftp_host(
    *, host: dict[str, str], remote_paths: list[str], username: str, password: str,
    port: int, allow_unknown_hosts: bool, output_dir: Path, timestamp: str,
    filename_pattern: str, budget: _TransferBudget, used_names: set[str],
    name_lock: threading.Lock,
) -> list[dict[str, Any]]:
    del allow_unknown_hosts
    address, label = host["host"], host.get("label", "")
    ftp = ftplib.FTP()
    try:
        ftp.connect(address, port, timeout=15); ftp.login(username, password); ftp.voidcmd("TYPE I")
    except Exception as exc:
        try: ftp.close()
        except Exception: pass
        return [_result(address, label, path, "error", error=f"Connection failed: {type(exc).__name__}: {exc}") for path in remote_paths]
    results = []
    try:
        for remote_path in remote_paths:
            reserved = 0; temporary = None
            try:
                try:
                    reported_size = ftp.size(remote_path)
                except ftplib.all_errors:
                    reported_size = None
                if reported_size is not None and (int(reported_size) < 0 or int(reported_size) > SFTP_MAX_FILE_BYTES):
                    raise ToolInputError("Remote file exceeds the 256 MiB per-file limit.")
                filename = _unique_output_name(filename_pattern, timestamp, address, label, remote_path, used_names, name_lock)
                destination = output_dir / filename; temporary = output_dir / f".{filename}.part"; written = 0
                with temporary.open("wb") as target:
                    def consume(chunk: bytes) -> None:
                        nonlocal written, reserved
                        if written + len(chunk) > SFTP_MAX_FILE_BYTES:
                            raise ToolInputError("Remote file exceeded the 256 MiB per-file limit.")
                        budget.reserve(len(chunk)); reserved += len(chunk); written += len(chunk)
                        target.write(chunk)
                    ftp.retrbinary(f"RETR {remote_path}", consume, blocksize=1024 * 1024)
                os.chmod(temporary, 0o600); temporary.replace(destination)
                results.append(_result(address, label, remote_path, "success", filename=filename, size=written))
            except Exception as exc:
                if temporary and temporary.exists(): temporary.unlink()
                if reserved: budget.release(reserved)
                results.append(_result(address, label, remote_path, "error", error=f"{type(exc).__name__}: {exc}"))
    finally:
        try: ftp.quit()
        except Exception: ftp.close()
    return results


def _scp_recv_exact(channel: Any, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = channel.recv(size - len(chunks))
        if not chunk:
            raise OSError("SCP connection closed unexpectedly.")
        chunks.extend(chunk)
    return bytes(chunks)


def _scp_read_line(channel: Any, limit: int = 8192) -> bytes:
    value = bytearray()
    while len(value) < limit:
        byte = _scp_recv_exact(channel, 1)
        value.extend(byte)
        if byte == b"\n":
            return bytes(value)
    raise OSError("SCP protocol line exceeded its safety limit.")


def _result(
    host: str,
    label: str,
    remote_path: str,
    status: str,
    *,
    filename: str = "",
    size: int = 0,
    error: str = "",
) -> dict[str, Any]:
    return {
        "host": host,
        "host_label": label,
        "remote_path": remote_path,
        "status": status,
        "filename": filename,
        "size": size,
        "error": error,
    }


def _unique_output_name(
    pattern: str,
    timestamp: str,
    host: str,
    label: str,
    remote_path: str,
    used_names: set[str],
    lock: threading.Lock,
) -> str:
    base = format_sftp_filename(
        pattern, timestamp=timestamp, host=host, label=label, remote_path=remote_path
    )
    with lock:
        candidate = base
        index = 2
        while candidate.casefold() in used_names:
            stem, suffix = os.path.splitext(base)
            candidate = f"{stem}-{index}{suffix}"
            index += 1
        used_names.add(candidate.casefold())
    return candidate


def _safe_component(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip(".-_")
    return (cleaned or fallback)[:120]


def _safe_suffix(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.]", "", str(value))
    return cleaned[:40]
