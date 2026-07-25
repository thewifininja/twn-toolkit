from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import fcntl
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from string import Formatter
from typing import Any, Callable, Iterator

from .network_tools import ToolInputError
from .operational import ensure_storage_capacity


MIN_DURATION_SECONDS = 5
MAX_DURATION_SECONDS = 300
MIN_SNAP_LENGTH = 64
MAX_SNAP_LENGTH = 65535
MAX_PACKET_COUNT = 1_000_000
MIN_SIZE_MIB = 1
MAX_SIZE_MIB = 512
DEFAULT_DURATION_SECONDS = 60
DEFAULT_PACKET_COUNT = 0
DEFAULT_SIZE_MIB = 100
DEFAULT_SNAP_LENGTH = 0
DEFAULT_CAPTURE_FILENAME_PATTERN = "{timestamp}-{action}-{interface}.pcap"
CAPTURE_FILENAME_TOKENS = {"timestamp", "action", "interface"}
ACTIVE_STATUSES = {"queued", "running", "stopping"}


def validate_capture_filename_pattern(value: str) -> str:
    pattern = str(value or "").strip() or DEFAULT_CAPTURE_FILENAME_PATTERN
    if len(pattern) > 240 or "/" in pattern or "\\" in pattern or "\x00" in pattern:
        raise ToolInputError(
            "Capture filename patterns must be 240 characters or fewer without slashes."
        )
    try:
        parsed = list(Formatter().parse(pattern))
        fields = {
            field_name
            for _literal, field_name, format_spec, conversion in parsed
            if field_name and not format_spec and not conversion
        }
        if any(field not in CAPTURE_FILENAME_TOKENS for field in fields):
            raise ValueError
        if any(
            format_spec or conversion
            for _literal, _field, format_spec, conversion in parsed
        ):
            raise ValueError
        format_capture_filename(
            pattern,
            timestamp="20260725193422",
            action="WAN Degradation",
            interface="en7",
        )
    except (IndexError, KeyError, ValueError):
        raise ToolInputError(
            "Capture filename pattern tokens are {timestamp}, {action}, and {interface}."
        ) from None
    return pattern


def format_capture_filename(
    pattern: str, *, timestamp: str, action: str, interface: str
) -> str:
    values = {
        "timestamp": _safe_filename_component(timestamp, "timestamp"),
        "action": _safe_filename_component(action, "packet-capture"),
        "interface": _safe_filename_component(interface, "interface"),
    }
    return normalize_capture_filename(pattern.format(**values))


def normalize_capture_filename(value: str) -> str:
    filename = str(value or "").strip()
    if not filename:
        raise ToolInputError("Enter a packet capture filename.")
    if "/" in filename or "\\" in filename or "\x00" in filename:
        raise ToolInputError("Packet capture filenames cannot contain slashes.")
    if not filename.casefold().endswith(".pcap"):
        filename = f"{filename}.pcap"
    if filename in {".", ".."} or len(filename) > 255:
        raise ToolInputError("Packet capture filenames must be 255 characters or fewer.")
    return filename


def _safe_filename_component(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip(".-_")
    return (cleaned or fallback)[:120]


def capture_capability() -> dict[str, Any]:
    executable = shutil.which("tcpdump")
    return {
        "available": bool(executable),
        "executable": executable or "",
        "detail": (
            "tcpdump is available."
            if executable
            else "tcpdump is not installed or is not on the toolkit service PATH."
        ),
    }


def capture_interfaces() -> list[dict[str, Any]]:
    interfaces = []
    for index, name in socket.if_nameindex():
        interfaces.append(
            {
                "index": index,
                "name": name,
                "loopback": name.lower().startswith(("lo", "loopback")),
            }
        )
    return interfaces


def validate_capture_config(
    config: dict[str, Any],
    *,
    compile_filter: bool = False,
    require_runtime: bool = True,
) -> dict[str, Any]:
    interface = str(config.get("interface", "")).strip()
    if not interface or len(interface) > 100 or any(
        character in interface for character in "\x00\r\n"
    ):
        raise ToolInputError("Select a valid capture interface.")
    if require_runtime:
        capability = capture_capability()
        if not capability["available"]:
            raise ToolInputError(capability["detail"])
        known_interfaces = {item["name"] for item in capture_interfaces()}
        if interface not in known_interfaces:
            raise ToolInputError("Select an available capture interface.")
    capture_filter = str(config.get("capture_filter", "")).strip()
    if len(capture_filter) > 1000:
        raise ToolInputError("The capture filter must be 1000 characters or fewer.")
    try:
        duration_seconds = int(config.get("duration_seconds", DEFAULT_DURATION_SECONDS))
        packet_count = int(config.get("packet_count", DEFAULT_PACKET_COUNT))
        max_size_mib = int(config.get("max_size_mib", DEFAULT_SIZE_MIB))
        snap_length = int(config.get("snap_length", DEFAULT_SNAP_LENGTH))
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Capture limits must be whole numbers.") from exc
    if not MIN_DURATION_SECONDS <= duration_seconds <= MAX_DURATION_SECONDS:
        raise ToolInputError(
            f"Capture duration must be {MIN_DURATION_SECONDS}–{MAX_DURATION_SECONDS} seconds."
        )
    if not 0 <= packet_count <= MAX_PACKET_COUNT:
        raise ToolInputError(
            f"Packet limit must be 0–{MAX_PACKET_COUNT:,}; use 0 for duration-only capture."
        )
    if not MIN_SIZE_MIB <= max_size_mib <= MAX_SIZE_MIB:
        raise ToolInputError(
            f"Maximum capture size must be {MIN_SIZE_MIB}–{MAX_SIZE_MIB} MiB."
        )
    if snap_length and not MIN_SNAP_LENGTH <= snap_length <= MAX_SNAP_LENGTH:
        raise ToolInputError(
            f"Snapshot length must be 0 or {MIN_SNAP_LENGTH}–{MAX_SNAP_LENGTH} bytes."
        )
    normalized = {
        "interface": interface,
        "capture_filter": capture_filter,
        "duration_seconds": duration_seconds,
        "packet_count": packet_count,
        "max_size_mib": max_size_mib,
        "snap_length": snap_length,
        "promiscuous": bool(config.get("promiscuous", True)),
    }
    if compile_filter and capture_filter:
        if not require_runtime:
            raise ValueError("Filter compilation requires runtime validation.")
        _compile_capture_filter(normalized)
    return normalized


def _compile_capture_filter(config: dict[str, Any]) -> None:
    command = [
        capture_capability()["executable"],
        "-d",
        "-i",
        config["interface"],
        "--",
        config["capture_filter"],
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ToolInputError(f"Could not validate the capture filter: {exc}") from exc
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise ToolInputError(
            f"tcpdump rejected the capture filter: {detail or 'invalid filter'}"
        )


@contextmanager
def capture_interface_lock(instance_path: str | Path, interface: str) -> Iterator[None]:
    lock_root = Path(instance_path) / "packet_capture_locks"
    lock_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    safe_interface = re.sub(r"[^A-Za-z0-9_.-]+", "-", interface).strip("-") or "interface"
    lock_path = lock_root / f"{safe_interface}.lock"
    with lock_path.open("a+", encoding="ascii") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ToolInputError(
                f"Another packet capture is already running on {interface}."
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def run_packet_capture(
    config: dict[str, Any],
    *,
    instance_path: str | Path,
    output_path: str | Path,
    should_stop: Callable[[], bool] | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    normalized = validate_capture_config(config, compile_filter=True)
    instance = Path(instance_path)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    max_bytes = normalized["max_size_mib"] * 1024 * 1024
    ensure_storage_capacity(instance, "automation_artifacts", max_bytes)
    tcpdump_command = [
        capture_capability()["executable"],
        "-i",
        normalized["interface"],
        "-nn",
        "-U",
        "-w",
        str(output),
        "-s",
        str(normalized["snap_length"]),
    ]
    if not normalized["promiscuous"]:
        tcpdump_command.append("-p")
    if normalized["packet_count"]:
        tcpdump_command.extend(["-c", str(normalized["packet_count"])])
    if normalized["capture_filter"]:
        tcpdump_command.extend(["--", normalized["capture_filter"]])
    command = [
        sys.executable,
        "-m",
        "twn_toolkit.packet_capture_exec",
        str(max_bytes),
        *tcpdump_command,
    ]

    started_at = time.time()
    termination_reason = "tcpdump exited"
    stderr = ""
    with capture_interface_lock(instance, normalized["interface"]):
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise ToolInputError(f"Could not start tcpdump: {exc}") from exc
        try:
            while process.poll() is None:
                elapsed = time.time() - started_at
                size = output.stat().st_size if output.exists() else 0
                if progress:
                    progress(
                        {
                            "elapsed_seconds": int(elapsed),
                            "size_bytes": size,
                            "tcpdump_pid": process.pid,
                        }
                    )
                if should_stop and should_stop():
                    termination_reason = "stopped by user"
                    _signal_capture(process)
                    break
                if size >= max_bytes:
                    termination_reason = "size limit reached"
                    _signal_capture(process)
                    break
                if elapsed >= normalized["duration_seconds"]:
                    termination_reason = "duration reached"
                    _signal_capture(process)
                    break
                time.sleep(0.25)
            try:
                _stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                _stdout, stderr = process.communicate(timeout=2)
                termination_reason = "tcpdump did not stop cleanly"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)

    finished_at = time.time()
    size_bytes = output.stat().st_size if output.exists() else 0
    packet_count = _captured_packet_count(stderr)
    if size_bytes >= max_bytes:
        termination_reason = "size limit reached"
    if normalized["packet_count"] and packet_count >= normalized["packet_count"]:
        termination_reason = "packet limit reached"
    if process.returncode not in {0, -signal.SIGINT, -signal.SIGTERM} and not size_bytes:
        detail = _capture_error(stderr)
        raise ToolInputError(detail or f"tcpdump exited with status {process.returncode}.")
    if not output.exists() or size_bytes < 24:
        detail = _capture_error(stderr)
        raise ToolInputError(detail or "The capture completed without producing a PCAP file.")
    os.chmod(output, 0o600)
    return {
        **normalized,
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_seconds": round(finished_at - started_at, 3),
        "size_bytes": size_bytes,
        "packet_count_captured": packet_count,
        "termination_reason": termination_reason,
        "stderr_summary": _capture_error(stderr),
    }


def _signal_capture(process: subprocess.Popen[str]) -> None:
    try:
        process.send_signal(signal.SIGINT)
    except ProcessLookupError:
        pass


def _captured_packet_count(stderr: str) -> int:
    match = re.search(r"(?m)^(\d+)\s+packets captured$", stderr or "")
    return int(match.group(1)) if match else 0


def _capture_error(stderr: str) -> str:
    lines = [
        line.strip()
        for line in (stderr or "").splitlines()
        if line.strip()
        and not re.match(
            r"^\d+\s+packets (captured|received by filter|dropped by kernel)$", line.strip()
        )
        and not line.startswith("listening on ")
    ]
    return " ".join(lines)[-2000:]


class PacketCaptureStore:
    def __init__(self, instance_path: str | Path) -> None:
        self.instance_path = Path(instance_path).resolve()
        self.root = self.instance_path / "packet_captures"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.instance_path / "packet_captures.sqlite3"
        with self._connect():
            pass

    def create(self, config: dict[str, Any], *, created_by: str) -> str:
        normalized = validate_capture_config(config, compile_filter=True)
        self._reconcile_workers()
        capture_id = os.urandom(12).hex()
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                """
                SELECT id FROM packet_captures
                WHERE interface = ? AND status IN ('queued', 'running', 'stopping')
                LIMIT 1
                """,
                (normalized["interface"],),
            ).fetchone()
            if active:
                raise ToolInputError(
                    f"A packet capture is already active on {normalized['interface']}."
                )
            connection.execute(
                """
                INSERT INTO packet_captures (
                    id, status, interface, capture_filter, duration_seconds,
                    packet_limit, max_size_mib, snap_length, promiscuous,
                    output_path, created_by, created_at, updated_at
                ) VALUES (?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    capture_id,
                    normalized["interface"],
                    normalized["capture_filter"],
                    normalized["duration_seconds"],
                    normalized["packet_count"],
                    normalized["max_size_mib"],
                    normalized["snap_length"],
                    int(normalized["promiscuous"]),
                    str(self.root / f"{capture_id}.pcap"),
                    created_by,
                    now,
                    now,
                ),
            )
        return capture_id

    def launch(self, capture_id: str) -> None:
        command = [
            sys.executable,
            "-m",
            "twn_toolkit.packet_capture_worker",
            "--instance",
            str(self.instance_path),
            "--capture-id",
            capture_id,
            "--daemon",
        ]
        try:
            process = subprocess.Popen(
                command,
                cwd=str(Path(__file__).resolve().parent.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            self.finish(capture_id, status="error", error=f"Worker launch failed: {exc}")
            raise ToolInputError(f"Could not launch the packet capture worker: {exc}") from exc
        with self._connect() as connection:
            connection.execute(
                "UPDATE packet_captures SET worker_pid = ?, updated_at = ? WHERE id = ?",
                (process.pid, time.time(), capture_id),
            )

    def get(self, capture_id: str) -> dict[str, Any] | None:
        self._reconcile_workers()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM packet_captures WHERE id = ?", (capture_id,)
            ).fetchone()
        return self._from_row(row) if row else None

    def recent(self, limit: int = 25) -> list[dict[str, Any]]:
        self._reconcile_workers()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM packet_captures ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def begin(self, capture_id: str) -> dict[str, Any]:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE packet_captures
                SET status = 'running', worker_pid = ?, started_at = ?,
                    updated_at = ?
                WHERE id = ? AND status IN ('queued', 'stopping')
                """,
                (os.getpid(), now, now, capture_id),
            )
        capture = self.get(capture_id)
        if not capture or capture["status"] != "running":
            raise ToolInputError("Packet capture job is not available to run.")
        return capture

    def progress(self, capture_id: str, values: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE packet_captures
                SET tcpdump_pid = ?, elapsed_seconds = ?, size_bytes = ?, updated_at = ?
                WHERE id = ? AND status IN ('running', 'stopping')
                """,
                (
                    values.get("tcpdump_pid"),
                    values.get("elapsed_seconds", 0),
                    values.get("size_bytes", 0),
                    time.time(),
                    capture_id,
                ),
            )

    def stop_requested(self, capture_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT stop_requested FROM packet_captures WHERE id = ?",
                (capture_id,),
            ).fetchone()
        return bool(row and row["stop_requested"])

    def request_stop(self, capture_id: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE packet_captures
                SET stop_requested = 1, status = 'stopping', updated_at = ?
                WHERE id = ? AND status IN ('queued', 'running')
                """,
                (time.time(), capture_id),
            )
        if not cursor.rowcount:
            raise ToolInputError("That packet capture is no longer running.")

    def finish(
        self,
        capture_id: str,
        *,
        status: str,
        result: dict[str, Any] | None = None,
        error: str = "",
    ) -> None:
        result = result or {}
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE packet_captures
                SET status = ?, finished_at = ?, elapsed_seconds = ?,
                    size_bytes = ?, packet_count = ?, termination_reason = ?,
                    error = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    now,
                    result.get("elapsed_seconds", 0),
                    result.get("size_bytes", 0),
                    result.get("packet_count_captured", 0),
                    result.get("termination_reason", ""),
                    error[:2000],
                    now,
                    capture_id,
                ),
            )

    def delete(self, capture_id: str) -> dict[str, Any]:
        capture = self.get(capture_id)
        if not capture:
            raise ToolInputError("Packet capture not found.")
        if capture["status"] in ACTIVE_STATUSES:
            raise ToolInputError("Stop the packet capture before deleting it.")
        path = self.output_file(capture)
        with self._connect() as connection:
            connection.execute("DELETE FROM packet_captures WHERE id = ?", (capture_id,))
        path.unlink(missing_ok=True)
        return capture

    def output_file(self, capture: dict[str, Any]) -> Path:
        path = Path(str(capture["output_path"])).resolve()
        root = self.root.resolve()
        if path.parent != root or path.suffix != ".pcap":
            raise ToolInputError("The stored packet capture path is invalid.")
        return path

    def _reconcile_workers(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, worker_pid, updated_at FROM packet_captures
                WHERE status IN ('queued', 'running', 'stopping')
                """
            ).fetchall()
            now = time.time()
            for row in rows:
                if row["worker_pid"] is None:
                    if now - float(row["updated_at"]) <= 30:
                        continue
                    connection.execute(
                        """
                        UPDATE packet_captures
                        SET status = 'error', finished_at = ?, updated_at = ?,
                            error = 'The packet capture worker did not start.'
                        WHERE id = ? AND status = 'queued'
                        """,
                        (now, now, row["id"]),
                    )
                    continue
                try:
                    os.kill(int(row["worker_pid"]), 0)
                except (OSError, ValueError):
                    connection.execute(
                        """
                        UPDATE packet_captures
                        SET status = 'error', finished_at = ?, updated_at = ?,
                            error = CASE WHEN error = ''
                                THEN 'The packet capture worker exited unexpectedly.'
                                ELSE error END
                        WHERE id = ? AND status IN ('queued', 'running', 'stopping')
                        """,
                        (now, now, row["id"]),
                    )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS packet_captures (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    capture_filter TEXT NOT NULL,
                    duration_seconds INTEGER NOT NULL,
                    packet_limit INTEGER NOT NULL,
                    max_size_mib INTEGER NOT NULL,
                    snap_length INTEGER NOT NULL,
                    promiscuous INTEGER NOT NULL,
                    output_path TEXT NOT NULL,
                    worker_pid INTEGER,
                    tcpdump_pid INTEGER,
                    stop_requested INTEGER NOT NULL DEFAULT 0,
                    elapsed_seconds REAL NOT NULL DEFAULT 0,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    packet_count INTEGER NOT NULL DEFAULT 0,
                    termination_reason TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    started_at REAL,
                    finished_at REAL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS packet_captures_recent
                    ON packet_captures(created_at DESC);
                CREATE INDEX IF NOT EXISTS packet_captures_active
                    ON packet_captures(interface, status);
                """
            )
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
            if self.path.exists():
                os.chmod(self.path, 0o600)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["promiscuous"] = bool(item["promiscuous"])
        item["stop_requested"] = bool(item["stop_requested"])
        item["active"] = item["status"] in ACTIVE_STATUSES
        item["downloadable"] = (
            item["status"] in {"completed", "stopped"} and item["size_bytes"] >= 24
        )
        item["viewable"] = item["active"] or item["size_bytes"] >= 24
        item["created_display"] = datetime.fromtimestamp(
            float(item["created_at"])
        ).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        item["size_display"] = _format_bytes(int(item["size_bytes"]))
        return item


def _format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value / (1024 * 1024):.1f} MiB"
