from __future__ import annotations

import ipaddress
import json
import shlex
import shutil
import subprocess
from typing import Any

from .network_tools import ToolInputError, validate_hosts


IPERF_DEFAULT_PORT = 5201
IPERF_MAX_DURATION_SECONDS = 60
IPERF_MAX_PARALLEL_STREAMS = 20
IPERF_MAX_SERVER_WINDOW_SECONDS = 180
IPERF_MAX_UDP_MEGABITS = 100_000
IPERF_RAW_JSON_LIMIT = 1024 * 1024


def iperf3_capability() -> dict[str, Any]:
    executable = shutil.which("iperf3")
    if not executable:
        return {
            "available": False,
            "executable": "",
            "version": "",
            "detail": (
                "iperf3 is not installed or is not on the toolkit service PATH. "
                "Install it outside the toolkit, then restart the service."
            ),
        }
    version = ""
    try:
        completed = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        version = next(
            (
                line.strip()
                for line in (completed.stdout or completed.stderr or "").splitlines()
                if line.strip()
            ),
            "",
        )
    except (OSError, subprocess.SubprocessError):
        pass
    return {
        "available": True,
        "executable": executable,
        "version": version,
        "detail": version or f"iperf3 is available at {executable}.",
    }


def run_iperf3_client(config: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_iperf3_client_config(config)
    executable = _iperf3_executable()
    command = [
        executable,
        "-c",
        normalized["host"],
        "-p",
        str(normalized["port"]),
        "-J",
        "-i",
        "1",
        "-t",
        str(normalized["duration_seconds"]),
        "-P",
        str(normalized["parallel_streams"]),
    ]
    if normalized["family"] == "ipv4":
        command.append("-4")
    elif normalized["family"] == "ipv6":
        command.append("-6")
    if normalized["bind_address"]:
        command.extend(["-B", normalized["bind_address"]])
    if normalized["reverse"]:
        command.append("-R")
    if normalized["protocol"] == "udp":
        command.extend(
            ["-u", "-b", f"{normalized['udp_megabits']}M"]
        )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=normalized["duration_seconds"] + 15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolInputError(
            "The iPerf3 client did not finish within the bounded test window."
        ) from exc
    except OSError as exc:
        raise ToolInputError(f"Could not start iPerf3: {exc}") from exc
    payload = _iperf3_payload(
        completed.stdout,
        completed.stderr,
        completed.returncode,
    )
    return _normalized_iperf3_result(
        payload,
        mode="client",
        config=normalized,
        command=command,
    )


def run_iperf3_server(config: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_iperf3_server_config(config)
    executable = _iperf3_executable()
    command = [
        executable,
        "-s",
        "-1",
        "-J",
        "-p",
        str(normalized["port"]),
        "-B",
        normalized["bind_address"],
    ]
    bind_family = ipaddress.ip_address(
        normalized["bind_address"].split("%", 1)[0]
    ).version
    command.append("-4" if bind_family == 4 else "-6")
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise ToolInputError(f"Could not start the iPerf3 server: {exc}") from exc
    try:
        stdout, stderr = process.communicate(
            timeout=normalized["window_seconds"]
        )
    except subprocess.TimeoutExpired as exc:
        process.terminate()
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=2)
        raise ToolInputError(
            "No iPerf3 client completed before the server window closed."
        ) from exc
    payload = _iperf3_payload(stdout, stderr, process.returncode or 0)
    return _normalized_iperf3_result(
        payload,
        mode="server",
        config=normalized,
        command=command,
    )


def validate_iperf3_client_config(config: dict[str, Any]) -> dict[str, Any]:
    host = str(config.get("host", "")).strip()
    validate_hosts(host, limit=1)
    port = _whole_number(config.get("port"), "Port")
    duration_seconds = _whole_number(
        config.get("duration_seconds"), "Duration"
    )
    parallel_streams = _whole_number(
        config.get("parallel_streams"), "Parallel streams"
    )
    udp_megabits = _whole_number(
        config.get("udp_megabits", 100), "UDP target rate"
    )
    protocol = str(config.get("protocol", "tcp")).strip().lower()
    family = str(config.get("family", "auto")).strip().lower()
    bind_address = str(config.get("bind_address", "")).strip()
    if not 1024 <= port <= 65535:
        raise ToolInputError("iPerf3 ports must be between 1024 and 65535.")
    if not 1 <= duration_seconds <= IPERF_MAX_DURATION_SECONDS:
        raise ToolInputError(
            f"Client duration must be between 1 and "
            f"{IPERF_MAX_DURATION_SECONDS} seconds."
        )
    if not 1 <= parallel_streams <= IPERF_MAX_PARALLEL_STREAMS:
        raise ToolInputError(
            f"Parallel streams must be between 1 and "
            f"{IPERF_MAX_PARALLEL_STREAMS}."
        )
    if not 1 <= udp_megabits <= IPERF_MAX_UDP_MEGABITS:
        raise ToolInputError(
            f"UDP target rate must be between 1 and "
            f"{IPERF_MAX_UDP_MEGABITS:,} Mbps."
        )
    if protocol not in {"tcp", "udp"}:
        raise ToolInputError("Choose TCP or UDP for the iPerf3 client.")
    if family not in {"auto", "ipv4", "ipv6"}:
        raise ToolInputError("Choose Auto, IPv4, or IPv6.")
    if bind_address:
        try:
            bind_ip = ipaddress.ip_address(bind_address.split("%", 1)[0])
        except ValueError as exc:
            raise ToolInputError(
                "The optional client source must be an IPv4 or IPv6 address."
            ) from exc
        if family == "ipv4" and bind_ip.version != 4:
            raise ToolInputError("The selected IPv4 family requires an IPv4 source.")
        if family == "ipv6" and bind_ip.version != 6:
            raise ToolInputError("The selected IPv6 family requires an IPv6 source.")
    return {
        "host": host,
        "port": port,
        "duration_seconds": duration_seconds,
        "parallel_streams": parallel_streams,
        "protocol": protocol,
        "family": family,
        "bind_address": bind_address,
        "reverse": bool(config.get("reverse")),
        "udp_megabits": udp_megabits,
    }


def validate_iperf3_server_config(config: dict[str, Any]) -> dict[str, Any]:
    bind_address = str(config.get("bind_address", "0.0.0.0")).strip()
    try:
        ipaddress.ip_address(bind_address.split("%", 1)[0])
    except ValueError as exc:
        raise ToolInputError(
            "The server bind address must be an IPv4 or IPv6 address."
        ) from exc
    port = _whole_number(config.get("port"), "Port")
    window_seconds = _whole_number(
        config.get("window_seconds"), "Server window"
    )
    if not 1024 <= port <= 65535:
        raise ToolInputError("iPerf3 ports must be between 1024 and 65535.")
    if not 5 <= window_seconds <= IPERF_MAX_SERVER_WINDOW_SECONDS:
        raise ToolInputError(
            f"Server window must be between 5 and "
            f"{IPERF_MAX_SERVER_WINDOW_SECONDS} seconds."
        )
    return {
        "bind_address": bind_address,
        "port": port,
        "window_seconds": window_seconds,
    }


def _iperf3_executable() -> str:
    capability = iperf3_capability()
    if not capability["available"]:
        raise ToolInputError(capability["detail"])
    return str(capability["executable"])


def _whole_number(value: Any, label: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ToolInputError(f"{label} must be a whole number.") from exc


def _iperf3_payload(stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
    try:
        payload = json.loads(stdout or "")
    except (TypeError, json.JSONDecodeError) as exc:
        detail = _iperf3_error(stderr or stdout)
        raise ToolInputError(
            f"iPerf3 did not return valid JSON{f': {detail}' if detail else '.'}"
        ) from exc
    if not isinstance(payload, dict):
        raise ToolInputError("iPerf3 returned an unexpected JSON response.")
    if payload.get("error"):
        raise ToolInputError(f"iPerf3 reported: {_iperf3_error(payload['error'])}")
    if returncode:
        detail = _iperf3_error(stderr)
        raise ToolInputError(
            f"iPerf3 exited with status {returncode}"
            f"{f': {detail}' if detail else '.'}"
        )
    return payload


def _normalized_iperf3_result(
    payload: dict[str, Any],
    *,
    mode: str,
    config: dict[str, Any],
    command: list[str],
) -> dict[str, Any]:
    start = payload.get("start") if isinstance(payload.get("start"), dict) else {}
    end = payload.get("end") if isinstance(payload.get("end"), dict) else {}
    test_start = (
        start.get("test_start")
        if isinstance(start.get("test_start"), dict)
        else {}
    )
    connected = start.get("connected")
    connection = (
        connected[0]
        if isinstance(connected, list)
        and connected
        and isinstance(connected[0], dict)
        else {}
    )
    sender = _metric_summary(end.get("sum_sent"))
    receiver = _metric_summary(end.get("sum_received"))
    generic_sum = _metric_summary(end.get("sum"))
    if generic_sum:
        if generic_sum.get("sender") and not sender:
            sender = generic_sum
        elif not receiver:
            receiver = generic_sum
    if not sender or not receiver:
        stream_sender, stream_receiver = _stream_summaries(end.get("streams"))
        sender = sender or stream_sender
        receiver = receiver or stream_receiver
    cpu = (
        end.get("cpu_utilization_percent")
        if isinstance(end.get("cpu_utilization_percent"), dict)
        else {}
    )
    intervals = []
    for interval in payload.get("intervals", []):
        if not isinstance(interval, dict):
            continue
        summary = _metric_summary(interval.get("sum"))
        if not summary:
            summary, _unused = _stream_summaries(interval.get("streams"))
        if summary:
            intervals.append(summary)
        if len(intervals) >= 240:
            break
    raw_json = json.dumps(payload, indent=2, ensure_ascii=False)
    raw_json_truncated = len(raw_json) > IPERF_RAW_JSON_LIMIT
    if raw_json_truncated:
        raw_json = (
            raw_json[:IPERF_RAW_JSON_LIMIT]
            + "\n\n[Raw iPerf3 JSON truncated by the toolkit.]"
        )
    transferred_bytes = max(
        int((sender or {}).get("bytes") or 0),
        int((receiver or {}).get("bytes") or 0),
    )
    protocol = str(
        test_start.get("protocol") or config.get("protocol") or "TCP"
    ).upper()
    return {
        "mode": mode,
        "protocol": protocol,
        "direction": (
            "reverse"
            if bool(test_start.get("reverse", config.get("reverse", False)))
            else "forward"
        ),
        "version": str(start.get("version") or ""),
        "system_info": str(start.get("system_info") or ""),
        "connection": {
            key: connection.get(key)
            for key in (
                "local_host",
                "local_port",
                "remote_host",
                "remote_port",
            )
        },
        "sender": sender,
        "receiver": receiver,
        "intervals": intervals,
        "cpu": {
            key: round(float(cpu[key]), 2)
            for key in (
                "host_total",
                "host_user",
                "host_system",
                "remote_total",
                "remote_user",
                "remote_system",
            )
            if isinstance(cpu.get(key), (int, float))
        },
        "transferred_bytes": transferred_bytes,
        "transferred_display": _format_bytes(transferred_bytes),
        "command": shlex.join(command),
        "raw_json": raw_json,
        "raw_json_truncated": raw_json_truncated,
    }


def _metric_summary(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    bits_per_second = _number(value.get("bits_per_second"))
    byte_count = int(_number(value.get("bytes")) or 0)
    result = {
        "start": _rounded(value.get("start")),
        "end": _rounded(value.get("end")),
        "seconds": _rounded(value.get("seconds")),
        "bytes": byte_count,
        "bytes_display": _format_bytes(byte_count),
        "bits_per_second": bits_per_second,
        "megabits_per_second": (
            round(bits_per_second / 1_000_000, 2)
            if bits_per_second is not None
            else None
        ),
        "sender": bool(value.get("sender")),
        "omitted": bool(value.get("omitted")),
    }
    for source, target in (
        ("retransmits", "retransmits"),
        ("packets", "packets"),
        ("lost_packets", "lost_packets"),
    ):
        if isinstance(value.get(source), (int, float)):
            result[target] = int(value[source])
    for source, target in (
        ("jitter_ms", "jitter_ms"),
        ("lost_percent", "lost_percent"),
    ):
        if isinstance(value.get(source), (int, float)):
            result[target] = round(float(value[source]), 3)
    return result


def _stream_summaries(
    values: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not isinstance(values, list):
        return None, None
    sender_values = [
        item["sender"]
        for item in values
        if isinstance(item, dict) and isinstance(item.get("sender"), dict)
    ]
    receiver_values = [
        item["receiver"]
        for item in values
        if isinstance(item, dict) and isinstance(item.get("receiver"), dict)
    ]
    return _aggregate_summaries(sender_values), _aggregate_summaries(
        receiver_values
    )


def _aggregate_summaries(values: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not values:
        return None
    summary = {
        "start": min((_number(item.get("start")) or 0) for item in values),
        "end": max((_number(item.get("end")) or 0) for item in values),
        "seconds": max((_number(item.get("seconds")) or 0) for item in values),
        "bytes": sum(int(_number(item.get("bytes")) or 0) for item in values),
        "bits_per_second": sum(
            _number(item.get("bits_per_second")) or 0 for item in values
        ),
        "sender": bool(values[0].get("sender")),
        "omitted": any(bool(item.get("omitted")) for item in values),
    }
    summary["bytes_display"] = _format_bytes(summary["bytes"])
    summary["megabits_per_second"] = round(
        summary["bits_per_second"] / 1_000_000,
        2,
    )
    retransmits = [
        int(item["retransmits"])
        for item in values
        if isinstance(item.get("retransmits"), (int, float))
    ]
    if retransmits:
        summary["retransmits"] = sum(retransmits)
    return summary


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def _rounded(value: Any) -> float | None:
    number = _number(value)
    return round(number, 3) if number is not None else None


def _format_bytes(value: int) -> str:
    amount = float(max(0, value))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == units[-1]:
            break
        amount /= 1024
    precision = 0 if unit == "B" else 2
    return f"{amount:.{precision}f} {unit}"


def _iperf3_error(value: Any) -> str:
    return " ".join(str(value or "").split())[:1000]
