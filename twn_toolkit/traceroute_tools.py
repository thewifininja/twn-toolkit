from __future__ import annotations

import ipaddress
import os
import platform
import re
import selectors
import shutil
import socket
import subprocess
import time
from typing import Any

from .network_tools import ToolInputError, validate_hosts


HOP_LINE = re.compile(r"^\s*(\d+)\s+(.*)$")
LATENCY = re.compile(r"(?<![\d.])(\d+(?:\.\d+)?)\s*ms\b", re.IGNORECASE)


def run_traceroute(
    host: str,
    *,
    family: str = "auto",
    method: str = "udp",
    max_hops: int = 30,
    probes: int = 3,
    timeout: float = 2.0,
) -> dict[str, Any]:
    prepared = prepare_traceroute(
        host,
        family=family,
        method=method,
        max_hops=max_hops,
        probes=probes,
        timeout=timeout,
    )
    command = prepared["command"]
    destination_addresses = prepared["destination_addresses"]
    resolved_family = prepared["resolved_family"]
    host = prepared["host"]
    method = prepared["method"]
    max_hops = prepared["max_hops"]
    probes = prepared["probes"]
    timeout = prepared["timeout"]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=min(110, max_hops * probes * timeout + 10),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = "\n".join(part for part in (exc.stdout or "", exc.stderr or "") if part).strip()
        raise ToolInputError(
            f"Traceroute exceeded its safety timeout.{f' Partial output: {output}' if output else ''}"
        ) from exc
    except OSError as exc:
        raise ToolInputError(f"Traceroute could not be started: {exc}") from exc

    raw_output = completed.stdout.strip() if completed.stdout else ""
    if not raw_output:
        raise ToolInputError("Traceroute returned no output.")
    hops = parse_traceroute_output(raw_output, probes=probes)
    if not hops:
        raise ToolInputError(raw_output)

    reached = _destination_reached(hops, host, destination_addresses)
    responding = [hop for hop in hops if hop["responded"]]
    return {
        "host": host,
        "family": "IPv6" if resolved_family == socket.AF_INET6 else "IPv4",
        "method": method.upper(),
        "command": " ".join(command),
        "raw_output": raw_output,
        "hops": hops,
        "hop_count": hops[-1]["number"],
        "responding_hops": len(responding),
        "reached": reached,
        "destination_addresses": sorted(destination_addresses),
    }


def prepare_traceroute(
    host: str,
    *,
    family: str = "auto",
    method: str = "udp",
    max_hops: int = 30,
    probes: int = 3,
    timeout: float = 2.0,
) -> dict[str, Any]:
    host = host.strip()
    validate_hosts(host, limit=1)
    if family not in {"auto", "ipv4", "ipv6"}:
        raise ToolInputError("Address family must be Auto, IPv4, or IPv6.")
    if method not in {"udp", "icmp"}:
        raise ToolInputError("Traceroute method must be UDP or ICMP.")
    if not 1 <= max_hops <= 64:
        raise ToolInputError("Maximum hops must be between 1 and 64.")
    if not 1 <= probes <= 3:
        raise ToolInputError("Probes per hop must be between 1 and 3.")
    if not 1 <= timeout <= 5 or not float(timeout).is_integer():
        raise ToolInputError("Probe timeout must be a whole number from 1 to 5 seconds.")

    resolved_family, destination_addresses = _resolve_destination(host, family)
    command = _build_command(
        host,
        resolved_family,
        method=method,
        max_hops=max_hops,
        probes=probes,
        timeout=timeout,
    )
    return {
        "host": host,
        "resolved_family": resolved_family,
        "destination_addresses": destination_addresses,
        "method": method,
        "max_hops": max_hops,
        "probes": probes,
        "timeout": timeout,
        "command": command,
    }


def stream_traceroute(prepared: dict[str, Any]):
    command = prepared["command"]
    process = None
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
    except OSError as exc:
        raise ToolInputError(f"Traceroute could not be started: {exc}") from exc
    hops: list[dict[str, Any]] = []
    safety_timeout = min(
        110,
        prepared["max_hops"] * prepared["probes"] * prepared["timeout"] + 10,
    )
    deadline = started + safety_timeout
    try:
        yield {
            "type": "start",
            "host": prepared["host"],
            "family": "IPv6" if prepared["resolved_family"] == socket.AF_INET6 else "IPv4",
            "method": prepared["method"].upper(),
            "command": " ".join(command),
        }
        for raw_line in _iter_process_lines(process, deadline):
            line = raw_line.rstrip("\r\n")
            yield {"type": "output", "line": line}
            parsed = parse_traceroute_output(line, probes=prepared["probes"])
            if parsed:
                hop = parsed[0]
                hops.append(hop)
                yield {"type": "hop", "hop": hop}
        process.wait(timeout=max(0.05, deadline - time.monotonic()))
        if not hops:
            yield {"type": "error", "error": "Traceroute returned no hop results."}
            return
        reached = _destination_reached(
            hops,
            prepared["host"],
            prepared["destination_addresses"],
        )
        yield {
            "type": "complete",
            "reached": reached,
            "hop_count": hops[-1]["number"],
            "responding_hops": sum(hop["responded"] for hop in hops),
        }
    except subprocess.TimeoutExpired:
        yield {"type": "error", "error": "Traceroute exceeded its safety timeout."}
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass


def _iter_process_lines(process: subprocess.Popen[bytes], deadline: float):
    """Yield decoded lines without letting a silent child bypass its deadline."""
    assert process.stdout is not None
    try:
        descriptor = process.stdout.fileno()
    except (AttributeError, OSError):
        # Lightweight file-like test doubles do not expose a selectable pipe.
        for raw_line in process.stdout:
            yield raw_line.decode(errors="replace") if isinstance(raw_line, bytes) else raw_line
        return

    selector = selectors.DefaultSelector()
    pending = b""
    try:
        selector.register(descriptor, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(
                    getattr(process, "args", "traceroute"), 0
                )
            events = selector.select(timeout=min(0.25, remaining))
            if not events:
                if process.poll() is not None:
                    break
                continue
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            pending += chunk
            while b"\n" in pending:
                raw_line, pending = pending.split(b"\n", 1)
                yield raw_line.decode(errors="replace") + "\n"
        if pending:
            yield pending.decode(errors="replace")
    finally:
        selector.close()


def parse_traceroute_output(output: str, probes: int = 3) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = HOP_LINE.match(line)
        if not match:
            continue
        number, body = int(match.group(1)), match.group(2)
        addresses: list[str] = []
        names: list[str] = []
        tokens = body.split()
        for index, token in enumerate(tokens):
            candidate = token.strip("(),")
            try:
                address = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            if address not in addresses:
                addresses.append(address)
            if index and tokens[index - 1] != "*" and not LATENCY.search(tokens[index - 1]):
                possible_name = tokens[index - 1].strip("(),")
                if possible_name != address and possible_name not in names:
                    names.append(possible_name)
        latencies = [round(float(value), 3) for value in LATENCY.findall(body)]
        if not names and not addresses and tokens and tokens[0] != "*":
            candidate_name = tokens[0].strip("(),")
            if candidate_name and not candidate_name.replace(".", "", 1).isdigit():
                names.append(candidate_name)
        average = round(sum(latencies) / len(latencies), 3) if latencies else None
        loss_percent = round(max(0, probes - len(latencies)) / probes * 100)
        hops.append(
            {
                "number": number,
                "name": names[0] if names else "",
                "addresses": addresses,
                "latencies_ms": latencies,
                "average_ms": average,
                "loss_percent": loss_percent,
                "responded": bool(latencies or addresses),
                "raw": line,
            }
        )
    return hops


def _destination_reached(
    hops: list[dict[str, Any]],
    host: str,
    destination_addresses: set[str],
) -> bool:
    normalized_host = host.rstrip(".").lower()
    return any(
        any(address in destination_addresses for address in hop["addresses"])
        or (hop["responded"] and hop["name"].rstrip(".").lower() == normalized_host)
        for hop in hops
    )


def _resolve_destination(host: str, family: str) -> tuple[int, set[str]]:
    requested_family = {
        "auto": socket.AF_UNSPEC,
        "ipv4": socket.AF_INET,
        "ipv6": socket.AF_INET6,
    }[family]
    try:
        answers = socket.getaddrinfo(host, None, requested_family, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise ToolInputError(f"Could not resolve traceroute destination '{host}': {exc}") from exc
    if not answers:
        raise ToolInputError(f"Could not resolve traceroute destination '{host}'.")
    selected_family = answers[0][0]
    addresses = {
        str(ipaddress.ip_address(answer[4][0]))
        for answer in answers
        if answer[0] == selected_family
    }
    return selected_family, addresses


def _build_command(
    host: str,
    family: int,
    *,
    method: str,
    max_hops: int,
    probes: int,
    timeout: float,
) -> list[str]:
    system = platform.system()
    if family == socket.AF_INET6 and system == "Darwin":
        executable = shutil.which("traceroute6")
        command = [executable] if executable else []
    else:
        executable = shutil.which("traceroute")
        command = [executable] if executable else []
        if family == socket.AF_INET6 and system != "Darwin":
            command.append("-6")
    if not command:
        raise ToolInputError("The traceroute command is not installed on this system.")
    if method == "icmp":
        command.append("-I")
    command.extend(["-m", str(max_hops), "-q", str(probes), "-w", str(int(timeout)), host])
    return command
