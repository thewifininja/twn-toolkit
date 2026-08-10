from __future__ import annotations

import array
import errno
import ipaddress
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any


BROKER_ENVIRONMENT = "TWN_TOOLKIT_NETWORK_BROKER"
DEFAULT_CONNECT_TIMEOUT = 10.0
BROKER_STARTUP_GRACE = 1.0
_REQUEST_HEADER = struct.Struct("!4sBBBBIHH")
_RESPONSE = struct.Struct("!I")
_ORIGINAL_SOCKET = socket.socket
_INSTALLED = False


class BrokerProtocolError(OSError):
    pass


def _broker_path() -> str:
    return os.environ.get(BROKER_ENVIRONMENT, "").strip()


def _connection_timeout(value: float | None) -> float:
    if value is None:
        return DEFAULT_CONNECT_TIMEOUT
    return max(0.1, min(float(value), 30.0))


def _is_loopback(host: str) -> bool:
    normalized = host.split("%", 1)[0]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return normalized.lower() == "localhost"


def _broker_candidate(
    family: int,
    sock_type: int,
    address: Any,
    timeout: float | None,
) -> tuple[str, int, int, float] | None:
    path = _broker_path()
    if not path or family not in {socket.AF_INET, socket.AF_INET6}:
        return None
    if sock_type & socket.SOCK_STREAM != socket.SOCK_STREAM:
        return None
    if timeout == 0.0 or not isinstance(address, tuple) or len(address) < 2:
        return None
    host = str(address[0]).strip()
    try:
        port = int(address[1])
    except (TypeError, ValueError):
        return None
    if not host or not 1 <= port <= 65535 or _is_loopback(host):
        return None
    family_code = 4 if family == socket.AF_INET else 6
    return host, port, family_code, _connection_timeout(timeout)


def _recv_descriptor(channel: socket.socket) -> int:
    descriptor_size = array.array("i").itemsize
    payload, ancillary, _flags, _address = channel.recvmsg(
        _RESPONSE.size,
        socket.CMSG_SPACE(descriptor_size),
    )
    if len(payload) != _RESPONSE.size:
        raise BrokerProtocolError(errno.EPROTO, "Network broker returned a short response")
    status = _RESPONSE.unpack(payload)[0]
    if status:
        raise OSError(status, os.strerror(status))
    for level, message_type, data in ancillary:
        if level == socket.SOL_SOCKET and message_type == socket.SCM_RIGHTS:
            descriptors = array.array("i")
            descriptors.frombytes(data[: len(data) - (len(data) % descriptor_size)])
            if descriptors:
                received = int(descriptors[0])
                os.set_inheritable(received, False)
                for extra in descriptors[1:]:
                    os.close(int(extra))
                return received
    raise BrokerProtocolError(errno.EPROTO, "Network broker omitted the connected socket")


def request_connected_descriptor(
    path: str,
    host: str,
    port: int,
    *,
    family_code: int,
    timeout: float,
) -> int:
    encoded_host = host.encode("utf-8")
    if not 1 <= len(encoded_host) <= 255 or b"\0" in encoded_host:
        raise OSError(errno.EINVAL, "Unsupported network broker hostname")
    timeout_ms = max(100, min(round(timeout * 1000), 30_000))
    request = _REQUEST_HEADER.pack(
        b"TWNB",
        1,
        family_code,
        1,
        0,
        timeout_ms,
        port,
        len(encoded_host),
    ) + encoded_host

    deadline = time.monotonic() + min(BROKER_STARTUP_GRACE, timeout)
    while True:
        channel = _ORIGINAL_SOCKET(socket.AF_UNIX, socket.SOCK_STREAM)
        channel.settimeout(max(0.1, timeout))
        try:
            channel.connect(path)
            channel.sendall(request)
            return _recv_descriptor(channel)
        except (FileNotFoundError, ConnectionRefusedError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
        finally:
            channel.close()


class BrokeredSocket(_ORIGINAL_SOCKET):
    """Socket subclass that delegates service TCP connects to the root broker."""

    def connect(self, address: Any) -> None:
        candidate = _broker_candidate(self.family, self.type, address, self.gettimeout())
        if candidate is None:
            return super().connect(address)
        host, port, family_code, timeout = candidate
        received = request_connected_descriptor(
            _broker_path(),
            host,
            port,
            family_code=family_code,
            timeout=timeout,
        )
        original_timeout = self.gettimeout()
        try:
            os.dup2(received, self.fileno(), inheritable=False)
        finally:
            os.close(received)
        self.settimeout(original_timeout)

    def connect_ex(self, address: Any) -> int:
        try:
            self.connect(address)
        except OSError as exc:
            return int(exc.errno or errno.EIO)
        return 0


def install_socket_broker_from_environment(*, force: bool = False) -> bool:
    """Install the process-wide socket shim only for managed macOS workers."""
    global _INSTALLED
    if _INSTALLED:
        return True
    path = _broker_path()
    if not path or (sys.platform != "darwin" and not force):
        return False
    if not Path(path).is_absolute():
        raise RuntimeError(f"{BROKER_ENVIRONMENT} must contain an absolute path")
    socket.socket = BrokeredSocket
    _INSTALLED = True
    return True
