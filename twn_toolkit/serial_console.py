from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Any, Iterable

import serial
from serial.tools import list_ports
from .serial_permissions import serial_permission_message


SERIAL_BAUD_RATES = (
    300,
    600,
    1200,
    2400,
    4800,
    9600,
    19200,
    38400,
    57600,
    115200,
    230400,
    460800,
    921600,
)
SERIAL_DATA_BITS = (5, 6, 7, 8)
SERIAL_PARITIES = ("none", "even", "odd", "mark", "space")
SERIAL_STOP_BITS = ("1", "1.5", "2")
SERIAL_FLOW_CONTROLS = ("none", "software", "hardware")


class SerialConsoleError(ValueError):
    pass


def serial_settings(
    *,
    baud_rate: object = 9600,
    data_bits: object = 8,
    parity: object = "none",
    stop_bits: object = "1",
    flow_control: object = "none",
) -> dict[str, Any]:
    try:
        clean_baud = int(baud_rate)
        clean_data_bits = int(data_bits)
    except (TypeError, ValueError) as exc:
        raise SerialConsoleError("Choose valid console line settings.") from exc
    clean_parity = str(parity).strip().lower()
    clean_stop_bits = str(stop_bits).strip().lower()
    if clean_stop_bits in {"1.0", "2.0"}:
        clean_stop_bits = clean_stop_bits.removesuffix(".0")
    clean_flow_control = str(flow_control).strip().lower()
    if clean_baud not in SERIAL_BAUD_RATES:
        raise SerialConsoleError("Choose a supported console baud rate.")
    if clean_data_bits not in SERIAL_DATA_BITS:
        raise SerialConsoleError("Console data bits must be 5, 6, 7, or 8.")
    if clean_parity not in SERIAL_PARITIES:
        raise SerialConsoleError("Choose a supported console parity.")
    if clean_stop_bits not in SERIAL_STOP_BITS:
        raise SerialConsoleError("Choose 1, 1.5, or 2 console stop bits.")
    if clean_flow_control not in SERIAL_FLOW_CONTROLS:
        raise SerialConsoleError("Choose a supported console flow-control mode.")
    return {
        "baud_rate": clean_baud,
        "data_bits": clean_data_bits,
        "parity": clean_parity,
        "stop_bits": clean_stop_bits,
        "flow_control": clean_flow_control,
    }


def list_serial_devices(
    ports: Iterable[Any] | None = None,
) -> list[dict[str, Any]]:
    try:
        discovered = list(ports if ports is not None else list_ports.comports())
    except Exception as exc:
        raise SerialConsoleError(
            "Local console devices could not be enumerated."
        ) from exc

    devices: list[dict[str, Any]] = []
    for port in discovered:
        path = str(getattr(port, "device", "") or "").strip()
        if not _supported_device_path(path) or _ignored_device_path(path):
            continue
        if sys.platform == "darwin" and path.startswith("/dev/tty."):
            callout = f"/dev/cu.{path.removeprefix('/dev/tty.')}"
            if any(
                str(getattr(candidate, "device", "") or "") == callout
                for candidate in discovered
            ):
                continue
        description = _clean_metadata(getattr(port, "description", ""))
        product = _clean_metadata(getattr(port, "product", ""))
        manufacturer = _clean_metadata(getattr(port, "manufacturer", ""))
        serial_number = _clean_metadata(getattr(port, "serial_number", ""))
        hwid = _clean_metadata(getattr(port, "hwid", ""))
        vid = getattr(port, "vid", None)
        pid = getattr(port, "pid", None)
        location = _clean_metadata(getattr(port, "location", ""))
        transport = _transport_label(
            path, description, product, manufacturer, hwid
        )
        identity = _device_identity(
            path=path,
            hwid=hwid,
            vid=vid,
            pid=pid,
            serial_number=serial_number,
            location=location,
        )
        label = product or description or Path(path).name
        devices.append(
            {
                "id": "console_"
                + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
                "path": path,
                "label": label,
                "description": description or label,
                "transport": transport,
                "manufacturer": manufacturer,
                "serial_number": serial_number,
                "vid": f"{int(vid):04X}" if vid is not None else "",
                "pid": f"{int(pid):04X}" if pid is not None else "",
                "location": location,
                "hwid": hwid,
                "accessible": os.access(path, os.R_OK | os.W_OK),
            }
        )
    return sorted(
        devices,
        key=lambda item: (
            str(item["transport"]),
            str(item["label"]).casefold(),
            str(item["path"]),
        ),
    )


def resolve_serial_device(
    device_id: object,
    *,
    devices: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    clean_id = str(device_id).strip()
    if not clean_id or len(clean_id) > 80:
        raise SerialConsoleError("Choose a local console device.")
    candidates = list(devices) if devices is not None else list_serial_devices()
    device = next((item for item in candidates if item.get("id") == clean_id), None)
    if not device:
        raise SerialConsoleError(
            "That console device is not currently attached to the toolkit host."
        )
    if not bool(device.get("accessible")):
        raise SerialConsoleError(_permission_message(str(device.get("path", ""))))
    return dict(device)


class SerialConsoleChannel:
    """Paramiko-like adapter over a local serial character device."""

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def settimeout(self, _timeout: float) -> None:
        # The session manager polls ``in_waiting`` and must never block a worker.
        self.connection.timeout = 0

    def recv_ready(self) -> bool:
        return bool(self.connection.is_open and self.connection.in_waiting)

    def recv(self, size: int) -> bytes:
        return bytes(self.connection.read(max(1, int(size))))

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = int(self.connection.write(view))
            if written <= 0:
                raise SerialConsoleError("The console device accepted no input.")
            view = view[written:]

    def exit_status_ready(self) -> bool:
        return not bool(self.connection.is_open)

    def resize_pty(self, *, width: int, height: int) -> None:
        # Physical serial consoles do not negotiate terminal dimensions.
        del width, height

    def close(self) -> None:
        self.connection.close()


def open_serial_channel(
    *,
    device_path: str,
    baud_rate: int,
    data_bits: int,
    parity: str,
    stop_bits: str,
    flow_control: str,
) -> SerialConsoleChannel:
    settings = serial_settings(
        baud_rate=baud_rate,
        data_bits=data_bits,
        parity=parity,
        stop_bits=stop_bits,
        flow_control=flow_control,
    )
    path = str(device_path).strip()
    if not _supported_device_path(path):
        raise SerialConsoleError("Choose a supported local console device.")
    bytesizes = {
        5: serial.FIVEBITS,
        6: serial.SIXBITS,
        7: serial.SEVENBITS,
        8: serial.EIGHTBITS,
    }
    parities = {
        "none": serial.PARITY_NONE,
        "even": serial.PARITY_EVEN,
        "odd": serial.PARITY_ODD,
        "mark": serial.PARITY_MARK,
        "space": serial.PARITY_SPACE,
    }
    stopbits = {
        "1": serial.STOPBITS_ONE,
        "1.5": serial.STOPBITS_ONE_POINT_FIVE,
        "2": serial.STOPBITS_TWO,
    }
    kwargs = {
        "port": path,
        "baudrate": settings["baud_rate"],
        "bytesize": bytesizes[settings["data_bits"]],
        "parity": parities[settings["parity"]],
        "stopbits": stopbits[settings["stop_bits"]],
        "timeout": 0,
        "write_timeout": 2,
        "xonxoff": settings["flow_control"] == "software",
        "rtscts": settings["flow_control"] == "hardware",
    }
    if os.name == "posix":
        kwargs["exclusive"] = True
    try:
        return SerialConsoleChannel(serial.Serial(**kwargs))
    except serial.SerialException as exc:
        if isinstance(exc.__cause__, PermissionError) or "permission" in str(exc).lower():
            raise SerialConsoleError(_permission_message(path)) from exc
        raise SerialConsoleError(
            f"The console device {path} could not be opened: {exc}"
        ) from exc
    except OSError as exc:
        if isinstance(exc, PermissionError):
            raise SerialConsoleError(_permission_message(path)) from exc
        raise SerialConsoleError(
            f"The console device {path} could not be opened: {exc}"
        ) from exc


def _supported_device_path(path: str) -> bool:
    if not path or len(path) > 255 or not path.startswith("/dev/"):
        return False
    if any(character in path for character in ("\x00", "\r", "\n")):
        return False
    name = Path(path).name
    prefixes = (
        "ttyUSB",
        "ttyACM",
        "ttyAMA",
        "ttyS",
        "rfcomm",
        "cu.",
        "cuaU",
        "cua",
    )
    return name.startswith(prefixes)


def _ignored_device_path(path: str) -> bool:
    """Hide macOS service endpoints that are not outbound device consoles."""
    return Path(path).name.casefold() in {
        "cu.bluetooth-incoming-port",
        "cu.debug-console",
        "tty.bluetooth-incoming-port",
        "tty.debug-console",
    }


def _device_identity(
    *,
    path: str,
    hwid: str,
    vid: object,
    pid: object,
    serial_number: str,
    location: str,
) -> str:
    if vid is not None and pid is not None and serial_number:
        return f"usb:{int(vid):04x}:{int(pid):04x}:{serial_number}"
    if vid is not None and pid is not None and location:
        return f"usb-location:{int(vid):04x}:{int(pid):04x}:{location}"
    if hwid:
        return f"hwid:{hwid}"
    return f"path:{os.path.realpath(path)}"


def _transport_label(path: str, *metadata: str) -> str:
    combined = " ".join((path, *metadata)).casefold()
    if "bluetooth" in combined or "/rfcomm" in combined:
        return "Bluetooth serial"
    if "usb" in combined or "/ttyacm" in combined:
        return "USB serial"
    return "Local serial"


def _clean_metadata(value: object) -> str:
    clean = " ".join(str(value or "").strip().split())
    return "" if clean.casefold() in {"n/a", "none"} else clean[:255]


def _permission_message(path: str) -> str:
    return serial_permission_message(path)


__all__ = [
    "SERIAL_BAUD_RATES",
    "SERIAL_DATA_BITS",
    "SERIAL_FLOW_CONTROLS",
    "SERIAL_PARITIES",
    "SERIAL_STOP_BITS",
    "SerialConsoleChannel",
    "SerialConsoleError",
    "list_serial_devices",
    "open_serial_channel",
    "resolve_serial_device",
    "serial_settings",
]
