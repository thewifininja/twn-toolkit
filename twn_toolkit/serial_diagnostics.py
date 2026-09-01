from __future__ import annotations

from pathlib import Path
from typing import Any

from .serial_permissions import serial_permission_status


def linux_serial_capability() -> dict[str, Any]:
    paths = sorted(
        {
            path
            for pattern in ("ttyUSB*", "ttyACM*", "ttyAMA*", "rfcomm*", "cuaU*")
            for path in Path("/dev").glob(pattern)
        }
    )
    statuses = [serial_permission_status(path) for path in paths]
    if not statuses:
        return {
            "name": "Linux serial device access",
            "available": False,
            "status": "No devices",
            "detail": (
                "No supported USB, UART, or paired Bluetooth serial devices "
                "are attached."
            ),
        }
    inaccessible = [item for item in statuses if not item["accessible"]]
    details = []
    for item in statuses:
        access = "read/write ready" if item["accessible"] else "permission required"
        missing = list(item["missing_groups"])
        requirement = f"; missing service group {missing[0]}" if missing else ""
        details.append(
            f"{item['path']} is {item['owner']}:{item['group']} mode {item['mode']}: "
            f"{access}{requirement}"
        )
    return {
        "name": "Linux serial device access",
        "available": not inaccessible,
        "status": "Ready" if not inaccessible else "Permission needed",
        "detail": ". ".join(details) + ".",
    }


__all__ = ["linux_serial_capability"]
