from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from twn_toolkit.serial_diagnostics import linux_serial_capability


def test_linux_serial_diagnostics_report_group_and_service_access():
    device = Path("/dev/ttyUSB0")
    with (
        patch("twn_toolkit.serial_diagnostics.Path.glob", return_value=[device]),
        patch(
            "twn_toolkit.serial_diagnostics.serial_permission_status",
            return_value={
                "path": str(device),
                "present": True,
                "accessible": False,
                "owner": "root",
                "group": "uucp",
                "mode": "0660",
                "service_user": "nkarrick",
                "missing_groups": ["uucp"],
            },
        ),
    ):
        capability = linux_serial_capability()

    assert capability["available"] is False
    assert capability["status"] == "Permission needed"
    assert "/dev/ttyUSB0 is root:uucp mode 0660" in capability["detail"]
    assert "missing service group uucp" in capability["detail"]


def test_linux_serial_diagnostics_report_ready_acl_access():
    device = Path("/dev/ttyACM0")
    with (
        patch("twn_toolkit.serial_diagnostics.Path.glob", return_value=[device]),
        patch(
            "twn_toolkit.serial_diagnostics.serial_permission_status",
            return_value={
                "path": str(device),
                "present": True,
                "accessible": True,
                "owner": "root",
                "group": "dialout",
                "mode": "0660",
                "service_user": "toolkit",
                "missing_groups": [],
            },
        ),
    ):
        capability = linux_serial_capability()

    assert capability["available"] is True
    assert capability["status"] == "Ready"
    assert "read/write ready" in capability["detail"]


def test_linux_serial_diagnostics_handle_no_attached_device():
    with patch("twn_toolkit.serial_diagnostics.Path.glob", return_value=[]):
        capability = linux_serial_capability()

    assert capability["status"] == "No devices"
    assert capability["available"] is False
