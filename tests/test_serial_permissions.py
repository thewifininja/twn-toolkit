from __future__ import annotations

import stat
from types import SimpleNamespace
from unittest.mock import patch

from twn_toolkit.serial_permissions import (
    linux_serial_service_groups,
    serial_permission_message,
    serial_permission_status,
)


def _metadata(*, group_id: int = 984, mode: int = 0o660):
    return SimpleNamespace(
        st_uid=0,
        st_gid=group_id,
        st_mode=stat.S_IFCHR | mode,
    )


def test_permission_message_reports_actual_arch_uucp_group(tmp_path):
    device = tmp_path / "ttyUSB0"
    device.touch()
    with (
        patch("twn_toolkit.serial_permissions.Path.stat", return_value=_metadata()),
        patch("twn_toolkit.serial_permissions.os.access", return_value=False),
        patch("twn_toolkit.serial_permissions.os.getegid", return_value=1000),
        patch("twn_toolkit.serial_permissions.os.getgroups", return_value=[998, 1000]),
        patch("twn_toolkit.serial_permissions.os.geteuid", return_value=1000),
        patch(
            "twn_toolkit.serial_permissions.grp.getgrgid",
            return_value=SimpleNamespace(gr_name="uucp"),
        ),
        patch(
            "twn_toolkit.serial_permissions.pwd.getpwuid",
            side_effect=lambda user_id: SimpleNamespace(
                pw_name="root" if user_id == 0 else "nkarrick"
            ),
        ),
        patch("twn_toolkit.serial_permissions.sys.platform", "linux"),
    ):
        message = serial_permission_message(device)

    assert "root:uucp with mode 0660" in message
    assert "service account nkarrick" in message
    assert "uucp supplementary group" in message
    assert "dialout" not in message


def test_permission_status_respects_acl_or_existing_group_access(tmp_path):
    device = tmp_path / "ttyACM0"
    device.touch()
    with (
        patch("twn_toolkit.serial_permissions.Path.stat", return_value=_metadata()),
        patch("twn_toolkit.serial_permissions.os.access", return_value=True),
        patch("twn_toolkit.serial_permissions.os.getegid", return_value=1000),
        patch("twn_toolkit.serial_permissions.os.getgroups", return_value=[984, 1000]),
        patch("twn_toolkit.serial_permissions.os.geteuid", return_value=1000),
        patch(
            "twn_toolkit.serial_permissions.grp.getgrgid",
            return_value=SimpleNamespace(gr_name="uucp"),
        ),
        patch(
            "twn_toolkit.serial_permissions.pwd.getpwuid",
            side_effect=lambda user_id: SimpleNamespace(
                pw_name="root" if user_id == 0 else "toolkit"
            ),
        ),
    ):
        status = serial_permission_status(device)

    assert status["accessible"] is True
    assert status["missing_groups"] == []


def test_missing_device_is_reported_as_detached(tmp_path):
    device = tmp_path / "ttyUSB9"

    message = serial_permission_message(device)

    assert "no longer attached" in message


def test_live_serial_device_group_is_authoritative():
    device = SimpleNamespace(stat=lambda: _metadata(group_id=984))
    with (
        patch("twn_toolkit.serial_permissions.sys.platform", "linux"),
        patch(
            "twn_toolkit.serial_permissions.grp.getgrgid",
            return_value=SimpleNamespace(gr_name="uucp"),
        ),
    ):
        groups = linux_serial_service_groups([device])

    assert groups == ("uucp",)


def test_platform_fallback_uses_uucp_on_arch_and_dialout_on_debian(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text("ID=omarchy\nID_LIKE=arch\n", encoding="utf-8")

    def local_group(name: str):
        if name in {"uucp", "dialout"}:
            return SimpleNamespace(gr_name=name)
        raise KeyError(name)

    with (
        patch("twn_toolkit.serial_permissions.sys.platform", "linux"),
        patch("twn_toolkit.serial_permissions.grp.getgrnam", side_effect=local_group),
    ):
        assert linux_serial_service_groups([], os_release_path=os_release) == ("uucp",)
        os_release.write_text("ID=ubuntu\nID_LIKE=debian\n", encoding="utf-8")
        assert linux_serial_service_groups([], os_release_path=os_release) == (
            "dialout",
        )


def test_devices_without_group_read_write_are_not_granted():
    device = SimpleNamespace(stat=lambda: _metadata(group_id=984, mode=0o600))
    with (
        patch("twn_toolkit.serial_permissions.sys.platform", "linux"),
        patch(
            "twn_toolkit.serial_permissions.grp.getgrnam",
            side_effect=KeyError,
        ),
    ):
        assert linux_serial_service_groups([device]) == ()
