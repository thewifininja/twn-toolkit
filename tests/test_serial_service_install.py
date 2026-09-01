from __future__ import annotations

from unittest.mock import patch

from twn_toolkit.service_cli import ServiceUser, install_service


def test_linux_service_install_scopes_lldp_and_serial_groups(tmp_path):
    user = ServiceUser("toolkit", "toolkit", 1001, 1001, "/home/toolkit")
    written: dict[str, bytes] = {}

    def capture(path, content, **_options):
        written[str(path)] = bytes(content)

    with (
        patch("twn_toolkit.service_cli._validate_install_request"),
        patch("twn_toolkit.service_cli._require_root"),
        patch(
            "twn_toolkit.service_cli._ensure_instance_directory",
            return_value=tmp_path / "instance",
        ),
        patch("twn_toolkit.service_cli.shutil.which", return_value="/usr/bin/systemctl"),
        patch(
            "twn_toolkit.service_cli.linux_lldp_service_groups",
            return_value=("lldpd",),
        ),
        patch(
            "twn_toolkit.service_cli.linux_serial_service_groups",
            return_value=("uucp",),
        ),
        patch("twn_toolkit.service_cli._write_system_file", side_effect=capture),
        patch("twn_toolkit.service_cli.raspberry_pi_hardware", return_value=False),
        patch("twn_toolkit.service_cli._remove_pi_network_broker"),
        patch("twn_toolkit.service_cli._run") as run,
    ):
        install_service(
            tmp_path,
            user,
            system="Linux",
            network_capabilities=True,
        )

    unit = next(iter(written.values())).decode("utf-8")
    assert "SupplementaryGroups=lldpd uucp" in unit
    assert "CAP_NET_ADMIN" in unit
    assert any(call.args[0] == ("systemctl", "restart", "twn-toolkit.service") for call in run.call_args_list)
