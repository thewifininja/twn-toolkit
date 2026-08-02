from __future__ import annotations

import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from twn_toolkit.service_cli import (
    LAUNCHD_LABEL,
    NETWORK_CAPABILITIES,
    SYSTEMD_UNIT_NAME,
    ServiceError,
    ServiceUser,
    _ensure_instance_directory,
    _validate_macos_service_location,
    install_service,
    render_launchd_plist,
    render_systemd_unit,
    service_user,
    service_status,
    uninstall_service,
)


class ServiceCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.user = ServiceUser("toolkit", "toolkit", 1001, 1001, "/home/toolkit")

    def test_systemd_unit_runs_as_user_and_restarts_supervisor(self) -> None:
        root = Path("/srv/The WiFi Toolkit")
        unit = render_systemd_unit(root, self.user)

        self.assertIn("Type=simple", unit)
        self.assertIn("User=toolkit", unit)
        self.assertIn("Group=toolkit", unit)
        self.assertIn(f"WorkingDirectory={root}\n", unit)
        self.assertNotIn(f'WorkingDirectory="{root}"', unit)
        self.assertIn(f'ExecStart="{root / "twn"}" service-run', unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("KillMode=mixed", unit)
        self.assertIn("UMask=0077", unit)
        self.assertIn('Environment="HOME=/home/toolkit"', unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        self.assertNotIn("AmbientCapabilities=", unit)

    def test_systemd_network_capabilities_are_explicit_and_bounded(self) -> None:
        unit = render_systemd_unit(
            Path("/srv/twn-toolkit"),
            self.user,
            network_capabilities=True,
        )
        joined = " ".join(NETWORK_CAPABILITIES)

        self.assertIn(f"CapabilityBoundingSet={joined}", unit)
        self.assertIn(f"AmbientCapabilities={joined}", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertNotIn("CAP_SYS_ADMIN", unit)

    def test_launchd_job_starts_at_boot_as_the_installing_user(self) -> None:
        root = Path("/Users/toolkit/twn-toolkit")
        payload = plistlib.loads(render_launchd_plist(root, self.user))

        self.assertEqual(payload["Label"], LAUNCHD_LABEL)
        self.assertEqual(payload["ProgramArguments"], [str(root / "twn"), "service-run"])
        self.assertEqual(payload["UserName"], "toolkit")
        self.assertEqual(payload["GroupName"], "toolkit")
        self.assertTrue(payload["RunAtLoad"])
        self.assertEqual(payload["KeepAlive"], {"SuccessfulExit": False})
        self.assertEqual(payload["Umask"], 0o077)
        self.assertEqual(payload["EnvironmentVariables"]["HOME"], "/home/toolkit")
        self.assertEqual(
            payload["StandardErrorPath"],
            str(root / "instance" / "twn-service-error.log"),
        )

    @mock.patch("twn_toolkit.service_cli.grp.getgrgid")
    @mock.patch("twn_toolkit.service_cli.pwd.getpwnam")
    def test_root_service_requires_explicit_override(
        self,
        getpwnam: mock.Mock,
        getgrgid: mock.Mock,
    ) -> None:
        getpwnam.return_value = mock.Mock(pw_uid=0, pw_gid=0)
        getgrgid.return_value = mock.Mock(gr_name="wheel")

        with self.assertRaisesRegex(ServiceError, "Refusing to run"):
            service_user("root")
        getpwnam.return_value = mock.Mock(pw_uid=0, pw_gid=0, pw_dir="/var/root")
        self.assertEqual(service_user("root", allow_root=True).uid, 0)

    def test_install_rejects_linux_capability_flag_on_macos(self) -> None:
        with (
            mock.patch("twn_toolkit.service_cli._require_root"),
            mock.patch("twn_toolkit.service_cli._validate_installation"),
            self.assertRaisesRegex(ServiceError, "only for systemd-based Linux"),
        ):
            install_service(
                Path("/Users/toolkit/twn-toolkit"),
                self.user,
                system="Darwin",
                network_capabilities=True,
            )

    def test_macos_install_rejects_privacy_protected_user_folder(self) -> None:
        user = ServiceUser("toolkit", "staff", 501, 20, "/Users/toolkit")

        with self.assertRaisesRegex(ServiceError, "privacy controls"):
            _validate_macos_service_location(
                Path("/Users/toolkit/Documents/twn-toolkit"),
                user,
            )
        _validate_macos_service_location(Path("/Users/toolkit/twn-toolkit"), user)

    def test_macos_status_does_not_call_scheduled_job_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plist_path = Path(temporary) / "toolkit.plist"
            plist_path.touch()
            launchctl = subprocess.CompletedProcess(
                args=("launchctl", "print"),
                returncode=0,
                stdout="state = spawn scheduled\nlast exit code = 78: EX_CONFIG\n",
                stderr="",
            )
            with (
                mock.patch("twn_toolkit.service_cli.LAUNCHD_PLIST_PATH", plist_path),
                mock.patch("twn_toolkit.service_cli.subprocess.run", return_value=launchctl),
                mock.patch("builtins.print") as output,
            ):
                result = service_status(system="Darwin")

        self.assertEqual(result, 1)
        output.assert_any_call(
            "Autostart service: loaded but not running "
            "(state: spawn scheduled, last exit: 78: EX_CONFIG)"
        )

    def test_install_refuses_runtime_data_owned_by_another_account(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instance = root / "instance"
            instance.mkdir()
            other_user = ServiceUser(
                "other",
                "other",
                os.getuid() + 1,
                os.getgid() + 1,
                "/home/other",
            )

            with self.assertRaisesRegex(ServiceError, "Runtime data is not owned"):
                _ensure_instance_directory(root, other_user)

    def test_linux_uninstall_resets_state_before_removing_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unit_path = Path(temporary) / "twn-toolkit.service"
            unit_path.touch()
            with (
                mock.patch("twn_toolkit.service_cli._require_root"),
                mock.patch("twn_toolkit.service_cli.SYSTEMD_UNIT_PATH", unit_path),
                mock.patch("twn_toolkit.service_cli._run") as run,
            ):
                uninstall_service(system="Linux")

        self.assertFalse(unit_path.exists())
        self.assertEqual(
            run.call_args_list,
            [
                mock.call(
                    ("systemctl", "disable", "--now", "twn-toolkit.service"),
                    check=False,
                ),
                mock.call(
                    ("systemctl", "reset-failed", "twn-toolkit.service"),
                    check=False,
                ),
                mock.call(("systemctl", "daemon-reload")),
            ],
        )

    def test_service_identifiers_remain_stable(self) -> None:
        self.assertEqual(SYSTEMD_UNIT_NAME, "twn-toolkit.service")
        self.assertEqual(LAUNCHD_LABEL, "com.thewifininja.toolkit")


if __name__ == "__main__":
    unittest.main()
