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
    _launchd_details,
    _managed_toolkit_is_ready,
    _validate_macos_service_location,
    _wait_for_launchd_running,
    _wait_for_managed_toolkit,
    install_service,
    render_launchd_plist,
    render_systemd_unit,
    service_runtime_status,
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

    def test_macos_status_accepts_active_launchdaemon(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plist_path = Path(temporary) / "toolkit.plist"
            plist_path.touch()
            launchctl = subprocess.CompletedProcess(
                args=("launchctl", "print"),
                returncode=0,
                stdout="state = active\n",
                stderr="",
            )
            with (
                mock.patch("twn_toolkit.service_cli.LAUNCHD_PLIST_PATH", plist_path),
                mock.patch("twn_toolkit.service_cli.subprocess.run", return_value=launchctl),
                mock.patch("builtins.print") as output,
            ):
                result = service_status(system="Darwin")

        self.assertEqual(result, 0)
        output.assert_any_call("Autostart service: loaded, active")

    def test_bounded_launchd_status_reports_a_timeout(self) -> None:
        with mock.patch(
            "twn_toolkit.service_cli.subprocess.run",
            side_effect=subprocess.TimeoutExpired(("launchctl", "print"), 0.1),
        ):
            result, state, last_exit = _launchd_details(timeout_seconds=0.1)

        self.assertEqual(result.returncode, 124)
        self.assertEqual(state, "timed out")
        self.assertEqual(last_exit, "")

    def test_runtime_status_preserves_a_bounded_launchd_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "instance").mkdir()
            plist_path = root / "toolkit.plist"
            plist_path.touch()
            timed_out = subprocess.CompletedProcess((), 124, "", "")
            with (
                mock.patch("twn_toolkit.service_cli.LAUNCHD_PLIST_PATH", plist_path),
                mock.patch(
                    "twn_toolkit.service_cli.shutil.which",
                    return_value="/bin/launchctl",
                ),
                mock.patch(
                    "twn_toolkit.service_cli._launchd_details",
                    return_value=(timed_out, "timed out", ""),
                ) as details,
            ):
                status = service_runtime_status(
                    root,
                    system="Darwin",
                    manager_timeout_seconds=0.2,
                )

        self.assertEqual(status["manager_state"], "timed out")
        details.assert_called_once_with(timeout_seconds=0.2)

    def test_runtime_status_identifies_active_linux_boot_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instance = root / "instance"
            instance.mkdir()
            for name in (
                "twn-service-launcher.pid",
                "twn-toolkit.pid",
                "twn-automation.pid",
                "twn-supervisor.pid",
            ):
                (instance / name).write_text("42\n", encoding="utf-8")
            unit_path = root / "twn-toolkit.service"
            unit_path.write_text("[Service]\nUser=toolkit\nGroup=toolkit\n", encoding="utf-8")
            successful = subprocess.CompletedProcess(args=(), returncode=0)
            with (
                mock.patch("twn_toolkit.service_cli.SYSTEMD_UNIT_PATH", unit_path),
                mock.patch("twn_toolkit.service_cli.shutil.which", return_value="/bin/systemctl"),
                mock.patch("twn_toolkit.service_cli._run_quiet", return_value=successful),
                mock.patch("twn_toolkit.service_cli.os.kill"),
            ):
                status = service_runtime_status(root, system="Linux")

        self.assertEqual(status["mode"], "Boot-managed service")
        self.assertEqual(status["state"], "Active")
        self.assertTrue(status["healthy"])
        self.assertEqual(status["service_user"], "toolkit")

    def test_runtime_status_distinguishes_manual_process_from_installed_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instance = root / "instance"
            instance.mkdir()
            for name in ("twn-toolkit.pid", "twn-automation.pid", "twn-supervisor.pid"):
                (instance / name).write_text("42\n", encoding="utf-8")
            missing_unit = root / "missing.service"
            with (
                mock.patch("twn_toolkit.service_cli.SYSTEMD_UNIT_PATH", missing_unit),
                mock.patch("twn_toolkit.service_cli.os.kill"),
            ):
                status = service_runtime_status(root, system="Linux")

        self.assertEqual(status["mode"], "Manual process")
        self.assertEqual(status["state"], "Running")
        self.assertFalse(status["installed"])

    def test_macos_install_wait_accepts_active_launchdaemon(self) -> None:
        launchctl = subprocess.CompletedProcess(
            args=("launchctl", "print"),
            returncode=0,
            stdout="",
            stderr="",
        )
        with mock.patch(
            "twn_toolkit.service_cli._launchd_details",
            return_value=(launchctl, "active", ""),
        ):
            running, state, last_exit = _wait_for_launchd_running(timeout=0.1)

        self.assertTrue(running)
        self.assertEqual(state, "active")
        self.assertEqual(last_exit, "")

    def test_managed_toolkit_readiness_requires_all_processes_and_endpoint_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instance = root / "instance"
            instance.mkdir()
            for name in (
                "twn-service-launcher.pid",
                "twn-toolkit.pid",
                "twn-automation.pid",
                "twn-supervisor.pid",
            ):
                (instance / name).write_text("42\n", encoding="utf-8")
            for name in (
                "twn-toolkit.scheme",
                "twn-toolkit.host",
                "twn-toolkit.port",
            ):
                (instance / name).touch()

            with mock.patch("twn_toolkit.service_cli.os.kill"):
                self.assertTrue(_managed_toolkit_is_ready(root))
                (instance / "twn-supervisor.pid").unlink()
                self.assertFalse(_managed_toolkit_is_ready(root))

    def test_managed_toolkit_waits_until_process_set_is_ready(self) -> None:
        with mock.patch(
            "twn_toolkit.service_cli._managed_toolkit_is_ready",
            side_effect=(False, True),
        ) as ready:
            with mock.patch("twn_toolkit.service_cli.time.sleep"):
                self.assertTrue(_wait_for_managed_toolkit(Path("/srv/twn"), timeout=1))

        self.assertEqual(ready.call_count, 2)

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
