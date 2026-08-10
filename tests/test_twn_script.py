from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class TwnScriptTests(unittest.TestCase):
    def test_transfer_service_cleanup_and_restart_share_the_service_lock(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "twn").read_text(
            encoding="utf-8"
        )
        start_function = re.search(
            r"start_managed_worker\(\) \{(?P<body>.*?)\n\}", source, re.DOTALL
        )
        restart_function = re.search(
            r"restart_managed_worker\(\) \{(?P<body>.*?)\n\}", source, re.DOTALL
        )
        self.assertIsNotNone(start_function)
        self.assertIsNotNone(restart_function)
        start_body = start_function.group("body")
        restart_body = restart_function.group("body")
        self.assertLess(
            start_body.index("acquire_managed_worker_lock"),
            start_body.index("cleanup_managed_daemon"),
        )
        self.assertLess(
            start_body.index("cleanup_managed_daemon"),
            start_body.index("release_managed_worker_lock"),
        )
        self.assertLess(
            restart_body.index("acquire_managed_worker_lock"),
            restart_body.index("stop_managed_worker_unlocked"),
        )
        self.assertLess(
            restart_body.index("start_managed_worker_unlocked"),
            restart_body.index("release_managed_worker_lock"),
        )
        self.assertIn('--ready-file "$worker_readyfile"', source)

    def test_managed_iperf_workers_follow_toolkit_lifecycle(self) -> None:
        source = (
            Path(__file__).resolve().parents[1] / "twn"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "twn_toolkit.iperf_server:resume_iperf_server_workers",
            source,
        )
        self.assertIn(
            "twn_toolkit.iperf_server:stop_iperf_server_workers",
            source,
        )
        self.assertIn('IPERF_LOG="$INSTANCE/twn-iperf3.log"', source)

    def test_complete_start_records_generation_before_scheduler_starts(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "twn").read_text(
            encoding="utf-8"
        )
        start_function = re.search(
            r"^start\(\) \{(?P<body>.*?)^\}",
            source,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(start_function)
        body = start_function.group("body")
        marker = (
            '"$PYTHON" -m twn_toolkit.system_identity mark-start '
            '--instance "$INSTANCE"'
        )
        self.assertEqual(body.count(marker), 1)
        success_path = body.index('if is_running; then', body.index('attempts=0'))
        self.assertLess(body.index('printf "%s\\n" "$SCHEME"', success_path), body.index(marker))
        self.assertLess(body.index(marker), body.index("start_automation", success_path))
        self.assertIn('if [ "$SUPPRESS_TOOLKIT_START_EVENT" != "1" ]; then', body)

    def test_transfer_services_start_and_stop_concurrently(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "twn").read_text(
            encoding="utf-8"
        )
        start_function = re.search(
            r"start_transfer_services\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        stop_function = re.search(
            r"stop_transfer_services\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(start_function)
        self.assertIsNotNone(stop_function)
        start_body = start_function.group("body")
        stop_body = stop_function.group("body")
        for service in ("tftp", "ssh_transfer", "ftp"):
            self.assertIn(f"start_{service} &", start_body)
            self.assertIn(f"stop_{service} &", stop_body)
        self.assertIn('wait "$tftp_start_job"', start_body)
        self.assertIn('wait "$ssh_transfer_start_job"', start_body)
        self.assertIn('wait "$ftp_start_job"', start_body)
        self.assertIn('wait "$tftp_stop_job"', stop_body)
        self.assertIn('wait "$ssh_transfer_stop_job"', stop_body)
        self.assertIn('wait "$ftp_stop_job"', stop_body)

    def test_process_checks_reject_linux_zombies(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "twn").read_text(
            encoding="utf-8"
        )

        self.assertIn('[ -r "/proc/$1/stat" ]', source)
        self.assertIn(r"Z\ *|X\ *) return 1", source)

    def test_fix_permissions_repairs_all_runtime_locations(self) -> None:
        source = Path(__file__).resolve().parents[1] / "twn"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "toolkit"
            root.mkdir()
            script = root / "twn"
            script.write_bytes(source.read_bytes())
            script.chmod(0o755)
            (root / "instance").mkdir()
            (root / ".twn-upgrades" / "backups").mkdir(parents=True)
            (root / ".twn-release-manifest.json").write_text(
                "{}\n", encoding="utf-8",
            )

            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            fake_id = fake_bin / "id"
            fake_id.write_text(
                "#!/bin/sh\n"
                'case "$1" in\n'
                '  -u) echo 0 ;;\n'
                '  -un) echo root ;;\n'
                '  -gn) echo operators ;;\n'
                "esac\n",
                encoding="utf-8",
            )
            fake_id.chmod(0o755)
            fake_chown = fake_bin / "chown"
            fake_chown.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$*" >> "$TWN_TEST_CHOWN_LOG"\n',
                encoding="utf-8",
            )
            fake_chown.chmod(0o755)

            chown_log = Path(temporary) / "chown.log"
            environment = os.environ.copy()
            environment.update({
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "SUDO_USER": "nkarrick",
                "TWN_TEST_CHOWN_LOG": str(chown_log),
            })
            result = subprocess.run(
                [str(script), "fix-permissions"],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "Repaired toolkit runtime permissions for nkarrick:operators.",
                result.stdout,
            )
            self.assertEqual(chown_log.read_text(encoding="utf-8").splitlines(), [
                f"-R nkarrick:operators {root / 'instance'}",
                f"-R nkarrick:operators {root / '.twn-upgrades'}",
                f"nkarrick:operators {root / '.twn-release-manifest.json'}",
            ])

    def test_autostart_supervisor_preserves_manual_and_upgrade_lifecycle(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "twn").read_text(
            encoding="utf-8"
        )

        self.assertIn('SERVICE_LAUNCHER_PIDFILE="$INSTANCE/twn-service-launcher.pid"', source)
        self.assertIn('SERVICE_PAUSE_FILE="$INSTANCE/twn-service-paused"', source)
        self.assertIn('SERVICE_RESUME_FILE="$INSTANCE/twn-service-resume"', source)
        self.assertIn("request_service_start() {", source)
        self.assertIn("request_service_reload() {", source)
        self.assertIn("request_deferred_service_reload() {", source)
        self.assertIn("deferred_service_reload() {", source)
        self.assertIn("prepare_upgrade_service_reload() {", source)
        self.assertIn("arm_deferred_service_reload() {", source)
        self.assertIn("withhold_deferred_service_launcher() {", source)
        self.assertIn("upgrade_reload_should_be_deferred() {", source)
        self.assertIn(
            "SERVICE_RELOAD_REQUESTED=${TWN_TOOLKIT_RELOAD_SERVICE_LAUNCHER:-0}",
            source,
        )
        self.assertIn(
            "UPGRADE_REQUEST_ID=${TWN_TOOLKIT_UPGRADE_REQUEST_ID:-}",
            source,
        )
        self.assertIn(
            "SUPPRESS_TOOLKIT_START_EVENT=${TWN_TOOLKIT_SUPPRESS_START_EVENT:-0}",
            source,
        )
        self.assertIn('[ "$current_launcher_pid" != "$previous_launcher_pid" ]', source)
        self.assertIn("&& is_running && automation_is_running && supervisor_is_running", source)
        self.assertIn('[ "$SERVICE_RELOAD_REQUESTED" = "1" ]', source)
        self.assertIn(
            '&& [ -f "$SCHEME_FILE" ] && [ -f "$HOST_FILE" ] && [ -f "$PORT_FILE" ]',
            source,
        )
        self.assertIn("service_run_cleanup() {", source)
        self.assertIn("service_run() {", source)
        self.assertIn("trap service_run_cleanup EXIT", source)
        self.assertIn("if [ -f \"$SERVICE_PAUSE_FILE\" ]; then", source)
        self.assertIn("if [ -f \"$SERVICE_RESUME_FILE\" ]; then", source)
        self.assertIn("twn_toolkit.service_cli --root \"$ROOT\"", source)
        self.assertIn('install --validate-only "$@"', source)
        self.assertIn("service-run)", source)

        deferred = re.search(
            r"deferred_service_reload\(\) \{(?P<body>.*?)\n\}", source, re.DOTALL
        )
        request = re.search(
            r"request_deferred_service_reload\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        arm = re.search(
            r"arm_deferred_service_reload\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(deferred)
        self.assertIsNotNone(request)
        self.assertIsNotNone(arm)
        deferred_body = deferred.group("body")
        request_body = request.group("body")
        arm_body = arm.group("body")
        self.assertLess(
            deferred_body.index('while [ -f "$UPGRADE_OPERATION_LOCK" ]'),
            deferred_body.index('"$ROOT/twn" stop'),
        )
        self.assertLess(
            deferred_body.index('deferred_installed_version=$(installed_source_version'),
            deferred_body.index('"$ROOT/twn" stop'),
        )
        self.assertIn(
            'restore_deferred_service_launcher "$deferred_launcher_pid"',
            deferred_body,
        )
        self.assertLess(
            request_body.index("arm_deferred_service_reload"),
            request_body.index("TWN_TOOLKIT_SUPPRESS_START_EVENT=1"),
        )
        self.assertLess(
            arm_body.index("withhold_deferred_service_launcher"),
            arm_body.index("schedule_deferred_service_reload"),
        )
        self.assertIn("withhold_deferred_service_launcher", deferred_body)
        self.assertIn(
            'SERVICE_RELOAD_LOG="$UPGRADE_WORKSPACE/service-reload.log"', source
        )
        self.assertIn("prepare-upgrade-service-reload)", source)

    def test_macos_service_mode_keeps_workers_in_launchd_process_tree(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "twn").read_text(
            encoding="utf-8"
        )

        foreground = re.search(
            r"launchd_foreground_children\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        service_run = re.search(
            r"service_run\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(foreground)
        self.assertIsNotNone(service_run)
        self.assertIn('"$SERVICE_RUN_MODE" = "1"', foreground.group("body"))
        self.assertIn('= "Darwin"', foreground.group("body"))
        self.assertIn("TWN_TOOLKIT_SERVICE_RUN=1", service_run.group("body"))
        self.assertIn("export TWN_TOOLKIT_SERVICE_RUN", service_run.group("body"))

        for marker in (
            '"$PYTHON" -m "$worker_module"',
            '"$PYTHON" -m twn_toolkit.automation_worker',
            '"$PYTHON" -m twn_toolkit.supervisor_worker',
            'set -- "$@" --daemon',
        ):
            self.assertIn(marker, source)
        self.assertGreaterEqual(source.count("if launchd_foreground_children; then"), 4)

        transfer_start = re.search(
            r"start_transfer_services\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(transfer_start)
        transfer_body = transfer_start.group("body")
        self.assertLess(
            transfer_body.index("if launchd_foreground_children; then"),
            transfer_body.index("start_tftp &"),
        )
        self.assertIn("if start_tftp; then tftp_started=1; fi", transfer_body)
        self.assertIn(
            "if start_ssh_transfer; then ssh_transfer_started=1; fi",
            transfer_body,
        )
        self.assertIn("if start_ftp; then ftp_started=1; fi", transfer_body)

    def test_macos_direct_launchd_jobs_exec_each_network_process(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "twn").read_text(
            encoding="utf-8"
        )

        launchd_run = re.search(
            r"launchd_run\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        direct_coordinator = re.search(
            r"service_run_direct\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(launchd_run)
        self.assertIsNotNone(direct_coordinator)
        body = launchd_run.group("body")
        for role in (
            "web)",
            "automation)",
            "supervisor)",
            "tftp)",
            "ssh-transfer)",
            "ftp)",
        ):
            self.assertIn(role, body)
        self.assertIn('exec "$@"', body)
        self.assertGreaterEqual(body.count('exec "$PYTHON" -m'), 5)
        self.assertNotIn("--daemon", body)
        self.assertIn('SERVICE_LAUNCHD_MARKER="$INSTANCE/twn-launchd-direct-enabled"', source)
        self.assertIn('[ -f "$SERVICE_LAUNCHD_MARKER" ] || return 0', body)
        self.assertIn("TWN_TOOLKIT_LAUNCHD_DIRECT=0", source)
        self.assertIn('launchd-run)', source)
        self.assertIn('launchd_run "$@"', source)
        self.assertIn("sync_launchd_transfer_markers", direct_coordinator.group("body"))
        self.assertNotIn("start_automation", direct_coordinator.group("body"))
        self.assertNotIn("start_supervisor", direct_coordinator.group("body"))

    def test_stop_snapshots_web_pid_before_stopping_sibling_workers(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "twn").read_text(
            encoding="utf-8"
        )
        stop = re.search(
            r"^stop\(\) \{(?P<body>.*?)^\}",
            source,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(stop)
        body = stop.group("body")
        self.assertIn('web_pid=$(cat "$PIDFILE" 2>/dev/null || true)', body)
        self.assertLess(body.index("web_pid="), body.index("stop_supervisor"))
        self.assertNotIn('pid=$(cat "$PIDFILE")', body)


if __name__ == "__main__":
    unittest.main()
