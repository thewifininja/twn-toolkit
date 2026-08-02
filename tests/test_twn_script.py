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


if __name__ == "__main__":
    unittest.main()
