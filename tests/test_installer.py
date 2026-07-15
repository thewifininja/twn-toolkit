from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InstallerLifecycleTests(unittest.TestCase):
    def _sandbox(self, *, running: bool) -> tuple[Path, dict[str, str]]:
        sandbox = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, sandbox)
        shutil.copy2(ROOT / "install.sh", sandbox / "install.sh")
        (sandbox / "requirements.txt").write_text("example==1\n", encoding="utf-8")
        (sandbox / ".venv" / "bin").mkdir(parents=True)
        fake_python = sandbox / ".venv" / "bin" / "python"
        fake_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_python.chmod(0o755)

        fake_bin = sandbox / "fake-bin"
        fake_bin.mkdir()
        python3 = fake_bin / "python3"
        python3.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        python3.chmod(0o755)

        toolkit_cli = sandbox / "twn"
        toolkit_cli.write_text(
            """#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
printf '%s\\n' "${1:-}" >> "$TWN_TEST_LOG"
case "${1:-}" in
  status)
    [ -f "$ROOT/running" ] || exit 1
    echo "Toolkit access URLs:"
    echo "  https://127.0.0.1:5050"
    ;;
  start|restart)
    touch "$ROOT/running"
    ;;
  enable-https)
    mkdir -p "$ROOT/instance/tls"
    touch "$ROOT/instance/tls/enabled"
    ;;
esac
""",
            encoding="utf-8",
        )
        toolkit_cli.chmod(0o755)
        if running:
            (sandbox / "running").touch()
            instance = sandbox / "instance"
            instance.mkdir()
            (instance / "saved-profile.json").write_text(
                '{"name": "preserve me"}\n', encoding="utf-8"
            )

        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
        environment["TWN_TEST_LOG"] = str(sandbox / "commands.log")
        return sandbox, environment

    def _run_installer(self, sandbox: Path, environment: dict[str, str]) -> list[str]:
        result = subprocess.run(
            ["./install.sh"],
            cwd=sandbox,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Installation complete.", result.stdout)
        return (sandbox / "commands.log").read_text(encoding="utf-8").splitlines()

    def test_fresh_install_enables_https_and_starts_services(self) -> None:
        sandbox, environment = self._sandbox(running=False)

        commands = self._run_installer(sandbox, environment)

        self.assertEqual(commands, ["status", "enable-https", "start", "status"])
        self.assertTrue((sandbox / "instance" / "installation.initialized").exists())

    def test_existing_running_install_restarts_and_preserves_instance_data(self) -> None:
        sandbox, environment = self._sandbox(running=True)

        commands = self._run_installer(sandbox, environment)

        self.assertEqual(commands, ["status", "restart", "status"])
        self.assertEqual(
            (sandbox / "instance" / "saved-profile.json").read_text(encoding="utf-8"),
            '{"name": "preserve me"}\n',
        )


if __name__ == "__main__":
    unittest.main()
