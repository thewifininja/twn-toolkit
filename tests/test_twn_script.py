from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class TwnScriptTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
