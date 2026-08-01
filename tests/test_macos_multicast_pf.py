from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from twn_toolkit.macos_multicast_pf import (
    PF_BEGIN_MARKER,
    PF_END_MARKER,
    MulticastPfError,
    install_multicast_pf,
    multicast_pf_status,
    parse_anchor_interfaces,
    render_anchor_rule,
    uninstall_multicast_pf,
)


BASE_PF_CONF = """# test PF configuration
scrub-anchor "com.apple/*"
# ----- FortiClient anchor (GEN BY FORTICLIENT DONT EDIT) -----
anchor "com.fortinet.forticlient00"
# ----- End FortiClient anchor (GEN BY FORTICLIENT DONT EDIT) -----
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
"""


class MacosMulticastPfTests(unittest.TestCase):
    def _paths(self) -> tuple[Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        anchors = root / "pf.anchors"
        anchors.mkdir()
        pf_conf = root / "pf.conf"
        pf_conf.write_text(BASE_PF_CONF, encoding="utf-8")
        pf_conf.chmod(0o644)
        return pf_conf, anchors / "twn_toolkit"

    def test_status_is_not_applicable_off_macos(self) -> None:
        status = multicast_pf_status(["eth0"], system="Linux")

        self.assertEqual(status["state"], "not_applicable")
        self.assertTrue(status["ready"])
        self.assertFalse(status["applicable"])

    def test_status_reports_missing_config_and_generated_command(self) -> None:
        pf_conf, anchor = self._paths()

        status = multicast_pf_status(
            ["en0", "en6"],
            system="Darwin",
            pf_conf_path=pf_conf,
            anchor_path=anchor,
            boot_time=time.time() + 60,
        )

        self.assertEqual(status["state"], "missing")
        self.assertTrue(status["attention"])
        self.assertEqual(
            status["install_command"],
            "sudo ./twn multicast-pf install --interfaces en0 en6",
        )

    def test_install_is_scoped_idempotent_and_uninstallable(self) -> None:
        pf_conf, anchor = self._paths()
        validator_calls: list[tuple[str, str]] = []

        def validate(config_path: Path, anchor_path: Path) -> None:
            validator_calls.append(
                (
                    config_path.read_text(encoding="utf-8"),
                    anchor_path.read_text(encoding="utf-8"),
                )
            )

        installed = install_multicast_pf(
            ["en6", "en0", "en0"],
            system="Darwin",
            pf_conf_path=pf_conf,
            anchor_path=anchor,
            effective_uid=0,
            validator=validate,
        )

        self.assertTrue(installed["changed"])
        self.assertEqual(installed["interfaces"], ["en0", "en6"])
        configured = pf_conf.read_text(encoding="utf-8")
        self.assertEqual(configured.count(PF_BEGIN_MARKER), 1)
        self.assertEqual(configured.count(PF_END_MARKER), 1)
        self.assertLess(
            configured.index(PF_BEGIN_MARKER),
            configured.index('\nanchor "com.apple/*"'),
        )
        self.assertIn('scrub-anchor "com.apple/*"', configured)
        self.assertEqual(parse_anchor_interfaces(anchor.read_text()), ["en0", "en6"])
        self.assertEqual(anchor.stat().st_mode & 0o777, 0o644)
        self.assertTrue(Path(str(installed["backup"])).exists())
        self.assertEqual(len(validator_calls), 1)

        repeated = install_multicast_pf(
            ["en0", "en6"],
            system="Darwin",
            pf_conf_path=pf_conf,
            anchor_path=anchor,
            effective_uid=0,
            validator=validate,
        )
        self.assertFalse(repeated["changed"])
        self.assertEqual(len(validator_calls), 1)

        removed = uninstall_multicast_pf(
            system="Darwin",
            pf_conf_path=pf_conf,
            anchor_path=anchor,
            effective_uid=0,
            validator=validate,
        )
        self.assertTrue(removed["changed"])
        self.assertEqual(pf_conf.read_text(encoding="utf-8"), BASE_PF_CONF)
        self.assertFalse(anchor.exists())
        self.assertEqual(len(validator_calls), 2)

    def test_status_detects_restart_missing_interfaces_and_active_rule(self) -> None:
        pf_conf, anchor = self._paths()
        install_multicast_pf(
            ["en0"],
            system="Darwin",
            pf_conf_path=pf_conf,
            anchor_path=anchor,
            effective_uid=0,
            validator=lambda _config, _anchor: None,
        )

        missing = multicast_pf_status(
            ["en0", "en6"],
            system="Darwin",
            pf_conf_path=pf_conf,
            anchor_path=anchor,
            boot_time=time.time() + 60,
        )
        self.assertEqual(missing["state"], "interfaces_missing")
        self.assertEqual(missing["missing_interfaces"], ["en6"])

        install_multicast_pf(
            ["en0", "en6"],
            system="Darwin",
            pf_conf_path=pf_conf,
            anchor_path=anchor,
            effective_uid=0,
            validator=lambda _config, _anchor: None,
        )
        restart = multicast_pf_status(
            ["en0", "en6"],
            system="Darwin",
            pf_conf_path=pf_conf,
            anchor_path=anchor,
            boot_time=0,
        )
        self.assertEqual(restart["state"], "restart_required")

        active_rule = render_anchor_rule(["en0", "en6"])

        def runner(*_args, **_kwargs):
            return subprocess.CompletedProcess([], 0, stdout=active_rule, stderr="")

        active = multicast_pf_status(
            ["en0", "en6"],
            system="Darwin",
            pf_conf_path=pf_conf,
            anchor_path=anchor,
            boot_time=time.time() + 60,
            check_active=True,
            effective_uid=0,
            runner=runner,
        )
        self.assertEqual(active["state"], "configured")
        self.assertTrue(active["active"])

    def test_refuses_foreign_or_malformed_configuration(self) -> None:
        pf_conf, anchor = self._paths()
        anchor.write_text("pass all\n", encoding="utf-8")
        with self.assertRaises(MulticastPfError):
            install_multicast_pf(
                ["en0"],
                system="Darwin",
                pf_conf_path=pf_conf,
                anchor_path=anchor,
                effective_uid=0,
                validator=lambda _config, _anchor: None,
            )

        anchor.unlink()
        pf_conf.write_text(BASE_PF_CONF + PF_BEGIN_MARKER + "\n", encoding="utf-8")
        with self.assertRaises(MulticastPfError):
            uninstall_multicast_pf(
                system="Darwin",
                pf_conf_path=pf_conf,
                anchor_path=anchor,
                effective_uid=0,
                validator=lambda _config, _anchor: None,
            )

    def test_requires_darwin_root_and_valid_interface_names(self) -> None:
        pf_conf, anchor = self._paths()
        for kwargs in (
            {"system": "Linux", "effective_uid": 0},
            {"system": "Darwin", "effective_uid": os.getuid() or 501},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(MulticastPfError):
                install_multicast_pf(
                    ["en0"],
                    pf_conf_path=pf_conf,
                    anchor_path=anchor,
                    validator=lambda _config, _anchor: None,
                    **kwargs,
                )
        with self.assertRaises(ValueError):
            render_anchor_rule(["en0; block all"])


if __name__ == "__main__":
    unittest.main()
