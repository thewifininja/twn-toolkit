from __future__ import annotations

import signal
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from twn_toolkit import recovery


class RecoveryProcessTests(unittest.TestCase):
    def test_ss_parser_collects_all_unique_listener_pids(self) -> None:
        output = (
            'LISTEN users:(("gunicorn",pid=401,fd=5),'
            '("gunicorn",pid=400,fd=5))\n'
            'LISTEN users:(("gunicorn",pid=401,fd=6))'
        )

        self.assertEqual(recovery.parse_ss_listener_pids(output), [400, 401])

    def test_pid_line_parser_ignores_non_pid_output(self) -> None:
        self.assertEqual(
            recovery.parse_pid_lines("5050/tcp:  501 502\nwarning"),
            [501, 502],
        )

    def test_linux_socket_table_parser_selects_listening_port(self) -> None:
        output = "\n".join([
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm retr uid timeout inode",
            "   0: 00000000:13BA 00000000:0000 0A 0:0 00:0 0 1000 0 12001",
            "   1: 00000000:13BA 00000000:0000 01 0:0 00:0 0 1000 0 12002",
            "   2: 00000000:0016 00000000:0000 0A 0:0 00:0 0 1000 0 12003",
        ])

        self.assertEqual(
            recovery.parse_linux_listener_inodes(output, 5050),
            {"12001"},
        )

    @mock.patch("twn_toolkit.recovery._run")
    def test_linux_listener_discovery_prefers_ss(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess(
            [], 0, 'LISTEN users:(("gunicorn",pid=601,fd=5))\n', "",
        )

        self.assertEqual(
            recovery.listener_pids(5050, system="Linux"),
            [601],
        )
        run.assert_called_once_with([
            "ss", "-H", "-ltnp", "sport = :5050",
        ])

    @mock.patch("twn_toolkit.recovery._run")
    def test_macos_listener_discovery_uses_lsof(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, "701\n702\n", "")

        self.assertEqual(
            recovery.listener_pids(5050, system="Darwin"),
            [701, 702],
        )
        run.assert_called_once_with([
            "lsof", "-nP", "-t", "-iTCP:5050", "-sTCP:LISTEN",
        ])

    def test_process_table_matching_is_scoped_to_installation(self) -> None:
        gunicorn = Path("/srv/twn/.venv/bin/gunicorn")
        output = "\n".join([
            "801 /srv/twn/.venv/bin/gunicorn twn_toolkit:create_app()",
            "802 /srv/other/.venv/bin/gunicorn twn_toolkit:create_app()",
            "803 /srv/twn/.venv/bin/gunicorn other:create_app()",
        ])

        self.assertEqual(
            recovery.matching_process_table_pids(output, gunicorn),
            [801],
        )

    @mock.patch("twn_toolkit.recovery._process_cwd")
    @mock.patch("twn_toolkit.recovery._process_command")
    def test_changed_gunicorn_title_is_verified_by_cwd(
        self, command: mock.Mock, cwd: mock.Mock,
    ) -> None:
        command.return_value = "gunicorn: master [twn_toolkit:create_app()]"
        cwd.return_value = Path("/srv/twn")

        self.assertTrue(recovery.is_toolkit_server_process(
            901,
            Path("/srv/twn"),
            Path("/srv/twn/.venv/bin/gunicorn"),
            system="Linux",
        ))
        self.assertFalse(recovery.is_toolkit_server_process(
            901,
            Path("/srv/other"),
            Path("/srv/other/.venv/bin/gunicorn"),
            system="Linux",
        ))

    @mock.patch("twn_toolkit.recovery._process_table_pids", return_value=[])
    @mock.patch("twn_toolkit.recovery.is_toolkit_server_process")
    @mock.patch("twn_toolkit.recovery.listener_pids", return_value=[951])
    def test_unrelated_listener_is_not_selected_for_recovery(
        self,
        _listeners: mock.Mock,
        is_toolkit: mock.Mock,
        _processes: mock.Mock,
    ) -> None:
        is_toolkit.return_value = False

        self.assertEqual(recovery.toolkit_server_pids(
            5050,
            Path("/srv/twn"),
            Path("/srv/twn/.venv/bin/gunicorn"),
            system="Linux",
        ), [])

    @mock.patch(
        "twn_toolkit.recovery.is_toolkit_server_process",
        side_effect=lambda pid, *_args, **_kwargs: pid == 952,
    )
    @mock.patch(
        "twn_toolkit.recovery.listener_pids",
        return_value=[951, 952],
    )
    def test_listener_matching_rejects_unrelated_port_owner(
        self,
        _listeners: mock.Mock,
        _is_toolkit: mock.Mock,
    ) -> None:
        self.assertEqual(recovery.toolkit_listener_pids(
            5050,
            Path("/srv/twn"),
            Path("/srv/twn/.venv/bin/gunicorn"),
            system="Linux",
        ), [952])

    @mock.patch("twn_toolkit.recovery._pid_exists")
    @mock.patch("twn_toolkit.recovery.os.kill")
    @mock.patch("twn_toolkit.recovery.toolkit_server_pids")
    def test_stop_only_signals_verified_toolkit_servers(
        self,
        server_pids: mock.Mock,
        kill: mock.Mock,
        pid_exists: mock.Mock,
    ) -> None:
        server_pids.return_value = [1001, 1002]
        pid_exists.side_effect = [False, False]

        matched, remaining = recovery.stop_toolkit_servers(
            5050,
            Path("/srv/twn"),
            Path("/srv/twn/.venv/bin/gunicorn"),
            system="Linux",
        )

        self.assertEqual(matched, [1001, 1002])
        self.assertEqual(remaining, [])
        self.assertEqual(kill.call_args_list, [
            mock.call(1001, signal.SIGTERM),
            mock.call(1002, signal.SIGTERM),
        ])


if __name__ == "__main__":
    unittest.main()
