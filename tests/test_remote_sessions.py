from __future__ import annotations

import tempfile
import time
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import patch

from twn_toolkit.app import create_app
from twn_toolkit.datastore import LocalDatastore
from twn_toolkit.investigations import InvestigationStore
from twn_toolkit.remote_sessions import (
    REMOTE_SESSION_INPUT_LIMIT_BYTES,
    REMOTE_SESSION_LIMIT_PER_USER,
    RemoteSessionError,
    RemoteSessionManager,
    RemoteSessionStore,
    sanitize_terminal_text,
)


class FakeChannel:
    def __init__(self, output: bytes = b"switch# \x1b[32mready\x1b[0m\r\n") -> None:
        self.output = deque([output])
        self.sent: list[bytes] = []
        self.closed = False
        self.size = (0, 0)

    def settimeout(self, _timeout: float) -> None:
        return None

    def recv_ready(self) -> bool:
        return bool(self.output)

    def recv(self, _size: int) -> bytes:
        return self.output.popleft() if self.output else b""

    def exit_status_ready(self) -> bool:
        return self.closed

    def sendall(self, data: bytes) -> None:
        if self.closed:
            raise OSError("channel closed")
        self.sent.append(data)

    def resize_pty(self, *, width: int, height: int) -> None:
        self.size = (width, height)

    def close(self) -> None:
        self.closed = True


class FakeClient:
    def __init__(self, channel: FakeChannel) -> None:
        self.channel = channel
        self.closed = False

    def invoke_shell(self, **_options: object) -> FakeChannel:
        return self.channel

    def close(self) -> None:
        self.closed = True
        self.channel.close()


class FakeSshOpener:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.clients: list[FakeClient] = []

    def __call__(self, **options: object) -> FakeClient:
        self.calls.append(options)
        client = FakeClient(FakeChannel())
        self.clients.append(client)
        return client


class FakeTelnetOpener:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.channels: list[FakeChannel] = []

    def __call__(self, **options: object) -> FakeChannel:
        self.calls.append(options)
        channel = FakeChannel(b"Username: admin\r\nswitch# ready\r\n")
        self.channels.append(channel)
        return channel


class FakeSerialOpener:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.channels: list[FakeChannel] = []

    def __call__(self, **options: object) -> FakeChannel:
        self.calls.append(options)
        channel = FakeChannel(b"switch console ready\r\n")
        self.channels.append(channel)
        return channel


def wait_for_state(
    store: RemoteSessionStore, session_id: str, state: str, timeout: float = 2
) -> dict[str, object]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        session = store.get_session(session_id)
        if session and session["state"] == state:
            return session
        time.sleep(0.01)
    raise AssertionError(f"Session {session_id} did not reach {state}.")


def wait_for_output(
    store: RemoteSessionStore, session_id: str, timeout: float = 2
) -> dict[str, object]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        session = store.get_session(session_id)
        if session and int(session["output_bytes"]) > 0:
            return session
        time.sleep(0.01)
    raise AssertionError(f"Session {session_id} did not retain output.")


class RemoteSessionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = RemoteSessionStore(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_store_owns_sessions_and_pages_reconnect_scrollback(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Core switch",
            host="192.0.2.10",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )
        self.store.mark_connected(str(session["id"]))
        self.store.append_output(str(session["id"]), "first\n")
        self.store.append_output(str(session["id"]), "second\n")

        self.assertIsNone(
            self.store.output_page(
                str(session["id"]), user_id="different-user", after_id=0
            )
        )
        first = self.store.output_page(
            str(session["id"]), user_id="user-one", after_id=0
        )
        self.assertEqual(
            [chunk["output"] for chunk in first["chunks"]],
            ["first\n", "second\n"],
        )
        second = self.store.output_page(
            str(session["id"]),
            user_id="user-one",
            after_id=first["next_cursor"],
        )
        self.assertEqual(second["chunks"], [])

    def test_session_geometry_is_durable_and_defaults_to_wide_terminal(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Core switch",
            host="192.0.2.10",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )

        self.assertEqual(session["terminal_columns"], 120)
        self.assertEqual(session["terminal_rows"], 32)
        resized = self.store.update_terminal_geometry(
            str(session["id"]),
            user_id="user-one",
            columns=160,
            rows=40,
        )
        self.assertEqual(resized["terminal_columns"], 160)
        self.assertEqual(resized["terminal_rows"], 40)
        reopened = RemoteSessionStore(self.directory.name).get_session(
            str(session["id"]), user_id="user-one"
        )
        self.assertEqual(reopened["terminal_columns"], 160)
        self.assertEqual(reopened["terminal_rows"], 40)

    def test_existing_transcript_rows_migrate_once_into_live_delivery(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Existing shell",
            host="192.0.2.10",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )
        session_id = str(session["id"])
        self.store.append_output(session_id, "legacy output\n")
        with self.store._connect() as connection:
            connection.execute("DELETE FROM remote_session_live_output")
            connection.execute(
                "DELETE FROM remote_session_store_metadata WHERE key = 'live_output_v1'"
            )
            connection.execute(
                """
                UPDATE remote_sessions
                SET live_output_bytes = 0, live_output_floor_cursor = 0
                """
            )

        migrated = RemoteSessionStore(self.directory.name)
        page = migrated.output_page(session_id, user_id="user-one")
        self.assertEqual(
            [chunk["output"] for chunk in page["chunks"]], ["legacy output\n"]
        )
        reopened = RemoteSessionStore(self.directory.name)
        second_page = reopened.output_page(session_id, user_id="user-one")
        self.assertEqual(len(second_page["chunks"]), 1)

    def test_checkpoint_bootstrap_restores_state_then_returns_only_new_output(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Core switch",
            host="192.0.2.10",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )
        session_id = str(session["id"])
        self.store.append_output(session_id, "first\n")
        first = self.store.output_page(session_id, user_id="user-one")
        checkpoint_cursor = int(first["next_cursor"])
        snapshot = {
            "version": 1,
            "columns": 80,
            "rows": 24,
            "history": [],
            "screen": [[["first", ""]]],
        }

        self.assertTrue(
            self.store.save_checkpoint(
                session_id,
                user_id="user-one",
                output_cursor=checkpoint_cursor,
                snapshot=snapshot,
            )
        )
        self.assertFalse(
            self.store.save_checkpoint(
                session_id,
                user_id="user-one",
                output_cursor=checkpoint_cursor,
                snapshot=snapshot,
            )
        )
        self.store.append_output(session_id, "second\n")

        bootstrap = self.store.output_page(
            session_id,
            user_id="user-one",
            include_checkpoint=True,
        )
        self.assertEqual(bootstrap["checkpoint"]["cursor"], checkpoint_cursor)
        self.assertEqual(bootstrap["checkpoint"]["snapshot"], snapshot)
        self.assertEqual(
            [chunk["output"] for chunk in bootstrap["chunks"]], ["second\n"]
        )
        complete = self.store.output_page(session_id, user_id="user-one")
        self.assertIsNone(complete["checkpoint"])
        self.assertEqual(
            [chunk["output"] for chunk in complete["chunks"]],
            ["first\n", "second\n"],
        )

    def test_checkpoint_is_owner_scoped_and_requires_a_real_output_cursor(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Core switch",
            host="192.0.2.10",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )
        session_id = str(session["id"])
        snapshot = {
            "version": 1,
            "columns": 80,
            "rows": 24,
            "history": [],
            "screen": [[]],
        }
        self.assertFalse(
            self.store.save_checkpoint(
                session_id,
                user_id="different-user",
                output_cursor=1,
                snapshot=snapshot,
            )
        )
        with self.assertRaisesRegex(RemoteSessionError, "cursor is invalid"):
            self.store.save_checkpoint(
                session_id,
                user_id="user-one",
                output_cursor=0,
                snapshot=snapshot,
            )
        with self.assertRaisesRegex(RemoteSessionError, "cursor is unavailable"):
            self.store.save_checkpoint(
                session_id,
                user_id="user-one",
                output_cursor=999,
                snapshot=snapshot,
            )

    def test_output_page_reports_when_more_chunks_are_ready(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Core switch",
            host="192.0.2.10",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )
        session_id = str(session["id"])
        self.store.append_output(session_id, "one")
        self.store.append_output(session_id, "two")
        with patch("twn_toolkit.remote_sessions.REMOTE_SESSION_OUTPUT_PAGE_LIMIT", 1):
            first = self.store.output_page(session_id, user_id="user-one")
        self.assertEqual([chunk["output"] for chunk in first["chunks"]], ["one"])
        self.assertTrue(first["has_more"])

    def test_live_delivery_rolls_without_truncating_retained_transcript(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Long running shell",
            host="192.0.2.10",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )
        session_id = str(session["id"])
        with patch(
            "twn_toolkit.remote_sessions.REMOTE_SESSION_LIVE_OUTPUT_LIMIT_BYTES", 5
        ):
            self.store.append_output(session_id, "one")
            self.store.append_output(session_id, "two")

        page = self.store.output_page(session_id, user_id="user-one")
        self.assertTrue(page["history_gap"])
        self.assertEqual([chunk["output"] for chunk in page["chunks"]], ["two"])
        self.assertEqual(self.store.transcript(session_id), "onetwo")
        reopened = RemoteSessionStore(self.directory.name)
        restarted_page = reopened.output_page(session_id, user_id="user-one")
        self.assertTrue(restarted_page["history_gap"])
        self.assertEqual(
            [chunk["output"] for chunk in restarted_page["chunks"]], ["two"]
        )

    def test_retained_transcript_limit_never_stops_live_delivery(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Very noisy shell",
            host="192.0.2.10",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )
        session_id = str(session["id"])
        with patch("twn_toolkit.remote_sessions.REMOTE_SESSION_OUTPUT_LIMIT_BYTES", 4):
            self.store.append_output(session_id, "abcdef")
            self.store.append_output(session_id, "XYZ")

        retained = self.store.get_session(session_id, user_id="user-one")
        page = self.store.output_page(session_id, user_id="user-one")
        self.assertEqual(self.store.transcript(session_id), "abcd")
        self.assertTrue(retained["output_truncated"])
        self.assertEqual(
            [chunk["output"] for chunk in page["chunks"]],
            ["abcdef", "XYZ"],
        )

    def test_new_manager_marks_orphaned_shell_interrupted(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Orphan",
            host="switch.example",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )
        self.store.mark_connected(str(session["id"]))
        RemoteSessionManager(
            self.store,
            InvestigationStore(self.directory.name),
            ssh_opener=FakeSshOpener(),
        )
        interrupted = self.store.get_session(str(session["id"]))
        self.assertEqual(interrupted["state"], "interrupted")
        self.assertEqual(interrupted["termination"], "toolkit_restart")

    def test_terminal_text_removes_ansi_without_losing_lines(self) -> None:
        self.assertEqual(
            sanitize_terminal_text("one\r\n\x1b[31mtwo\x1b[0m\x00\n"),
            "one\ntwo\n",
        )
        self.assertEqual(
            sanitize_terminal_text("switch# typo\b \b\r\nspeed 10%\rspeed 100%\r\n"),
            "switch# typ\nspeed 100%\n",
        )

    def test_completed_scrollback_can_be_deleted_but_active_session_cannot(self) -> None:
        session = self.store.create_session(
            user_id="user-one",
            username="operator",
            title="Disposable shell",
            host="192.0.2.20",
            port=22,
            remote_username="admin",
            record_transcript=False,
        )
        session_id = str(session["id"])
        self.store.append_output(session_id, "retained output\n")
        with self.assertRaises(RemoteSessionError):
            self.store.delete_session(session_id, user_id="user-one")

        self.store.finish(session_id, state="stopped", termination="operator")
        deleted = self.store.delete_session(session_id, user_id="user-one")

        self.assertEqual(deleted["id"], session_id)
        self.assertIsNone(self.store.get_session(session_id))
        self.assertIsNone(
            self.store.output_page(session_id, user_id="user-one", after_id=0)
        )

    def test_operator_can_keep_twelve_concurrent_sessions(self) -> None:
        self.assertEqual(REMOTE_SESSION_LIMIT_PER_USER, 12)
        for index in range(REMOTE_SESSION_LIMIT_PER_USER):
            self.store.create_session(
                user_id="user-one",
                username="operator",
                title=f"Shell {index + 1}",
                host="192.0.2.30",
                port=22,
                remote_username="admin",
                record_transcript=False,
            )

        with self.assertRaisesRegex(RemoteSessionError, "up to 12"):
            self.store.create_session(
                user_id="user-one",
                username="operator",
                title="One too many",
                host="192.0.2.30",
                port=22,
                remote_username="admin",
                record_transcript=False,
            )

    def test_console_device_is_exclusive_across_operators(self) -> None:
        first = self.store.create_session(
            protocol="console",
            user_id="user-one",
            username="operator-one",
            title="Switch console",
            host="/dev/cu.usbserial-1",
            port=0,
            remote_username="",
            record_transcript=False,
            console_device_id="console_123",
            console_device_path="/dev/cu.usbserial-1",
            console_device_label="USB Serial",
        )
        with self.assertRaisesRegex(RemoteSessionError, "already in use"):
            self.store.create_session(
                protocol="console",
                user_id="user-two",
                username="operator-two",
                title="Same console",
                host="/dev/cu.usbserial-1",
                port=0,
                remote_username="",
                record_transcript=False,
                console_device_id="console_123",
                console_device_path="/dev/cu.usbserial-1",
                console_device_label="USB Serial",
            )
        self.store.finish(str(first["id"]), state="stopped", termination="operator")

class RemoteSessionRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.app = create_app(self.directory.name)
        self.app.testing = True
        self.opener = FakeSshOpener()
        self.telnet_opener = FakeTelnetOpener()
        self.serial_opener = FakeSerialOpener()
        self.manager = RemoteSessionManager(
            RemoteSessionStore(self.directory.name),
            self.app.extensions["investigation_store"],
            ssh_opener=self.opener,
            telnet_opener=self.telnet_opener,
            serial_opener=self.serial_opener,
        )
        self.app.extensions["remote_session_manager"] = self.manager
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        for session in self.manager.store.sessions_for_user("test-user"):
            self.manager.stop_session(str(session["id"]), user_id="test-user")
        self.manager.close()
        self.directory.cleanup()

    def start_session(self, **overrides: object):
        payload = {
            "title": "Distribution switch",
            "host": "192.0.2.25",
            "port": 22,
            "username": "network-admin",
            "password": "do-not-persist-this-password",
            "allow_unknown_hosts": True,
            "record_transcript": False,
        }
        payload.update(overrides)
        return self.client.post("/tools/remote-terminal/sessions", json=payload)

    def test_start_reconnect_input_resize_and_stop(self) -> None:
        response = self.start_session()
        self.assertEqual(response.status_code, 201)
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")

        output = self.client.get(session["output_url"])
        self.assertEqual(output.status_code, 200)
        self.assertIn("ready", output.get_json()["chunks"][0]["output"])
        sent = self.client.post(session["input_url"], json={"data": "show clock\r"})
        self.assertEqual(sent.status_code, 200)
        self.assertEqual(self.opener.clients[0].channel.sent, [b"show clock\r"])
        resized = self.client.post(
            session["resize_url"], json={"columns": 100, "rows": 40}
        )
        self.assertEqual(resized.status_code, 200)
        self.assertEqual(self.opener.clients[0].channel.size, (100, 40))
        stored = self.manager.store.get_session(session["id"], user_id="test-user")
        self.assertEqual(stored["terminal_columns"], 100)
        self.assertEqual(stored["terminal_rows"], 40)

        stopped = self.client.post(session["stop_url"])
        self.assertEqual(stopped.status_code, 200)
        self.assertEqual(stopped.get_json()["session"]["state"], "stopped")

    def test_reconnect_endpoint_uses_owner_checkpoint_and_output_delta(self) -> None:
        response = self.start_session()
        self.assertEqual(response.status_code, 201)
        session = response.get_json()["session"]
        wait_for_output(self.manager.store, session["id"])
        initial = self.client.get(session["output_url"]).get_json()
        checkpoint_cursor = int(initial["next_cursor"])
        snapshot = {
            "version": 1,
            "columns": 120,
            "rows": 32,
            "history": [],
            "screen": [[["switch# ready", "terminal-fg-2"]]],
        }

        saved = self.client.post(
            session["checkpoint_url"],
            json={"cursor": checkpoint_cursor, "snapshot": snapshot},
        )
        self.assertEqual(saved.status_code, 200)
        self.assertTrue(saved.get_json()["saved"])
        self.manager.store.append_output(session["id"], "show system status\r\n")

        bootstrap = self.client.get(
            f'{session["output_url"]}?after=0&bootstrap=1'
        )
        self.assertEqual(bootstrap.status_code, 200)
        payload = bootstrap.get_json()
        self.assertEqual(payload["checkpoint"]["cursor"], checkpoint_cursor)
        self.assertEqual(payload["checkpoint"]["snapshot"], snapshot)
        self.assertEqual(
            [chunk["output"] for chunk in payload["chunks"]],
            ["show system status\r\n"],
        )

        rejected = self.client.post(
            session["checkpoint_url"],
            json={"cursor": checkpoint_cursor, "snapshot": {"version": 99}},
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("not supported", rejected.get_json()["error"])

    def test_telnet_uses_the_same_persistent_terminal_lifecycle(self) -> None:
        response = self.start_session(
            protocol="telnet",
            port=23,
            allow_unknown_hosts=True,
            allow_legacy_algorithms=True,
        )
        self.assertEqual(response.status_code, 201)
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")

        self.assertEqual(session["protocol"], "telnet")
        self.assertFalse(session["allow_unknown_hosts"])
        self.assertFalse(session["allow_legacy_algorithms"])
        self.assertTrue(session["telnet_username_available"])
        self.assertTrue(session["telnet_password_available"])
        self.assertEqual(
            self.telnet_opener.calls[-1],
            {
                "hostname": "192.0.2.25",
                "port": 23,
                "width": 120,
                "height": 32,
            },
        )

        sent_username = self.client.post(
            session["credential_url"], json={"field": "username"}
        )
        sent_password = self.client.post(
            session["credential_url"], json={"field": "password"}
        )
        sent = self.client.post(session["input_url"], json={"data": "show clock\r"})
        resized = self.client.post(
            session["resize_url"], json={"columns": 96, "rows": 28}
        )
        stopped = self.client.post(session["stop_url"])

        self.assertEqual(sent.status_code, 200)
        self.assertEqual(sent_username.status_code, 200)
        self.assertEqual(sent_password.status_code, 200)
        self.assertNotIn(
            "do-not-persist-this-password", str(sent_password.get_json())
        )
        retained = b"".join(
            path.read_bytes()
            for path in Path(self.directory.name).iterdir()
            if path.is_file()
        )
        self.assertNotIn(b"do-not-persist-this-password", retained)
        self.assertEqual(
            self.telnet_opener.channels[0].sent,
            [b"network-admin\r", b"do-not-persist-this-password\r", b"show clock\r"],
        )
        self.assertEqual(resized.status_code, 200)
        self.assertEqual(self.telnet_opener.channels[0].size, (96, 28))
        self.assertEqual(stopped.get_json()["session"]["state"], "stopped")

    def test_invalid_remote_protocol_is_rejected_before_connecting(self) -> None:
        response = self.start_session(protocol="rlogin")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Choose SSH, Telnet, or Console.")
        self.assertEqual(self.opener.calls, [])
        self.assertEqual(self.telnet_opener.calls, [])

        host_response = self.client.post(
            "/tools/remote-terminal/hosts",
            json={"protocol": "rlogin", "credential_mode": "saved"},
        )
        self.assertEqual(host_response.status_code, 400)
        self.assertEqual(host_response.get_json()["error"], "Choose SSH, Telnet, or Console.")

    def test_terminal_page_captures_keyboard_and_paste_inside_the_shell(self) -> None:
        response = self.client.get("/tools/remote-terminal")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="remote-connection-tree"', response.data)
        self.assertIn(b'id="remote-connection-width-resizer"', response.data)
        self.assertIn(b'id="remote-terminal-height-resizer"', response.data)
        self.assertIn(b'id="remote-terminal-width"', response.data)
        self.assertIn(b'>120 columns</option>', response.data)
        self.assertIn(b"Resize terminal", response.data)
        self.assertIn(b'id="remote-host-import-dialog"', response.data)
        self.assertIn(b'id="remote-quick-connect-dialog"', response.data)
        self.assertIn(b'id="remote-credential-dialog"', response.data)
        self.assertIn(b'id="remote-terminal-surface"', response.data)
        self.assertIn(b'id="remote-terminal-input-capture"', response.data)
        self.assertIn(b"Type and paste directly into the terminal", response.data)
        self.assertIn(b'terminal-emulator.js', response.data)
        self.assertIn(b'data-terminal-key="backspace"', response.data)
        self.assertIn(b'data-terminal-key="paste"', response.data)
        self.assertIn(b'data-terminal-key="ctrl-y"', response.data)
        self.assertIn(b'data-terminal-key="left"', response.data)
        self.assertIn(b'data-terminal-key="right"', response.data)
        self.assertIn(b'data-telnet-credential="username"', response.data)
        self.assertIn(b'data-telnet-credential="password"', response.data)
        self.assertIn(b'value="none"', response.data)
        self.assertIn(b'id="remote-terminal-protocol"', response.data)
        self.assertIn(b'value="console"', response.data)
        self.assertIn(b'id="remote-terminal-console-device"', response.data)
        self.assertIn(b'id="remote-host-console-device"', response.data)
        self.assertIn(b'id="remote-terminal-download"', response.data)
        self.assertIn(b'id="remote-terminal-delete"', response.data)
        self.assertIn(b"remote-connections.js", response.data)
        self.assertNotIn(b"Command input", response.data)
        self.assertNotIn(b'id="remote-terminal-send"', response.data)

    def test_console_uses_same_terminal_lifecycle_without_credentials(self) -> None:
        device = {
            "id": "console_123",
            "path": "/dev/cu.usbserial-123",
            "label": "USB Console",
            "accessible": True,
        }
        with patch(
            "twn_toolkit.remote_terminal_routes.resolve_serial_device",
            return_value=device,
        ):
            response = self.start_session(
                protocol="console",
                host="",
                port=0,
                username="",
                password="",
                console_device_id=device["id"],
                console_baud_rate=115200,
                console_data_bits=8,
                console_parity="none",
                console_stop_bits="1",
                console_flow_control="none",
            )
        self.assertEqual(response.status_code, 201)
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")
        self.assertEqual(session["protocol"], "console")
        self.assertEqual(session["console_device_id"], device["id"])
        self.assertEqual(session["remote_username"], "")
        self.assertEqual(
            self.serial_opener.calls[-1],
            {
                "device_path": device["path"],
                "baud_rate": 115200,
                "data_bits": 8,
                "parity": "none",
                "stop_bits": "1",
                "flow_control": "none",
            },
        )
        sent = self.client.post(session["input_url"], json={"data": "show version\r"})
        self.assertEqual(sent.status_code, 200)
        self.assertEqual(self.serial_opener.channels[-1].sent, [b"show version\r"])

    def test_saved_host_import_previews_and_atomically_adds_inherited_hosts(self) -> None:
        folder = self.client.post(
            "/tools/remote-terminal/folders",
            json={"name": "Imported", "parent_id": ""},
        ).get_json()["library"]["folders"][0]
        payload = {
            "folder_id": folder["id"],
            "default_protocol": "ssh",
            "text": (
                "name,host,protocol,port\n"
                "Core switch,192.0.2.10,,\n"
                "Legacy console,192.0.2.11,telnet,2323\n"
            ),
        }

        preview = self.client.post(
            "/tools/remote-terminal/hosts/import/preview", json=payload
        )
        self.assertEqual(preview.status_code, 200)
        reviewed = preview.get_json()["preview"]
        self.assertTrue(reviewed["ready"])
        self.assertEqual(reviewed["count"], 2)
        self.assertEqual(reviewed["rows"][0]["port"], 22)
        self.assertEqual(reviewed["rows"][1]["protocol"], "telnet")

        imported = self.client.post(
            "/tools/remote-terminal/hosts/import", json=payload
        )
        self.assertEqual(imported.status_code, 201)
        hosts = imported.get_json()["library"]["hosts"]
        self.assertEqual(len(hosts), 2)
        self.assertTrue(all(host["credential_mode"] == "inherit" for host in hosts))
        self.assertTrue(all(host["folder_id"] == folder["id"] for host in hosts))

        duplicate = self.client.post(
            "/tools/remote-terminal/hosts/import",
            json={
                "folder_id": folder["id"],
                "default_protocol": "ssh",
                "text": "New switch,192.0.2.12\nCore switch,192.0.2.13",
            },
        )
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(
            len(
                self.client.get("/tools/remote-terminal/library")
                .get_json()["library"]["hosts"]
            ),
            2,
        )

    def test_saved_library_connects_with_encrypted_vault_credential(self) -> None:
        credential_response = self.client.post(
            "/tools/remote-terminal/credentials",
            json={
                "name": "Network admin",
                "username": "vault-user",
                "password": "vault-only-password",
            },
        )
        self.assertEqual(credential_response.status_code, 201)
        credential_payload = credential_response.get_json()
        self.assertNotIn("password", str(credential_payload).lower())
        credential = credential_payload["library"]["credentials"][0]

        folder_response = self.client.post(
            "/tools/remote-terminal/folders",
            json={"name": "Campus", "parent_id": ""},
        )
        self.assertEqual(folder_response.status_code, 201)
        folder = folder_response.get_json()["library"]["folders"][0]

        host_response = self.client.post(
            "/tools/remote-terminal/hosts",
            json={
                "name": "Core switch",
                "host": "core.example.test",
                "port": 2222,
                "folder_id": folder["id"],
                "credential_mode": "saved",
                "credential_id": credential["id"],
                "allow_unknown_hosts": True,
                "allow_legacy_algorithms": True,
                "notes": "Main distribution frame",
            },
        )
        self.assertEqual(host_response.status_code, 201)
        host = host_response.get_json()["library"]["hosts"][0]

        response = self.client.post(
            "/tools/remote-terminal/sessions", json={"host_id": host["id"]}
        )
        self.assertEqual(response.status_code, 201)
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")
        self.assertEqual(session["source_host_id"], host["id"])
        self.assertEqual(
            self.opener.calls[-1],
            {
                "hostname": "core.example.test",
                "port": 2222,
                "username": "vault-user",
                "password": "vault-only-password",
                "allow_unknown_hosts": True,
                "allow_legacy_algorithms": True,
            },
        )

    def test_saved_telnet_host_uses_vault_credential_and_telnet_transport(self) -> None:
        credential = self.client.post(
            "/tools/remote-terminal/credentials",
            json={
                "name": "Legacy admin",
                "username": "console-user",
                "password": "vault-telnet-password",
            },
        ).get_json()["library"]["credentials"][0]
        host_response = self.client.post(
            "/tools/remote-terminal/hosts",
            json={
                "name": "Legacy access switch",
                "host": "legacy.example.test",
                "protocol": "telnet",
                "port": 23,
                "folder_id": "",
                "credential_mode": "saved",
                "credential_id": credential["id"],
                "allow_unknown_hosts": True,
                "allow_legacy_algorithms": True,
            },
        )
        self.assertEqual(host_response.status_code, 201)
        host = host_response.get_json()["library"]["hosts"][0]

        response = self.client.post(
            "/tools/remote-terminal/sessions", json={"host_id": host["id"]}
        )
        self.assertEqual(response.status_code, 201)
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")

        self.assertEqual(session["protocol"], "telnet")
        self.assertNotIn("username", self.telnet_opener.calls[-1])
        self.assertNotIn("password", self.telnet_opener.calls[-1])
        sent_username = self.client.post(
            session["credential_url"], json={"field": "username"}
        )
        sent_password = self.client.post(
            session["credential_url"], json={"field": "password"}
        )
        self.assertEqual(sent_username.status_code, 200)
        self.assertEqual(sent_password.status_code, 200)
        self.assertEqual(
            self.telnet_opener.channels[-1].sent,
            [b"console-user\r", b"vault-telnet-password\r"],
        )
        self.assertEqual(self.opener.calls, [])

    def test_telnet_can_connect_without_credentials(self) -> None:
        response = self.start_session(
            protocol="telnet", port=23, username="", password=""
        )
        self.assertEqual(response.status_code, 201)
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")

        self.assertEqual(session["remote_username"], "")
        self.assertFalse(session["telnet_username_available"])
        self.assertFalse(session["telnet_password_available"])
        self.assertNotIn("@", session["title"])
        unavailable = self.client.post(
            session["credential_url"], json={"field": "password"}
        )
        self.assertEqual(unavailable.status_code, 409)
        self.assertIn("No password was provided", unavailable.get_json()["error"])

        host_response = self.client.post(
            "/tools/remote-terminal/hosts",
            json={
                "name": "Manual Telnet",
                "host": "manual.example.test",
                "protocol": "telnet",
                "port": 23,
                "folder_id": "",
                "credential_mode": "none",
            },
        )
        self.assertEqual(host_response.status_code, 201)
        host = host_response.get_json()["library"]["hosts"][0]
        self.assertEqual(host["credential_id"], "")
        saved_response = self.client.post(
            "/tools/remote-terminal/sessions", json={"host_id": host["id"]}
        )
        self.assertEqual(saved_response.status_code, 201)
        saved_session = saved_response.get_json()["session"]
        self.assertFalse(saved_session["telnet_username_available"])
        self.assertFalse(saved_session["telnet_password_available"])

        ssh_response = self.start_session(username="", password="")
        self.assertEqual(ssh_response.status_code, 400)

    def test_saved_host_supports_multiple_independently_named_sessions(self) -> None:
        credential = self.client.post(
            "/tools/remote-terminal/credentials",
            json={
                "name": "Shared admin",
                "username": "netadmin",
                "password": "vault-password",
            },
        ).get_json()["library"]["credentials"][0]
        host = self.client.post(
            "/tools/remote-terminal/hosts",
            json={
                "name": "Home FortiGate",
                "host": "firewall.example.test",
                "port": 22,
                "folder_id": "",
                "credential_mode": "saved",
                "credential_id": credential["id"],
                "allow_unknown_hosts": True,
                "allow_legacy_algorithms": False,
                "notes": "",
            },
        ).get_json()["library"]["hosts"][0]

        first = self.client.post(
            "/tools/remote-terminal/sessions", json={"host_id": host["id"]}
        ).get_json()["session"]
        second = self.client.post(
            "/tools/remote-terminal/sessions", json={"host_id": host["id"]}
        ).get_json()["session"]
        wait_for_state(self.manager.store, first["id"], "running")
        wait_for_state(self.manager.store, second["id"], "running")

        renamed = self.client.post(
            first["rename_url"], json={"title": "Firewall maintenance"}
        )
        library = self.client.get("/tools/remote-terminal/library").get_json()[
            "library"
        ]

        self.assertEqual(renamed.status_code, 200)
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["source_host_id"], second["source_host_id"])
        self.assertEqual(renamed.get_json()["session"]["title"], "Firewall maintenance")
        self.assertEqual(
            self.manager.store.get_session(second["id"])["title"],
            "Home FortiGate",
        )
        self.assertEqual(library["hosts"][0]["name"], "Home FortiGate")

    def test_saved_host_uses_inherited_folder_credential_and_bulk_route(self) -> None:
        store = self.app.extensions["remote_connection_store"]
        credential = store.save_credential(
            user_id="test-user",
            name="Inherited administrator",
            remote_username="inherited-admin",
            password="inherited-secret",
        )
        source = store.create_folder(
            user_id="test-user",
            name="Branches",
            credential_mode="credential",
            credential_id=credential["id"],
        )
        destination = store.create_folder(
            user_id="test-user", name="Datacenter"
        )
        host = store.save_host(
            user_id="test-user",
            name="Branch switch",
            host="192.0.2.90",
            port=22,
            folder_id=source["id"],
            credential_id="",
            credential_mode="inherit",
            allow_unknown_hosts=False,
            allow_legacy_algorithms=False,
        )

        started = self.client.post(
            "/tools/remote-terminal/sessions", json={"host_id": host["id"]}
        )
        self.assertEqual(started.status_code, 201)
        session = started.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")
        self.assertEqual(self.opener.calls[-1]["username"], "inherited-admin")
        self.assertEqual(self.opener.calls[-1]["password"], "inherited-secret")

        moved = self.client.post(
            "/tools/remote-terminal/library/bulk",
            json={
                "host_ids": [host["id"]],
                "folder_ids": [],
                "change_location": True,
                "destination_id": destination["id"],
                "change_credential": True,
                "credential_mode": "credential",
                "credential_id": credential["id"],
            },
        )
        self.assertEqual(moved.status_code, 200)
        moved_host = next(
            item
            for item in moved.get_json()["library"]["hosts"]
            if item["id"] == host["id"]
        )
        self.assertEqual(moved_host["folder_id"], destination["id"])
        self.assertEqual(moved_host["credential_mode"], "credential")

        page = self.client.get("/tools/remote-terminal")
        self.assertIn(b"Credential inheritance", page.data)
        self.assertIn(b"Edit selected items", page.data)

    def test_saved_host_inherits_active_case_transcript_capture(self) -> None:
        investigation_store = self.app.extensions["investigation_store"]
        case = investigation_store.create(
            owner_user_id="test-user",
            owner_username="test-user",
            title="Firewall outage",
            description="",
        )
        credential = self.client.post(
            "/tools/remote-terminal/credentials",
            json={
                "name": "Shared admin",
                "username": "netadmin",
                "password": "vault-password",
            },
        ).get_json()["library"]["credentials"][0]
        host = self.client.post(
            "/tools/remote-terminal/hosts",
            json={
                "name": "Edge firewall",
                "host": "firewall.example.test",
                "port": 22,
                "folder_id": "",
                "credential_mode": "saved",
                "credential_id": credential["id"],
                "allow_unknown_hosts": True,
                "allow_legacy_algorithms": False,
                "notes": "",
            },
        ).get_json()["library"]["hosts"][0]

        response = self.client.post(
            "/tools/remote-terminal/sessions", json={"host_id": host["id"]}
        )

        self.assertEqual(response.status_code, 201)
        session = response.get_json()["session"]
        self.assertEqual(session["investigation_id"], case["id"])
        self.assertEqual(session["investigation_title"], "Firewall outage")
        self.assertTrue(session["record_transcript"])
        recording_page = self.client.get("/tools/remote-terminal")
        self.assertNotIn(b'id="remote-terminal-transcript"', recording_page.data)

        recording_cannot_opt_out = self.client.post(
            "/tools/remote-terminal/sessions",
            json={"host_id": host["id"], "record_transcript": False},
        ).get_json()["session"]
        self.assertEqual(recording_cannot_opt_out["investigation_id"], case["id"])
        self.assertTrue(recording_cannot_opt_out["record_transcript"])

        investigation_store.set_state(
            case["id"], "test-user", "test-user", "paused"
        )
        paused_default = self.client.post(
            "/tools/remote-terminal/sessions", json={"host_id": host["id"]}
        ).get_json()["session"]
        self.assertEqual(paused_default["investigation_id"], "")
        self.assertFalse(paused_default["record_transcript"])

        paused_explicit_capture = self.client.post(
            "/tools/remote-terminal/sessions",
            json={"host_id": host["id"], "record_transcript": True},
        ).get_json()["session"]
        self.assertEqual(paused_explicit_capture["investigation_id"], "")
        self.assertFalse(paused_explicit_capture["record_transcript"])

    def test_quick_connect_can_use_saved_credential_without_saving_host(self) -> None:
        created = self.client.post(
            "/tools/remote-terminal/credentials",
            json={
                "name": "Reusable admin",
                "username": "quick-user",
                "password": "quick-vault-password",
            },
        ).get_json()
        credential = created["library"]["credentials"][0]

        response = self.client.post(
            "/tools/remote-terminal/sessions",
            json={
                "host": "temporary.example.test",
                "port": 22,
                "credential_id": credential["id"],
                "allow_unknown_hosts": True,
            },
        )
        self.assertEqual(response.status_code, 201)
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")
        library = self.client.get("/tools/remote-terminal/library").get_json()[
            "library"
        ]
        self.assertEqual(library["hosts"], [])
        self.assertEqual(session["source_host_id"], "")
        self.assertEqual(self.opener.calls[-1]["username"], "quick-user")
        self.assertEqual(self.opener.calls[-1]["password"], "quick-vault-password")

    def test_active_session_has_standalone_popout_view(self) -> None:
        response = self.start_session()
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")

        popout = self.client.get(session["popout_url"])
        self.assertEqual(popout.status_code, 200)
        self.assertIn(b"same persistent shell", popout.data)
        self.assertIn(b'id="remote-terminal-input-capture"', popout.data)
        self.assertNotIn(b'id="remote-terminal-save-host"', popout.data)
        self.assertNotIn(b"remote-connections.js", popout.data)

    def test_multiline_terminal_input_is_delivered_as_one_raw_write(self) -> None:
        response = self.start_session()
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")

        block = "configure terminal\rinterface Ethernet1/1\rdescription Uplink\rend\r"
        sent = self.client.post(session["input_url"], json={"data": block})

        self.assertEqual(sent.status_code, 200)
        self.assertEqual(self.opener.clients[0].channel.sent, [block.encode("utf-8")])

    def test_completed_scrollback_can_be_downloaded_and_deleted(self) -> None:
        response = self.start_session()
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")

        active_delete = self.client.delete(session["delete_url"])
        self.assertEqual(active_delete.status_code, 409)

        self.client.post(session["stop_url"])
        download = self.client.get(session["download_url"])
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.content_type, "text/plain; charset=utf-8")
        self.assertIn("attachment;", download.headers["Content-Disposition"])
        self.assertIn(b"switch# ready", download.data)
        self.assertNotIn(b"\x1b", download.data)
        transcript = self.client.get(session["transcript_url"])
        self.assertEqual(transcript.status_code, 200)
        self.assertIn("inline;", transcript.headers["Content-Disposition"])
        self.assertIn(b"switch# ready", transcript.data)

        deleted = self.client.delete(session["delete_url"])
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.get_json()["deleted_id"], session["id"])
        self.assertEqual(self.client.get(session["detail_url"]).status_code, 404)

    def test_active_and_completed_sessions_can_be_attached_to_open_case(self) -> None:
        investigation_store = self.app.extensions["investigation_store"]
        active_response = self.start_session()
        active_session = active_response.get_json()["session"]
        wait_for_state(self.manager.store, active_session["id"], "running")
        wait_for_output(self.manager.store, active_session["id"])
        completed_response = self.start_session(title="Earlier session")
        completed_session = completed_response.get_json()["session"]
        wait_for_state(self.manager.store, completed_session["id"], "running")
        wait_for_output(self.manager.store, completed_session["id"])
        self.client.post(completed_session["stop_url"])
        case = investigation_store.create(
            owner_user_id="test-user",
            owner_username="test-user",
            title="Campus outage",
            description="",
        )

        active_attached = self.client.post(
            active_session["attach_case_url"],
            json={"investigation_id": case["id"]},
        )
        completed_attached = self.client.post(
            completed_session["attach_case_url"],
            json={"investigation_id": case["id"]},
        )

        self.assertEqual(active_attached.status_code, 200)
        self.assertTrue(active_attached.get_json()["session"]["record_transcript"])
        self.assertEqual(
            active_attached.get_json()["session"]["investigation_title"],
            "Campus outage",
        )
        self.assertEqual(completed_attached.status_code, 200)
        self.assertIsNotNone(
            self.manager.store.get_session(completed_session["id"])[
                "evidence_finalized_at"
            ]
        )
        self.client.post(active_session["stop_url"])
        remote_events = [
            event
            for event in investigation_store.events_for_user(case["id"], "test-user")
            if event["tool_id"] == "tools.remote_terminal"
        ]
        self.assertEqual(
            [event["event_type"] for event in remote_events],
            [
                "remote_terminal.session.attached",
                "remote_terminal.transcript.attached",
                "remote_terminal.session.completed",
            ],
        )
        self.assertEqual(
            len(investigation_store.artifacts_for_user(case["id"], "test-user")),
            2,
        )

    def test_scrollback_can_be_saved_to_datastore_without_overwriting(self) -> None:
        datastore = LocalDatastore(self.directory.name)
        datastore.create_folder("", "Terminal captures")
        response = self.start_session()
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")
        wait_for_output(self.manager.store, session["id"])

        snapshot = self.client.post(
            session["datastore_url"], json={"folder": "Terminal captures"}
        )
        self.client.post(session["stop_url"])
        completed = self.client.post(
            session["datastore_url"], json={"folder": "Terminal captures"}
        )
        repeated = self.client.post(
            session["datastore_url"], json={"folder": "Terminal captures"}
        )

        self.assertEqual(snapshot.status_code, 200)
        self.assertEqual(snapshot.get_json()["saved"]["kind"], "live snapshot")
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(
            completed.get_json()["saved"]["kind"], "completed scrollback"
        )
        self.assertNotEqual(
            completed.get_json()["saved"]["path"],
            repeated.get_json()["saved"]["path"],
        )
        for item in (snapshot, completed, repeated):
            saved = datastore.file(item.get_json()["saved"]["path"])
            self.assertIn("switch# ready", saved.read_text())

    def test_second_web_worker_controls_the_owning_worker(self) -> None:
        response = self.start_session()
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")
        owned = self.manager.store.get_session(session["id"])
        if not owned or not owned.get("_control_path"):
            self.skipTest("Unix-domain sockets are blocked in this test sandbox.")
        second_worker = RemoteSessionManager(
            RemoteSessionStore(self.directory.name),
            self.app.extensions["investigation_store"],
            ssh_opener=FakeSshOpener(),
        )

        second_worker.send_input(
            session["id"], user_id="test-user", data="show version\r"
        )
        self.assertEqual(
            self.opener.clients[0].channel.sent,
            [b"show version\r"],
        )
        stopped = second_worker.stop_session(
            session["id"], user_id="test-user"
        )
        self.assertEqual(stopped["state"], "stopped")

    def test_second_web_worker_requests_telnet_credential_from_owner(self) -> None:
        response = self.start_session(protocol="telnet", port=23)
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")
        owned = self.manager.store.get_session(session["id"])
        if not owned or not owned.get("_control_path"):
            self.skipTest("Unix-domain sockets are blocked in this test sandbox.")
        second_worker = RemoteSessionManager(
            RemoteSessionStore(self.directory.name),
            self.app.extensions["investigation_store"],
            telnet_opener=FakeTelnetOpener(),
        )

        accepted = second_worker.send_telnet_credential(
            session["id"], user_id="test-user", field="password"
        )

        self.assertEqual(accepted, len(b"do-not-persist-this-password\r"))
        self.assertEqual(
            self.telnet_opener.channels[0].sent,
            [b"do-not-persist-this-password\r"],
        )
        second_worker.close()

    def test_credentials_and_terminal_input_are_not_persisted(self) -> None:
        response = self.start_session()
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")
        self.client.post(session["input_url"], json={"data": "secret command\r"})
        self.client.post(session["stop_url"])

        retained = b"".join(
            path.read_bytes()
            for path in Path(self.directory.name).iterdir()
            if path.is_file()
        )
        self.assertNotIn(b"do-not-persist-this-password", retained)
        self.assertNotIn(b"secret command", retained)
        self.assertNotIn("password", session)

    def test_input_is_bounded(self) -> None:
        response = self.start_session()
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")
        oversized = self.client.post(
            session["input_url"],
            json={"data": "x" * (REMOTE_SESSION_INPUT_LIMIT_BYTES + 1)},
        )
        self.assertEqual(oversized.status_code, 409)

    def test_case_records_lifecycle_and_sanitized_transcript(self) -> None:
        investigation_store = self.app.extensions["investigation_store"]
        case = investigation_store.create(
            owner_user_id="test-user",
            owner_username="test-user",
            title="Switch outage",
            description="",
        )
        response = self.start_session(record_transcript=True)
        session = response.get_json()["session"]
        self.assertEqual(session["investigation_id"], case["id"])
        wait_for_state(self.manager.store, session["id"], "running")
        self.client.post(session["stop_url"])

        events = investigation_store.events_for_user(case["id"], "test-user")
        remote_events = [
            event
            for event in events
            if event["tool_id"] == "tools.remote_terminal"
        ]
        self.assertEqual(
            [event["event_type"] for event in remote_events],
            [
                "remote_terminal.session.started",
                "remote_terminal.session.completed",
            ],
        )
        artifacts = investigation_store.artifacts_for_user(case["id"], "test-user")
        transcript = next(
            item for item in artifacts if item["event_id"] == remote_events[-1]["id"]
        )
        transcript_path = Path(self.directory.name) / "datastore" / transcript["relative_path"]
        retained = transcript_path.read_text()
        self.assertIn("switch# ready", retained)
        self.assertNotIn("\x1b", retained)

    def test_closing_case_stops_attached_shell_before_case_closes(self) -> None:
        investigation_store = self.app.extensions["investigation_store"]
        case = investigation_store.create(
            owner_user_id="test-user",
            owner_username="test-user",
            title="Case closure",
            description="",
        )
        response = self.start_session(record_transcript=True)
        session = response.get_json()["session"]
        wait_for_state(self.manager.store, session["id"], "running")

        closed = self.client.post(
            f"/investigations/{case['id']}/state",
            data={"state": "completed"},
        )
        self.assertEqual(closed.status_code, 302)
        stopped = self.manager.store.get_session(session["id"])
        self.assertEqual(stopped["state"], "stopped")
        self.assertEqual(stopped["termination"], "case_closed")
        self.assertIsNotNone(stopped["evidence_finalized_at"])
        self.assertEqual(
            investigation_store.get_for_user(case["id"], "test-user")["state"],
            "completed",
        )


if __name__ == "__main__":
    unittest.main()
