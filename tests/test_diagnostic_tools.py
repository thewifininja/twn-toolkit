from __future__ import annotations

import socket
import selectors
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from twn_toolkit import create_app
from twn_toolkit.diagnostic_tools import (
    parse_http_headers,
    receive_syslog,
    send_syslog,
    send_api_request,
    test_path_mtu as run_path_mtu,
)
from twn_toolkit.network_tools import ToolInputError


class DiagnosticToolTests(unittest.TestCase):
    def test_path_mtu_binary_searches_largest_success(self) -> None:
        def probe(_address, _family, payload, _timeout):
            mtu = payload + 28
            return mtu <= 1400, "reply" if mtu <= 1400 else "too large"

        with (
            patch(
                "twn_toolkit.diagnostic_tools.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.1", 0))],
            ),
            patch("twn_toolkit.diagnostic_tools._mtu_probe", side_effect=probe),
        ):
            result = run_path_mtu("example.test", minimum=576, maximum=1500)
        self.assertEqual(result["mtu"], 1400)
        self.assertLessEqual(len(result["probes"]), 10)
        self.assertTrue(any(not item["success"] for item in result["probes"]))

    def test_parses_headers_and_rejects_malformed_lines(self) -> None:
        self.assertEqual(
            parse_http_headers("Accept: application/json\nX-Test: yes"),
            {"Accept": "application/json", "X-Test": "yes"},
        )
        with self.assertRaises(ToolInputError):
            parse_http_headers("not a header")

    def test_api_request_is_bounded_no_redirect_and_redacts_secrets(self) -> None:
        response = Mock()
        response.status_code = 302
        response.reason = "Found"
        response.headers = {"Location": "https://example.test/next", "Set-Cookie": "secret"}
        response.encoding = "utf-8"
        response.iter_content.return_value = [b'{"ok": true}']
        with (
            patch(
                "twn_toolkit.diagnostic_tools.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 443))],
            ),
            patch("twn_toolkit.diagnostic_tools.requests.request", return_value=response) as request_mock,
        ):
            result = send_api_request(
                "POST",
                "https://example.test/hook",
                headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
                body='{"hello":"world"}',
            )
        self.assertEqual(result["status"], 302)
        self.assertEqual(result["request_headers"]["Authorization"], "[redacted]")
        self.assertEqual(result["response_headers"]["Set-Cookie"], "[redacted]")
        self.assertFalse(request_mock.call_args.kwargs["allow_redirects"])
        self.assertTrue(request_mock.call_args.kwargs["stream"])

    def test_receives_udp_syslog_and_decodes_priority(self) -> None:
        listener = Mock()
        listener.recvfrom.return_value = (
            b"<134>test syslog message",
            ("192.0.2.4", 12345),
        )
        selector = Mock()
        selector.select.return_value = [
            (SimpleNamespace(fileobj=listener, data="listener"), selectors.EVENT_READ)
        ]
        with (
            patch("twn_toolkit.diagnostic_tools.socket.socket", return_value=listener),
            patch("twn_toolkit.diagnostic_tools.selectors.DefaultSelector", return_value=selector),
        ):
            messages = receive_syslog("udp", "127.0.0.1", 5514, duration=1, max_messages=1)
        self.assertEqual(messages[0]["priority"], 134)
        self.assertEqual(messages[0]["facility"], 16)
        self.assertEqual(messages[0]["severity"], 6)
        self.assertIn("test syslog message", messages[0]["message"])

    def test_generates_rfc5424_syslog_message(self) -> None:
        client = Mock()
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)
        client.sendto.return_value = 100
        with (
            patch(
                "twn_toolkit.diagnostic_tools.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.8", 514))],
            ),
            patch("twn_toolkit.diagnostic_tools.socket.socket", return_value=client),
        ):
            result = send_syslog(
                "udp",
                "syslog.example",
                514,
                facility=16,
                severity=6,
                hostname="toolkit",
                app_name="test-app",
                message="hello syslog",
            )
        payload, address = client.sendto.call_args.args
        self.assertEqual(address, ("192.0.2.8", 514))
        self.assertTrue(payload.startswith(b"<134>1 "))
        self.assertTrue(payload.endswith(b" toolkit test-app - - - hello syslog"))
        self.assertEqual(result["priority"], 134)

    def test_routes_render_results(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()
            with patch(
                "twn_toolkit.tools.test_path_mtu",
                return_value={
                    "host": "example.test", "address": "192.0.2.1", "family": "IPv4",
                    "mtu": 1400, "minimum": 576, "maximum": 1500, "overhead": 28,
                    "conclusive": True, "probes": [],
                },
            ):
                page = client.post("/tools/path-mtu", data={
                    "host": "example.test", "family": "auto", "minimum": "576",
                    "maximum": "1500", "timeout": "1",
                })
            self.assertIn(b"Largest working MTU", page.data)

            with patch(
                "twn_toolkit.tools.send_api_request",
                return_value={
                    "status": 200, "reason": "OK", "elapsed_ms": 5, "bytes": 2,
                    "resolved_addresses": ["192.0.2.2"], "request_headers": {},
                    "response_headers": {"Content-Type": "text/plain"}, "body": "OK",
                    "truncated": False, "redirect": "",
                },
            ):
                page = client.post("/tools/api-request", data={
                    "method": "GET", "url": "https://example.test", "headers": "",
                    "body": "", "timeout": "10", "verify_tls": "on",
                })
            self.assertIn(b"200 OK", page.data)

            with patch(
                "twn_toolkit.tools.receive_syslog",
                return_value=[{
                    "received_at": "2026-01-01T00:00:00.000Z", "source": "192.0.2.4",
                    "source_port": 1234, "priority": 134, "facility": 16,
                    "severity": 6, "message": "<134>hello", "bytes": 10,
                }],
            ):
                page = client.post("/tools/syslog-receiver", data={
                    "protocol": "udp", "bind_address": "0.0.0.0", "port": "5514",
                    "duration": "1", "max_messages": "10",
                })
            self.assertIn(b"&lt;134&gt;hello", page.data)

            with patch(
                "twn_toolkit.tools.send_syslog",
                return_value={
                    "protocol": "UDP", "host": "syslog.example", "address": "192.0.2.8",
                    "port": 514, "priority": 134, "facility": 16, "severity": 6,
                    "bytes": 80, "wire_message": "<134>1 timestamp toolkit test - - - hello",
                },
            ):
                page = client.post("/tools/syslog-receiver", data={
                    "action": "send", "send_protocol": "udp",
                    "send_host": "syslog.example", "send_port": "514",
                    "send_facility": "16", "send_severity": "6",
                    "send_hostname": "toolkit", "send_app_name": "test",
                    "send_message": "hello", "send_timeout": "3",
                })
            self.assertIn(b"Sent 80 bytes", page.data)
            self.assertIn(b"Message on the Wire", page.data)


if __name__ == "__main__":
    unittest.main()
