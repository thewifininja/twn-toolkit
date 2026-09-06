from __future__ import annotations

import socket
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

from twn_toolkit.network_tools import scan_tcp_checks, scan_tcp_ports


IPV4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0))
IPV6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1", 0, 7, 3))


class TCPResolutionTests(unittest.TestCase):
    def test_concurrent_ports_share_pending_lookup_and_next_scan_refreshes(self):
        entered = threading.Event()
        release = threading.Event()

        def lookup(*_args):
            entered.set()
            self.assertTrue(release.wait(5))
            return [IPV4]

        checks = [({"host": "router.example", "label": str(i)}, 1000 + i) for i in range(40)]
        with patch("twn_toolkit.network_tools.socket.getaddrinfo", side_effect=lookup) as dns, patch(
            "twn_toolkit.network_tools.socket.socket"
        ), ThreadPoolExecutor(max_workers=1) as runner:
            scan = runner.submit(scan_tcp_checks, checks, max_workers=8)
            try:
                self.assertTrue(entered.wait(5))
            finally:
                release.set()
            results = scan.result(timeout=5)
            self.assertEqual(dns.call_count, 1)
            self.assertEqual([r["label"] for r in results], [str(i) for i in range(40)])
            self.assertTrue(all(r["status"] == "open" for r in results))
            dns.side_effect = None
            dns.return_value = [IPV6]
            with patch("twn_toolkit.network_tools.socket.socket") as factory:
                scan_tcp_checks(checks[:1], max_workers=1)
                factory.return_value.__enter__.return_value.connect.assert_called_once_with(
                    ("fe80::1", 1000, 7, 3)
                )
            self.assertEqual(dns.call_count, 2)

    def test_dns_failure_is_shared_without_affecting_other_hosts(self):
        def lookup(host, *_args):
            if host == "missing.example":
                raise socket.gaierror(-2, "Name not known")
            return [IPV4]

        with patch("twn_toolkit.network_tools.socket.getaddrinfo", side_effect=lookup) as dns, patch(
            "twn_toolkit.network_tools.socket.socket"
        ) as factory:
            results = scan_tcp_ports(
                [{"host": "missing.example"}, {"host": "healthy.example"}],
                [22, 80, 443], max_workers=1,
            )
        self.assertEqual(dns.call_count, 2)
        self.assertEqual(factory.call_count, 3)
        self.assertTrue(all(r["status"] == "error" for r in results[:3]))
        self.assertTrue(all("DNS resolution failed" in r["detail"] for r in results[:3]))
        self.assertTrue(all(r["status"] == "open" for r in results[3:]))

    def test_address_fallback_preserves_scope_timeout_and_closes_sockets(self):
        first, second = MagicMock(), MagicMock()
        first.__enter__.return_value = first
        second.__enter__.return_value = second
        first.connect.side_effect = OSError("Network unreachable")
        with patch("twn_toolkit.network_tools.socket.getaddrinfo", return_value=[IPV6, IPV4]), patch(
            "twn_toolkit.network_tools.socket.socket", side_effect=[first, second]
        ) as factory:
            result = scan_tcp_checks([({"host": "router.example"}, 443)], timeout=0.7)[0]
        self.assertEqual(result["status"], "open")
        self.assertEqual([call.args for call in factory.call_args_list],
                         [(socket.AF_INET6, socket.SOCK_STREAM, 6), (socket.AF_INET, socket.SOCK_STREAM, 6)])
        first.connect.assert_called_once_with(("fe80::1", 443, 7, 3))
        second.connect.assert_called_once_with(("192.0.2.10", 443))
        for connection in (first, second):
            connection.settimeout.assert_called_once_with(0.7)
            connection.__exit__.assert_called_once()

    def test_final_address_error_determines_result(self):
        for error, status in [(ConnectionRefusedError(), "closed"), (TimeoutError(), "timeout"),
                              (OSError("Network unreachable"), "error")]:
            with self.subTest(status=status):
                first, second = MagicMock(), MagicMock()
                first.__enter__.return_value = first
                second.__enter__.return_value = second
                first.connect.side_effect = TimeoutError()
                second.connect.side_effect = error
                with patch("twn_toolkit.network_tools.socket.getaddrinfo", return_value=[IPV6, IPV4]), patch(
                    "twn_toolkit.network_tools.socket.socket", side_effect=[first, second]
                ):
                    result = scan_tcp_checks([({"host": "router.example"}, 22)])[0]
                self.assertEqual(result["status"], status)
                first.__exit__.assert_called_once()
                second.__exit__.assert_called_once()

    def test_empty_resolution_returns_error(self):
        with patch("twn_toolkit.network_tools.socket.getaddrinfo", return_value=[]), patch(
            "twn_toolkit.network_tools.socket.socket"
        ) as factory:
            result = scan_tcp_checks([({"host": "router.example"}, 22)])[0]
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["detail"], "getaddrinfo returns an empty list")
        factory.assert_not_called()
