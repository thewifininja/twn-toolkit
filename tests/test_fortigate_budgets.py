from __future__ import annotations

import gzip
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import requests

from twn_toolkit.fortigate import FortiGateClient, FortiGateError, FortiGateLimitError


MAC = "aa:bb:cc:dd:ee:ff"


def api_response(data, status=200):
    body = json.dumps(data).encode()
    response = Mock(status_code=status, reason="Test", headers={})
    response.iter_content.side_effect = lambda chunk_size: iter([body])
    return response, len(body)


def log_row(name):
    return {"stamac": MAC, "logdesc": "Wireless client authenticated", "ap": name}


class FortiGateBudgetTests(unittest.TestCase):
    def setUp(self):
        self.client = FortiGateClient("https://fortigate.example", "secret")

    def test_lookup_session_closes_and_is_not_reused_by_another_operation(self):
        first, _ = api_response({"results": [log_row("A")]})
        end, _ = api_response({"results": []})
        with patch("requests.Session", autospec=True) as factory:
            session = factory.return_value.__enter__.return_value
            session.request.side_effect = [first, end]
            self.assertEqual(len(self.client.get_wireless_client_logs(MAC, "root", 24)), 1)
            self.assertEqual(factory.call_count, 1)
            factory.return_value.__exit__.assert_called_once()
            session.request.side_effect = requests.exceptions.SSLError("bad certificate")
            with self.assertRaisesRegex(FortiGateError, "TLS verification failed"):
                self.client.get_wireless_clients("root")
            self.assertEqual(factory.call_count, 2)
            self.assertEqual(factory.return_value.__exit__.call_count, 2)
        first.close.assert_called_once()
        end.close.assert_called_once()

    def test_nested_pool_scope_uses_one_session_for_multiple_operations(self):
        response, _ = api_response({"status": "success"})
        with patch("requests.Session", autospec=True) as factory:
            factory.return_value.__enter__.return_value.request.return_value = response
            with self.client.pooled() as client:
                client.move_managed_switch_after("one", "two", "root")
                with client.pooled() as nested:
                    self.assertIs(nested, client)
                    nested.rename_object("/api/object/{current_name}", "a", "b", "root")
            self.assertEqual(factory.call_count, 1)
            factory.return_value.__exit__.assert_called_once()
        self.assertIsNone(self.client._session)

    def test_limit_error_stops_before_more_filters_or_pages(self):
        response = Mock(status_code=200)
        consumed = []
        def chunks(**_kwargs):
            for chunk in [b"1234", b"5678", b"unused"]:
                consumed.append(chunk)
                yield chunk
        response.iter_content.side_effect = chunks
        with patch("requests.Session.request", return_value=response) as request, patch(
            "twn_toolkit.fortigate.MAX_RESPONSE_BYTES", 5
        ), self.assertRaises(FortiGateLimitError):
            self.client.get_wireless_client_logs(MAC, "root", 24)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(len(consumed), 2)
        response.close.assert_called_once()

    def test_total_byte_budget_counts_pages_and_error_bodies(self):
        for status in (200, 400):
            with self.subTest(status=status):
                first, n1 = api_response({"results": [log_row("A")]} if status == 200 else {"error": "unsupported"}, status)
                second, n2 = api_response({"results": []})
                with patch("requests.Session.request", side_effect=[first, second]) as request, patch(
                    "twn_toolkit.fortigate.MAX_LOG_BYTES", n1 + n2 - 1
                ), self.assertRaises(FortiGateLimitError):
                    self.client.get_wireless_client_logs(MAC, "root", 24)
                self.assertEqual(request.call_count, 2)
                second.close.assert_called_once()

    def test_request_budget_is_shared_across_fallback_filters(self):
        unsupported, _ = api_response({"error": "unsupported"}, 400)
        with patch("requests.Session.request", return_value=unsupported) as request, patch(
            "twn_toolkit.fortigate.MAX_LOG_REQUESTS", 2
        ), self.assertRaisesRegex(FortiGateLimitError, "exceeded 2 requests"):
            self.client.get_wireless_client_logs(MAC, "root", 24)
        self.assertEqual(request.call_count, 2)

    def test_row_and_page_limits_do_not_return_partial_history(self):
        response, _ = api_response({"results": [log_row("A"), log_row("B")]})
        with patch("requests.Session.request", return_value=response), patch(
            "twn_toolkit.fortigate.MAX_LOG_ROWS", 1
        ), self.assertRaisesRegex(FortiGateLimitError, "matching rows"):
            self.client.get_wireless_client_logs(MAC, "root", 24, limit=1)
        with patch("requests.Session.request", return_value=response) as request, patch(
            "twn_toolkit.fortigate.MAX_LOG_PAGES_PER_FILTER", 1
        ), self.assertRaisesRegex(FortiGateLimitError, "reached 1 pages"):
            self.client.get_wireless_client_logs(MAC, "root", 24)
        self.assertEqual(request.call_count, 1)

    def test_auth_server_and_transport_errors_stop_fallback(self):
        for status in (401, 403, 500):
            with self.subTest(status=status):
                response, _ = api_response({"error": "failure"}, status)
                with patch("requests.Session.request", return_value=response) as request, self.assertRaises(FortiGateError):
                    self.client.get_wireless_client_logs(MAC, "root", 24)
                self.assertEqual(request.call_count, 1)
        with patch("requests.Session.request", side_effect=requests.ConnectionError("lost")) as request, self.assertRaises(FortiGateError):
            self.client.get_wireless_clients("root")
        self.assertEqual(request.call_count, 1)

    def test_failed_later_page_does_not_return_earlier_matches(self):
        first, _ = api_response({"results": [log_row("A")]})
        failure, _ = api_response({"error": "failed"}, 400)
        with patch("requests.Session.request", side_effect=[first, failure]) as request, self.assertRaises(FortiGateError):
            self.client.get_wireless_client_logs(MAC, "root", 24)
        self.assertEqual(request.call_count, 2)

    def test_missing_endpoint_and_unsupported_filter_still_fall_back(self):
        missing, _ = api_response({"error": "not found"}, 404)
        unsupported, _ = api_response({"error": "bad filter"}, 400)
        match, _ = api_response({"results": [log_row("A")]})
        end, _ = api_response({"results": []})
        with patch("requests.Session.request", side_effect=[missing, unsupported, match, end]) as request:
            self.assertEqual(len(self.client.get_wireless_client_logs(MAC, "root", 24)), 1)
        self.assertIn("/memory/", request.call_args_list[0].args[1])
        self.assertIn("/disk/", request.call_args_list[1].args[1])

    def test_successful_empty_fallback_does_not_raise_an_earlier_404(self):
        missing, _ = api_response({"error": "not found"}, 404)
        empty, _ = api_response({"results": []})
        with patch("requests.Session.request", side_effect=[missing] + [empty] * 10):
            self.assertEqual(self.client.get_wireless_client_logs(MAC, "root", 24), [])

    def test_mutation_stream_failure_and_redirect_are_not_retried(self):
        response = Mock(status_code=200)
        response.iter_content.side_effect = requests.ConnectionError("stream interrupted")
        with patch("requests.Session.request", return_value=response) as request, self.assertRaises(FortiGateError):
            self.client.move_managed_switch_after("one", "two", "root")
        self.assertEqual(request.call_count, 1)
        response.close.assert_called_once()
        redirect = Mock(status_code=307)
        with patch("requests.Session.request", return_value=redirect) as request, self.assertRaisesRegex(FortiGateError, "redirect"):
            self.client.move_managed_switch_after("one", "two", "root")
        self.assertFalse(request.call_args.kwargs["allow_redirects"])
        redirect.iter_content.assert_not_called()
        redirect.close.assert_called_once()

    def test_malformed_json_and_non_object_responses_fail_cleanly(self):
        for body in (b"[1, 2]", b"not json", b"\xff"):
            with self.subTest(body=body):
                response = Mock(status_code=200)
                response.iter_content.return_value = iter([body])
                with patch("requests.Session.request", return_value=response), self.assertRaises(FortiGateError):
                    self.client.test_connection()
                response.close.assert_called_once()

    def test_malformed_history_page_does_not_hide_earlier_matches(self):
        for data in ({}, {"results": [1]}, {"results": {}}):
            with self.subTest(data=data):
                first, _ = api_response({"results": [log_row("A")]})
                bad, _ = api_response(data)
                with patch("requests.Session.request", side_effect=[first, bad]), self.assertRaises(FortiGateError):
                    self.client.get_wireless_client_logs(MAC, "root", 24)

    def test_real_http_pooling_and_decompressed_byte_limit(self):
        class Server(ThreadingHTTPServer):
            accepted = 0
            def get_request(self):
                result = super().get_request()
                self.accepted += 1
                return result

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_GET(self):
                if self.path.startswith("/large"):
                    data = {"results": ["x" * 10000]}
                elif "start=0" in self.path:
                    data = {"results": [log_row("A")]}
                else:
                    data = {"results": []}
                body = gzip.compress(json.dumps(data).encode())
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Encoding", "gzip")
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_args):
                pass

        with Server(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = FortiGateClient(f"http://127.0.0.1:{server.server_port}", "secret")
                self.assertEqual(len(client.get_wireless_client_logs(MAC, "root", 24)), 1)
                self.assertEqual(server.accepted, 1)
                client.get_wireless_client_logs(MAC, "root", 24)
                self.assertEqual(server.accepted, 2)
                with patch("twn_toolkit.fortigate.MAX_RESPONSE_BYTES", 1024), self.assertRaises(FortiGateLimitError):
                    client.request("GET", "/large")
            finally:
                server.shutdown()
                thread.join(timeout=5)
