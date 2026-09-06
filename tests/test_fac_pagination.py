from __future__ import annotations

import gzip
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import requests

from twn_toolkit.fortiauthenticator import FortiAuthenticatorClient, FortiAuthenticatorError


def response_for(data, status=200):
    body = json.dumps(data).encode()
    response = Mock(status_code=status, reason="Test", headers={})
    response.iter_content.return_value = iter([body])
    return response, len(body)


class FACPaginationTests(unittest.TestCase):
    def setUp(self):
        self.client = FortiAuthenticatorClient("https://fac.example", "user", "secret")

    def test_sessions_are_scoped_and_closed_after_success_and_failure(self):
        first, _ = response_for({"objects": [{"id": 1}], "meta": {"next": "?offset=1"}})
        second, _ = response_for({"objects": [{"id": 2}]})
        with patch("requests.Session", autospec=True) as factory:
            session = factory.return_value.__enter__.return_value
            session.request.side_effect = [first, second]
            self.assertEqual(len(self.client.get_all_mac_devices()), 2)
            self.assertEqual(factory.call_count, 1)
            self.assertEqual(session.request.call_count, 2)
            factory.return_value.__exit__.assert_called_once()
            session.request.side_effect = requests.ConnectionError("disconnected")
            with self.assertRaises(FortiAuthenticatorError):
                self.client.get_all_mac_devices()
            self.assertEqual(factory.call_count, 2)
            self.assertEqual(factory.return_value.__exit__.call_count, 2)
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_response_budget_stops_reading_and_closes_response(self):
        response = Mock(status_code=200)
        consumed = []

        def chunks(**_kwargs):
            for chunk in [b"1234", b"5678", b"never read"]:
                consumed.append(chunk)
                yield chunk

        response.iter_content.side_effect = chunks
        with patch("requests.Session.request", return_value=response), patch(
            "twn_toolkit.fortiauthenticator.MAX_RESPONSE_BYTES", 5
        ), self.assertRaisesRegex(FortiAuthenticatorError, "byte budget"):
            self.client.get_all_mac_devices()
        self.assertEqual(consumed, [b"1234", b"5678"])
        response.close.assert_called_once()

    def test_collection_byte_budget_and_exact_boundary(self):
        for extra in (0, -1):
            with self.subTest(extra=extra):
                first, n1 = response_for({"objects": [{"id": 1}], "meta": {"next": "?offset=1"}})
                second, n2 = response_for({"objects": [{"id": 2}]})
                with patch("requests.Session.request", side_effect=[first, second]), patch(
                    "twn_toolkit.fortiauthenticator.MAX_COLLECTION_BYTES", n1 + n2 + extra
                ):
                    if extra:
                        with self.assertRaisesRegex(FortiAuthenticatorError, "byte budget"):
                            self.client.get_all_mac_devices()
                    else:
                        self.assertEqual(len(self.client.get_all_mac_devices()), 2)
                first.close.assert_called_once()
                second.close.assert_called_once()

    def test_object_budget_counts_all_pages_and_rejects_partial_collection(self):
        first, _ = response_for({"objects": [{"id": 1}], "meta": {"next": "?offset=1"}})
        second, _ = response_for({"objects": [{"id": 2}, {"id": 3}]})
        with patch("requests.Session.request", side_effect=[first, second]), patch(
            "twn_toolkit.fortiauthenticator.MAX_COLLECTION_OBJECTS", 2
        ), self.assertRaisesRegex(FortiAuthenticatorError, "exceeded 2 objects"):
            self.client.get_all_mac_devices()
        second.close.assert_called_once()

    def test_page_budget_and_loop_detection(self):
        for cap, message in [(1, "exceeded 1 pages"), (10, "repeating")]:
            with self.subTest(cap=cap):
                response, _ = response_for({"objects": [], "meta": {"next": "/api/v1/macdevices/"}})
                with patch("requests.Session.request", return_value=response) as request, patch(
                    "twn_toolkit.fortiauthenticator.MAX_PAGINATION_PAGES", cap
                ), self.assertRaisesRegex(FortiAuthenticatorError, message):
                    self.client.get_all_mac_devices()
                self.assertEqual(request.call_count, 1)

    def test_invalid_collection_shapes_are_not_treated_as_empty_success(self):
        for data in [{}, {"objects": None}, {"objects": [1]}, {"objects": [], "meta": []},
                     {"objects": [], "meta": {"next": 42}}, []]:
            with self.subTest(data=data):
                response, _ = response_for(data)
                with patch("requests.Session.request", return_value=response), self.assertRaises(FortiAuthenticatorError):
                    self.client.get_all_mac_devices()
                response.close.assert_called_once()

    def test_stream_errors_and_tls_errors_are_wrapped_without_retries(self):
        response = Mock(status_code=200)
        response.iter_content.side_effect = requests.ConnectionError("stream interrupted")
        with patch("requests.Session.request", return_value=response) as request, self.assertRaises(FortiAuthenticatorError):
            self.client.delete_mac_device("42")
        self.assertEqual(request.call_count, 1)
        response.close.assert_called_once()
        with patch("requests.Session.request", side_effect=requests.exceptions.SSLError("bad cert")), self.assertRaisesRegex(
            FortiAuthenticatorError, "TLS verification failed"
        ):
            self.client.test_connection()

    def test_redirects_are_rejected_before_reading_the_body(self):
        response = Mock(status_code=302)
        with patch("requests.Session.request", return_value=response) as request, self.assertRaisesRegex(
            FortiAuthenticatorError, "API redirect"
        ):
            self.client.get_all_mac_devices()
        self.assertFalse(request.call_args.kwargs["allow_redirects"])
        response.iter_content.assert_not_called()
        response.close.assert_called_once()

    def test_real_http_reuses_connection_and_bounds_decompressed_data(self):
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
                    data = {"objects": [{"value": "x" * 10_000}]}
                elif "offset" in self.path:
                    data = {"objects": [{"id": 2}]}
                else:
                    data = {"objects": [{"id": 1}], "meta": {"next": "/api/v1/macdevices/?offset=1"}}
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
                client = FortiAuthenticatorClient(f"http://127.0.0.1:{server.server_port}", "u", "p")
                self.assertEqual(client.get_all_mac_devices(), [{"id": 1}, {"id": 2}])
                self.assertEqual(server.accepted, 1)
                client.get_all_mac_devices()
                self.assertEqual(server.accepted, 2)
                with patch("twn_toolkit.fortiauthenticator.MAX_RESPONSE_BYTES", 1024), self.assertRaisesRegex(
                    FortiAuthenticatorError, "byte budget"
                ):
                    client.get_all("/large")
            finally:
                server.shutdown()
                thread.join(timeout=5)
