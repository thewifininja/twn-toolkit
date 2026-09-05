from __future__ import annotations

import http.client
import socket
import ssl
import time

import pytest

from twn_toolkit import distributed_transport as transport


@pytest.fixture
def listener(tmp_path, monkeypatch):
    monkeypatch.setattr(transport, "MAX_LISTENER_CONNECTIONS", 2)
    monkeypatch.setattr(transport, "LISTENER_HANDSHAKE_TIMEOUT_SECONDS", 0.5, raising=False)
    monkeypatch.setattr(transport, "LISTENER_READ_TIMEOUT_SECONDS", 0.5, raising=False)
    monkeypatch.setattr(transport, "LISTENER_WRITE_TIMEOUT_SECONDS", 0.5, raising=False)
    server = transport.EnrollmentServer(tmp_path, "127.0.0.1", 0)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _context(server):
    return ssl.create_default_context(cafile=str(server.pki_store.ca_cert_path))


def _connect(server):
    raw = socket.create_connection(("127.0.0.1", server.port), timeout=2)
    try:
        return _context(server).wrap_socket(raw, server_hostname="127.0.0.1")
    except BaseException:
        raw.close()
        raise


def _get(server, path="/"):
    client = http.client.HTTPSConnection("127.0.0.1", server.port, timeout=2, context=_context(server))
    try:
        client.request("GET", path)
        response = client.getresponse()
        response.read()
        return response.status
    finally:
        client.close()


def test_silent_tcp_peer_does_not_block_healthy_tls_clients(listener):
    assert _get(listener) == 404
    with socket.create_connection(("127.0.0.1", listener.port), timeout=2):
        assert _get(listener) == 404


def test_silent_handshake_expires_and_releases_capacity(listener):
    with socket.create_connection(("127.0.0.1", listener.port), timeout=2) as silent:
        assert silent.recv(1) == b""
    assert _get(listener) == 404


@pytest.mark.parametrize("partial", [
    b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Unfinished: ",
    b"POST /v1/enrollment HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n{",
], ids=["headers", "body"])
def test_incomplete_http_requests_expire_without_holding_slots(listener, partial):
    with _connect(listener) as connection:
        connection.sendall(partial)
        assert connection.recv(1) == b""
    assert _get(listener) == 404


def test_invalid_tls_releases_its_slot(listener):
    with socket.create_connection(("127.0.0.1", listener.port), timeout=2) as connection:
        connection.sendall(b"This is not TLS.\r\n")
        try:
            assert connection.recv(1024) == b""
        except ConnectionResetError:
            pass
    assert _get(listener) == 404


def test_request_read_deadline_does_not_shorten_server_side_wait(listener, monkeypatch):
    def slow_status(_session_id, _token):
        time.sleep(0.8)
        return {"state": "pending"}

    monkeypatch.setattr(listener, "enrollment_status", slow_status)
    assert _get(listener, "/v1/enrollment/test-session") == 200


def test_slow_trickle_does_not_reset_the_absolute_read_budget(monkeypatch):
    import io

    clock = [0.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: clock[0])

    class TrickleSocket:
        timeout = None

        def settimeout(self, value):
            self.timeout = value

        def recv_into(self, buffer):
            # Each byte takes 0.4 seconds: an inactivity timeout would let all
            # ten arrive, while a total one-second budget must stop the read.
            if self.timeout < 0.4:
                clock[0] += self.timeout
                raise TimeoutError("read budget exhausted")
            clock[0] += 0.4
            buffer[0] = ord("x")
            return 1

    reader = io.BufferedReader(transport._DeadlineSocketReader(TrickleSocket(), 1.0))
    try:
        with pytest.raises(TimeoutError):
            reader.read(10)
        assert clock[0] <= 1.0
    finally:
        reader.close()


def test_connection_limit_applies_before_tls_negotiation(listener, monkeypatch):
    monkeypatch.setattr(transport, "LISTENER_HANDSHAKE_TIMEOUT_SECONDS", 3)
    first = socket.create_connection(("127.0.0.1", listener.port), timeout=2)
    second = socket.create_connection(("127.0.0.1", listener.port), timeout=2)
    try:
        with pytest.raises((ConnectionError, ssl.SSLError)):
            with _connect(listener):
                pytest.fail("Excess connection completed a TLS handshake.")
    finally:
        first.close()
        second.close()
    # Slot release runs in each handler's finally block; allow it to catch up.
    deadline = time.monotonic() + 2
    while True:
        try:
            assert _get(listener) == 404
            break
        except (ConnectionError, ssl.SSLError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def test_backend_os_errors_are_reported_instead_of_hidden_as_disconnects(listener, monkeypatch):
    from threading import Event

    reported = Event()

    def failing_status(_session_id, _token):
        raise OSError("Injected local storage failure")

    monkeypatch.setattr(listener, "enrollment_status", failing_status)
    monkeypatch.setattr(listener.httpd, "handle_error", lambda *_args: reported.set())
    with pytest.raises(http.client.RemoteDisconnected):
        _get(listener, "/v1/enrollment/test-session")
    assert reported.wait(2)
    assert _get(listener) == 404


def test_body_spanning_tls_records_reaches_the_handler_intact(listener, monkeypatch):
    import json

    payload = {"padding": "x" * 20000}
    received = []

    def begin(value, _address):
        received.append(value)
        return {"state": "pending"}

    monkeypatch.setattr(listener, "begin_enrollment", begin)
    client = http.client.HTTPSConnection("127.0.0.1", listener.port, timeout=2, context=_context(listener))
    try:
        client.request("POST", "/v1/enrollment", body=json.dumps(payload), headers={"Content-Type": "application/json"})
        response = client.getresponse()
        assert response.status == 201
        response.read()
    finally:
        client.close()
    assert received == [payload]


def test_stalled_response_reader_does_not_hold_a_worker_indefinitely(listener, monkeypatch):
    from threading import Event

    finished = Event()
    original = listener.httpd.finish_request

    def finish_request(connection, address):
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        try:
            original(connection, address)
        finally:
            finished.set()

    monkeypatch.setattr(listener.httpd, "finish_request", finish_request)
    monkeypatch.setattr(listener, "enrollment_status", lambda *_args: {"padding": "x" * (8 * 1024 * 1024)})
    with _connect(listener) as connection:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        connection.sendall(b"GET /v1/enrollment/test-session HTTP/1.0\r\n\r\n")
        assert finished.wait(3), "Response write did not honor its timeout."
    assert _get(listener) == 404
