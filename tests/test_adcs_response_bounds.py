import gzip
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest
import requests
from urllib3.response import HTTPResponse

from twn_toolkit.adcs_response_bounds import BoundedAdcsAdapter, AdcsResponseTooLarge, ADCS_RESPONSE_BYTES


@pytest.fixture
def web_server():
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass
        def do_GET(self):
            content = b'x' * (ADCS_RESPONSE_BYTES + 1) if self.path != '/small' else b'valid body'
            compressed = self.path == '/gzip'
            if compressed:
                content = gzip.compress(content)
            self.send_response(401 if self.path == '/challenge' else 200)
            self.send_header('Content-Length', str(len(content)))
            if compressed:
                self.send_header('Content-Encoding', 'gzip')
            if self.path == '/challenge':
                self.send_header('WWW-Authenticate', 'NTLM')
            self.end_headers()
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_port)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)


@pytest.mark.parametrize('path', ['/large', '/gzip', '/challenge'])
def test_adapter_bounds_actual_decoded_http_bodies(web_server, path):
    with requests.Session() as session:
        session.mount('http://', BoundedAdcsAdapter())
        if path == '/challenge':
            from requests_ntlm import HttpNtlmAuth
            session.auth = HttpNtlmAuth('example\\user', 'fixture-password')
        with pytest.raises(AdcsResponseTooLarge, match='4 MiB'):
            session.get(web_server + path, timeout=2)
        assert session.get(web_server + '/small', timeout=2).content == b'valid body'


def test_adapter_preserves_raw_identity_and_does_not_preconsume_channel_binding_socket():
    raw = HTTPResponse(body=io.BytesIO(b'hello'), status=200, preload_content=False)
    request = requests.Request('GET', 'https://pki.example.test').prepare()
    response = BoundedAdcsAdapter().build_response(request, raw)
    assert response.raw is raw
    assert raw.tell() == 0
    assert response.content == b'hello'


def test_stream_limit_is_cumulative_across_partial_consumption():
    raw = HTTPResponse(body=io.BytesIO(b'x' * (ADCS_RESPONSE_BYTES + 1)), preload_content=False)
    response = BoundedAdcsAdapter().build_response(requests.Request('GET', 'https://pki.example.test').prepare(), raw)
    stream = response.iter_content(chunk_size=4096)
    assert len(next(stream)) == 4096
    with pytest.raises(AdcsResponseTooLarge):
        list(stream)
    assert raw.closed


@pytest.mark.parametrize('oversized_challenge', [False, True])
def test_tls_ntlm_channel_binding_and_intermediate_challenge_bound(tmp_path, monkeypatch, oversized_challenge):
    import base64
    from datetime import datetime, timedelta, timezone
    import hashlib
    import ipaddress
    import ssl
    import spnego
    from spnego.channel_bindings import GssChannelBindings
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from requests_ntlm import HttpNtlmAuth

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .sign(key, hashes.SHA256()))
    cert_path = tmp_path / 'tls.pem'; cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = tmp_path / 'tls.key'; key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    credentials = tmp_path / 'ntlm-users'; credentials.write_text('EXAMPLE:user:fixture-password\n')
    monkeypatch.setenv('NTLM_USER_FILE', str(credentials))
    binding = GssChannelBindings(application_data=b'tls-server-end-point:' + hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest())
    steps = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass
        def do_GET(self):
            header = self.headers.get('Authorization', '')
            if not header:
                steps.append(0); status, challenge, body = 401, 'NTLM', b'Authenticate'
            else:
                token = base64.b64decode(header.split()[1]); kind = int.from_bytes(token[8:12], 'little')
                steps.append(kind)
                if kind == 1:
                    self.context = spnego.server(protocol='ntlm', channel_bindings=binding)
                output = self.context.step(token)
                if output:
                    status, challenge = 401, 'NTLM ' + base64.b64encode(output).decode()
                    body = b'x' * (ADCS_RESPONSE_BYTES + 1) if oversized_challenge else b'Challenge'
                else:
                    assert self.context.complete
                    status, challenge, body = 200, '', b'Authenticated with TLS channel binding'
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            if challenge:
                self.send_header('WWW-Authenticate', challenge)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        with requests.Session() as session:
            session.auth = HttpNtlmAuth('EXAMPLE\\user', 'fixture-password')
            session.mount('https://', BoundedAdcsAdapter())
            if oversized_challenge:
                with pytest.raises(AdcsResponseTooLarge):
                    session.get(f'https://127.0.0.1:{server.server_port}/', verify=str(cert_path), timeout=3)
                assert steps == [0, 1]
            else:
                response = session.get(f'https://127.0.0.1:{server.server_port}/', verify=str(cert_path), timeout=3)
                assert response.status_code == 200
                assert response.content == b'Authenticated with TLS channel binding'
                assert steps == [0, 1, 3]
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)


def test_primary_and_direct_backend_adapters_bound_authentication_responses():
    from twn_toolkit.certificate_automation import AdcsWebEnrollmentProvider, _DirectAddressAdapter, _request_error
    provider = AdcsWebEnrollmentProvider({'enrollment_url': 'https://pki.example.test/certsrv'}, 'user', 'password')
    try:
        assert isinstance(provider.session.get_adapter('https://pki.example.test/'), BoundedAdcsAdapter)
        assert isinstance(_DirectAddressAdapter('pki.example.test'), BoundedAdcsAdapter)
        assert '4 MiB' in _request_error(AdcsResponseTooLarge('fixture'))
    finally:
        provider.session.close()
