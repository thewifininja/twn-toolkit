from __future__ import annotations

import io
from unittest.mock import Mock, patch

import pytest

from twn_toolkit import create_app
from twn_toolkit.network_tools import ToolInputError, radius_authenticate
from twn_toolkit.radius_eap_tools import EAP_DISABLED_REASON, eapol_test_available, radius_eap_authenticate
from twn_toolkit.investigations import InvestigationStore


@pytest.mark.parametrize('protocol', ['peap-mschapv2', 'eap-tls'])
def test_eap_cannot_execute_even_when_binary_is_installed(protocol):
    with patch('shutil.which', return_value='/usr/bin/eapol_test') as binary, patch('subprocess.run') as run, patch('socket.getaddrinfo') as resolve, patch('tempfile.TemporaryDirectory') as directory:
        assert not eapol_test_available()
        with pytest.raises(ToolInputError, match='temporarily disabled'):
            radius_eap_authenticate([], {}, protocol, timeout=3, ca_certificate=b'private-ca', private_key=b'private-key')
        binary.assert_not_called(); run.assert_not_called(); resolve.assert_not_called(); directory.assert_not_called()


@pytest.mark.parametrize('protocol', ['peap-mschapv2', 'eap-tls'])
def test_general_radius_api_does_not_bypass_eap_disablement(protocol):
    with patch('twn_toolkit.network_tools._radius_authenticate_one') as authenticate:
        with pytest.raises(ToolInputError, match='PAP or CHAP'):
            radius_authenticate([], {}, protocol)
        authenticate.assert_not_called()


@pytest.mark.parametrize('protocol', ['peap-mschapv2', 'eap-tls', 'EAP-TLS'])
def test_old_form_post_is_rejected_without_authentication_or_secret_echo(tmp_path, monkeypatch, protocol):
    app = create_app(str(tmp_path)); app.testing = True; client = app.test_client()
    client.post('/tools/radius-test/profiles/servers', data={'name':'Lab','host':'192.0.2.1','secret':'server-secret','port':'1812'})
    client.post('/tools/radius-test/profiles/credentials', data={'name':'User','username':'test','password':'user-secret'})
    before = {path.name:path.read_bytes() for path in tmp_path.glob('radius*.json')}
    client.post('/investigations', data={'title':'EAP disabled'})
    authenticate = Mock(); monkeypatch.setattr('twn_toolkit.radius_routes.radius_authenticate', authenticate)
    response = client.post('/tools/radius-test', data={'protocol':protocol,'server_names':'Lab','credential_name':'User',
        'private_key_password':'key-secret', 'private_key':(io.BytesIO(b'private-key-material'), 'client.key'),
        'ca_certificate':(io.BytesIO(b'private-ca-material'), 'ca.crt')})
    assert response.status_code == 200
    assert EAP_DISABLED_REASON.encode() in response.data
    assert b'Choose PAP or CHAP' in response.data
    for secret in (b'server-secret', b'user-secret', b'key-secret', b'private-key-material', b'private-ca-material'):
        assert secret not in response.data
    authenticate.assert_not_called()
    assert before == {path.name:path.read_bytes() for path in tmp_path.glob('radius*.json')}
    cases = InvestigationStore(str(tmp_path)); case = cases.active_for_user('test-user')
    events = [e for e in cases.events_for_user(case['id'], 'test-user') if e['tool_id']=='tools.radius_test']
    assert len(events)==1 and events[0]['outcome']=='failed'
    assert not events[0]['details']['results']


def test_gui_keeps_supported_protocols_and_removes_eap_uploads(tmp_path):
    app=create_app(str(tmp_path));app.testing=True
    page=app.test_client().get('/tools/radius-test').data
    assert b'<option value="pap"' in page and b'<option value="chap"' in page
    assert b'<option value="peap-mschapv2" disabled>' in page
    assert b'<option value="eap-tls" disabled>' in page
    assert b'name="private_key"' not in page and b'name="ca_certificate"' not in page
    assert b'Installing <code>eapol_test</code> will not enable this feature' in page
