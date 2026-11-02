"""Synthetic API admission and transient-response contracts; never outbound."""
from unittest.mock import Mock
import pytest
from twn_toolkit import create_app

RESULT = {'status': 200, 'reason': 'PrivateRemoteReasonFixture', 'elapsed_ms': 1, 'bytes': 12,
          'resolved_addresses': [], 'request_headers': {}, 'response_headers': {},
          'body': 'PrivateResponseFixture', 'truncated': False, 'redirect': ''}

@pytest.fixture
def isolated(tmp_path, monkeypatch):
    boundaries = []
    for target in ('socket.getaddrinfo', 'socket.create_connection', 'requests.request', 'subprocess.Popen'):
        mock = Mock(side_effect=AssertionError('Unexpected outbound boundary: ' + target))
        monkeypatch.setattr(target, mock); boundaries.append(mock)
    app = create_app(str(tmp_path)); app.testing = True
    sender = Mock(return_value=RESULT.copy())
    monkeypatch.setattr('twn_toolkit.api_request_routes.send_api_request', sender)
    yield app.test_client(), sender, tmp_path
    for mock in boundaries: mock.assert_not_called()
    app.extensions['remote_session_manager'].close()

def compose(client, **changes):
    token = client.get('/tools/api-request/admission').json['token']
    values = dict(admission_token=token, method='POST', url='https://fixture.test/PrivatePath?PrivateQuery',
                  headers='Authorization: PrivateHeaderFixture', body='PrivateBodyFixture', timeout='1',
                  verify_tls='on', write_consent='yes')
    values.update(changes)
    return values

def send(client, values):
    return client.post('/tools/api-request', data=values, headers={'Accept': 'application/json'})

def test_repeated_admission_sends_once_and_never_saves_payload(isolated):
    client, sender, path = isolated
    values = compose(client)
    first = send(client, values); second = send(client, values)
    assert first.status_code == 200 and first.json['dispatched'] is True
    assert second.status_code == 409 and second.json['dispatched'] is False
    assert sender.call_count == 1
    assert first.json['result']['body'] == RESULT['body']
    receipt = client.get(first.json['receipt_url'])
    assert receipt.status_code == 200 and b'HTTP 200' in receipt.data
    assert b'PrivateResponseFixture' not in receipt.data
    for database in path.glob('*.sqlite3'):
        raw = database.read_bytes()
        for secret in (b'PrivateHeaderFixture', b'PrivateBodyFixture', b'PrivateResponseFixture', b'PrivatePath', b'PrivateQuery', b'PrivateRemoteReasonFixture'):
            assert secret not in raw, database.name

@pytest.mark.parametrize('changes', [{'write_consent': ''}, {'timeout': 'bad'}, {'headers': 'Invalid line'}])
def test_validation_does_not_consume_or_send(isolated, changes):
    client, sender, _ = isolated; values = compose(client)
    invalid = dict(values, **changes)
    response = send(client, invalid)
    assert response.status_code == 400 and response.json['dispatched'] is False
    sender.assert_not_called()
    assert send(client, values).json['dispatched'] is True
    assert sender.call_count == 1

def test_native_post_redirect_receipt_refresh_never_sends(isolated):
    client, sender, _ = isolated
    response = client.post('/tools/api-request', data=compose(client))
    assert response.status_code == 303
    for _ in range(2):
        receipt = client.get(response.location)
        assert receipt.status_code == 200
        assert b'contents were not saved' in receipt.data
    assert sender.call_count == 1

def test_uncertain_failure_redacts_exception_and_never_replays(isolated):
    client, sender, path = isolated
    from twn_toolkit.network_tools import ToolInputError
    sender.side_effect = ToolInputError('PrivateQuery PrivateHeaderFixture PrivateBodyFixture')
    values = compose(client); response = send(client, values)
    assert response.json['dispatched'] is True and response.json['result'] is None
    assert 'may already have executed' in response.json['error']
    send(client, values)
    assert sender.call_count == 1
    for database in path.glob('*.sqlite3'):
        assert b'PrivateHeaderFixture' not in database.read_bytes()

def login(client, user):
    import time
    with client.session_transaction() as session:
        session.update(user_id=user['id'], session_version=user['session_version'], last_seen=int(time.time()))

def test_foreign_owner_cannot_claim_or_read(isolated):
    client, sender, path = isolated
    from twn_toolkit.auth import AuthStore
    auth = AuthStore(str(path))
    admin = auth.create_user('fixture-admin', 'FixturePassword123!', is_admin=True)
    other_user = auth.create_user('fixture-other', 'FixturePassword123!', is_admin=True)
    client.application.testing = False
    login(client, admin)
    values = compose(client)
    other = client.application.test_client(); login(other, other_user)
    assert send(other, values).json['dispatched'] is False
    sender.assert_not_called()
    first = send(client, values)
    assert other.get(first.json['receipt_url']).status_code == 404

@pytest.mark.parametrize('allowed', [True, False])
def test_current_tool_permission_covers_issue_and_send(isolated, allowed):
    client, sender, path = isolated
    from twn_toolkit.auth import AuthStore
    auth = AuthStore(str(path)); auth.create_user('fixture-admin', 'FixturePassword123!', is_admin=True)
    grant = auth.save_access_profile(name='API grant', tool_ids=['tools.api_request'])
    user = auth.create_user('fixture-member', 'FixturePassword123!', access_profile_ids=[grant['id']] if allowed else [])
    client.application.testing = False; login(client, user)
    response = client.get('/tools/api-request/admission')
    assert response.status_code == (200 if allowed else 403)
    if not allowed:
        assert send(client, dict(admission_token='0'*64)).status_code == 403
        sender.assert_not_called()


def test_unexpected_sender_exception_and_recording_failures_do_not_replay(isolated, monkeypatch):
    client, sender, path = isolated
    sender.side_effect = RuntimeError('PrivateQuery PrivateHeaderFixture')
    response = send(client, compose(client))
    assert response.json['dispatched'] is True and response.json['result'] is None
    assert 'PrivateQuery' not in response.get_data(as_text=True)
    assert client.get(response.json['receipt_url']).status_code == 200
    sender.side_effect = None
    monkeypatch.setattr('twn_toolkit.api_request_routes.annotate_tool_run', Mock(side_effect=RuntimeError('PrivateQuery')))
    confirmed = send(client, compose(client))
    assert confirmed.json['result']['status'] == 200
    assert 'recording could not be confirmed' in confirmed.json['recording_warning']
    page = client.get(confirmed.json['receipt_url'])
    assert b'HTTP 200' in page.data
    assert sender.call_count == 2


def test_next_token_capacity_cannot_discard_confirmed_response(isolated, monkeypatch):
    client, sender, _ = isolated
    values = compose(client)
    from twn_toolkit.api_request_receipts import ApiRequestReceiptStore, ReceiptCapacityError
    monkeypatch.setattr(ApiRequestReceiptStore, 'issue', Mock(side_effect=ReceiptCapacityError('busy')))
    response = send(client, values)
    assert response.status_code == 200
    assert response.json['next_token'] == ''
    assert response.json['result']['status'] == 200
    assert sender.call_count == 1


@pytest.mark.parametrize('field', ['method', 'timeout'])
def test_invalid_metadata_cannot_persist_secret_markers(isolated, field):
    client, sender, path = isolated
    marker = 'PrivateInvalidMetadataFixture'
    response = send(client, compose(client, **{field: marker}))
    assert response.status_code == 400 and response.json['dispatched'] is False
    sender.assert_not_called()
    for database in path.glob('*.sqlite3'):
        assert marker.encode() not in database.read_bytes(), database.name
