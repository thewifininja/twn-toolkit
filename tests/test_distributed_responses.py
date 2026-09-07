from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from flask import Flask, Response

from twn_toolkit.distributed_http import MAX_TUNNEL_BODY_BYTES, _dispatch
from twn_toolkit.distributed_jobs import DistributedJobStore
from twn_toolkit.distributed_operations import OperationReceipts, execute_owned
from twn_toolkit.distributed_response import response_writer
from twn_toolkit.distributed_response_http import build_agent_response
from twn_toolkit.distributed_response_policy import RESPONSE_CHUNK_BYTES, RESPONSE_LIMITS
from twn_toolkit.distributed_transport import EnrollmentClient, EnrollmentServer, EnrollmentTransportError
from twn_toolkit.operational import OperationalSettingsStore

BLOCK = b'private-response-canary\x00\xff' * 1024


def started(store, *, capability='system.http.tunnel', owner='owner', agent='agent'):
    store.enqueue(agent_id=agent, requester_id=owner, capability_id=capability, capability_version='1')
    job = store.claim(agent)[0]
    store.control(job['id'], agent_id=agent, attempt_token=job['attempt_token'], action='start')
    return job


def append(store, job, data=BLOCK, position=0, **overrides):
    values = dict(agent_id='agent', attempt_token=job['attempt_token'], activation_id=job['activation_id'],
                  position=position, body=base64.b64encode(data).decode())
    values.update(overrides)
    return store.append_response_chunk(job['id'], **values)


def descriptor(data):
    return dict(body_transfer=1, body_size=len(data), body_sha256=hashlib.sha256(data).hexdigest(),
                status=200, headers=[['Content-Type', 'application/octet-stream']])


def finish(store, job, output, **overrides):
    values = dict(agent_id='agent', attempt_token=job['attempt_token'], activation_id=job['activation_id'],
                  state='succeeded', output=output)
    values.update(overrides)
    return store.complete(job['id'], **values)


def chunk_count(store):
    with sqlite3.connect(store.path) as db:
        return db.execute('SELECT COUNT(*) FROM distributed_response_chunks').fetchone()[0]


def test_encrypted_ordered_idempotent_chunks_and_one_time_delivery(tmp_path):
    store = DistributedJobStore(tmp_path)
    job = started(store)
    assert append(store, job) == {'accepted': True}
    assert append(store, job) == {'accepted': True}
    with pytest.raises(ValueError, match='conflicts'):
        append(store, job, b'changed')
    with pytest.raises(ValueError, match='in order'):
        append(store, job, position=2)
    append(store, job, b'last', 1)
    output = descriptor(BLOCK + b'last')
    completed = finish(store, job, output)
    assert BLOCK not in store.path.read_bytes()
    assert base64.b64encode(BLOCK) not in store.path.read_bytes()
    reopened = DistributedJobStore(tmp_path)
    with pytest.raises(ValueError, match='unavailable'):
        reopened.consume_response(job['id'], 'other')
    response = build_agent_response(reopened, completed, 'owner')
    with pytest.raises(ValueError, match='unavailable'):
        reopened.consume_response(job['id'], 'owner')
    assert response.content_length == len(BLOCK) + 4
    assert response.get_data() == BLOCK + b'last'
    response.close()
    assert chunk_count(store) == 0
    assert reopened.get(job['id'])['output'] is None
    assert finish(store, job, output)['output'] is None
    assert reopened.claim('agent') == []


@pytest.mark.parametrize('values', [dict(agent_id='other'), dict(attempt_token='bad'),
                                   dict(activation_id='22' * 16), dict(position=True), dict(position=-1),
                                   dict(position=4096), dict(body='not-base64'), dict(body=''),
                                   dict(body=base64.b64encode(b'x' * (RESPONSE_CHUNK_BYTES + 1)).decode())])
def test_chunk_rejects_invalid_ownership_and_input(tmp_path, values):
    store = DistributedJobStore(tmp_path)
    with pytest.raises(ValueError):
        append(store, started(store), **values)
    assert chunk_count(store) == 0


@pytest.mark.parametrize('state', ['claimed', 'cancel_requested', 'unknown', 'succeeded', 'failed'])
def test_chunk_requires_running_gui_attempt(tmp_path, state):
    store = DistributedJobStore(tmp_path)
    job = started(store)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE distributed_jobs SET state=?', (state,))
    with pytest.raises(ValueError, match='running GUI'):
        append(store, job)
    assert chunk_count(store) == 0


def test_non_gui_and_expired_lease_reject_transfer(tmp_path):
    store = DistributedJobStore(tmp_path)
    job = started(store, capability='system.identity')
    with pytest.raises(ValueError, match='GUI'):
        append(store, job)
    job = started(store)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE distributed_jobs SET lease_expires_at=0 WHERE id=?', (job['id'],))
    with pytest.raises(ValueError, match='running GUI'):
        append(store, job)
    assert store.get(job['id'])['state'] == 'unknown'


@pytest.mark.parametrize('change', [dict(body_size=123), dict(body_sha256='0' * 64),
                                   dict(body_transfer=True), dict(body_size=True)])
def test_completion_verifies_descriptor_before_publishing(tmp_path, change):
    store = DistributedJobStore(tmp_path)
    job = started(store)
    append(store, job)
    with pytest.raises(ValueError):
        finish(store, job, {**descriptor(BLOCK), **change})
    assert store.get(job['id'])['state'] == 'running'
    assert finish(store, job, descriptor(BLOCK))['state'] == 'succeeded'


def test_missing_and_cross_job_ciphertext_are_rejected(tmp_path):
    store = DistributedJobStore(tmp_path)
    first = started(store)
    second = started(store)
    append(store, first)
    with pytest.raises(ValueError, match='verification'):
        finish(store, second, descriptor(BLOCK))
    append(store, second)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE distributed_response_chunks SET payload=(SELECT payload FROM distributed_response_chunks WHERE job_id=?) WHERE job_id=?', (first['id'], second['id']))
    with pytest.raises(ValueError):
        finish(store, second, descriptor(BLOCK))


def test_expiry_cleanup_cannot_restart_transfer_window(tmp_path):
    store = DistributedJobStore(tmp_path)
    job = started(store)
    append(store, job)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE distributed_response_chunks SET expires=0')
        db.execute('UPDATE distributed_response_transfers SET expires=0')
    store.prune_payloads()
    assert chunk_count(store) == 0
    with pytest.raises(ValueError, match='expired'):
        append(store, job)
    with pytest.raises(ValueError):
        finish(store, job, descriptor(BLOCK))
    assert store.get(job['id'])['state'] == 'running'


@pytest.mark.parametrize('cleanup', ['failed', 'payload_expiry', 'delete'])
def test_abandoned_chunks_cleanup_preserves_outcome(tmp_path, cleanup):
    store = DistributedJobStore(tmp_path)
    job = started(store)
    append(store, job)
    finish(store, job, descriptor(BLOCK), state='failed' if cleanup == 'failed' else 'succeeded')
    if cleanup == 'delete':
        assert not store.delete(job['id'], requester_id='other')
        assert chunk_count(store) == 1
        assert store.delete(job['id'], requester_id='owner')
    elif cleanup == 'payload_expiry':
        with sqlite3.connect(store.path) as db:
            db.execute('UPDATE distributed_jobs SET payload_expires_at=0')
    store.prune_payloads()
    assert chunk_count(store) == 0
    if cleanup != 'delete':
        assert store.get(job['id'])['state'] == ('failed' if cleanup == 'failed' else 'succeeded')


def test_early_browser_close_discards_unread_chunks(tmp_path):
    store = DistributedJobStore(tmp_path)
    job = started(store)
    append(store, job)
    response = build_agent_response(store, finish(store, job, descriptor(BLOCK)), 'owner')
    response.close()
    assert chunk_count(store) == 0
    assert store.get(job['id'])['output'] is None


def test_delivery_does_not_hold_database_lock_between_chunks(tmp_path):
    store = DistributedJobStore(tmp_path)
    job = started(store)
    append(store, job)
    append(store, job, BLOCK, 1)
    finish(store, job, descriptor(BLOCK * 2))
    iterator, _ = store.consume_response(job['id'], 'owner')
    assert next(iterator) == BLOCK
    # A separate writer must progress while the browser is idle.
    with ThreadPoolExecutor(max_workers=1) as pool:
        other = pool.submit(started, DistributedJobStore(tmp_path)).result(timeout=2)
    assert other['id'] != job['id']
    assert next(iterator) == BLOCK
    iterator.close()
    assert chunk_count(store) == 0


@pytest.mark.parametrize('bulk', [False, True])
def test_concurrent_consumers_only_one_claims_output(tmp_path, bulk):
    store = DistributedJobStore(tmp_path)
    job = started(store)
    if bulk:
        append(store, job)
    finish(store, job, descriptor(BLOCK) if bulk else dict(body=base64.b64encode(BLOCK).decode(), status=200))
    def consume(_):
        try:
            return DistributedJobStore(tmp_path).consume_response(job['id'], 'owner')
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(consume, range(2)))
    successful = [result for result in results if result]
    assert len(successful) == 1
    content = successful[0][0]
    assert (b''.join(content) if bulk else content) == BLOCK


def test_size_quota_and_free_disk_admission(tmp_path, monkeypatch):
    store = DistributedJobStore(tmp_path)
    job = started(store)
    policy = store.operational_store.get()
    monkeypatch.setattr(store.operational_store, 'get', lambda: policy)
    policy['distributed_response_mib'] = len(BLOCK) / 1024**2
    append(store, job)
    with pytest.raises(ValueError, match='size limit'):
        append(store, job, b'x', 1)
    policy['distributed_response_mib'] = 1
    policy['distributed_response_quota_mib'] = 1 / 1024**2
    with pytest.raises(ValueError, match='quota'):
        append(store, job, b'x', 1)
    policy['distributed_response_quota_mib'] = 128
    monkeypatch.setattr('twn_toolkit.distributed_response.shutil.disk_usage', lambda _: SimpleNamespace(free=0))
    with pytest.raises(ValueError, match='free-disk'):
        append(store, job, b'x', 1)
    assert chunk_count(store) == 1


def test_independent_stores_share_atomic_aggregate_quota(tmp_path):
    first = DistributedJobStore(tmp_path)
    jobs = [started(first), started(first)]
    # Enough encrypted space for one block, but not two.
    encrypted_size = len(first._cipher.seal(base64.b64encode(BLOCK).decode(), 'measurement'))
    def upload(job):
        store = DistributedJobStore(tmp_path)
        policy = store.operational_store.get()
        policy['distributed_response_quota_mib'] = (encrypted_size + 256) / 1024**2
        with patch.object(store.operational_store, 'get', return_value=policy):
            try:
                append(store, job)
                return True
            except ValueError as exc:
                assert 'quota' in str(exc)
                return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(upload, jobs)) == [False, True]
    assert chunk_count(first) == 1


@pytest.mark.parametrize('size', [0, 10, MAX_TUNNEL_BODY_BYTES, MAX_TUNNEL_BODY_BYTES + 1, 1024 * 1024])
def test_dispatch_frames_binary_body_without_get_data(size):
    body = (BLOCK * (size // len(BLOCK) + 1))[:size]
    app = Flask(__name__)
    closed = []
    @app.get('/download')
    def download():
        response = Response((body[start:start + 7919] for start in range(0, len(body), 7919)),
                            headers={'Content-Disposition': 'attachment; filename="fixture.bin"'})
        response.call_on_close(lambda: closed.append(True))
        return response
    pieces = []
    with response_writer(lambda position, encoded: pieces.append((position, base64.b64decode(encoded)))):
        output = _dispatch(app.test_client(), '/download', {}, transfer={'version': 1, 'max_bytes': 2 * 1024**2})
    assert closed == [True]
    if size > MAX_TUNNEL_BODY_BYTES:
        assert [pos for pos, _ in pieces] == list(range(len(pieces)))
        assert all(0 < len(data) <= RESPONSE_CHUNK_BYTES for _, data in pieces)
        assert b''.join(data for _, data in pieces) == body
        assert output['body_sha256'] == hashlib.sha256(body).hexdigest()
        assert output['body_size'] == size
        assert len(json.dumps(output)) < 1024
    else:
        assert not pieces
        assert base64.b64decode(output['body']) == body
    assert ['Content-Disposition', 'attachment; filename="fixture.bin"'] in output['headers']


def test_tiny_source_fragments_are_coalesced():
    class TinyResponse:
        status_code = 200
        headers = {}
        def iter_encoded(self):
            yield from (b'x' for _ in range(MAX_TUNNEL_BODY_BYTES + 1))
        def close(self):
            pass
    chunks = []
    with response_writer(lambda position, body: chunks.append(base64.b64decode(body))):
        _dispatch(SimpleNamespace(open=lambda *args, **kwargs: TinyResponse()), '/', {},
                  transfer={'version': 1, 'max_bytes': 1024**2})
    assert len(chunks) == 3
    assert sum(map(len, chunks)) == MAX_TUNNEL_BODY_BYTES + 1


@pytest.mark.parametrize('failure', ['oversize', 'writer', 'iteration'])
def test_dispatch_closes_response_without_replaying_on_transfer_failure(failure):
    app = Flask(__name__)
    calls = []
    closed = []
    def stream():
        for _ in range(5):
            yield b'x' * RESPONSE_CHUNK_BYTES
        if failure == 'iteration':
            raise OSError('stream failed')
    @app.post('/effect')
    def effect():
        calls.append(True)
        response = Response(stream())
        response.call_on_close(lambda: closed.append(True))
        return response
    def write(position, body):
        if failure == 'writer':
            raise ValueError('upload failed')
    with response_writer(write), pytest.raises((ValueError, OSError)):
        _dispatch(app.test_client(), '/effect', {'method': 'POST'},
                  transfer={'version': 1, 'max_bytes': 200000 if failure == 'oversize' else 1024**2})
    assert calls == closed == [True]


@pytest.mark.parametrize('key', RESPONSE_LIMITS)
def test_response_policy_is_persisted_and_validated(tmp_path, key):
    store = OperationalSettingsStore(str(tmp_path))
    default, low, high, _ = RESPONSE_LIMITS[key]
    assert store.get()[key] == default
    for value in [True, 1.5, low - 1, high + 1, 'invalid']:
        with pytest.raises(ValueError):
            store.save({key: value})
    store.save({key: str(low)})
    assert OperationalSettingsStore(str(tmp_path)).get()[key] == low


def test_enrolled_tls_response_transfer_receipt_and_no_reexecution(tmp_path):
    server = EnrollmentServer(tmp_path / 'mainframe', '127.0.0.1', 0)
    server.enrollment_window.open(5)
    server.start()
    body = BLOCK * 12
    calls = []
    app = Flask(__name__)
    @app.post('/effect')
    def effect():
        calls.append(True)
        return Response((body[offset:offset + 10001] for offset in range(0, len(body), 10001)),
                        status=206, headers={'Content-Type': 'application/octet-stream',
                                             'Content-Range': f'bytes 0-{len(body)-1}/{len(body)}'})
    try:
        agent_path = tmp_path / 'agent'
        client = EnrollmentClient(agent_path, f'https://127.0.0.1:{server.port}')
        client.begin('Download Agent')
        agent_id = server.agent_store.list('pending')[0]['id']
        server.agent_store.set_state(agent_id, 'approved')
        client.poll()
        queued = server.job_store.enqueue(agent_id=agent_id, requester_id='owner',
                    capability_id='system.http.tunnel', capability_version='1',
                    inputs={'path': '/effect', 'method': 'POST', 'response_transfer': {'version': 1, 'max_bytes': 1024**2}})
        job = client.interactive(wait_seconds=0)['requests'][0]
        def execute(instance, capability, version, inputs):
            return _dispatch(app.test_client(), inputs['path'], {'method': inputs['method']}, transfer=inputs['response_transfer'])
        execute_owned(agent_path, [job], client, 'interactive', execute)
        receipts = OperationReceipts(agent_path)
        result = receipts.pending('interactive', job['activation_id'])
        assert result[0]['state'] == 'succeeded', result
        assert result[0]['output']['body_size'] == len(body)
        assert len(json.dumps(result)) < 1024
        client.interactive(result, wait_seconds=0)
        completed = server.job_store.get(queued['id'])
        assert completed['state'] == 'succeeded'
        response = build_agent_response(server.job_store, completed, 'owner')
        assert response.status_code == 206
        assert response.headers['Content-Range'] == f'bytes 0-{len(body)-1}/{len(body)}'
        assert response.get_data() == body
        response.close()
        assert chunk_count(server.job_store) == 0
        execute_owned(agent_path, [job], client, 'interactive', execute)
        assert calls == [True]
        assert BLOCK not in server.job_store.path.read_bytes()
        assert BLOCK not in receipts.path.read_bytes()
        with pytest.raises(EnrollmentTransportError):
            client.response_chunk({**job, 'attempt_token': 'wrong'}, 0, base64.b64encode(BLOCK).decode())
        server.agent_store.set_state(agent_id, 'revoked')
        with pytest.raises(EnrollmentTransportError):
            client.response_chunk(job, 0, base64.b64encode(BLOCK).decode())
    finally:
        server.stop()


def test_expired_success_is_unavailable_without_losing_outcome(tmp_path):
    from twn_toolkit.distributed_response import ResponseUnavailable
    store = DistributedJobStore(tmp_path)
    job = started(store)
    append(store, job)
    completed = finish(store, job, descriptor(BLOCK))
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE distributed_response_transfers SET expires=0')
        db.execute('UPDATE distributed_response_chunks SET expires=0')
    with pytest.raises(ResponseUnavailable, match='expired'):
        build_agent_response(store, completed, 'owner')
    store.prune_payloads()
    assert store.get(job['id'])['state'] == 'succeeded'
    assert store.get(job['id'])['output'] is None
    assert chunk_count(store) == 0


@pytest.mark.parametrize('path', ['//external.test/path', '/../../settings', '/%2e%2e/settings', '/%2F../settings', '/a\\b', '/path#fragment', '/path\nheader'])
def test_recovered_location_cannot_escape_agent_context(path):
    from twn_toolkit.distributed_response_http import completed_response_location
    with pytest.raises(ValueError):
        completed_response_location(dict(id='job', agent_id='agent', output={'request_path': path}))
