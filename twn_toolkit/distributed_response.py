"""Attempt-bound, encrypted response chunks; small control messages stay small."""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import time
from contextlib import contextmanager
from contextvars import ContextVar

from .distributed_response_policy import RESPONSE_CHUNK_BYTES

_writer = ContextVar('distributed_response_writer', default=None)


@contextmanager
def response_writer(writer):
    token = _writer.set(writer)
    try:
        yield
    finally:
        _writer.reset(token)


def current_response_writer():
    return _writer.get()


class ResponseUnavailable(ValueError):
    """A completed response no longer has a retrievable body."""


class ResponseChunksMixin:
    def _init_response_tables(self, connection):
        connection.execute('''CREATE TABLE IF NOT EXISTS distributed_response_chunks (
            job_id TEXT NOT NULL, attempt TEXT NOT NULL, position INTEGER NOT NULL,
            payload TEXT NOT NULL, size INTEGER NOT NULL, digest TEXT NOT NULL, expires REAL NOT NULL,
            PRIMARY KEY(job_id, position))''')
        connection.execute('CREATE INDEX IF NOT EXISTS response_chunk_expiry ON distributed_response_chunks(expires)')
        # Keep the original deadline even after expired chunks are removed.
        # Retrying chunk zero must not open a new retention window.
        connection.execute('''CREATE TABLE IF NOT EXISTS distributed_response_transfers (
            job_id TEXT PRIMARY KEY, attempt TEXT NOT NULL, expires REAL NOT NULL)''')

    def _prune_response_chunks(self, connection):
        connection.execute('''UPDATE distributed_jobs SET output_json=NULL
            WHERE state='succeeded' AND capability_id='system.http.tunnel' AND id IN (
                SELECT job_id FROM distributed_response_transfers WHERE expires <= ?)''', (time.time(),))
        connection.execute('''DELETE FROM distributed_response_chunks WHERE expires <= ? OR NOT EXISTS (
            SELECT 1 FROM distributed_jobs j WHERE j.id=job_id AND j.state NOT IN ('failed','cancelled')
            AND j.payload_expires_at IS NOT NULL)''', (time.time(),))
        connection.execute('''DELETE FROM distributed_response_transfers WHERE NOT EXISTS (
            SELECT 1 FROM distributed_jobs j WHERE j.id=job_id AND j.payload_expires_at IS NOT NULL)''')

    def append_response_chunk(self, job_id, *, agent_id, attempt_token, activation_id, position, body):
        if type(position) is not int or not 0 <= position < 4096:
            raise ValueError('Invalid response chunk position.')
        if not isinstance(body, str) or len(body) > (RESPONSE_CHUNK_BYTES + 2) // 3 * 4:
            raise ValueError('Response chunk is too large.')
        data = base64.b64decode(body, validate=True)
        if not 0 < len(data) <= RESPONSE_CHUNK_BYTES:
            raise ValueError('Invalid response chunk size.')
        policy = self.operational_store.get()
        digest = hashlib.sha256(data).hexdigest()
        sealed = self._cipher.seal(body, f'{job_id}:{attempt_token}:response:{position}')
        with self._connect(write=True) as db:
            self._expire(db, job_id)
            self._prune_response_chunks(db)
            job = self._owned(db, job_id, agent_id, attempt_token, activation_id)
            if job['state'] != 'running' or job['capability_id'] != 'system.http.tunnel':
                raise ValueError('Response transfer no longer owns a running GUI operation.')
            transfer = db.execute('SELECT * FROM distributed_response_transfers WHERE job_id=?', (job_id,)).fetchone()
            if transfer and (transfer['attempt'] != attempt_token or transfer['expires'] <= time.time()):
                raise ValueError('Response transfer is expired or belongs to another attempt.')
            previous = db.execute('SELECT * FROM distributed_response_chunks WHERE job_id=? AND position=?', (job_id, position)).fetchone()
            if previous:
                if previous['attempt'] == attempt_token and previous['size'] == len(data) and previous['digest'] == digest:
                    return {'accepted': True}
                raise ValueError('Response chunk conflicts with a previous chunk.')
            count, size = db.execute('SELECT COUNT(*),COALESCE(SUM(size),0) FROM distributed_response_chunks WHERE job_id=?', (job_id,)).fetchone()
            if position != count:
                raise ValueError('Response chunks must arrive in order.')
            if size + len(data) > policy['distributed_response_mib'] * 1024**2:
                raise ValueError('Agent response exceeds the configured size limit.')
            used = db.execute('SELECT COALESCE(SUM(length(payload)),0) FROM distributed_response_chunks').fetchone()[0]
            if used + len(sealed) > policy['distributed_response_quota_mib'] * 1024**2:
                raise ValueError('Agent response storage quota is full.')
            if shutil.disk_usage(self.path.parent).free - len(sealed) * 3 < policy['minimum_free_gib'] * 1024**3:
                raise ValueError('Agent response would cross the free-disk reserve.')
            expires = transfer['expires'] if transfer else time.time() + policy['distributed_response_retention_minutes'] * 60
            if transfer is None:
                db.execute('INSERT INTO distributed_response_transfers VALUES (?,?,?)', (job_id, attempt_token, expires))
            db.execute('INSERT INTO distributed_response_chunks VALUES (?,?,?,?,?,?,?)',
                       (job_id, attempt_token, position, sealed, len(data), digest, expires))
        return {'accepted': True}

    def _verify_response(self, db, job, output):
        if type(output.get('body_transfer')) is not int or output.get('body_transfer') != 1:
            raise ValueError('Unsupported response transfer.')
        if job['capability_id'] != 'system.http.tunnel':
            raise ValueError('Response transfer is limited to GUI operations.')
        size = output.get('body_size')
        if type(size) is not int or size <= 0 or not isinstance(output.get('body_sha256'), str):
            raise ValueError('Invalid response descriptor.')
        digest = hashlib.sha256()
        total = count = 0
        for chunk in db.execute('SELECT * FROM distributed_response_chunks WHERE job_id=? ORDER BY position', (job['id'],)):
            if chunk['attempt'] != job['attempt_token'] or chunk['position'] != count or chunk['expires'] <= time.time():
                raise ValueError('Response transfer is incomplete or expired.')
            data = self._response_chunk_data(chunk)
            digest.update(data)
            total += len(data)
            count += 1
        if total != size or digest.hexdigest() != output['body_sha256']:
            raise ValueError('Response transfer failed size or checksum verification.')
        return count

    def _response_chunk_data(self, chunk):
        encoded = self._cipher.open(chunk['payload'], f"{chunk['job_id']}:{chunk['attempt']}:response:{chunk['position']}")
        return base64.b64decode(encoded, validate=True)

    def consume_response(self, job_id, requester_id):
        # Claim delivery by clearing the descriptor atomically. Concurrent GETs
        # cannot both consume the same response, and refresh cannot replay HTTP.
        with self._connect(write=True) as db:
            self._expire(db, job_id)
            job = db.execute('SELECT * FROM distributed_jobs WHERE id=? AND requester_id=?', (job_id, requester_id)).fetchone()
            if not job or job['capability_id'] != 'system.http.tunnel' or job['state'] != 'succeeded' or not job['output_json']:
                raise ResponseUnavailable('The response is unavailable or has already been retrieved.')
            output = json.loads(self._cipher.open(job['output_json'], job_id + ':output'))
            if output.get('body_transfer'):
                transfer = db.execute('SELECT expires FROM distributed_response_transfers WHERE job_id=?', (job_id,)).fetchone()
                if transfer is None or transfer['expires'] <= time.time():
                    raise ResponseUnavailable('The response has expired.')
                count = self._verify_response(db, job, output)
                content = None
            else:
                content = base64.b64decode(output.get('body', ''), validate=True)
                count = 0
            db.execute('UPDATE distributed_jobs SET output_json=NULL WHERE id=?', (job_id,))

        if content is not None:
            self.discard_tunnel_output(job_id, requester_id=requester_id)
            return content, output

        def chunks():
            try:
                for position in range(count):
                    with self._connect() as db:
                        chunk = db.execute('SELECT * FROM distributed_response_chunks WHERE job_id=? AND position=?', (job_id, position)).fetchone()
                    if chunk is None or chunk['expires'] <= time.time():
                        raise ValueError('Response expired during delivery.')
                    yield self._response_chunk_data(chunk)
            finally:
                self.discard_tunnel_output(job_id, requester_id=requester_id)
        return chunks(), output
