import io
import json
import re
import time
from unittest.mock import patch

import pytest

from twn_toolkit import create_app
from twn_toolkit import bulk_ssh_jobs as jobs
from twn_toolkit import network_tools as network
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan, _abort
from twn_toolkit.operational import OperationalSettingsStore


@pytest.fixture
def setup(tmp_path):
    app = create_app(str(tmp_path))
    app.testing = True
    OperationalSettingsStore(str(tmp_path)).save({'minimum_free_gib': 0})
    return app, DiagnosticJobStore(tmp_path)


def submit(app, *, hosts='first.test', **extra):
    client = app.test_client()
    form = dict(matrix='Name | Host\n' + '\n'.join(f'Host {i} | {host}' for i, host in enumerate(hosts.splitlines())), commands='show status', command_timeout='1', port='22')
    for key in ('command_timeout', 'port'):
        if key in extra:
            form[key] = extra[key]
    page = client.post('/tools/multi-ssh', data={**form, 'action': 'preview'})
    token = re.search(rb'name="preview_token" type="hidden" value="([^"]+)"', page.data).group(1).decode()
    form.update(action='run', preview_token=token, username='operator', password='fixture-secret', confirm_execution='on')
    response = client.post('/tools/multi-ssh', data={**form, **extra}, headers={'Accept': 'application/json'})
    assert response.status_code == 202, response.data
    return response.json['job_id'], form


def complete(store):
    claimed = store.claim()
    execute_scan(store, claimed['id'], claimed['token'])
    store.release(claimed['id'], claimed['token'])
    return store.get(claimed['id'], claimed['user_id'])


def success(*args):
    return {'host': args[0], 'host_label': args[8], 'status': 'success', 'output': 'fixture output'}


def test_admission_deduplicates_without_network_or_key_change(setup):
    app, store = setup
    with patch.object(network, '_ssh_host_connection', side_effect=AssertionError('foreground execution')):
        job_id, form = submit(app)
        again = app.test_client().post('/tools/multi-ssh', data=form, headers={'Accept': 'application/json'})
    assert again.json['job_id'] == job_id
    assert len(store.recent('test-user', 'bulk_ssh')) == 1
    assert b'fixture-secret' not in store.path.read_bytes()
    page = app.test_client().get('/tools/multi-ssh/jobs/' + job_id)
    assert page.status_code == 200 and b'fixture-secret' not in page.data
    assert b'not started' in page.data
    # An explicit fresh preview creates a new admission even within the same second.
    other, _ = submit(app)
    assert other != job_id


def test_completed_hosts_retained_and_terminal_credentials_scrubbed(setup, monkeypatch):
    app, store = setup
    job_id, _ = submit(app, hosts='first.test\nsecond.test')
    def connected(*args):
        with store.connect() as db:
            assert db.execute('SELECT COUNT(*) FROM diagnostic_rows WHERE job_id=? AND is_open=1', (job_id,)).fetchone()[0] > 0
        return {**success(*args), 'output': 'fixture-secret safe output'}
    monkeypatch.setattr(network, '_ssh_host_connection', connected)
    job = complete(store)
    assert job['state'] == 'succeeded'
    assert 'password' not in job['config'] and 'login' not in job['config']
    rows = jobs.host_rows(store, job)
    assert len(rows) == 2 and all(row['status'] == 'success' for row in rows)
    assert all(row['output'] == '[redacted] safe output' for row in rows)
    download = app.test_client().get(f'/tools/multi-ssh/jobs/{job_id}/download')
    assert b'safe output' in download.data and b'fixture-secret' not in download.data
    monkeypatch.setattr(network, '_ssh_host_connection', lambda *a: pytest.fail('replayed'))
    assert store.claim() is None
    store.recover()
    assert store.claim() is None


def test_interruption_keeps_completed_unknown_and_not_started_hosts(setup, monkeypatch):
    app, store = setup
    job_id, _ = submit(app, hosts='first.test\nsecond.test\nthird.test')
    monkeypatch.setattr(network, 'SSH_EXECUTION_WORKERS', 1)
    calls = []
    def connected(*args):
        calls.append(args[0])
        if args[0] == 'second.test':
            raise KeyboardInterrupt()
        return success(*args)
    monkeypatch.setattr(network, '_ssh_host_connection', connected)
    job = store.claim()
    with pytest.raises(KeyboardInterrupt):
        execute_scan(store, job_id, job['token'])
    _abort(store, job_id, job['token'], 'cancelled', 'Interrupted fixture')
    store.release(job_id, job['token'])
    retained = store.get(job_id, 'test-user')
    assert retained['state'] == 'unknown'
    assert [r['status'] for r in jobs.host_rows(store, retained)] == ['success', 'unknown', 'not_started']
    assert calls == ['first.test', 'second.test']
    assert 'password' not in retained['config']


def test_intent_storage_failure_prevents_connection(setup, monkeypatch):
    app, store = setup
    submit(app)
    job = store.claim()
    monkeypatch.setattr(jobs, '_persist_host', lambda *a, **k: (_ for _ in ()).throw(OSError('disk failure')))
    monkeypatch.setattr(network, '_ssh_host_connection', lambda *a: pytest.fail('connected without durable intent'))
    with pytest.raises(OSError):
        execute_scan(store, job['id'], job['token'])


def test_queue_cancel_scrubs_and_never_executes(setup):
    app, store = setup
    job_id, _ = submit(app)
    response = app.test_client().post(f'/tools/multi-ssh/jobs/{job_id}/cancel')
    assert response.status_code == 303
    job = store.get(job_id, 'test-user')
    assert job['state'] == 'cancelled' and 'password' not in job['config']
    assert store.claim() is None
    assert all(r['status'] == 'not_started' for r in jobs.host_rows(store, job))


def test_recovery_preserves_host_intent_without_replay(setup):
    app, store = setup
    job_id, _ = submit(app)
    job = store.claim()
    jobs._persist_host(store, job, 0, {'host': 'first.test', 'host_label': '', 'status': 'running', 'output': ''}, started=True)
    store.recover()
    retained = store.get(job_id, 'test-user')
    assert retained['state'] == 'unknown' and 'password' not in retained['config']
    assert jobs.host_rows(store, retained)[0]['status'] == 'unknown'
    assert store.claim() is None


def test_failed_command_acknowledgement_is_explicitly_unknown(setup, monkeypatch):
    app, store = setup
    submit(app)
    monkeypatch.setattr(network, '_ssh_host_connection', lambda *args: {**success(*args), 'status': 'timeout', 'execution_unknown': True})
    retained = complete(store)
    assert retained['state'] == 'unknown'
    assert jobs.host_rows(store, retained)[0]['status'] == 'unknown'
    assert jobs.counts(store, retained)['unconfirmed'] == 1


def test_status_and_download_require_owner_and_matching_tool(setup):
    app, store = setup
    other = store.enqueue(user_id='other-user', tool='tcp_scan', config={})
    own_wrong_tool = store.enqueue(user_id='test-user', tool='tcp_scan', config={})
    client = app.test_client()
    for job_id in (other, own_wrong_tool):
        for suffix in ('', '/status', '/download'):
            assert client.get(f'/tools/multi-ssh/jobs/{job_id}{suffix}').status_code == 404
        assert client.post(f'/tools/multi-ssh/jobs/{job_id}/cancel').status_code == 404


def test_worker_rechecks_access_before_any_connection(setup, monkeypatch):
    app, store = setup
    job_id, _ = submit(app)
    job = store.claim()
    monkeypatch.setattr(jobs, 'allowed', lambda *args: False)
    monkeypatch.setattr(network, '_ssh_host_connection', lambda *args: pytest.fail('revoked user connected'))
    with pytest.raises(ValueError, match='revoked'):
        execute_scan(store, job_id, job['token'])


def test_result_budget_handles_unicode_and_control_characters():
    result = jobs._bounded_result({'host':'host', 'status':'success','output':'\x00😀' * 10000}, {}, 1000)
    assert result['output_truncated']
    assert len(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode()) <= 1000


def test_banner_capture_is_bounded_under_continuous_output(monkeypatch):
    class Channel:
        def recv_ready(self): return True
        def recv(self, size): return b'x' * size
    ticks = iter([0, 0, 0, .1, .2, .3, 1, 2])
    monkeypatch.setattr(network.time, 'monotonic', lambda: next(ticks, 5))
    assert len(network._read_channel(Channel(), .5, capture_limit=100)) == 100


@pytest.fixture
def ssh_server():
    """A disposable actual Paramiko server; no external host or known-host write."""
    import socket
    import threading
    import paramiko
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(10)
    listener.settimeout(.1)
    stop = threading.Event()
    received = threading.Event()
    disconnected = threading.Event()
    transports = []
    key = paramiko.RSAKey.generate(2048)
    commands = []
    class Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL
        def get_allowed_auths(self, username): return 'password'
        def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED
        def check_channel_pty_request(self, *args): return True
        def check_channel_shell_request(self, channel): return True
    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            transport = paramiko.Transport(connection)
            transports.append(transport)
            try:
                transport.add_server_key(key)
                transport.start_server(server=Server())
                channel = transport.accept(5)
                if channel is None:
                    continue
                channel.settimeout(.1)
                channel.send(b'fixture # ')
                while not stop.is_set():
                    try:
                        data = channel.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        disconnected.set()
                        break
                    commands.append(data)
                    received.set()
                    # Keep a command in flight until the worker closes the socket.
            except (EOFError, OSError, paramiko.SSHException):
                disconnected.set()
            finally:
                transport.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield listener.getsockname()[1], received, disconnected, commands
    stop.set()
    listener.close()
    for transport in transports:
        transport.close()
    thread.join(3)


def wait_for(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.025)
    raise AssertionError('Fixture did not reach expected state')


@pytest.mark.parametrize('reason', ['cancel', 'deadline', 'shutdown', 'worker_crash'])
def test_actual_ssh_worker_stop_closes_socket_and_retains_unknown(setup, ssh_server, reason):
    from twn_toolkit.diagnostic_worker import DiagnosticScheduler
    app, _ = setup
    port, received, disconnected, commands = ssh_server
    scheduler = DiagnosticScheduler(app.instance_path)
    job_id, _ = submit(app, hosts='127.0.0.1', port=str(port), allow_unknown_hosts='on', command_timeout='30')
    try:
        scheduler.tick()
        wait_for(received.is_set)
        work = scheduler.active[job_id]
        if reason == 'cancel':
            scheduler.store.cancel(job_id, 'test-user')
        elif reason == 'deadline':
            work['deadline'] = time.monotonic() - 1
        elif reason == 'shutdown':
            scheduler.close()
        else:
            work['process'].kill()
        def finished():
            scheduler.tick(running=lambda: False)
            return job_id not in scheduler.active
        wait_for(finished)
        wait_for(disconnected.is_set)
        job = scheduler.store.get(job_id, 'test-user')
        assert job['state'] == 'unknown'
        assert jobs.host_rows(scheduler.store, job)[0]['status'] == 'unknown'
        assert 'password' not in job['config']
        count = len(commands)
        assert scheduler.store.claim() is None
        scheduler.store.recover()
        assert scheduler.store.claim() is None and len(commands) == count
    finally:
        scheduler.close()


def test_retained_retry_needs_confirmation_and_cannot_mutate_before_admission(setup, monkeypatch):
    app, store = setup
    job_id, _ = submit(app)
    mismatch = {'host':'first.test', 'host_label':'Host 0', 'status':'error', 'output':'', 'host_key_mismatch':{
        'expected_fingerprint':'SHA256:'+'E'*43, 'presented_fingerprint':'SHA256:'+'P'*43,
        'expected_key_type':'ssh-rsa','presented_key_type':'ssh-rsa'}}
    monkeypatch.setattr(network, '_ssh_host_connection', lambda *args: mismatch)
    original = complete(store)
    token = jobs.host_rows(store, original)[0]['host_key_retry_token']
    body = dict(source_job=job_id, position='0', retry_token=token, username='operator', password='retry-secret')
    client = app.test_client()
    with patch('twn_toolkit.ssh_security.forget_ssh_known_host') as forget:
        rejected = client.post('/tools/multi-ssh/host-keys/retry', json=body)
        assert rejected.status_code == 400
        with patch.object(DiagnosticJobStore, 'enqueue', side_effect=ValueError('Queue full')):
            assert client.post('/tools/multi-ssh/host-keys/retry', json={**body, 'verified':'on'}).status_code == 400
        forget.assert_not_called()
        admitted = client.post('/tools/multi-ssh/host-keys/retry', json={**body, 'verified':'on'})
        repeated = client.post('/tools/multi-ssh/host-keys/retry', json={**body, 'verified':'on'})
        assert admitted.status_code == 202
        assert admitted.json['job_id'] == repeated.json['job_id']
        forget.assert_not_called()
    retry = store.get(admitted.json['job_id'], 'test-user')
    plan = jobs.plans_for(retry['config'])[0]
    assert plan['required_host_key_fingerprint'] == 'SHA256:'+'P'*43
    assert retry['config']['allow_unknown_hosts'] is False


def test_expired_preview_cannot_outlive_deduplication_receipt(setup):
    app, store = setup
    _, form = submit(app)
    future = time.time() + 1802
    with patch('itsdangerous.timed.time.time', return_value=future):
        response = app.test_client().post('/tools/multi-ssh', data=form, headers={'Accept':'application/json'})
    assert response.status_code == 400 and 'expired' in response.json['error']


def test_large_matrix_uses_compact_config_and_bounded_result_pages(setup):
    app, store = setup
    hosts = '\n'.join(f'host-{i:04d}.example.test' for i in range(2000))
    job_id, _ = submit(app, hosts=hosts)
    job = store.get(job_id, 'test-user')
    assert len(json.dumps(job['config']).encode()) > 64 * 1024
    assert len(jobs.host_rows(store, job, offset=100)) == 100
    assert len(jobs.plans_for(job['config'])) == 2000
    page = app.test_client().get(f'/tools/multi-ssh/jobs/{job_id}?page=2')
    assert page.status_code == 200 and len(page.data) < 256 * 1024
    assert b'host-0100.example.test' in page.data and b'host-0000.example.test' not in page.data


def test_original_case_receives_streamed_output_and_actor_after_navigation(setup, monkeypatch):
    from twn_toolkit.investigations import InvestigationStore
    app, store = setup
    client = app.test_client()
    client.post('/investigations', data={'title':'Original case'})
    cases = InvestigationStore(app.instance_path)
    original = cases.active_for_user('test-user')['id']
    job_id, _ = submit(app)
    client.post('/investigations', data={'title':'Different case'})
    monkeypatch.setattr(network, '_ssh_host_connection', success)
    job = complete(store)
    assert 'recording_warning' not in job['summary'], job['summary']
    events = [event for event in cases.events_for_user(original, 'test-user') if event['operation_id']=='multi-ssh:'+job_id]
    assert len(events) == 1 and events[0]['outcome'] == 'succeeded'
    assert job['summary']['journal_event']['investigation_id'] == original
    assert 'fixture-secret' not in json.dumps(events)
    artifact = cases.artifacts_for_user(original, 'test-user')[0]
    assert artifact['byte_count'] > 0


def test_recording_failure_keeps_retained_outcome_and_warning(setup, monkeypatch):
    app, store = setup
    submit(app)
    monkeypatch.setattr(network, '_ssh_host_connection', success)
    with patch('twn_toolkit.activity.ActivityStore.record_event', side_effect=OSError('fixture')):
        job = complete(store)
    assert job['state'] == 'succeeded'
    assert 'activity' in job['summary']['recording_warning']
    assert jobs.host_rows(store, job)[0]['output'] == 'fixture output'


def test_real_accounts_enforce_owner_and_revoked_tool_access(setup):
    from twn_toolkit.auth import AuthStore
    app, store = setup
    auth = AuthStore(app.instance_path)
    auth.create_user('admin', 'TemporaryPassword123!', is_admin=True)
    profile = auth.save_access_profile(name='SSH', tool_ids=['tools.multi_ssh'])
    owner = auth.create_user('owner', 'TemporaryPassword123!', access_profile_ids=[profile['id']])
    job_id, _ = submit(app)
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET user_id=? WHERE id=?', (owner['id'], job_id))
    app.testing = False
    client = app.test_client()
    client.post('/login', data={'username':'owner', 'password':'TemporaryPassword123!'})
    assert client.get(f'/tools/multi-ssh/jobs/{job_id}').status_code == 200
    auth.update_user_access(owner['id'], is_admin=False, access_profile_ids=[])
    client.post('/login', data={'username':'owner', 'password':'TemporaryPassword123!'})
    for suffix in ('', '/status', '/download'):
        assert client.get(f'/tools/multi-ssh/jobs/{job_id}{suffix}').status_code == 403
    assert client.post(f'/tools/multi-ssh/jobs/{job_id}/cancel').status_code == 403
    assert not jobs.allowed(app.instance_path, owner['id'])


def test_scheduler_parent_loss_closes_actual_ssh_and_recovery_does_not_replay(setup, ssh_server):
    import subprocess
    import sys
    from pathlib import Path
    from twn_toolkit.diagnostic_worker import DiagnosticScheduler
    app, store = setup
    port, received, disconnected, commands = ssh_server
    job_id, _ = submit(app, hosts='127.0.0.1', port=str(port), allow_unknown_hosts='on', command_timeout='30')
    code = ('import sys,time;from twn_toolkit.diagnostic_worker import DiagnosticScheduler;'
            'scheduler=DiagnosticScheduler(sys.argv[1]);scheduler.tick();'
            'time.sleep(60)')
    parent = subprocess.Popen([sys.executable, '-c', code, app.instance_path],
                              cwd=str(Path(__file__).resolve().parents[1]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for(received.is_set)
        parent.kill()
        parent.wait(timeout=5)
        wait_for(disconnected.is_set)
        recovered = DiagnosticScheduler(app.instance_path)
        try:
            job = recovered.store.get(job_id, 'test-user')
            assert job['state'] == 'unknown' and 'password' not in job['config']
            assert recovered.store.claim() is None
            assert len(commands) == 1
        finally:
            recovered.close()
    finally:
        if parent.poll() is None:
            parent.kill()
        parent.wait(timeout=5)


def test_legacy_retry_payload_cannot_bypass_retained_job_ownership(setup, monkeypatch):
    app, store = setup
    job_id, form = submit(app)
    mismatch = {'host':'first.test', 'host_label':'Host 0', 'status':'error', 'output':'', 'host_key_mismatch':{
        'expected_fingerprint':'SHA256:'+'E'*43, 'presented_fingerprint':'SHA256:'+'P'*43}}
    monkeypatch.setattr(network, '_ssh_host_connection', lambda *args: mismatch)
    retained = complete(store)
    token = jobs.host_rows(store, retained)[0]['host_key_retry_token']
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET user_id=? WHERE id=?', ('other-user',job_id))
    response = app.test_client().post('/tools/multi-ssh/host-keys/retry', json={
        **form, 'retry_token': token, 'verified':'on'})
    assert response.status_code == 404


def test_delegation_is_only_accepted_from_authenticated_dispatch_context(setup, monkeypatch):
    app, store = setup
    job_id, _ = submit(app, delegated='true')
    assert store.get(job_id,'test-user')['config']['delegated'] is False
    job = store.claim()
    config = store.get(job_id,'test-user')['config']
    # Model a Mainframe-authorized dispatch; remote identities need not exist in
    # the Agent's local user database. Submitted form fields cannot select this.
    config['delegated'] = True
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET config=? WHERE id=?', (store.cipher.seal(json.dumps(config), job_id+':diagnostic-config'),job_id))
    monkeypatch.setattr(jobs,'allowed',lambda *args:False)
    monkeypatch.setattr(network,'_ssh_host_connection',success)
    execute_scan(store,job_id,job['token'])
    assert store.get(job_id,'test-user')['state']=='succeeded'


def test_single_host_download_is_bounded_to_the_selected_host(setup,monkeypatch):
    app,store=setup
    job_id,_=submit(app,hosts='first.test\nsecond.test')
    monkeypatch.setattr(network,'_ssh_host_connection',success)
    complete(store)
    client=app.test_client()
    response=client.get(f'/tools/multi-ssh/jobs/{job_id}/download?host=1')
    assert b'second.test' in response.data and b'first.test' not in response.data
    assert client.get(f'/tools/multi-ssh/jobs/{job_id}/download?host=2').status_code==404
    assert client.get(f'/tools/multi-ssh/jobs/{job_id}/download?host=invalid').status_code==400
