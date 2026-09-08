import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from twn_toolkit import iperf_tools as tools
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import DiagnosticScheduler, execute_scan
from twn_toolkit.iperf_client_jobs import prepare_iperf_client
from twn_toolkit.network_tools import ToolInputError
from tests.test_iperf_stream_bounds import executable
from tests.test_iperf_tools import TCP_PAYLOAD


FORM = dict(host='127.0.0.1', port='5201', protocol='tcp', family='auto',
            duration_seconds='1', parallel_streams='1', bind_address='', reverse='',
            udp_megabits='1', authorized='on')


def prepared(tmp_path, monkeypatch, body=None):
    path = executable(tmp_path, body or 'print(' + repr(json.dumps(TCP_PAYLOAD)) + ')')
    monkeypatch.setattr('twn_toolkit.iperf_client_jobs._iperf3_executable', lambda: path)
    return {**prepare_iperf_client(FORM.copy()), 'username': 'owner', 'investigation_id': ''}


def wait_for(check, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError('Timed out waiting for fixture state')


@pytest.mark.parametrize('body, expected', [
    ('os.write(1,b"x"*(2*1024*1024+1))', '2 MiB'),
    ('os.write(2,b"x"*(2*1024*1024+1))', '2 MiB'),
    ('os.close(1);os.close(2);time.sleep(60)', 'timeout'),
    ('os.write(1,b"{");time.sleep(60)', 'timeout'),
])
def test_client_reader_bounds_both_pipes_and_silent_child(tmp_path, body, expected):
    path = executable(tmp_path, body)
    exception = subprocess.TimeoutExpired if expected == 'timeout' else ToolInputError
    with pytest.raises(exception):
        tools._run_iperf3_client_command([path], timeout=0.25)


def test_client_reader_preserves_stderr_and_final_json(tmp_path):
    path = executable(tmp_path, 'os.write(2,b"warning");os.write(1,b"{\\\"ok\\\":true}")')
    result = tools._run_iperf3_client_command([path], timeout=2)
    assert json.loads(result.stdout) == {'ok': True}
    assert result.stderr == 'warning'


def test_worker_retains_normalized_result_and_does_not_replay(tmp_path, monkeypatch):
    config = prepared(tmp_path, monkeypatch)
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id='owner', tool='iperf_client', config=config)
    job = store.claim()
    execute_scan(store, job_id, job['token'])
    result = store.get(job_id, 'owner')
    assert result['state'] == 'succeeded'
    assert result['summary']['result']['receiver']['megabits_per_second'] == 980
    from twn_toolkit.activity import ActivityStore
    assert ActivityStore(str(tmp_path)).summary()['counters']['speedtest']['runs'] == 1
    monkeypatch.setattr('twn_toolkit.iperf_client_jobs.run_iperf3_client', lambda *a, **k: pytest.fail('replayed'))
    execute_scan(store, job_id, job['token'])
    store.recover()
    assert store.claim() is None


def test_binary_drift_rejects_before_traffic(tmp_path, monkeypatch):
    config = prepared(tmp_path, monkeypatch)
    Path(config['executable']).write_text('changed')
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id='owner', tool='iperf_client', config=config)
    job = store.claim()
    monkeypatch.setattr('twn_toolkit.iperf_client_jobs.run_iperf3_client', lambda *a, **k: pytest.fail('launched'))
    execute_scan(store, job_id, job['token'])
    assert 'changed' in store.get(job_id, 'owner')['error']


def locked_child_body(tmp_path):
    lock = tmp_path / 'descendant.lock'
    ready = tmp_path / 'ready'
    code = ('import fcntl,signal,time;from pathlib import Path;'
            'signal.signal(signal.SIGTERM,signal.SIG_IGN);'
            f'f=open({str(lock)!r},"w");fcntl.flock(f,fcntl.LOCK_EX);'
            f'Path({str(ready)!r}).write_text("ready");time.sleep(60)')
    return f'subprocess.Popen([sys.executable,"-c",{code!r}]);time.sleep(60)', lock, ready


def assert_unlocked(lock):
    with lock.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.mark.parametrize('reason', ['cancel', 'deadline', 'shutdown', 'worker_crash'])
def test_scheduler_stops_external_descendants(tmp_path, monkeypatch, reason):
    body, lock, ready = locked_child_body(tmp_path)
    config = prepared(tmp_path, monkeypatch, body)
    scheduler = DiagnosticScheduler(tmp_path)
    job_id = scheduler.store.enqueue(user_id='owner', tool='iperf_client', config=config)
    try:
        scheduler.tick()
        wait_for(ready.exists)
        work = scheduler.active[job_id]
        assert os.getpgid(work['process'].pid) == work['process'].pid
        if reason == 'cancel':
            scheduler.store.cancel(job_id, 'owner')
        elif reason == 'deadline':
            work['deadline'] = time.monotonic() - 1
        elif reason == 'shutdown':
            scheduler.close()
        else:
            work['process'].kill()
        def done():
            scheduler.tick(running=lambda: False)
            return job_id not in scheduler.active
        wait_for(done)
        wait_for(lambda: unlocked(lock))
        state = scheduler.store.get(job_id, 'owner')['state']
        assert state == {'cancel': 'cancelled', 'deadline': 'failed', 'shutdown': 'unknown', 'worker_crash': 'failed'}[reason]
        assert scheduler.store.claim() is None
    finally:
        scheduler.close()


def unlocked(lock):
    try:
        assert_unlocked(lock)
        return True
    except BlockingIOError:
        return False


def test_worker_deadline_stops_descendants_without_scheduler_ticks(tmp_path, monkeypatch):
    body, lock, ready = locked_child_body(tmp_path)
    config = prepared(tmp_path, monkeypatch, body)
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id='owner', tool='iperf_client', config=config)
    job = store.claim()
    process = subprocess.Popen([sys.executable, '-m', 'twn_toolkit.diagnostic_worker',
        '--instance', str(tmp_path), '--job', job_id], stdin=subprocess.PIPE, start_new_session=True)
    try:
        process.stdin.write(json.dumps({'token': job['token'], 'parent': os.getpid(), 'timeout': 2,
                                       'owned_group': True}).encode())
        process.stdin.close()
        wait_for(ready.exists)
        process.wait(timeout=5)
        assert process.returncode == -signal.SIGKILL
        wait_for(lambda: unlocked(lock))
        store.recover()
        assert store.get(job_id, 'owner')['state'] == 'unknown'
        assert store.claim() is None
    finally:
        tools._signal_iperf_group(process, signal.SIGKILL)
        process.wait(timeout=5)


def test_scheduler_parent_loss_stops_external_descendants(tmp_path, monkeypatch):
    body, lock, ready = locked_child_body(tmp_path)
    config = prepared(tmp_path, monkeypatch, body)
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id='owner', tool='iperf_client', config=config)
    code = ('import sys,time;from twn_toolkit.diagnostic_worker import DiagnosticScheduler;'
            's=DiagnosticScheduler(sys.argv[1]);s.tick();time.sleep(60)')
    process = subprocess.Popen([sys.executable, '-c', code, str(tmp_path)])
    try:
        wait_for(ready.exists)
        process.kill()
        process.wait(timeout=5)
        wait_for(lambda: unlocked(lock))
        recovered = DiagnosticScheduler(tmp_path)
        assert recovered.store.get(job_id, 'owner')['state'] == 'unknown'
        assert recovered.store.claim() is None
        recovered.close()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_http_submission_retained_result_original_case_and_raw_ownership(tmp_path, monkeypatch):
    from twn_toolkit import create_app
    from twn_toolkit.investigations import InvestigationStore
    config = prepared(tmp_path, monkeypatch)
    monkeypatch.setattr('twn_toolkit.iperf_routes.iperf3_capability', lambda: {'available': True})
    app = create_app(str(tmp_path)); app.testing = True
    client = app.test_client()
    client.post('/investigations', data={'title': 'Original case'})
    cases = InvestigationStore(str(tmp_path))
    original = cases.active_for_user('test-user')['id']
    with monkeypatch.context() as context:
        context.setattr('twn_toolkit.iperf_client_jobs.run_iperf3_client', lambda *a, **k: pytest.fail('HTTP launched traffic'))
        response = client.post('/tools/iperf3', data={'client_' + k: v for k, v in FORM.items()})
    assert response.status_code == 303
    store = app.extensions['diagnostic_job_store']
    job = store.claim()
    assert job['tool'] == 'iperf_client'
    assert b'Run in progress' in client.get(response.location).data
    client.post('/investigations', data={'title': 'Different case'})
    execute_scan(store, job['id'], job['token'])
    for _ in range(2):
        page = client.get(response.location)
        assert b'980.0 Mbps' in page.data
    events = [e for e in cases.events_for_user(original, 'test-user') if e['tool_id'] == 'tools.iperf3']
    assert len(events) == 1
    assert events[0]['details']['result']['receiver']['megabits_per_second'] == 980
    assert 'raw_json' not in events[0]['details']['result']
    assert client.get('/tools/iperf3/jobs/' + job['id'] + '/raw').status_code == 200
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET user_id=? WHERE id=?', ('other', job['id']))
    for suffix in ('status', 'raw'):
        assert client.get('/tools/iperf3/jobs/' + job['id'] + '/' + suffix).status_code == 404
    assert client.get(response.location).status_code == 404
    assert client.post('/tools/iperf3/jobs/' + job['id'] + '/cancel').status_code == 404


def test_recording_failure_is_visible_and_does_not_replay(tmp_path, monkeypatch):
    config = prepared(tmp_path, monkeypatch)
    store = DiagnosticJobStore(tmp_path)
    job_id = store.enqueue(user_id='owner', tool='iperf_client', config=config)
    job = store.claim()
    def fail(*a, **k):
        raise OSError('fixture')
    monkeypatch.setattr('twn_toolkit.activity.ActivityStore.record_event', fail)
    execute_scan(store, job_id, job['token'])
    retained = store.get(job_id, 'owner')
    assert retained['state'] == 'succeeded'
    assert 'activity' in retained['summary']['recording_warning']
    assert store.claim() is None


def test_raw_preview_is_bounded_without_shortening_retained_download(tmp_path, monkeypatch):
    from twn_toolkit import create_app
    prepared(tmp_path, monkeypatch)
    monkeypatch.setattr('twn_toolkit.iperf_routes.iperf3_capability', lambda: {'available': True})
    app = create_app(str(tmp_path)); app.testing = True
    client = app.test_client()
    response = client.post('/tools/iperf3', data={'client_' + k: v for k, v in FORM.items()})
    store = app.extensions['diagnostic_job_store']; job = store.claim()
    result = tools.normalize_iperf3_result(TCP_PAYLOAD, mode='client', config={}, command=[])
    result['raw_json'] = 'X' * (1024 * 1024)
    store.finish(job['id'], job['token'], [], {'result': result})
    page = client.get(response.location)
    assert b'first 16 KiB' in page.data
    assert len(page.data) < 150000
    raw = client.get('/tools/iperf3/jobs/' + job['id'] + '/raw')
    assert raw.data == result['raw_json'].encode()
    assert raw.headers['Cache-Control'] == 'no-store'


def test_queued_cancel_records_without_launch(tmp_path, monkeypatch):
    from twn_toolkit import create_app
    prepared(tmp_path, monkeypatch)
    monkeypatch.setattr('twn_toolkit.iperf_routes.iperf3_capability', lambda: {'available': True})
    app = create_app(str(tmp_path)); app.testing = True
    client = app.test_client()
    response = client.post('/tools/iperf3', data={'client_' + k: v for k, v in FORM.items()})
    store = app.extensions['diagnostic_job_store']
    job_id = response.location.split('job=')[1]
    assert client.post('/tools/iperf3/jobs/' + job_id + '/cancel').status_code == 303
    assert store.get(job_id, 'test-user')['state'] == 'cancelled'
    assert store.claim() is None


def test_current_tool_permission_protects_all_client_job_endpoints(tmp_path, monkeypatch):
    from twn_toolkit import create_app
    from twn_toolkit.auth import AuthStore
    prepared(tmp_path, monkeypatch)
    auth = AuthStore(str(tmp_path))
    auth.create_user('admin', 'long administrator password', is_admin=True)
    profile = auth.save_access_profile(name='iPerf only', tool_ids=['tools.iperf3'])
    auth.create_user('operator', 'long operator password', access_profile_ids=[profile['id']])
    app = create_app(str(tmp_path))
    client = app.test_client()
    client.post('/login', data={'username': 'operator', 'password': 'long operator password'})
    response = client.post('/tools/iperf3', data={'client_' + k: v for k, v in FORM.items()})
    assert response.status_code == 303
    job_id = response.location.split('job=')[1]
    auth.save_access_profile(profile_id=profile['id'], name='iPerf only', tool_ids=['tools.ping'])
    assert client.get(response.location).status_code == 403
    for suffix in ('status', 'raw'):
        assert client.get('/tools/iperf3/jobs/' + job_id + '/' + suffix).status_code == 403
    assert client.post('/tools/iperf3/jobs/' + job_id + '/cancel').status_code == 403
