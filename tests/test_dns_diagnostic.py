import base64
import json
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlencode

import dns.message
import dns.rrset
import pytest

from twn_toolkit import create_app
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import DiagnosticScheduler, execute_scan
from twn_toolkit.dns_diagnostic import prepare_dns_config
from twn_toolkit.operational import OperationalSettingsStore

FORM = dict(hosts='private.test', servers='127.0.0.1', mode='compare', record_type='A', timeout='.2',
            duration='1', qps='2', concurrency='1', authorized='on', host_profile='', server_profile='')


def config(**changes):
    return {**prepare_dns_config({**FORM, **changes}), 'username': 'owner', 'investigation_id': ''}


def row(i=0):
    return dict(host=f'private{i}.test', host_label='', server='127.0.0.1', server_label='', record_type='A',
                status='success', answers=['192.0.2.10'], response_ms=1)


def wait_finished(scheduler, job_id):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        scheduler.tick()
        job = scheduler.store.get(job_id, 'owner')
        if job['state'] not in {'queued', 'running', 'cancel_requested'}:
            return job
        time.sleep(.02)
    pytest.fail('DNS job did not finish')


def test_dns_enqueue_does_not_execute_and_results_are_paged(tmp_path, monkeypatch):
    app = create_app(str(tmp_path)); app.testing = True
    client = app.test_client()
    monkeypatch.setattr('twn_toolkit.dns_diagnostic.dns_lookup_matrix', lambda *a, **kw: pytest.fail('HTTP performed DNS'))
    response = client.post('/tools/dns-response', data=FORM)
    assert response.status_code == 303
    location = response.headers['Location']
    store = app.extensions['diagnostic_job_store']; job = store.claim()
    assert job['tool'] == 'dns'
    assert b'Run in progress' in client.get(location).data
    assert client.get('/health').status_code == 200
    rows = [row(i) for i in range(150)]
    monkeypatch.setattr('twn_toolkit.dns_diagnostic.dns_lookup_matrix', lambda *a, **kw: rows)
    execute_scan(store, job['id'], job['token'])
    first = client.get(location).data; second = client.get(location + '&page=2').data
    assert b'150 lookup results' in first and b'Next page' in first
    assert first.count(b'192.0.2.10') == 100 and second.count(b'192.0.2.10') == 50
    assert b'private149.test' not in first and b'private149.test' in second
    assert b'private.test' not in store.path.read_bytes()
    for path in [f"/tools/port-scanner?job={job['id']}", f"/tools/port-scanner/jobs/{job['id']}/status"]:
        assert client.get(path).status_code == 404
    assert client.post(f"/tools/port-scanner/jobs/{job['id']}/cancel").status_code == 404
    assert store.recent('test-user') == []
    assert len(store.recent('test-user', 'dns')) == 1
    tcp_id = store.enqueue(user_id='test-user', config={})
    assert client.get('/tools/dns-response?job=' + tcp_id).status_code == 404
    assert client.get(f'/tools/dns-response/jobs/{tcp_id}/status').status_code == 404
    assert client.post(f'/tools/dns-response/jobs/{tcp_id}/cancel').status_code == 404


@pytest.mark.parametrize('changes', [dict(mode='wrong'), dict(record_type='invalid'), dict(timeout='nan'),
    dict(mode='load', authorized=''), dict(mode='load', duration='31'), dict(mode='load', qps='501'),
    dict(mode='load', concurrency='201')])
def test_dns_invalid_requests_do_not_enter_queue(tmp_path, changes):
    app = create_app(str(tmp_path)); app.testing = True
    response = app.test_client().post('/tools/dns-response', data={**FORM, **changes})
    assert response.status_code == 200 and b'message error' in response.data
    assert app.extensions['diagnostic_job_store'].claim() is None


def test_dns_agent_redirect_ownership_and_cancel(tmp_path):
    from twn_toolkit.distributed_http import dispatch_http_request
    prefix = '/agents/test-agent/ui'
    def dispatch(path, method='GET', body='', user='owner'):
        return dispatch_http_request(tmp_path, {'method': method, 'path': path, 'prefix': prefix,
            'user': {'id': user, 'username': user, 'is_admin': True},
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'body': base64.b64encode(body.encode()).decode()})
    submitted = dispatch('/tools/dns-response', 'POST', urlencode(FORM))
    assert submitted['status'] == 303
    location = dict(submitted['headers'])['Location']
    assert location.startswith(prefix + '/tools/dns-response?job=')
    job_id = location.split('job=')[1]
    path = location.removeprefix(prefix)
    assert dispatch(path, user='intruder')['status'] == 404
    status = f'/tools/dns-response/jobs/{job_id}/status'
    cancel = f'/tools/dns-response/jobs/{job_id}/cancel'
    assert dispatch(status, user='intruder')['status'] == 404
    assert dispatch(cancel, 'POST', user='intruder')['status'] == 404
    assert dispatch(cancel, 'POST')['status'] == 303
    assert json.loads(base64.b64decode(dispatch(status)['body']))['state'] == 'cancelled'
    store = DiagnosticJobStore(tmp_path)
    assert store.claim() is None


def test_dns_real_scheduler_compare_and_load_use_udp(tmp_path, monkeypatch):
    # Redirect only the test child's resolver port to a local UDP fixture.
    from twn_toolkit import diagnostic_worker
    real_popen = subprocess.Popen
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1', 0)); server.settimeout(.1)
        def respond():
            while not stop.is_set():
                try:
                    data, peer = server.recvfrom(65535)
                except socket.timeout:
                    continue
                query = dns.message.from_wire(data)
                response = dns.message.make_response(query)
                response.answer.append(dns.rrset.from_text(query.question[0].name, 60, 'IN', 'A', '192.0.2.10'))
                server.sendto(response.to_wire(), peer)
        thread = threading.Thread(target=respond); thread.start()
        script = ("import dns.resolver,runpy; original=dns.resolver.Resolver.__init__; "
                  f"dns.resolver.Resolver.__init__=lambda self,*a,**kw:(original(self,*a,**kw),setattr(self,'port',{server.getsockname()[1]})) and None; "
                  "runpy.run_module('twn_toolkit.diagnostic_worker',run_name='__main__')")
        def start(command, **kwargs):
            return real_popen([sys.executable, '-c', script, *command[3:]], **kwargs)
        monkeypatch.setattr(diagnostic_worker.subprocess, 'Popen', start)
        scheduler = DiagnosticScheduler(tmp_path)
        try:
            for mode in ['compare', 'load']:
                job_id = scheduler.store.enqueue(user_id='owner', tool='dns', config=config(mode=mode, timeout='1'))
                job = wait_finished(scheduler, job_id)
                assert job['state'] == 'succeeded', job['error']
                if mode == 'compare':
                    assert scheduler.store.page(job_id, 'owner')[0][0]['answers'] == ['192.0.2.10']
                else:
                    assert job['summary']['load_result']['completed_queries'] == 2
                    assert job['summary']['load_result']['success_rate'] == 100
        finally:
            scheduler.close(); stop.set(); thread.join(2)


def test_dns_running_cancel_and_deadline_fence_results(tmp_path, monkeypatch):
    from twn_toolkit import diagnostic_worker
    real_popen = subprocess.Popen
    def start(command, **kwargs):
        return real_popen([sys.executable, '-c', 'import time;time.sleep(30)'], **kwargs)
    monkeypatch.setattr(diagnostic_worker.subprocess, 'Popen', start)
    OperationalSettingsStore(str(tmp_path)).save({'diagnostic_workers': 1})
    scheduler = DiagnosticScheduler(tmp_path)
    try:
        for outcome in ['cancelled', 'failed']:
            job_id = scheduler.store.enqueue(user_id='owner', tool='dns', config=config())
            scheduler.tick(); work = scheduler.active[job_id]
            if outcome == 'cancelled':
                scheduler.store.cancel(job_id, 'owner')
            else:
                work['deadline'] = time.monotonic() - 1
            job = wait_finished(scheduler, job_id)
            assert job['state'] == outcome
            assert work['process'].poll() is not None
            assert scheduler.store.page(job_id, 'owner') == ([], 0)
            assert not scheduler.store.finish(job_id, work['token'], [row()], {})
    finally:
        scheduler.close()


def test_dns_case_capture_survives_navigation_and_refresh_does_not_duplicate(tmp_path, monkeypatch):
    from twn_toolkit.investigations import InvestigationStore
    app = create_app(str(tmp_path)); app.testing = True
    client = app.test_client(); client.post('/investigations', data={'title': 'Original case'})
    cases = InvestigationStore(str(tmp_path))
    original = cases.active_for_user('test-user')['id']
    submitted = client.post('/tools/dns-response', data=FORM)
    client.post('/investigations', data={'title': 'Different case'})
    store = app.extensions['diagnostic_job_store']; job = store.claim()
    monkeypatch.setattr('twn_toolkit.dns_diagnostic.dns_lookup_matrix', lambda *a, **kw: [row()])
    execute_scan(store, job['id'], job['token'])
    for _ in range(2):
        assert client.get(submitted.headers['Location']).status_code == 200
    events = [e for e in cases.events_for_user(original, 'test-user') if e['tool_id'] == 'tools.dns_response']
    assert len(events) == 1 and events[0]['details']['results'] == [row()]
    assert store.claim() is None
