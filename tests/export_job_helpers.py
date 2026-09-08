"""Drive accepted export jobs in request tests without starting a scheduler."""
from urllib.parse import parse_qs, urlsplit
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan


def run_export(client, response):
    assert response.status_code == 303
    job_id = parse_qs(urlsplit(response.location).query)['job'][0]
    store = DiagnosticJobStore(client.application.instance_path)
    job = store.claim()
    assert job and job['id'] == job_id
    execute_scan(store, job_id, job['token'])
    store.release(job_id, job['token'])
    return store.get(job_id, job['user_id'])


def complete_export(client, response):
    if response.status_code != 303:
        return response
    result = run_export(client, response)
    job_id = result['id']
    assert result['state'] == 'succeeded', result['error']
    if result['config'].get('investigation_id'):
        return client.get(response.location)
    prefix = '/automations/exports' if result['tool'] == 'automation_export' else '/settings/backup/exports'
    return client.get(prefix+'/'+job_id+'/download')
