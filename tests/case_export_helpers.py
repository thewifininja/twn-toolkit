"""Drive the real queued export lifecycle in existing round-trip tests."""
from urllib.parse import parse_qs, urlsplit

from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan


def complete_case_export(client, response):
    assert response.status_code == 303
    identifier = parse_qs(urlsplit(response.location).query)['job'][0]
    store = DiagnosticJobStore(client.application.instance_path)
    job = store.claim()
    assert job and job['id'] == identifier
    execute_scan(store, identifier, job['token'])
    store.release(identifier, job['token'])
    result = store.get(identifier, job['user_id'])
    if result['state'] != 'succeeded':
        return client.get(response.location)
    return client.get('/investigations/exports/'+identifier+'/download')
