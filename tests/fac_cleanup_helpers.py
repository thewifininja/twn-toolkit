from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan


def complete_cleanup(client, response, expected='succeeded'):
    assert response.status_code == 303, response.status_code
    location = response.headers['Location']
    assert '/mac-cleanup/jobs/' in location
    identifier = location.rsplit('/', 1)[-1]
    store = DiagnosticJobStore(client.application.instance_path)
    job = store.claim()
    assert job['id'] == identifier
    execute_scan(store, identifier, job['token'])
    store.release(identifier, job['token'])
    saved = store.get(identifier, job['user_id'])
    assert saved['state'] == expected, saved
    result = client.get(location)
    assert result.status_code == 200
    return result
