from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan


def complete_rename(client, response, *, expected='succeeded'):
    assert response.status_code == 303
    assert '/rename-jobs/' in response.location
    store = DiagnosticJobStore(client.application.instance_path)
    job = store.claim()
    assert job and response.location.endswith('/' + job['id'])
    execute_scan(store, job['id'], job['token'])
    store.release(job['id'], job['token'])
    assert store.get(job['id'], job['user_id'])['state'] == expected
    result = client.get(response.location)
    assert result.status_code == 200
    return result
