from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan


def complete_switch_order(client, response):
    assert response.status_code == 202, response.get_data(as_text=True)
    queued = response.get_json()
    store = DiagnosticJobStore(client.application.instance_path)
    job = store.claim()
    assert job and queued['job_url'].endswith('/' + job['id'])
    execute_scan(store, job['id'], job['token'])
    store.release(job['id'], job['token'])
    result = client.get(queued['status_url'])
    assert result.status_code == 200
    assert result.get_json()['state'] not in {'queued', 'running', 'cancel_requested'}
    return result
