from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan


def complete_appliance_read(client, response):
    if response.status_code == 202:
        location = response.get_json()['job_url']
    elif response.status_code == 303:
        location = response.location
    else:
        location = response.request.path
    identifier = location.split('/jobs/')[-1].split('/connection-jobs/')[-1].split('/')[0]
    store = DiagnosticJobStore(client.application.instance_path)
    job = store.claim()
    assert job and job['id'] == identifier
    execute_scan(store, job['id'], job['token'])
    store.release(job['id'], job['token'])
    result = store.get(job['id'], job['user_id'])
    if result['state'] == 'succeeded' and result['summary'].get('archive'):
        return client.get(location.rsplit('/', 1)[0] + '/download')
    return client.get(location)


def export_fixture(text):
    def run(*args, **kwargs):
        kwargs['output'].write(text)
    return run
