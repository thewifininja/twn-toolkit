"""Worker completion does not prove that every requested file completed."""
import json
import re
from unittest.mock import Mock

import pytest

from twn_toolkit import create_app
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.transfer_diagnostic import prepare_transfer_config
from twn_toolkit.transfer_outcomes import completed_transfer_outcome, transfer_display

FORM = {'hosts': 'one.test\ntwo.test', 'username': 'fixture', 'port': '22',
        'remote_paths': '/config', 'allow_unknown_hosts': False, 'allow_legacy_algorithms': False,
        'destination': '', 'output_mode': 'download', 'filename_pattern': '{host}-{filename}', 'protocol': 'sftp'}


def result(status, host='one.test'):
    return {'host': host, 'host_label': '', 'remote_path': '/config', 'filename': host + '-config',
            'size': 12 if status == 'success' else 0, 'status': status, 'error': '' if status == 'success' else 'Synthetic file not found'}


@pytest.mark.parametrize('successful,total,outcome,label', [
    (2, 2, 'succeeded', 'Transfer complete'), (1, 2, 'incomplete', 'Partially complete'),
    (0, 2, 'failed', 'Transfer failed'), (0, 0, 'failed', 'Transfer failed')])
def test_completed_projection_matches_case_and_audit_classification(successful, total, outcome, label):
    display = transfer_display({'state': 'succeeded', 'summary': {'successful': successful, 'total': total, 'archive': bool(successful)}})
    assert display['outcome'] == completed_transfer_outcome(successful, total) == outcome
    assert display['label'] == label
    assert (display['tone'] == 'success') == (outcome == 'succeeded')


@pytest.mark.parametrize('summary', [{}, {'successful': True, 'total': 1}, {'successful': 3, 'total': 2},
                                    {'successful': '2', 'total': 2}, {'successful': 1, 'total': -1}])
def test_missing_or_invalid_counts_never_claim_complete(summary):
    display = transfer_display({'state': 'succeeded', 'summary': summary})
    assert display['outcome'] == 'unknown' and display['tone'] != 'success'


def test_rows_expected_total_and_archive_must_support_completion():
    job = {'state': 'succeeded', 'summary': {'successful': 2, 'total': 2, 'archive': True}, 'config': {'form': FORM}}
    assert transfer_display(job, rows=[result('success'), result('error')], expected_total=2)['outcome'] == 'unknown'
    assert transfer_display(job, rows=[result('success'), result('success')], expected_total=3)['outcome'] == 'unknown'
    job['summary']['archive'] = False
    assert transfer_display(job, rows=[result('success'), result('success')], expected_total=2)['outcome'] == 'unknown'


@pytest.mark.parametrize('state', ['unknown', 'failed', 'cancelled', 'cancel_requested', 'running'])
def test_interruption_keeps_execution_state_and_confirmed_published_evidence(state):
    job = {'state': state, 'summary': {'published_paths': ['one-config'], 'stage': 'Publishing files to datastore'},
           'config': {'form': {**FORM, 'output_mode': 'datastore'}}}
    display = transfer_display(job)
    assert display['state'] == state and display['tone'] != 'success'
    assert display['published_count'] == 1 and 'confirmed published' in display['message']
    if state in {'unknown', 'failed', 'cancelled'}:
        assert 'Inspect the destination' in display['retry_advice']


@pytest.fixture
def transfer(tmp_path):
    app = create_app(str(tmp_path)); app.testing = True
    return app, app.test_client(), DiagnosticJobStore(tmp_path)


def saved_job(store, rows, *, state='succeeded', mode='download', owner='test-user', error=''):
    config = {**prepare_transfer_config({**FORM, 'output_mode': mode}, 'fixture-only-password'),
              'username': 'fixture', 'investigation_id': ''}
    identifier = store.enqueue(user_id=owner, tool='transfer', config=config)
    job = store.claim()
    summary = {'successful': sum(row['status'] == 'success' for row in rows), 'total': len(rows),
               'archive': mode == 'download' and any(row['status'] == 'success' for row in rows),
               'published_paths': ['one-config'] if mode == 'datastore' and rows[0]['status'] == 'success' else [],
               'stage': 'Complete'}
    if state == 'succeeded':
        assert store.finish(identifier, job['token'], rows, summary)
    else:
        assert store.progress(identifier, job['token'], summary)
        store.abort(identifier, job['token'], state, error)
    store.release(identifier, job['token'])
    return identifier


@pytest.mark.parametrize('statuses,label', [(['success', 'success'], 'Transfer complete'),
                                         (['success', 'error'], 'Partially complete'),
                                         (['error', 'error'], 'Transfer failed')])
def test_result_status_history_and_runbar_agree_without_changing_job_state(transfer, statuses, label):
    app, client, store = transfer
    identifier = saved_job(store, [result(status, host) for status, host in zip(statuses, ['one.test', 'two.test'])])
    response = client.get('/tools/multi-transfer', query_string={'job': identifier})
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert label in page and 'Review another fetch' in page
    assert 'Fetch again' not in page and 'Ready to fetch' not in page
    assert 'fixture-only-password' not in page
    status = client.get(f'/tools/multi-transfer/jobs/{identifier}/status')
    assert status.json['state'] == store.get(identifier, 'test-user')['state'] == 'succeeded'
    assert status.json['display_label'] == label
    assert status.headers['Cache-Control'] == 'no-store'
    if 'error' in statuses:
        assert 'Inspect the destination' not in page  # ZIP mode has distinct guidance.
        assert 'A new fetch repeats the requested host/file set' in page
        assert 'tool-runbar-indicator stopped' in page
        assert 'recent-run-state">Finished<' not in page


@pytest.mark.parametrize('state', ['unknown', 'failed', 'cancelled'])
def test_interrupted_datastore_keeps_published_paths_and_safe_review(transfer, state):
    app, client, store = transfer
    identifier = saved_job(store, [result('success'), result('error')], state=state, mode='datastore', error='Synthetic deadline reached')
    response = client.get('/tools/multi-transfer', query_string={'job': identifier})
    text = response.get_data(as_text=True)
    assert 'Confirmed published files' in text and 'one-config' in text
    assert 'Inspect the destination' in text
    assert 'Transfer complete' not in text and 'Run complete.' not in text
    assert 'Download ZIP' not in text
    assert store.get(identifier, 'test-user')['state'] == state


def test_empty_validation_failure_never_claims_ready_or_fetches(transfer, monkeypatch):
    app, client, store = transfer
    fetch = Mock(side_effect=AssertionError('No network work from web route'))
    monkeypatch.setattr('twn_toolkit.transfer_diagnostic.fetch_transfer_files', fetch)
    for response in [client.get('/tools/multi-transfer'), client.post('/tools/multi-transfer', data={**FORM, 'hosts': '', 'password': 'fixture-only-password'})]:
        assert response.status_code == 200
        assert b'Ready to fetch' not in response.data and b'Review transfer settings' in response.data
    fetch.assert_not_called()
    assert store.recent('test-user', 'transfer') == []


def test_recent_summary_is_opt_in_owned_and_never_decrypts_config(transfer, monkeypatch):
    app, client, store = transfer
    identifier = saved_job(store, [result('success'), result('error')])
    saved_job(store, [result('error'), result('error')], owner='another-owner')
    default = store.recent('test-user', 'transfer')
    assert set(default[0]) == {'id', 'state', 'created'}
    original = store.cipher.open
    tags = []
    def open_summary(ciphertext, tag):
        tags.append(tag)
        assert tag.endswith(':diagnostic-summary')
        return original(ciphertext, tag)
    monkeypatch.setattr(store.cipher, 'open', open_summary)
    rows = store.recent('test-user', 'transfer', include_summary=True)
    assert [row['id'] for row in rows] == [identifier]
    assert rows[0]['summary']['successful'] == 1 and len(tags) == 1


def test_unreadable_history_summary_is_unconfirmed_without_hiding_other_runs(transfer):
    app, client, store = transfer
    identifier = saved_job(store, [result('success'), result('success')])
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET summary=? WHERE id=?', ('damaged summary', identifier))
    response = client.get('/tools/multi-transfer')
    assert response.status_code == 200 and b'Outcome unconfirmed' in response.data


def test_page_summary_uses_the_entire_run_not_just_the_current_page(transfer):
    app, client, store = transfer
    form = {**FORM, 'hosts': '\n'.join(f'host-{n}.test' for n in range(50)), 'remote_paths': '/one\n/two\n/three\n/four'}
    config = {**prepare_transfer_config(form, 'fixture-only-password'), 'username': 'fixture', 'investigation_id': ''}
    identifier = store.enqueue(user_id='test-user', tool='transfer', config=config)
    claimed = store.claim()
    rows = [result('success' if n < 190 else 'error', f'host-{n}.test') for n in range(200)]
    assert store.finish(identifier, claimed['token'], rows, {'successful':190, 'total':200, 'archive':True})
    store.release(identifier, claimed['token'])
    for page in (1, 2, 999):
        response = client.get('/tools/multi-transfer', query_string={'job':identifier, 'page':page})
        text = response.get_data(as_text=True)
        assert response.status_code == 200
        assert 'Partially complete' in text and '190 of 200 transfer(s)' in text
        assert 'Transfer complete' not in text
    assert '200 results · page 2' in text


@pytest.mark.parametrize('successful,outcome,label', [(2,'succeeded','Transfer complete'), (1,'incomplete','Partially complete'), (0,'failed','Transfer failed')])
def test_real_worker_case_audit_and_display_classify_the_same_file_outcome(transfer, monkeypatch, successful, outcome, label):
    from twn_toolkit.audit import AuditStore
    from twn_toolkit.diagnostic_worker import execute_scan
    from twn_toolkit.investigations import InvestigationStore
    app, client, store = transfer
    client.post('/investigations', data={'title':'Synthetic transfer case'})
    cases = InvestigationStore(str(store.instance))
    case_id = cases.active_for_user('test-user')['id']
    response = client.post('/tools/multi-transfer', data={**FORM, 'password':'fixture-only-password'})
    assert response.status_code == 303
    claimed = store.claim()
    def fixture_fetch(**kwargs):
        rows = [result('success' if index < successful else 'error', host) for index, host in enumerate(['one.test','two.test'])]
        for row in rows:
            if row['status'] == 'success':
                (kwargs['output_dir'] / row['filename']).write_bytes(b'fixture data')
        return rows
    monkeypatch.setattr('twn_toolkit.transfer_diagnostic.fetch_transfer_files', fixture_fetch)
    execute_scan(store, claimed['id'], claimed['token'])
    store.release(claimed['id'], claimed['token'])
    job = store.get(claimed['id'], 'test-user')
    assert job['state'] == 'succeeded'  # Worker execution state is deliberately unchanged.
    page = client.get(response.location)
    assert page.status_code == 200 and label.encode() in page.data
    events = [event for event in cases.events_for_user(case_id, 'test-user') if event['tool_id'] == 'tools.multi_sftp']
    assert len(events) == 1 and events[0]['outcome'] == outcome
    audit = [event for event in AuditStore(str(store.instance)).recent() if event.get('action') == 'transfer.multi_host_fetch.run_' + outcome]
    assert len(audit) == 1
    if successful:
        assert client.get(f"/tools/multi-transfer/jobs/{claimed['id']}/download").status_code == 200
    else:
        assert client.get(f"/tools/multi-transfer/jobs/{claimed['id']}/download").status_code == 404


@pytest.mark.parametrize('mode,statuses,published,stored,archive,typed,label', [
    ('download',['success','success'],[],[],True,True,'Transfer complete'),
    ('download',['success','error'],[],[],True,True,'Partially complete'),
    ('download',['error','error'],[],[],False,True,'Transfer failed'),
    ('download',['success','success'],[],[],False,True,'Outcome unconfirmed'),
    ('download',['success','success'],[],[],False,False,'Outcome unconfirmed'),
    ('datastore',['success','success'],['one','two'],['one','two'],False,True,'Transfer complete'),
    ('datastore',['success','success'],['one','two'],['one','two'],False,False,'Transfer complete'),
    ('datastore',['success','success'],[],['one','two'],False,True,'Outcome unconfirmed'),
    ('datastore',['success','success'],['one'],['one','two'],False,True,'Outcome unconfirmed'),
    ('datastore',['success','success'],['one','one'],['one','one'],False,True,'Outcome unconfirmed'),
])
def test_destination_proof_agrees_on_result_status_and_summary_only_history(transfer, mode, statuses, published, stored, archive, typed, label):
    app, client, store = transfer
    rows = [result(status, host) for status, host in zip(statuses, ['one.test','two.test'])]
    for row,path in zip(rows,stored):
        if row['status']=='success':row['stored_path']=path
    identifier=saved_job(store,rows,mode=mode)
    summary={'successful':statuses.count('success'),'total':2,'archive':archive,'published_paths':published}
    if typed:summary['output_mode']=mode
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET summary=? WHERE id=?', (store.cipher.seal(json.dumps(summary),identifier+':diagnostic-summary'),identifier))
    result_page=client.get('/tools/multi-transfer',query_string={'job':identifier}).get_data(as_text=True)
    overview=client.get('/tools/multi-transfer').get_data(as_text=True)
    status=client.get(f'/tools/multi-transfer/jobs/{identifier}/status').json
    assert status['state']=='succeeded' and status['display_label']==label
    assert re.findall(r'recent-run-state">([^<]+)</span>',result_page)==[label]
    assert re.findall(r'recent-run-state">([^<]+)</span>',overview)==[label]
    assert label in result_page
    if mode == 'download' and not archive and 'success' in statuses:
        assert 'included in ZIP' not in result_page
        assert result_page.count('output availability unconfirmed') == statuses.count('success')
        assert 'reported success' in result_page
    if mode == 'datastore':
        confirmed = set(published) if len(set(published)) == len(published) else set()
        assert result_page.count('published to Datastore') == sum(path in confirmed for path in stored)
        for path in set(stored) - confirmed:
            assert f'path={path}' not in result_page


def test_completed_result_has_one_primary_outcome_and_retains_run_identity(transfer):
    app, client, store = transfer
    identifier = saved_job(store, [result('success'), result('error', 'two.test')])
    page = client.get('/tools/multi-transfer', query_string={'job': identifier}).get_data(as_text=True)
    assert page.count('1 of 2 transfer(s) included in the retained ZIP.') == 1
    assert 'data-diagnostic-heading' not in page
    assert identifier in page and 'second deadline' in page
    assert 'reported successful on this page' in page


@pytest.mark.parametrize('rows,summary', [
    ([result('success'),result('error')], {'successful':2,'total':2,'archive':True,'published_paths':[]}),
    ([result('success'),result('success')], {'successful':2,'total':2,'archive':False,'published_paths':['one','two'],'output_mode':'datastore'}),
])
def test_opened_job_row_contradictions_override_its_history_projection(transfer, rows, summary):
    app, client, store=transfer
    mode='datastore' if summary.get('output_mode')=='datastore' else 'download'
    identifier=saved_job(store,rows,mode=mode)
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET summary=? WHERE id=?', (store.cipher.seal(json.dumps(summary),identifier+':diagnostic-summary'),identifier))
    text=client.get('/tools/multi-transfer',query_string={'job':identifier}).get_data(as_text=True)
    status=client.get(f'/tools/multi-transfer/jobs/{identifier}/status').json
    assert status['display_label']=='Outcome unconfirmed'
    assert re.findall(r'recent-run-state">([^<]+)</span>',text)==['Outcome unconfirmed']
    assert 'Transfer complete' not in text


@pytest.mark.parametrize('bad_mode',[[],{},True,'invalid'])
def test_invalid_output_mode_receipt_never_claims_a_destination(bad_mode):
    view=transfer_display({'state':'succeeded','summary':{'successful':2,'total':2,'archive':True,'published_paths':[],'output_mode':bad_mode}})
    assert view['outcome']=='unknown'


def test_zip_receipt_cannot_confirm_a_datastore_path(transfer):
    app, client, store = transfer
    row = result('success')
    row['stored_path'] = 'unconfirmed-datastore-path'
    identifier = saved_job(store, [row, result('success', 'two.test')], mode='download')
    page = client.get('/tools/multi-transfer', query_string={'job': identifier}).get_data(as_text=True)
    assert 'included in ZIP' in page
    assert 'published to Datastore' not in page
    assert 'unconfirmed-datastore-path' not in page


@pytest.mark.parametrize('stored_path', [[], {}])
def test_malformed_stored_path_renders_unconfirmed_instead_of_error(transfer, stored_path):
    app, client, store = transfer
    rows = [result('success'), result('success', 'two.test')]
    rows[0]['stored_path'] = stored_path
    identifier = saved_job(store, rows, mode='datastore')
    response = client.get('/tools/multi-transfer', query_string={'job': identifier})
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert 'Outcome unconfirmed' in page
    assert page.count('output availability unconfirmed') == 2
