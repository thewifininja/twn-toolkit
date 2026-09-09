import re
from flask import render_template
import pytest
from twn_toolkit import create_app
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.time_settings import TimeSettingsStore


@pytest.fixture
def app(tmp_path):
    app=create_app(str(tmp_path));app.testing=True
    return app


def test_history_is_compact_escaped_sorted_and_scoped_to_agent_url(app):
    with app.test_request_context('/',environ_overrides={'SCRIPT_NAME':'/agents/fixture'}):
        page=render_template('components/recent_runs.html',appliance_recent=[
            {'id':'older','mode':'export','profile_name':'<script>bad</script>','created':1,'created_display':'Yesterday','state':'failed','url':'/agents/fixture/older'},
            {'id':'newer','mode':'preview','profile_name':'Branch','created':2,'created_display':'Today','state':'unknown','url':'/agents/fixture/newer'}])
    assert re.search(r'<details[^>]*data-recent-runs>',page)
    assert not re.search(r'<details[^>]*\bopen\b',page)
    assert page.index('Branch')<page.index('&lt;script&gt;')
    assert '<script>bad' not in page
    assert 'Unconfirmed' in page and 'pill warning' in page
    assert 'href="/agents/fixture/newer"' in page
    assert 'aria-label="View Preview · Branch · Today"' in page


def test_diagnostic_links_use_existing_scoped_route_and_toolkit_timezone(app):
    TimeSettingsStore(app.instance_path).save('America/Kentucky/Louisville')
    with app.test_request_context('/',environ_overrides={'SCRIPT_NAME':'/agents/fixture'}):
        page=render_template('components/recent_runs.html',diagnostic_label='Bulk Transfer',
            diagnostic_result_endpoint='tools.multi_transfer',diagnostic_recent=[{'id':'job','state':'queued','created':1704067200}])
    assert '/agents/fixture/tools/multi-transfer?job=job' in page
    assert 'Dec 31, 2023' in page and 'EST' in page


def test_actual_bulk_ssh_page_history_only_lists_owner_and_precedes_setup(app):
    store=DiagnosticJobStore(app.instance_path)
    store.enqueue(user_id='test-user',tool='bulk_ssh',config={'host_count':2,'run_name':'Branch checks'})
    store.enqueue(user_id='someone-else',tool='bulk_ssh',config={'host_count':1,'run_name':'Private checks'})
    page=app.test_client().get('/tools/multi-ssh').data.decode()
    assert 'Branch checks' in page and 'Private checks' not in page
    assert page.index('<h1>Bulk SSH</h1>')<page.index('data-recent-runs')<page.index('id="multi-ssh-settings"')
    assert page.count('data-recent-runs')==1


def test_collapsing_history_cannot_hide_progress_or_cancel(app):
    with app.test_request_context('/'):
        page=render_template('components/recent_runs.html',diagnostic_recent=[])
        progress=render_template('components/diagnostic_job.html',diagnostic_job={'id':'job','state':'running','timeout':30},
            diagnostic_label='Bulk Transfer',diagnostic_status_endpoint='tools.transfer_job_status',
            diagnostic_cancel_endpoint='tools.cancel_transfer_job',diagnostic_result_endpoint='tools.multi_transfer')
    assert 'No retained runs yet.' in page
    assert 'Cancel run' not in page and 'Cancel run' in progress
    assert 'data-diagnostic-status-url' in progress and '<details' not in progress


def test_certificate_history_preserves_environment_and_failed_request_action(app):
    with app.test_request_context('/'):
        page=render_template('components/recent_runs.html',certificate_section='acme',acme_jobs=[
            {'id':'active','name':'Lab certificate','environment':'staging','status':'validating','created_at':2,'created_at_display':'Today'},
            {'id':'failed','name':'Office certificate','environment':'production','status':'failed','created_at':1,'created_at_display':'Yesterday'}])
    assert 'Lab certificate · Staging' in page and 'Office certificate · Production' in page
    assert 'pill warning recent-run-state">Validating' in page
    assert page.count('>Delete</button>')==1
    assert 'onsubmit="return confirm(\'Delete this failed ACME request?\');"' in page
