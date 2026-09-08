"""Certificate intent, recovery retention, and isolated request admission."""
import json
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives import serialization

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.certificate_automation import EnrollmentResult, CertificateAutomationError
from twn_toolkit.certificate_jobs import certificate_store, prepare_certificate, execute_certificate, cleanup_certificate_files
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import execute_scan, DiagnosticScheduler
from tests.test_certificate_automation import _ca_and_leaf


@pytest.fixture
def fixture(tmp_path):
    jobs = DiagnosticJobStore(tmp_path)
    jobs.policy.save({'minimum_free_gib':0})
    certificates = certificate_store(tmp_path)
    credential = certificates.save_credential(credential_id='', name='fixture', username='enroller', password='enrollment-password')
    server = certificates.save_server({'name':'fixture','enrollment_url':'https://ca.example.test/certsrv','credential_id':credential['id'],'provider':'adcs_web_enrollment','retrieval_strategy':'same_endpoint','timeout':15})
    template = certificates.save_template({'name':'fixture','server_id':server['id'],'template_identifier':'WebServer','key_size':2048,'renewal_days':30})
    form = {'name':'host certificate','common_name':'host.example.test','dns_names':'host.example.test','template_id':template['id'],'key_source':'generate'}
    return jobs, certificates, server, template, form


def queued(fixture, mode='enroll'):
    jobs, certificates, server, template, form = fixture
    config = prepare_certificate(jobs, mode, form, server_id=server['id'])
    config.update(username='Owner', investigation_id='')
    job_id = jobs.enqueue(user_id='owner', tool='certificate_'+mode, config=config)
    job = jobs.claim()
    assert job['id'] == job_id
    return job, config


class Provider:
    calls = 0
    status = 'pending'
    fail_fetch = False
    def __init__(self, *args, **kwargs):
        self.session = SimpleNamespace(close=lambda: None)
    def test_connection(self):
        return 200
    def enroll(self, csr, template, key_pem, cn, names, *, before_submit, acknowledged):
        before_submit()
        type(self).calls += 1
        receipt = EnrollmentResult(self.status, '123', 'Fixture CA', 'Fixture receipt')
        acknowledged(receipt)
        if self.fail_fetch:
            raise CertificateAutomationError('Fixture retrieval failed')
        if self.status == 'issued':
            key = serialization.load_pem_private_key(key_pem, password=None)
            leaf, _chain, ca = _ca_and_leaf(key, names)
            return EnrollmentResult('issued','123',certificate_pem=leaf,chain_pem=ca.public_bytes(serialization.Encoding.PEM))
        return receipt


@pytest.fixture
def provider(monkeypatch):
    class FixtureProvider(Provider):
        calls = 0
    monkeypatch.setattr('twn_toolkit.certificate_jobs.AdcsWebEnrollmentProvider', FixtureProvider)
    return FixtureProvider


@pytest.mark.parametrize('status', ['pending','issued','denied'])
def test_disposition_retained_without_replay(fixture, provider, status):
    jobs, certificates, *_ = fixture
    provider.status = status
    job, config = queued(fixture)
    execute_scan(jobs, job['id'], job['token'])
    retained = jobs.get(job['id'], 'owner')
    assert retained['state'] == 'succeeded', retained['error']
    assert retained['summary']['disposition'] == status
    assert 'private_key_pem' not in retained['summary']
    operation = certificates.enrollment_operation(job['id'])
    assert bool(operation) == (status != 'denied')
    if operation:
        assert operation['status'] == status
        assert certificates.managed_certificate(operation['managed_id'])['version_count'] == 1
    execute_scan(jobs, job['id'], job['token'])
    jobs.recover()
    assert provider.calls == 1


@pytest.mark.parametrize('stage,attempted', [
    ('Key and CSR saved; not submitted',False),
    ('Submission started; awaiting CA acknowledgement',True),
    ('CA acknowledgement saved',True),
    ('Request and key registered; retrieving certificate',True),
])
def test_interruption_retains_intent_key_and_no_replay(fixture, provider, monkeypatch, stage, attempted):
    jobs, certificates, *_ = fixture
    job, config = queued(fixture)
    progress = jobs.progress
    def interrupt(job_id, token, summary):
        result = progress(job_id, token, summary)
        if summary['stage'] == stage:
            raise SystemExit('fixture interruption')
        return result
    monkeypatch.setattr(jobs, 'progress', interrupt)
    with pytest.raises(SystemExit):
        execute_certificate(jobs, job, config)
    calls = provider.calls
    DiagnosticScheduler(jobs.instance).close()
    result = jobs.get(job['id'], 'owner')
    assert result['state'] == ('unknown' if attempted else 'failed')
    assert 'PRIVATE KEY' in result['summary']['private_key_pem']
    assert 'CERTIFICATE REQUEST' in result['summary']['csr_pem']
    assert result['summary']['attempted'] is attempted
    assert provider.calls == calls
    if 'acknowledgement saved' in stage or 'registered' in stage:
        assert result['summary']['request_id'] == '123'
    if 'registered' in stage:
        assert certificates.enrollment_operation(job['id'])


@pytest.mark.parametrize('stage', ['Key and CSR saved; not submitted', 'Submission started; awaiting CA acknowledgement'])
def test_unconfirmed_checkpoint_prevents_post(fixture, provider, monkeypatch, stage):
    jobs, *_ = fixture
    job, config = queued(fixture)
    progress = jobs.progress
    monkeypatch.setattr(jobs, 'progress', lambda i,t,s: False if s['stage']==stage else progress(i,t,s))
    execute_certificate(jobs, job, config)
    assert provider.calls == 0
    assert jobs.get(job['id'],'owner')['state'] == 'failed'


def test_failed_fetch_retains_ack_key_and_pending_version(fixture, provider):
    jobs, certificates, *_ = fixture
    provider.status='issued';provider.fail_fetch=True
    job, config=queued(fixture)
    execute_certificate(jobs,job,config)
    retained=jobs.get(job['id'],'owner')
    assert retained['state']=='unknown'
    assert retained['summary']['request_id']=='123'
    operation=certificates.enrollment_operation(job['id'])
    assert operation['status']=='pending'
    assert certificates.version_material(operation['managed_id'])['private_key_pem'].decode()==retained['summary']['private_key_pem']


def test_unknown_retention_capacity_and_same_target_block(fixture, provider):
    jobs, certificates, server, template, form=fixture
    provider.status='issued';provider.fail_fetch=True
    job,config=queued(fixture)
    execute_certificate(jobs,job,config);jobs.release(job['id'],job['token'])
    jobs.policy.save({'diagnostic_history_limit':1,'diagnostic_retention_hours':1})
    with jobs.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET completed=?',(time.time()-7200,))
    jobs.cleanup()
    assert jobs.get(job['id'],'owner')['state']=='unknown'
    with pytest.raises(ValueError):
        prepare_certificate(jobs,'enroll',form)
    with pytest.raises(ValueError,match='storage capacity'):
        jobs.enqueue(user_id='another',tool='certificate_test',config={})
    assert 'PRIVATE KEY' in jobs.get(job['id'],'owner')['summary']['private_key_pem']


@pytest.mark.parametrize('change',['server','credential','template'])
def test_profile_drift_prevents_submission(fixture,provider,change):
    jobs,certificates,server,template,form=fixture
    job,config=queued(fixture)
    with certificates._connect() as db:
        table={'server':'pki_servers','credential':'pki_credentials','template':'pki_templates'}[change]
        db.execute('UPDATE '+table+' SET updated_at=updated_at+1')
    execute_certificate(jobs,job,config)
    assert provider.calls==0
    assert jobs.get(job['id'],'owner')['state']=='failed'


def test_pending_registration_is_idempotent(fixture,provider):
    jobs,certificates,*_=fixture
    job,config=queued(fixture)
    execute_certificate(jobs,job,config)
    operation=certificates.enrollment_operation(job['id'])
    material=certificates.version_material(operation['managed_id'])
    arguments=dict(managed_id='', name=config['name'],server_id=config['server_id'],template_id=config['template_id'],
        common_name=config['common_name'],dns_names=config['dns_names'],private_key_pem=material['private_key_pem'],
        result=EnrollmentResult('pending','123'),operation_id=job['id'])
    for _ in range(2):
        result=certificates.save_enrollment(**arguments)
        assert result['version_count']==1
        assert result['current_version_id']==operation['id']


def test_cancel_after_intent_is_unknown_and_releases_temporary_files(fixture,provider,monkeypatch):
    jobs,*_=fixture
    job,config=queued(fixture)
    progress=jobs.progress
    def cancel(i,t,s):
        result=progress(i,t,s)
        if s['attempted']:
            jobs.cancel(i,'owner')
            raise InterruptedError('cancelled')
        return result
    monkeypatch.setattr(jobs,'progress',cancel)
    execute_certificate(jobs,job,config)
    assert provider.calls==0
    assert jobs.get(job['id'],'owner')['state']=='unknown'
    jobs.release(job['id'],job['token']);cleanup_certificate_files(jobs)
    assert list((jobs.instance/'certificate_job_temporary').iterdir())==[]


def test_http_admission_is_local_and_duplicate_nonce_returns_same_job(fixture,monkeypatch):
    jobs,certificates,server,template,form=fixture
    app=create_app(str(jobs.instance));app.testing=True
    client=app.test_client()
    monkeypatch.setattr('twn_toolkit.certificate_jobs.AdcsWebEnrollmentProvider',lambda *a,**k: pytest.fail('network in HTTP request'))
    monkeypatch.setattr('twn_toolkit.certificate_jobs.load_or_generate_private_key',lambda *a,**k: pytest.fail('key generation in HTTP request'))
    data={**form,'job_nonce':'a'*32}
    first=client.post('/tools/certificate-automation/enroll',data=data,headers={'Accept':'application/json'})
    assert first.status_code==202,first.json
    second=client.post('/tools/certificate-automation/enroll',data=data,headers={'Accept':'application/json'})
    assert second.json==first.json
    page=client.get(first.json['location'])
    assert page.status_code==200
    assert b'enrollment-password' not in page.data
    assert b'PRIVATE KEY' not in page.data


def test_invalid_request_returns_json_without_echoing_secret(fixture):
    jobs,*_=fixture
    app=create_app(str(jobs.instance));app.testing=True
    response=app.test_client().post('/tools/certificate-automation/enroll',data={'password':'do-not-echo'},headers={'Accept':'application/json'})
    assert response.status_code==400
    assert b'do-not-echo' not in response.data


def test_original_case_and_recovery_endpoints_are_owner_scoped(fixture,provider):
    from twn_toolkit.investigations import InvestigationStore
    jobs,certificates,server,template,form=fixture
    app=create_app(str(jobs.instance));app.testing=True;client=app.test_client()
    client.post('/investigations',data={'title':'Original'})
    cases=InvestigationStore(str(jobs.instance));original=cases.active_for_user('test-user')['id']
    response=client.post('/tools/certificate-automation/enroll',data=form)
    client.post('/investigations',data={'title':'Different'})
    provider.status='issued';provider.fail_fetch=True
    job=jobs.claim();execute_scan(jobs,job['id'],job['token']);jobs.release(job['id'],job['token'])
    events=[e for e in cases.events_for_user(original,'test-user') if e['operation_id']=='certificate:'+job['id']]
    assert len(events)==1
    assert events[0]['outcome']=='incomplete'
    assert 'PRIVATE KEY' not in json.dumps(events)
    base='/tools/certificate-automation/jobs/'+job['id']
    for suffix in ('','/status'):
        result=client.get(base+suffix)
        assert result.status_code==200
        assert b'PRIVATE KEY' not in result.data and b'enrollment-password' not in result.data
    key=client.get(base+'/recovery/key')
    assert b'PRIVATE KEY' in key.data
    assert key.headers['Cache-Control']=='no-store'
    assert client.post(base+'/reconcile').status_code==400
    with jobs.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET user_id=? WHERE id=?',('someone-else',job['id']))
    for suffix in ('','/status','/recovery/key','/recovery/csr'):
        assert client.get(base+suffix).status_code==404
    assert client.post(base+'/cancel').status_code==404
    assert client.post(base+'/reconcile',data={'confirmed':'yes'}).status_code==404
    with jobs.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET user_id=? WHERE id=?',('test-user',job['id']))
    assert client.post(base+'/reconcile',data={'confirmed':'yes'}).status_code==303
    assert client.get(base+'/recovery/key').status_code==404
    retained=jobs.get(job['id'],'test-user')
    assert 'private_key_pem' not in retained['summary']
    assert 'password' not in retained['config']
    assert certificates.enrollment_operation(job['id'])['status']=='pending'


def test_current_tool_permission_protects_all_certificate_endpoints(fixture):
    jobs,certificates,server,template,form=fixture
    auth=AuthStore(str(jobs.instance));auth.create_user('admin','long administrator password',is_admin=True)
    profile=auth.save_access_profile(name='Certificates',tool_ids=['tools.certificate_automation'])
    auth.create_user('operator','long operator password',access_profile_ids=[profile['id']])
    app=create_app(str(jobs.instance));client=app.test_client()
    client.post('/login',data={'username':'operator','password':'long operator password'})
    response=client.post('/tools/certificate-automation/enroll',data=form)
    assert response.status_code==303
    base=response.location
    auth.save_access_profile(profile_id=profile['id'],name='Certificates',tool_ids=['tools.ping'])
    for suffix in ('','/status','/recovery/key','/recovery/csr'):
        assert client.get(base+suffix).status_code==403
    for suffix in ('/cancel','/reconcile'):
        assert client.post(base+suffix,data={'confirmed':'yes'}).status_code==403


def test_recording_failure_stays_visible_without_replay(fixture,provider,monkeypatch):
    jobs,*_=fixture
    job,config=queued(fixture)
    monkeypatch.setattr('twn_toolkit.activity.ActivityStore.record_event',Mock(side_effect=OSError('fixture')))
    execute_certificate(jobs,job,config)
    assert 'activity' in jobs.get(job['id'],'owner')['summary']['recording_warning']
    execute_scan(jobs,job['id'],job['token'])
    assert provider.calls==1


def test_collection_uses_existing_key_and_version(fixture,provider):
    jobs,certificates,server,template,form=fixture
    job,config=queued(fixture);execute_certificate(jobs,job,config);jobs.release(job['id'],job['token'])
    operation=certificates.enrollment_operation(job['id'])
    def retrieve(self,request_id,key_pem,cn,names,**kwargs):
        key=serialization.load_pem_private_key(key_pem,password=None)
        leaf,_,ca=_ca_and_leaf(key,names)
        return EnrollmentResult('issued',request_id,certificate_pem=leaf,chain_pem=ca.public_bytes(serialization.Encoding.PEM))
    provider.retrieve=retrieve
    config=prepare_certificate(jobs,'collect',{},managed_id=operation['managed_id'])
    config.update(username='Owner',investigation_id='')
    job_id=jobs.enqueue(user_id='owner',tool='certificate_collect',config=config)
    collected=jobs.claim();execute_scan(jobs,job_id,collected['token'])
    retained=jobs.get(job_id,'owner')
    assert retained['state']=='succeeded',retained['error']
    assert retained['summary']['version_id']==operation['id']
    managed=certificates.managed_certificate(operation['managed_id'])
    assert managed['version_count']==1 and managed['status']=='issued'
    assert provider.calls==1


def test_later_queued_duplicate_does_not_send_after_first_succeeds(fixture,provider):
    jobs,*_=fixture
    first,config=queued(fixture)
    second_id=jobs.enqueue(user_id='owner',tool='certificate_enroll',config=config)
    execute_certificate(jobs,first,config)
    second=jobs.claim();assert second['id']==second_id
    execute_scan(jobs,second_id,second['token'])
    assert jobs.get(second_id,'owner')['state']=='failed'
    assert provider.calls==1


def test_unknown_without_request_id_blocks_after_restart(fixture,provider,monkeypatch):
    jobs,*_,form=fixture
    job,config=queued(fixture)
    def unknown(self,*args,before_submit,acknowledged,**kwargs):
        before_submit()
        raise ConnectionError('lost acknowledgement')
    monkeypatch.setattr(provider,'enroll',unknown)
    execute_certificate(jobs,job,config);jobs.release(job['id'],job['token'])
    with pytest.raises(ValueError,match='unresolved'):
        prepare_certificate(jobs,'enroll',form)
    assert jobs.get(job['id'],'owner')['state']=='unknown'


def test_terminal_release_removes_credentials_but_keeps_unknown_recovery(fixture,provider):
    jobs,*_=fixture
    provider.status='issued';provider.fail_fetch=True
    job,config=queued(fixture);execute_certificate(jobs,job,config)
    jobs.release(job['id'],job['token'])
    result=jobs.get(job['id'],'owner')
    assert result['state']=='unknown'
    assert not {'password','key_password','key_pem','login'} & result['config'].keys()
    assert result['config']['target']==config['target']
    assert 'PRIVATE KEY' in result['summary']['private_key_pem']


@pytest.mark.parametrize('phase',['before_submit','acknowledged'])
def test_provider_checkpoints_before_post_and_before_any_retrieval(fixture,phase):
    from twn_toolkit.certificate_automation import AdcsWebEnrollmentProvider,build_certificate_request,load_or_generate_private_key
    from tests.test_certificate_automation import _Session,_Response
    jobs,certificates,server,*_=fixture
    session=_Session(_Response(text='Certificate Issued <a href="certnew.cer?ReqID=123&Enc=b64">Download</a>'),[])
    provider=AdcsWebEnrollmentProvider(server,'fixture','password',session=session)
    key,csr=build_certificate_request('host.example.test',['host.example.test'],load_or_generate_private_key(key_size=2048))
    receipts=[]
    def before():
        assert session.posts==[]
        if phase=='before_submit':raise OSError('checkpoint failed')
    def ack(receipt):
        receipts.append(receipt)
        assert session.gets==[]
        raise OSError('checkpoint failed')
    with pytest.raises(OSError,match='checkpoint failed'):
        provider.enroll(csr,'WebServer',key,'host.example.test',['host.example.test'],before_submit=before,acknowledged=ack)
    assert len(session.posts)==(phase=='acknowledged')
    assert session.gets==[]
    if receipts:assert receipts[0].request_id=='123'


def test_completion_does_not_replace_a_newer_pending_version(fixture,provider):
    jobs,certificates,*_=fixture
    job,config=queued(fixture);execute_certificate(jobs,job,config)
    operation=certificates.enrollment_operation(job['id'])
    material=certificates.version_material(operation['managed_id'])
    key=serialization.load_pem_private_key(material['private_key_pem'],password=None)
    leaf,_,ca=_ca_and_leaf(key,config['dns_names'])
    newer=certificates.save_enrollment(managed_id=operation['managed_id'],name=config['name'],server_id=config['server_id'],template_id=config['template_id'],
        common_name=config['common_name'],dns_names=config['dns_names'],private_key_pem=material['private_key_pem'],result=EnrollmentResult('pending','124'))
    with pytest.raises(ValueError,match='no longer current'):
        certificates.complete_pending_version(operation['managed_id'],operation['id'],EnrollmentResult('issued','123',certificate_pem=leaf))
    assert certificates.managed_certificate(operation['managed_id'])['current_version_id']==newer['current_version_id']


def test_profile_change_after_ca_ack_preserves_key_without_registration(fixture,provider,monkeypatch):
    jobs,certificates,*_=fixture
    job,config=queued(fixture)
    original=jobs.progress
    def change(i,t,s):
        result=original(i,t,s)
        if s['stage']=='CA acknowledgement saved':
            with certificates._connect() as db:db.execute('UPDATE pki_servers SET updated_at=updated_at+1')
        return result
    monkeypatch.setattr(jobs,'progress',change)
    execute_certificate(jobs,job,config)
    retained=jobs.get(job['id'],'owner')
    assert retained['state']=='unknown' and retained['summary']['request_id']=='123'
    assert 'PRIVATE KEY' in retained['summary']['private_key_pem']
    assert certificates.enrollment_operation(job['id']) is None


def test_unknown_recovery_pages_are_bounded_and_old_records_accessible(fixture):
    jobs,*_=fixture
    app=create_app(str(jobs.instance));app.testing=True;client=app.test_client()
    jobs.policy.save({'diagnostic_user_limit':50})
    identifiers=[]
    for index in range(23):
        identifier=jobs.enqueue(user_id='test-user',tool='certificate_enroll',config={'mode':'enroll','username':'Owner'})
        job=jobs.claim()
        jobs.progress(identifier,job['token'],{'attempted':True,'private_key_pem':'fixture key','csr_pem':'fixture CSR'})
        jobs.abort(identifier,job['token'],'failed','lost receipt');jobs.release(identifier,job['token'])
        identifiers.append(identifier)
    page=client.get('/tools/certificate-automation?section=adcs')
    assert page.data.count(b'>Reconcile request ')==20
    assert b'Next recovery page' in page.data
    page=client.get('/tools/certificate-automation?section=adcs&recovery_page=2')
    assert page.data.count(b'>Reconcile request ')==3
    assert b'Previous recovery page' in page.data
    assert client.get('/tools/certificate-automation/jobs/'+identifiers[0]+'/recovery/key').data==b'fixture key'


def test_unknown_ca_disposition_preserves_observed_request_id(fixture):
    from twn_toolkit.certificate_automation import AdcsWebEnrollmentProvider,build_certificate_request,load_or_generate_private_key
    from tests.test_certificate_automation import _Session,_Response
    jobs,certificates,server,*_=fixture
    session=_Session(_Response(text='ReqID=456 Unexpected CA state'),[])
    provider=AdcsWebEnrollmentProvider(server,'fixture','password',session=session)
    key,csr=build_certificate_request('host.example.test',['host.example.test'],load_or_generate_private_key(key_size=2048))
    receipts=[]
    with pytest.raises(CertificateAutomationError):
        provider.enroll(csr,'WebServer',key,'host.example.test',['host.example.test'],acknowledged=receipts.append)
    assert len(receipts)==1 and receipts[0].status=='unknown' and receipts[0].request_id=='456'
    assert session.gets==[]


def test_submission_and_certificate_store_writes_require_full_sync(fixture):
    jobs,certificates,*_=fixture
    with jobs.connect(write=True) as db:
        assert db.execute('PRAGMA synchronous').fetchone()[0]==2
    with certificates._connect() as db:
        assert db.execute('PRAGMA synchronous').fetchone()[0]==2


def test_template_keeps_classic_forms_without_job_api_context(fixture,monkeypatch):
    from twn_toolkit import certificate_automation_routes as routes
    jobs,*_=fixture
    app=create_app(str(jobs.instance));app.testing=True
    render=routes.render_template
    def older_context(template,**values):
        for key in ('certificate_job_api','certificate_job_nonce','certificate_jobs','recovery_jobs','recovery_more','recovery_page'):
            values.pop(key,None)
        return render(template,**values)
    monkeypatch.setattr(routes,'render_template',older_context)
    response=app.test_client().get('/tools/certificate-automation?section=adcs')
    assert response.status_code==200
    assert b'data-certificate-job-form' not in response.data
    assert b'certificate-jobs.js' not in response.data
