"""Failure-state UI regressions; no network runner may be reached."""
from html.parser import HTMLParser
from unittest.mock import Mock
import pytest
from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.dns_diagnostic import prepare_dns_config
from twn_toolkit.profiles import NTPHostProfileStore, RadiusProfileStore

class Page(HTMLParser):
    def __init__(self): super().__init__();self.nodes=[];self.text=[]
    def handle_starttag(self,tag,attrs): self.nodes.append((tag,dict(attrs)))
    def handle_data(self,text): self.text.append(text)
    def by_id(self,value):return next(attrs for tag,attrs in self.nodes if attrs.get('id')==value)

@pytest.fixture
def setup(tmp_path,monkeypatch):
    mocks=[]
    for target in ('twn_toolkit.dns_diagnostic.dns_lookup_matrix','twn_toolkit.dns_diagnostic.dns_load_test','twn_toolkit.ntp_routes.test_ntp_servers','twn_toolkit.radius_routes.radius_authenticate','socket.create_connection','socket.getaddrinfo'):
        mock=Mock(side_effect=AssertionError('Network execution forbidden in UI regression'))
        monkeypatch.setattr(target,mock);mocks.append(mock)
    app=create_app(str(tmp_path));app.testing=True
    store=DiagnosticJobStore(str(tmp_path));app.extensions['diagnostic_job_store']=store
    yield app,app.test_client(),store,tmp_path
    for mock in mocks:mock.assert_not_called()
    app.extensions['remote_session_manager'].close()

def seed_dns(store,owner='test-user'):
    config={**prepare_dns_config({'hosts':'fixture.test','servers':'192.0.2.53','mode':'compare','record_type':'A','timeout':'1'}),'username':'fixture','investigation_id':''}
    job=store.enqueue(user_id=owner,tool='dns',config=config);claim=store.claim()
    reason='<script>alert("not executed")</script> '+'unbroken'*100
    base={'host':'fixture.test','server':'192.0.2.53','record_type':'A','host_label':'','server_label':'','answers':[],'status':'timeout','error':reason}
    rows=[{**base,'response_ms':None},{**base,'status':'success','answers':['192.0.2.1'],'error':'','response_ms':0},{**base,'status':'success','answers':['192.0.2.2'],'error':'','response_ms':12.5},{**base,'error':'Historic missing timing'}]
    assert store.finish(job,claim['token'],rows,{'load_result':None,'lookup_summary':{'queries':4,'successful':2,'failed':2,'average_ms':6.25,'slowest_ms':12.5}})
    store.release(job,claim['token']);return job,reason

def test_dns_error_is_visible_escaped_and_timing_is_precise(setup):
    app,client,store,path=setup;job,reason=seed_dns(store)
    response=client.get('/tools/dns-response',query_string={'job':job});page=Page();page.feed(response.get_data(as_text=True))
    assert response.status_code==200 and reason in ''.join(page.text)
    assert reason not in [attrs.get('title') for tag,attrs in page.nodes]
    assert b'&lt;script&gt;alert' in response.data and b'<script>alert' not in response.data
    assert b'None ms' not in response.data and b'<strong> ms</strong>' not in response.data
    assert b'<strong>0 ms</strong>' in response.data and b'<strong>12.5 ms</strong>' in response.data
    assert response.data.count('<strong>—</strong>'.encode())>=2
    csv=client.get(f'/tools/dns-response/jobs/{job}/csv')
    import csv as csv_module,io
    assert csv.status_code==200
    assert next(csv_module.DictReader(io.StringIO(csv.get_data(as_text=True))))['Error']==reason
    foreign,_=seed_dns(store,owner='foreign')
    assert client.get('/tools/dns-response',query_string={'job':foreign}).status_code==404
    assert client.get(f'/tools/dns-response/jobs/{foreign}/csv').status_code==404

@pytest.mark.parametrize('hosts',['edited-target.test',''])
def test_ntp_invalid_post_preserves_targets_and_profile_metadata(setup,hosts):
    app,client,store,path=setup
    NTPHostProfileStore(str(path)).upsert({'name':'Remembered','values':'remembered.test','targets':[{'host':'remembered.test','label':''}],'count':1})
    response=client.post('/tools/ntp-test',data={'hosts':hosts,'timeout':'invalid','host_profile':'Remembered','profile_name':'Draft name'})
    page=Page();page.feed(response.get_data(as_text=True))
    assert response.status_code==200 and page.by_id('ntp-form')['data-restore-remembered-profile']=='false'
    assert f'>{hosts}</textarea>'.encode() in response.data
    assert page.by_id('ntp-profile-name')['value']=='Draft name'
    assert any(tag=='option' and attrs.get('value')=='Remembered' and 'selected' in attrs for tag,attrs in page.nodes)
    fresh=Page();fresh.feed(client.get('/tools/ntp-test').get_data(as_text=True))
    assert fresh.by_id('ntp-form')['data-restore-remembered-profile']=='true'

def radius_profiles(path):
    RadiusProfileStore(str(path),'servers').upsert({'name':'Fixture server','host':'192.0.2.44','port':1812,'secret':'Synthetic secret'})
    RadiusProfileStore(str(path),'credentials').upsert({'name':'Fixture credentials','username':'fixture','password':'Synthetic password'})

@pytest.mark.parametrize('populated',[False,True])
def test_radius_stale_profile_error_forces_visible_run_and_repair(setup,populated):
    app,client,store,path=setup
    if populated:radius_profiles(path)
    response=client.post('/tools/radius-test',data={'server_names':'Removed','credential_name':'Removed','protocol':'pap','timeout':'4','retries':'2'})
    page=Page();page.feed(response.get_data(as_text=True))
    assert 'hidden' not in page.by_id('radius-workflows-panel')
    workspace=next(attrs for tag,attrs in page.nodes if 'data-workspace-tabs' in attrs)
    assert workspace['data-initial-tab']=='workflows' and workspace['data-forced-tab']=='true'
    assert b'role="alert"' in response.data and b'data-radius-show-profiles' in response.data
    assert b'value="4"' in response.data and b'value="2"' in response.data
    assert b'Profile Management below' not in response.data

@pytest.mark.parametrize('protocol,timeout',[('pap','invalid'),('eap-tls','3')])
def test_radius_nonprofile_errors_do_not_suggest_profile_repair(setup,protocol,timeout):
    app,client,store,path=setup;radius_profiles(path)
    response=client.post('/tools/radius-test',data={'server_names':'Fixture server','credential_name':'Fixture credentials','protocol':protocol,'timeout':timeout})
    page=Page();page.feed(response.get_data(as_text=True))
    assert 'hidden' not in page.by_id('radius-workflows-panel') and b'role="alert"' in response.data
    assert b'data-radius-show-profiles' not in response.data

@pytest.mark.parametrize('tool',['dns-response','ntp-test','radius-test'])
def test_denied_member_cannot_run_or_view_network_tool(setup,tool):
    app,client,store,path=setup;auth=AuthStore(str(path))
    auth.create_user('fixture-owner','SyntheticOnlyPassword123!',is_admin=True)
    member=auth.create_user('fixture-denied','SyntheticOnlyPassword123!')
    app.testing=False
    with client.session_transaction() as session:
        import time
        session['user_id']=member['id'];session['session_version']=member['session_version'];session['last_seen']=int(time.time())
    assert client.get('/tools/'+tool).status_code==403
    assert client.post('/tools/'+tool,data={}).status_code==403
