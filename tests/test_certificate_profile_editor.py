import pytest
from twn_toolkit import create_app
from twn_toolkit.certificate_automation import CertificateAutomationStore

@pytest.fixture
def editor(tmp_path):
 app=create_app(str(tmp_path));app.testing=True
 try:yield app.test_client(),CertificateAutomationStore(str(tmp_path),str(app.config['SECRET_KEY']))
 finally:app.extensions['remote_session_manager'].close()

JSON={'Accept':'application/json'}
BASE='/tools/certificate-automation/'


def test_acknowledged_credential_save_retains_identity_and_never_returns_secret(editor):
 client,store=editor
 response=client.post(BASE+'credentials',data={'name':'Identity','username':'api','password':'private-fixture'},headers=JSON)
 assert response.status_code==200
 saved=response.json['saved'];assert set(saved)=={'id','name'}
 assert b'private-fixture' not in response.data
 response=client.post(BASE+'credentials',data={'id':saved['id'],'name':'Renamed','username':'new-api','password':''},headers=JSON)
 assert response.status_code==200 and response.json['saved']['id']==saved['id']
 assert store.credential_profile(saved['id'],include_password=True)['password']=='private-fixture'
 assert store.credential_profile(saved['id'])['username']=='new-api'

@pytest.mark.parametrize('kind,payload',[
 ('credentials',{'name':'','username':'api','password':'private-fixture'}),
 ('credentials',{'name':'Identity','username':'','password':'private-fixture'}),
 ('credentials',{'name':'Identity','username':'api','password':''}),
 ('servers',{'name':'Server','enrollment_url':'http://insecure.invalid/certsrv'}),
 ('servers',{'name':'Server','enrollment_url':'https://pki.invalid/certsrv','timeout':'nan'}),
 ('servers',{'name':'Server','enrollment_url':'https://pki.invalid/certsrv','credential_id':'missing'}),
 ('templates',{'name':'Template','server_id':'missing','template_identifier':'WebServer'}),
])
def test_profile_validation_returns_error_without_redirect_or_secret(editor,kind,payload):
 client,_=editor;response=client.post(BASE+kind,data=payload,headers=JSON)
 assert response.status_code==400 and set(response.json)=={'error'}
 assert 'Location' not in response.headers and b'private-fixture' not in response.data


def test_acknowledged_server_template_workflow_uses_saved_ids(editor):
 client,store=editor
 response=client.post(BASE+'servers',data={'name':'Server','enrollment_url':'https://pki.invalid/certsrv','verify_tls':'1'},headers=JSON)
 assert response.status_code==200;server=response.json['saved']
 response=client.post(BASE+'templates',data={'name':'Template','server_id':server['id'],'template_identifier':'WebServer'},headers=JSON)
 assert response.status_code==200;template=response.json['saved']
 response=client.post(BASE+'templates',data={'id':template['id'],'name':'Renamed template','server_id':server['id'],'template_identifier':'WebServer','renewal_days':'45'},headers=JSON)
 assert response.status_code==200 and response.json['saved']['id']==template['id']
 assert store.template_profile(template['id'])['renewal_days']==45
 page=client.get(BASE.rstrip('/')+'?section=adcs')
 assert page.status_code==200 and b'data-certificate-profile-editor' in page.data


def test_native_profile_submission_keeps_redirect_contract_and_validates_name(editor):
 client,_=editor
 for name in ('Native',''):
  response=client.post(BASE+'credentials',data={'name':name,'username':'api','password':'private-fixture'})
  assert response.status_code==302 and '#pki-profiles' in response.headers['Location']
