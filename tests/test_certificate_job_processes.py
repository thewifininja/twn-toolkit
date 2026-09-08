"""Actual isolated AD CS workers interrupted during a partial TLS response."""
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ipaddress
import json
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from twn_toolkit.certificate_jobs import certificate_store,prepare_certificate
from twn_toolkit.diagnostic_jobs import DiagnosticJobStore
from twn_toolkit.diagnostic_worker import DiagnosticScheduler


def wait_for(predicate,timeout=12):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if predicate(): return
        time.sleep(.03)
    raise AssertionError('Timed out waiting for certificate worker')


@pytest.mark.parametrize('interruption',['cancel','deadline','shutdown','crash'])
def test_partial_tls_submission_retains_key_without_replay(tmp_path,interruption):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
          .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(key,hashes.SHA256()))
    cert_path=tmp_path/'tls.pem';cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path=tmp_path/'tls.key';key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    submitted=threading.Event();release=threading.Event();posts=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            posts.append(self.path)
            self.send_response(200);self.send_header('Content-Length','100000');self.end_headers()
            self.wfile.write(b'<html>partial');self.wfile.flush();submitted.set();release.wait(15)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert_path,key_path)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    jobs=DiagnosticJobStore(tmp_path);jobs.policy.save({'minimum_free_gib':0})
    certificates=certificate_store(tmp_path)
    profile=certificates.save_server({'name':'TLS fixture','provider':'adcs_web_enrollment','enrollment_url':f'https://127.0.0.1:{server.server_port}/certsrv',
        'retrieval_strategy':'same_endpoint','timeout':30,'ca_bundle_pem':cert_path.read_text()})
    template=certificates.save_template({'name':'fixture','server_id':profile['id'],'template_identifier':'WebServer','key_size':2048,'renewal_days':30})
    form={'name':'fixture','common_name':'host.example.test','dns_names':'host.example.test','template_id':template['id'],
          'key_source':'generate','username':'fixture','password':'fixture-password'}
    config=prepare_certificate(jobs,'enroll',form);config.update(username='Owner',investigation_id='')
    scheduler=DiagnosticScheduler(tmp_path)
    job_id=jobs.enqueue(user_id='owner',tool='certificate_enroll',config=config)
    try:
        scheduler.tick();wait_for(submitted.is_set)
        if interruption=='cancel':jobs.cancel(job_id,'owner')
        elif interruption=='deadline':scheduler.active[job_id]['deadline']=time.monotonic()-1
        elif interruption=='shutdown':scheduler.close()
        else:scheduler.active[job_id]['process'].kill()
        def finished():
            scheduler.tick()
            return not scheduler.active
        wait_for(finished)
        result=jobs.get(job_id,'owner')
        assert result['state']=='unknown',result
        assert result['summary']['attempted'] is True
        assert 'PRIVATE KEY' in result['summary']['private_key_pem']
        assert 'CERTIFICATE REQUEST' in result['summary']['csr_pem']
        DiagnosticScheduler(tmp_path).close()
        jobs.cleanup()
        assert len(posts)==1
        assert list((tmp_path/'certificate_job_temporary').iterdir())==[]
    finally:
        release.set();scheduler.close();server.shutdown();server.server_close();thread.join(3)
