"""Finite AD CS jobs with durable submission intent and owner-scoped recovery."""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
import hashlib
import hmac
import json
import shutil
import re
import sys
import time

from .auth import load_or_create_secret_key
from .certificate_automation import (
    AdcsWebEnrollmentProvider, CertificateAutomationStore, EnrollmentResult,
    build_certificate_request, load_or_generate_private_key,
    normalize_certificate_identity, validate_issued_certificate,
)
from .file_transactions import file_transaction

KINDS = {'certificate_test', 'certificate_enroll', 'certificate_collect'}
KEY_UPLOAD_BYTES = 16 * 1024


def certificate_store(instance):
    return CertificateAutomationStore(str(instance), load_or_create_secret_key(str(instance)))


def revision(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def admission_key(store, nonce, config):
    # The receipt key is plaintext metadata; never expose an unkeyed digest of
    # a configuration containing low-entropy credentials or key passphrases.
    key = load_or_create_secret_key(str(store.instance)).encode()
    digest = hmac.new(key, json.dumps(config, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    return 'certificate:' + nonce + ':' + digest


def _redact(value, config):
    text = str(value)
    for secret in (config.get('password'), config.get('key_password')):
        if secret:
            text = text.replace(secret, '[redacted]')
    return text[:2000]


def _unresolved(store, target, excluding=''):
    with store.connect() as db:
        for row in db.execute("SELECT id,config FROM diagnostic_jobs WHERE tool='certificate_enroll' AND state='unknown' AND id!=?", (excluding,)):
            config = json.loads(store.cipher.open(row['config'], row['id'] + ':diagnostic-config'))
            if config.get('target') == target:
                raise ValueError('An earlier submission is unresolved. Reconcile its recovery record before another enrollment.')


def prepare_certificate(store, mode, form, *, server_id='', managed_id='', key_bytes=b''):
    """Local validation only; no key generation, decoding or network traffic."""
    certificates = certificate_store(store.instance)
    existing = certificates.managed_certificate(managed_id) if managed_id else None
    if managed_id and not existing:
        raise ValueError('The managed certificate no longer exists.')
    template = None
    if mode == 'enroll':
        name = form.get('name', '').strip()
        if not name or len(name) > 100:
            raise ValueError('Enter a certificate name of no more than 100 characters.')
        template = certificates.template_profile(form.get('template_id', '').strip())
        if not template:
            raise ValueError('Select a valid certificate template profile.')
        server_id = template['server_id']
        common_name, dns_names = normalize_certificate_identity(form.get('common_name', ''), form.get('dns_names', ''))
        if existing and existing['status'] != 'issued':
            raise ValueError('Collect or reconcile the current request before rotating this certificate.')
        with certificates._connect() as db:
            conflict = db.execute('SELECT id FROM managed_certificates WHERE name=? COLLATE NOCASE', (name,)).fetchone()
        if conflict and conflict['id'] != managed_id:
            raise ValueError('A managed certificate already uses that name.')
    elif mode == 'collect':
        if not existing or existing['status'] != 'pending':
            raise ValueError('Pending certificate request not found.')
        server_id = existing['server_id']
    elif mode != 'test':
        raise ValueError('Invalid certificate operation.')
    server = certificates.server_profile(server_id)
    if not server:
        raise ValueError('Select an existing PKI server profile.')
    username, password = form.get('username', '').strip(), form.get('password', '')
    credential = None
    if username or password:
        if not username or not password:
            raise ValueError('Enter both a one-time enrollment username and password.')
    else:
        credential = certificates.credential_profile(form.get('credential_id', '').strip() or server.get('credential_id') or '', include_password=True)
        if not credential:
            raise ValueError('Select saved enrollment credentials or enter one-time credentials.')
        username, password = credential['username'], credential['password']
    config = {'mode': mode, 'server_id': server_id, 'server_revision': revision(server),
              'login': username, 'password': password, 'managed_id': managed_id,
              'managed_revision': revision(existing) if existing else '',
              'credential_id': credential['id'] if credential else '',
              'credential_revision': revision(credential) if credential else '',
              'label': existing['name'] if existing else server['name']}
    if mode == 'enroll':
        source = form.get('key_source', 'generate')
        if source not in {'generate', 'upload', 'reuse'} or (source == 'reuse' and not existing):
            raise ValueError('Select a valid private-key source.')
        if source == 'upload' and (not key_bytes or len(key_bytes) > KEY_UPLOAD_BYTES):
            raise ValueError('Choose a PEM RSA private key of no more than 16 KiB.')
        config.update(name=name, label=name, common_name=common_name, dns_names=dns_names,
                      template_id=template['id'], template_revision=revision(template),
                      key_source=source, key_pem=key_bytes.decode('ascii') if source == 'upload' else '',
                      key_password=form.get('private_key_password', ''),
                      target=revision({'managed_id': managed_id}) if managed_id else revision({'name': name.casefold()}))
        _unresolved(store, config['target'])
    return config


def _validate(store, config, *, job_id='', registered=None):
    certificates = certificate_store(store.instance)
    server = certificates.server_profile(config['server_id'])
    if not server or revision(server) != config['server_revision']:
        raise ValueError('The PKI server profile changed. Submit a new request.')
    if config['credential_id']:
        credential = certificates.credential_profile(config['credential_id'], include_password=True)
        if not credential or revision(credential) != config['credential_revision']:
            raise ValueError('The credential profile changed. Submit a new request.')
    managed_id = registered['managed_id'] if registered else config['managed_id']
    existing = certificates.managed_certificate(managed_id) if managed_id else None
    if registered:
        if not existing or existing['current_version_id'] != registered['id']:
            raise ValueError('The saved request changed before collection completed.')
    elif (revision(existing) if existing else '') != config['managed_revision']:
        raise ValueError('The managed certificate changed. Review its current version.')
    template = None
    if config['mode'] == 'enroll':
        template = certificates.template_profile(config['template_id'])
        if not template or revision(template) != config['template_revision']:
            raise ValueError('The certificate template changed. Submit a new request.')
        _unresolved(store, config['target'], job_id)
        with certificates._connect() as db:
            conflict = db.execute('SELECT id FROM managed_certificates WHERE name=? COLLATE NOCASE', (config['name'],)).fetchone()
        if conflict and conflict['id'] != managed_id:
            raise ValueError('A managed certificate already uses that name.')
    return certificates, server, template, existing


def interruption_state(store, job, state):
    try:
        summary = json.loads(store.cipher.open(job['summary'], job['id'] + ':diagnostic-summary'))
    except Exception:
        return 'unknown'  # Fail closed if durable intent cannot be read.
    if summary.get('attempted') and not summary.get('settled'):
        return 'unknown'
    return 'failed' if state == 'unknown' else state


def execute_certificate(store, job, config):
    summary = {'stage': 'Validating saved inputs', 'label': config['label'], 'attempted': False}
    provider = None

    def checkpoint(stage):
        summary['stage'] = stage
        if not store.progress(job['id'], job['token'], summary):
            raise InterruptedError('The certificate job no longer owns execution.')

    try:
        if job['tool'] != 'certificate_' + config['mode']:
            raise ValueError('The certificate operation does not match its retained job kind.')
        # Mutating certificate jobs serialize per instance. Waiting is covered by
        # the existing finite-worker deadline and releases on process exit.
        with (file_transaction(store.instance / 'certificate-operations') if config['mode'] != 'test' else nullcontext()):
            certificates, server, template, existing = _validate(store, config, job_id=job['id'])
            checkpoint('Preparing request')
            temporary = store.instance / 'certificate_job_temporary' / job['id']
            temporary.mkdir(parents=True, mode=0o700, exist_ok=True)
            temporary.parent.chmod(0o700)
            provider = AdcsWebEnrollmentProvider(server, config['login'], config['password'], temporary_directory=temporary)
            if config['mode'] == 'test':
                summary['http_status'] = provider.test_connection()
                summary['disposition'] = 'connected'
            elif config['mode'] == 'collect':
                material = certificates.version_material(existing['id'], existing['current_version_id'])
                result = provider.retrieve(material['request_id'], material['private_key_pem'], existing['common_name'], existing['dns_names'], ca_name=material['ca_name'])
                _validate(store, config, job_id=job['id'])
                checkpoint('Saving collected certificate')
                certificates.complete_pending_version(existing['id'], material['id'], result)
                summary.update(managed_id=existing['id'], version_id=material['id'], disposition='issued', request_id=result.request_id)
            else:
                key_bytes = config['key_pem'].encode('ascii')
                if config['key_source'] == 'reuse':
                    key_bytes = certificates.version_material(existing['id'], existing['current_version_id'])['private_key_pem']
                key = load_or_generate_private_key(key_size=int(template['key_size']), existing_key=key_bytes, password=config['key_password'])
                key_pem, csr = build_certificate_request(config['common_name'], config['dns_names'], key)
                summary.update(private_key_pem=key_pem.decode('ascii'), csr_pem=csr.decode('ascii'),
                               common_name=config['common_name'], dns_names=config['dns_names'],
                               enrollment_url=server['enrollment_url'], template_identifier=template['template_identifier'])
                checkpoint('Key and CSR saved; not submitted')

                def before_submit():
                    _validate(store, config, job_id=job['id'])
                    summary['attempted'] = True
                    checkpoint('Submission started; awaiting CA acknowledgement')

                def acknowledged(receipt):
                    if len(receipt.request_id) > 32:
                        receipt = replace(receipt, status='unknown', request_id='')
                    receipt = replace(receipt, ca_name=_redact(receipt.ca_name, config)[:256])
                    summary.update(disposition=receipt.status, request_id=receipt.request_id,
                                   ca_name=receipt.ca_name, message=_redact(receipt.message, config))
                    checkpoint('CA acknowledgement saved')
                    if receipt.status in {'issued', 'pending'} and receipt.request_id.isdigit():
                        _validate(store, config, job_id=job['id'])
                        certificates.save_enrollment(managed_id=config['managed_id'], name=config['name'],
                            server_id=config['server_id'], template_id=config['template_id'],
                            common_name=config['common_name'], dns_names=config['dns_names'], private_key_pem=key_pem,
                            result=replace(receipt, status='pending', message=summary['message']), operation_id=job['id'])
                        operation = certificates.enrollment_operation(job['id'])
                        summary.update(managed_id=operation['managed_id'], version_id=operation['id'])
                        checkpoint('Request and key registered; retrieving certificate')

                result = provider.enroll(csr, template['template_identifier'], key_pem, config['common_name'], config['dns_names'],
                                         before_submit=before_submit, acknowledged=acknowledged)
                if result.status == 'issued':
                    validate_issued_certificate(result.certificate_pem, key_pem, config['common_name'], config['dns_names'])
                    operation = certificates.enrollment_operation(job['id'])
                    if not operation:
                        raise ValueError('CA acknowledgement could not be registered; reconcile the retained request.')
                    _validate(store, config, job_id=job['id'], registered=operation)
                    # Registering the pending version deliberately changed the
                    # current version; the global job lock prevents another job
                    # racing this completion. The store requires this exact version.
                    certificates.complete_pending_version(operation['managed_id'], operation['id'], replace(result, message=_redact(result.message, config), ca_name=summary.get('ca_name','')))
                elif result.status == 'pending':
                    if not summary.get('managed_id'):
                        raise ValueError('Pending request has no recoverable request ID.')
                elif result.status != 'denied':
                    raise ValueError('The CA disposition is uncertain. Reconcile the retained request before retrying.')
                summary['settled'] = True
            checkpoint('Complete')
            # Settled keys are retained in the certificate store; unknown keys
            # remain in encrypted progress, excluded from normal history pruning.
            summary.pop('private_key_pem', None)
            summary.pop('csr_pem', None)
            if store.finish(job['id'], job['token'], [], summary):
                record_certificate_outcome(store, job, 'succeeded', '', config=config)
    except Exception as exc:
        error = _redact(str(exc) or type(exc).__name__, config)
        current = store.owned(job['id'], job['token'])
        state = 'cancelled' if current and current['state'] == 'cancel_requested' else 'failed'
        if store.abort(job['id'], job['token'], state, error):
            final = store.get(job['id'], job['user_id'])
            record_certificate_outcome(store, job, final['state'], error, config=config)
    finally:
        if provider is not None:
            provider.session.close()
        cleanup_certificate_files(store)


def record_certificate_outcome(store, job, state, error, *, config=None):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .investigations import InvestigationStore
    config = config or json.loads(store.cipher.open(job['config'], job['id'] + ':diagnostic-config'))
    retained = store.get(job['id'], job['user_id'])
    if not retained:
        return
    summary = retained['summary']
    state = retained['state']
    identity = {'user_id': job['user_id'], 'username': config['username']}
    disposition = summary.get('disposition', state)
    description = f"Certificate {config['mode']}: {disposition}."
    if state != 'succeeded':
        description += ' ' + _redact(error or retained['error'], config)
    details = {k: summary[k] for k in ('disposition', 'request_id', 'managed_id', 'version_id', 'attempted') if k in summary}
    warnings = []
    for name, callback in [
        ('activity', lambda: ActivityStore(str(store.instance)).record_event('TLS', 'Certificate ' + config['mode'], description, **identity)),
        ('audit', lambda: AuditStore(str(store.instance)).record(**identity, method='WORKER', endpoint='tools.certificate_automation', path='/tools/certificate-automation', status_code=200,
             category='Network tools', action='certificate_automation.enrollment.run_' + state, summary=description, resource_id=job['id'], details=details))]:
        try:
            callback()
        except Exception:
            warnings.append(name)
    if config.get('investigation_id'):
        try:
            outcome = ('failed' if disposition == 'denied' else 'incomplete' if disposition == 'pending' else 'succeeded') if state == 'succeeded' else ('incomplete' if state == 'unknown' else state)
            event = InvestigationStore(str(store.instance)).record_for_case(investigation_id=config['investigation_id'], **identity,
                operation_id='certificate:' + job['id'], event_type='certificate.' + outcome, tool_id='tools.certificate_automation',
                action='Certificate ' + config['mode'], outcome=outcome, summary=description, targets={'server_id': config['server_id']},
                parameters={'mode': config['mode']}, metrics={}, details=details, started_at=job.get('started') or job['created'], completed_at=time.time())
            summary['journal_event'] = {'id': event['id'], 'investigation_id': event['investigation_id']}
        except Exception:
            warnings.append('original case')
    if warnings:
        summary['recording_warning'] = 'Could not confirm recording to: ' + ', '.join(warnings) + '. This request will not be replayed.'
    try:
        with store.connect(write=True) as db:
            db.execute('UPDATE diagnostic_jobs SET summary=? WHERE id=?', (store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary'), job['id']))
    except Exception as exc:
        print('Certificate recording metadata failed: ' + type(exc).__name__, file=sys.stderr)


def cleanup_certificate_files(store):
    root = store.instance / 'certificate_job_temporary'
    if not root.is_dir() or root.is_symlink():
        return
    with store.connect() as db:
        retained = {row[0] for row in db.execute("SELECT id FROM diagnostic_jobs WHERE tool IN ('certificate_test','certificate_enroll','certificate_collect') AND (state IN ('queued','running','cancel_requested') OR token!='')")}
    for path in root.iterdir():
        if re.fullmatch(r'[a-f0-9]{32}', path.name) and path.name not in retained:
            if path.is_symlink():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)


def scrub_certificate_inputs(store, db, job_id=None):
    query = "SELECT id,config FROM diagnostic_jobs WHERE tool IN ('certificate_test','certificate_enroll','certificate_collect') AND completed IS NOT NULL AND token=''"
    if job_id:
        query += ' AND id=?'
    for row in db.execute(query, (job_id,) if job_id else ()):
        config = json.loads(store.cipher.open(row['config'], row['id'] + ':diagnostic-config'))
        sensitive = {'password','key_password','key_pem','login','credential_revision'}
        if any(key in config for key in sensitive):
            config = {key:value for key,value in config.items() if key not in sensitive}
            db.execute('UPDATE diagnostic_jobs SET config=? WHERE id=?',
                       (store.cipher.seal(json.dumps(config), row['id'] + ':diagnostic-config'), row['id']))
