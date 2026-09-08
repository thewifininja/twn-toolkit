"""Finite owner-only exports with durable case-attachment reconciliation."""
from datetime import datetime
import json
import sys

from .auth import AuthStore, load_or_create_secret_key
from .backup_source_reads import bounded_source_reads
from .automation import AutomationStore
from .automation_routes import _automation_run_archive
from .diagnostic_artifacts import PrivateArtifactStore, artifact_directory
from .profile_backup import (
    build_backup_catalog, selected_backup_items, build_profile_backup,
    encode_backup_json, encrypt_backup, MAX_BACKUP_WIRE_BYTES,
    MAX_ENCRYPTED_BACKUP_PLAINTEXT_BYTES,
)

FAMILIES = {'automation_export', 'configuration_export'}


class ExportJobError(ValueError):
    pass


def require_export_admin(instance, user_id):
    with bounded_source_reads(MAX_BACKUP_WIRE_BYTES):
        users = AuthStore(str(instance)).users()
    if not users and user_id == 'test-user':
        return
    user = next((item for item in users if item['id'] == user_id), None)
    if not user or not user.get('enabled', True) or not user.get('is_admin'):
        raise ExportJobError('Export access is no longer available for the requesting administrator.')


def check_running(store, job):
    current = store.owned(job['id'], job['token'])
    if not current or current['state'] != 'running':
        raise InterruptedError('This export no longer owns execution.')


def configuration_payload(instance, config):
    selected_ids = set(config['selected_ids'])
    selected = selected_backup_items(build_backup_catalog(str(instance)), selected_ids)
    if not selected or {item['id'] for item in selected} != selected_ids:
        raise ExportJobError('One or more selected configuration groups are no longer available. Select the export groups again.')
    sensitive = any(item['sensitive'] for item in selected)
    encrypted = bool(config['encrypted'])
    if sensitive and not encrypted:
        raise ExportJobError('The selected groups require an encrypted backup. Request a new export with an encryption password.')
    if encrypted and not config.get('password'):
        raise ExportJobError('The export encryption password is no longer available. Request a new export.')
    limit = MAX_ENCRYPTED_BACKUP_PLAINTEXT_BYTES if encrypted else MAX_BACKUP_WIRE_BYTES
    try:
        backup = build_profile_backup(selected, max_bytes=limit)
        payload = encode_backup_json(backup, limit)
        del backup
        if encrypted:
            envelope = encrypt_backup(payload, config['password'])
            del payload
            payload = encode_backup_json(envelope, MAX_BACKUP_WIRE_BYTES)
    except ValueError as exc:
        # Adapter validation messages can contain retained arbitrary input.
        raise ExportJobError('Selected configuration could not be exported within the source and file limits. Export fewer groups or repair invalid source data; saved configuration was not changed.') from exc
    prefix = 'twn-toolkit-encrypted-configuration-backup' if encrypted else 'twn-toolkit-configuration-backup'
    return payload, prefix+'-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'.json', {
        'group_count': len(selected), 'encrypted': encrypted,
        'contains_sensitive_groups': sensitive,
        'selected_groups': [{'type':'backup item','id':item['id'],'name':item['label']} for item in selected],
    }


def scrub_inputs(store, db, job_id=None):
    query = "SELECT id,config FROM diagnostic_jobs WHERE tool='configuration_export' AND completed IS NOT NULL AND token=''"
    if job_id:
        query += ' AND id=?'
    for row in db.execute(query, (job_id,) if job_id else ()):
        config = json.loads(store.cipher.open(row['config'], row['id']+':diagnostic-config'))
        if 'password' in config:
            config.pop('password')
            db.execute('UPDATE diagnostic_jobs SET config=? WHERE id=?',
                       (store.cipher.seal(json.dumps(config),row['id']+':diagnostic-config'),row['id']))


def execute_export(store, job, config):
    output = spool = None
    try:
        check_running(store, job)
        require_export_admin(store.instance, job['user_id'])
        family = job['tool']
        if family not in FAMILIES:
            raise ExportJobError('Unknown export format.')
        if not (family == 'automation_export' and config.get('investigation_id')):
            artifacts = PrivateArtifactStore(store.instance, family, config['artifact_bytes'])
            directory = artifact_directory(store, job['id'], family)
            directory.mkdir(mode=0o700)
            output = artifacts.begin_upload(job['id'], 'export.bin')
        if family == 'configuration_export':
            payload, filename, summary = configuration_payload(store.instance, config)
            for offset in range(0, len(payload), 65536):
                check_running(store, job)
                output.write(payload[offset:offset+65536])
            mimetype = 'application/json'
        else:
            runs = AutomationStore(str(store.instance), load_or_create_secret_key(str(store.instance)))
            try:
                run = runs.get_run(config['run_id'])
            except (ValueError, UnicodeError) as exc:
                raise ExportJobError('Retained run metadata exceeds its read limits or could not be decoded. Use the retained results JSON download to inspect the original data.') from exc
            if run is None:
                raise ExportJobError('The retained automation run is no longer available.')
            spool, filename = _automation_run_archive(runs, run, max_bytes=config['artifact_bytes'])
            if config.get('investigation_id'):
                summary = attach_run_to_original_case(store,job,config,run,spool,filename)
                if not store.finish(job['id'],job['token'],[],summary):
                    raise InterruptedError('Case attachment completion was not confirmed.')
                record_outcome(store,job,'succeeded')
                return
            while True:
                part = spool.read(65536)
                if not part:
                    break
                check_running(store, job)
                output.write(part)
            mimetype = 'application/zip'
            summary = {'run_id':run['id'], 'automation_id':run['automation_id']}
        check_running(store, job)
        require_export_admin(store.instance, job['user_id'])
        output.commit()
        summary.update(filename=filename,mimetype=mimetype,byte_count=output.total)
        if not store.finish(job['id'], job['token'], [], summary):
            raise InterruptedError('Export publication was not confirmed.')
        record_outcome(store, job, 'succeeded')
    except Exception as exc:
        current = store.owned(job['id'],job['token'])
        state = 'cancelled' if current and current['state']=='cancel_requested' else 'failed'
        error = str(exc) if isinstance(exc, ExportJobError) else 'Export failed ('+type(exc).__name__+'). Check source availability and private storage.'
        if current is not None:
            state,error=interruption_outcome(store,current,state,error)
        if store.abort(job['id'],job['token'],state,error):
            record_outcome(store,job,state)
    finally:
        if output is not None:
            output.close()
        if spool is not None:
            spool.close()


def record_outcome(store, job, state):
    from .audit import AuditStore
    try:
        current=store.owned(job['id'],job.get('token',''))
        if current and current['completed'] is not None:
            state=current['state']
        config=job['config']
        if isinstance(config,str):
            config=json.loads(store.cipher.open(config,job['id']+':diagnostic-config'))
        AuditStore(str(store.instance)).record(
            user_id=job['user_id'],username=str(config.get('username','')), method='WORKER',endpoint=job['tool']+'_job',
            path='/exports/'+job['id'],status_code=200,category='Exports',
            action='export.'+state,summary='Private export '+state+'.',
            resource_id=job['id'],details={'format':job['tool'],'outcome':state},
        )
    except Exception as exc:
        print('Export audit recording failed: '+type(exc).__name__,file=sys.stderr)


def mark_case_attachment(store, job, case_id):
    with store.connect(write=True) as db:
        summary=store.cipher.seal(json.dumps({'case_attachment_started':True,'case_id':case_id}),job['id']+':diagnostic-summary')
        changed=db.execute("UPDATE diagnostic_jobs SET summary=? WHERE id=? AND token=? AND state='running'",
                           (summary,job['id'],job['token'])).rowcount
        if not changed:
            raise InterruptedError('The export no longer owns case attachment.')


def interruption_outcome(store, job, state, error):
    if job['tool']!='automation_export':
        return state,error
    try:
        summary=job['summary']
        if isinstance(summary,str):
            summary=json.loads(store.cipher.open(summary,job['id']+':diagnostic-summary'))
    except (ValueError,TypeError):
        return 'unknown','Export completion could not be reconciled. Inspect the original case before retrying an attachment.'
    if summary.get('case_attachment_started'):
        return 'unknown','Case attachment may have completed before the export stopped. Inspect the original case before retrying.'
    return state,error


def attach_run_to_original_case(store, job, config, run, spool, filename):
    from .investigations import InvestigationStore
    cases=InvestigationStore(str(store.instance))
    case_id=config['investigation_id']
    case=cases.get_for_user(case_id,job['user_id'])
    if not case.get('is_open'):
        raise ExportJobError('The original case is closed. Open the intended case and request a new attachment.')
    check_running(store,job)
    require_export_admin(store.instance,job['user_id'])
    mark_case_attachment(store,job,case_id)
    results=[{
        'status':str(result.get('status',''))[:64],
        'summary':str(result.get('summary',''))[:2000],
        'stage':str(result.get('output',{}).get('_pipeline',{}).get('stage_name',''))[:256],
        'action':str(result.get('output',{}).get('_pipeline',{}).get('action_name',''))[:256],
    } for result in run.get('results',[])[:100] if isinstance(result,dict)]
    def before_publish():
        check_running(store,job)
        require_export_admin(store.instance,job['user_id'])
    spool.seek(0)
    attached=cases.add_generated_evidence_event(
        investigation_id=case_id,user_id=job['user_id'],username=config['username'],
        operation_id='automation-run:'+run['id'],event_type='automation.run.attached',tool_id='automation.home',
        action='Automation run',outcome='succeeded' if run['status']=='success' else 'failed' if run['status']=='error' else 'incomplete',
        summary='Attached collected run from automation '+str(run['automation_name'])[:512]+'.',
        targets={'automation_id':run['automation_id'],'automation':str(run['automation_name'])[:512]},
        parameters={'run_id':run['id'],'trigger':str(run['trigger_summary'])[:2000]},
        metrics={'result_count':len(results),'successful_results':sum(result['status']=='success' for result in results),
                 'failed_results':sum(result['status']=='error' for result in results),'archive_bytes':spool.upload.total},
        details={'results':results},started_at=float(run['started_at']),completed_at=float(run['finished_at']),
        filename=filename,content_type='application/zip',stream=spool,max_bytes=config['artifact_bytes'],
        before_publish=before_publish,
    )
    return {'case_id':case_id,'case_artifact_id':attached['artifact']['id'],'case_event_id':attached['event']['id'],
            'byte_count':attached['artifact']['byte_count'],'filename':filename,'mimetype':'application/zip',
            'run_id':run['id'],'automation_id':run['automation_id']}
