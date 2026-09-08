"""Supervised read-only appliance operations; no remote mutations are dispatched."""
from __future__ import annotations

import json
import sys
import time

from .datastore import DatastoreError
from .diagnostic_artifacts import PrivateArtifactStore, artifact_directory
from .fortigate import FortiGateClient, FortiGateError
from .fortiauthenticator import FortiAuthenticatorClient, FortiAuthenticatorError
from .csv_exports import csv_for_download
from .tasks import ExportTask, RenameTask, discover_export_fields, get_task

TOOL = 'appliance_read'
MAX_UI_BYTES = 1024 * 1024


class ApplianceReadLimitError(ValueError):
    pass


def execute_read(store, job, config):
    outputs = []
    try:
        mode = config['mode']
        provider = config['provider']
        if provider not in {'fortigate', 'fortiauthenticator'} or (provider == 'fortiauthenticator' and mode != 'connection'):
            raise ApplianceReadLimitError('Invalid appliance read provider or operation.')
        profile = config['profile']
        client = (FortiGateClient if provider == 'fortigate' else FortiAuthenticatorClient).from_profile(profile)
        data = {}
        if mode == 'connection':
            result = client.test_connection()
            if provider == 'fortigate':
                detail = str(result.get('version') or result.get('build') or 'reachable')[:512]
                message = 'Connection OK: ' + detail
            else:
                total = result.get('meta', {}).get('total_count')
                detail = str(total)[:64] + ' MAC devices available' if total is not None else 'reachable'
                message = "Connection to '" + profile['name'] + "' succeeded (" + detail + ').'
            data = {'message': message, 'activity_detail': profile['name'] + ': ' + detail}
        else:
            task = get_task(config['task_id'])
            endpoint = config['endpoint_template'] or task.endpoint_template
            vdom = profile.get('default_vdom', 'root')
            if isinstance(task, ExportTask):
                client = client.for_display_export()
            with client.pooled() as pooled:
                if mode == 'objects' and isinstance(task, RenameTask):
                    objects = task.discover_objects(client=pooled, endpoint_template=endpoint, default_vdom=vdom)
                    if len(objects) > 500:
                        raise ApplianceReadLimitError('The browser editor supports up to 500 devices. Use a scoped endpoint or the CSV workflow for larger inventories.')
                    data = {'objects': objects, 'row_count': len(objects)}
                elif isinstance(task, ExportTask):
                    if mode == 'export':
                        root = PrivateArtifactStore(store.instance, TOOL, config['artifact_bytes'])
                        artifact_directory(store, job['id'], TOOL).mkdir(mode=0o700)
                        for name in ('raw.csv', 'download.csv'):
                            outputs.append(root.begin_upload(job['id'], name))
                        class CsvOutput:
                            def write(self, text):
                                outputs[0].write(text.encode('utf-8'))
                                outputs[1].write(csv_for_download(text, config['csv_format']).encode('utf-8'))
                                return len(text)
                        writer = CsvOutput()
                        task.run(client=pooled, endpoint_template=endpoint, default_vdom=vdom,
                                 fields=config['fields'], output=writer)
                        for output in outputs:
                            output.commit()
                        data = {'archive': True, 'byte_count': outputs[0].total, 'message': 'CSV export is ready.'}
                    else:
                        rows, used = task.preview_rows_with_endpoint(client=pooled, endpoint_template=endpoint, default_vdom=vdom)
                        if mode == 'fields':
                            fields = discover_export_fields(task, rows)
                            if len(fields) > 256:
                                raise ApplianceReadLimitError('Field discovery exceeds 256 columns. Enter the required CSV fields directly.')
                            for field in fields:
                                field['sample'] = str(field.get('sample', ''))[:512]
                            data = {'fields': fields, 'row_count': len(rows), 'endpoint_used': used}
                        elif mode == 'preview':
                            columns, preview = task.format_rows(rows[:100], config['fields'])
                            if len(columns) > 64:
                                raise ApplianceReadLimitError('The browser preview supports 64 columns. Select fewer fields or export the full CSV.')
                            clipped = any(len(str(value)) > 512 for row in preview for value in row.values())
                            preview = [{key: str(value)[:512] if value is not None else '' for key, value in row.items()} for row in preview]
                            data = {'columns': columns, 'rows': preview, 'row_count': len(rows), 'endpoint_used': used,
                                    'preview_count': len(preview), 'fields_clipped': clipped}
                        else:
                            raise ApplianceReadLimitError('Unknown appliance read operation.')
                else:
                    raise ApplianceReadLimitError('Invalid appliance task.')
        if getattr(client, 'response_warnings', []):
            data['response_warnings'] = list(client.response_warnings)
        if len(json.dumps(data).encode()) > MAX_UI_BYTES:
            raise ApplianceReadLimitError('The browser result exceeds its 1 MiB envelope. Use a scoped endpoint or a CSV export.')
        if store.finish(job['id'], job['token'], [], data):
            record_read_outcome(store, job, 'succeeded', config=config, summary=data)
    except Exception as exc:
        if isinstance(exc, (FortiGateError, FortiAuthenticatorError)):
            error = 'Connection failed: ' + str(exc) if config['mode'] == 'connection' else str(exc)
        elif isinstance(exc, (ApplianceReadLimitError, DatastoreError)):
            error = str(exc)
        else:
            error = 'Appliance read failed (' + type(exc).__name__ + ').'
        for key in ('api_key', 'password'):
            secret = config['profile'].get(key)
            if secret:
                error = error.replace(str(secret), '[redacted]')
        current = store.owned(job['id'], job['token'])
        state = 'cancelled' if current and current['state'] == 'cancel_requested' else 'failed'
        if store.abort(job['id'], job['token'], state, error[:500]):
            record_read_outcome(store, job, state, config=config)
    finally:
        for output in outputs:
            output.close()


def record_read_outcome(store, job, state, *, config=None, summary=None):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .investigations import InvestigationStore
    try:
        if config is None:
            config = job['config']
            if isinstance(config, str):
                config = json.loads(store.cipher.open(config, job['id'] + ':diagnostic-config'))
        provider, mode = config['provider'], config['mode']
        label = 'FortiGate' if provider == 'fortigate' else 'FortiAuthenticator'
        title = 'Tested ' + label + ' profile' if mode == 'connection' else 'Ran FortiGate ' + mode
        identity = {'user_id': job['user_id'], 'username': config['username']}
        detail = (summary or {}).get('activity_detail', config['profile']['name'] + ': ' + state)
        ActivityStore(str(store.instance)).record_event('Fortinet', title, detail,
            counters={'fortinet': {'api_calls': int(bool(job.get('started'))), 'failures': int(state != 'succeeded')}},
            count_action=mode in {'connection', 'export'}, **identity)
        action = provider + ('.profile_test_' if mode == 'connection' else '.export_' if mode == 'export' else '.read_') + state
        AuditStore(str(store.instance)).record(**identity, method='WORKER', endpoint='appliance_read_job',
            path='/appliance-read/' + job['id'], status_code=200, category=label, action=action,
            summary=title + ': ' + state + '.', resource_id=config['profile']['name'],
            details={'outcome': state, 'operation id': job['id'], 'mode': mode})
        if not config.get('investigation_id'):
            return
        cases = InvestigationStore(str(store.instance))
        args = dict(investigation_id=config['investigation_id'], **identity,
            operation_id='appliance-read:' + job['id'], tool_id=config['tool_id'],
            event_type='external.export.completed' if mode == 'export' and state == 'succeeded' else 'diagnostic.' + state,
            action=config['label'], outcome='incomplete' if state == 'unknown' else state,
            summary=config['label'] + ': ' + state + '.', targets={'profile': config['profile']['name']},
            parameters={'mode': mode, 'download_format': config.get('csv_format', '')},
            metrics={'export_size_bytes': (summary or {}).get('byte_count', 0)}, details={},
            started_at=job.get('started') or job['created'], completed_at=time.time())
        if mode == 'export' and state == 'succeeded':
            with (artifact_directory(store, job['id'], TOOL) / 'raw.csv').open('rb') as stream:
                cases.add_generated_evidence_event(**args, filename=config['task_id'] + '-' + job['id'][:12] + '-raw.csv',
                    content_type='text/csv', stream=stream, max_bytes=config['artifact_bytes'])
        else:
            cases.record_for_case(**args)
    except Exception as exc:
        print('Appliance read outcome recording failed: ' + type(exc).__name__, file=sys.stderr)
        if summary is not None:
            warning = 'The appliance read completed, but activity, audit or case recording could not be fully confirmed. Check the original case before relying on its evidence.'
            try:
                sealed = store.cipher.seal(json.dumps({**summary, 'recording_warning': warning}), job['id'] + ':diagnostic-summary')
                with store.connect(write=True) as db:
                    db.execute("UPDATE diagnostic_jobs SET summary=? WHERE id=? AND token=? AND state='succeeded'", (sealed, job['id'], job['token']))
            except Exception as recording_error:
                print('Appliance read warning could not be retained: ' + type(recording_error).__name__, file=sys.stderr)
