"""Bounded FortiAuthenticator inventory jobs and streamed CSV publication."""
from __future__ import annotations

import csv
import io
import json
import re
import sys
import time
from typing import Any

from .csv_exports import csv_download_filename, normalize_csv_download_format, _spreadsheet_safe_cell
from .diagnostic_artifacts import artifact_directory, PrivateArtifactStore
from .datastore import DatastoreError
from .fortiauthenticator import FortiAuthenticatorClient, FortiAuthenticatorError

TOOLS = ('fac_inventory_devices', 'fac_inventory_memberships')
PREVIEW_LIMIT = 500
KINDS = {
    'devices': {'path':'mac-devices', 'endpoint':'fortiauthenticator_mac_devices',
                'tool_id':'fortiauthenticator.mac_devices', 'label':'MAC devices',
                'activity':'MAC devices', 'audit':'mac_devices', 'method':'get_all_mac_devices',
                'template':'fortiauthenticator/mac_devices.html',
                'fields':['ID','MAC Address','Name','Description','Resource URI']},
    'memberships': {'path':'mac-group-memberships', 'endpoint':'fortiauthenticator_mac_group_memberships',
                    'tool_id':'fortiauthenticator.group_memberships', 'label':'MAC group memberships',
                    'activity':'MAC memberships', 'audit':'mac_memberships', 'method':'get_all_mac_group_memberships',
                    'template':'fortiauthenticator/mac_group_memberships.html',
                    'fields':['Membership ID','Device ID','Device Name','Device URI','Group ID','Group Name','Group URI','Expiry Time','Resource URI']},
}


def resource_id(uri):
    match = re.search(r'/(\d+)/?$', str(uri or ''))
    return match.group(1) if match else ''


def format_device(item: dict[str, Any]) -> dict[str, Any]:
    resource_uri = str(item.get("resource_uri") or "")
    return {
        "ID": resource_id(resource_uri) or item.get("id", ""),
        "MAC Address": item.get("address", ""),
        "Name": item.get("name", ""),
        "Description": item.get("description", ""),
        "Resource URI": resource_uri,
    }


def format_membership(item: dict[str, Any]) -> dict[str, Any]:
    device_uri = str(item.get("device") or "")
    group_uri = str(item.get("group") or "")
    resource_uri = str(item.get("resource_uri") or "")
    return {
        "Membership ID": item.get("id", "") or resource_id(resource_uri),
        "Device ID": resource_id(device_uri),
        "Device Name": item.get("device_name", ""),
        "Device URI": device_uri,
        "Group ID": resource_id(group_uri),
        "Group Name": item.get("group_name", ""),
        "Group URI": group_uri,
        "Expiry Time": item.get("expiry_time") or "",
        "Resource URI": resource_uri,
    }


def prepare_inventory_config(profile, kind, mode, csv_format):
    if not profile or kind not in KINDS or mode not in {'preview','export'}:
        raise ValueError('Select a valid FortiAuthenticator profile and inventory operation.')
    return {'profile':profile, 'kind':kind, 'mode':mode, 'csv_format':normalize_csv_download_format(csv_format)}


class CsvFile:
    def __init__(self, artifacts, job_id, filename, limit):
        self.handle = artifacts.begin_upload(job_id, filename)
        self.limit, self.size = limit, 0
        self.buffer = io.StringIO(newline='')
        self.writer = csv.writer(self.buffer, lineterminator='\n')

    def row(self, cells):
        self.writer.writerow(cells)
        encoded = self.buffer.getvalue().encode('utf-8')
        self.buffer.seek(0); self.buffer.truncate()
        if self.size + len(encoded) > self.limit:
            raise ValueError('Inventory CSV exceeds the configured export file limit. Increase the limit in Settings → Operations or reduce the inventory.')
        self.handle.write(encoded)
        self.size += len(encoded)

    def commit(self):
        self.handle.commit()

    def close(self):
        self.handle.close()


def execute_inventory(store, job, config):
    prepared = prepare_inventory_config(config['profile'], config['kind'], config['mode'], config['csv_format'])
    spec = KINDS[prepared['kind']]
    profile = prepared['profile']
    directory = artifact_directory(store, job['id'], job['tool'])
    writers = []
    try:
        objects = getattr(FortiAuthenticatorClient.from_profile(profile), spec['method'])()
        rows = []
        clipped = False
        formatter = format_device if prepared['kind']=='devices' else format_membership
        if config['mode']=='export':
            artifacts = PrivateArtifactStore(store.instance, job['tool'], config['artifact_bytes'])
            directory.mkdir(mode=0o700)
            for name in ('raw.csv','download.csv'):
                writers.append(CsvFile(artifacts, job['id'], name, config['artifact_bytes']))
            for writer in writers:
                writer.row(spec['fields'])
        for index, item in enumerate(objects):
            mapped = formatter(item)
            values = [str(mapped[field]) if mapped[field] is not None else '' for field in spec['fields']]
            if index < PREVIEW_LIMIT:
                clipped |= any(len(value)>512 for value in values)
                rows.append({field:value[:512] for field,value in zip(spec['fields'],values)})
            if writers:
                writers[0].row(values)
                writers[1].row(values if config['csv_format']=='raw' else [_spreadsheet_safe_cell(value) for value in values])
        for writer in writers:
            writer.commit()
        summary = {'total_count':len(objects), 'preview_count':len(rows), 'fields_clipped':clipped, 'archive':bool(writers)}
        if store.finish(job['id'], job['token'], rows, summary):
            record_inventory_outcome(store, job, 'succeeded', '', config=config, summary=summary)
    except (FortiAuthenticatorError, DatastoreError, OSError, ValueError) as exc:
        error = str(exc).replace(str(profile.get('password') or '\0'), '[redacted]')[:500]
        current = store.owned(job['id'], job['token'])
        state = 'cancelled' if current and current['state']=='cancel_requested' else 'failed'
        if store.abort(job['id'], job['token'], state, error):
            record_inventory_outcome(store, job, state, error, config=config)
    finally:
        for writer in writers:
            try:
                writer.close()
            except OSError:
                pass


def record_inventory_outcome(store, job, state, error, *, config=None, summary=None):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .investigations import InvestigationStore
    try:
        if config is None:
            config = job['config']
            if isinstance(config,str):
                config = json.loads(store.cipher.open(config,job['id']+':diagnostic-config'))
        spec = KINDS[config['kind']]
        exporting = config['mode']=='export'
        identity = {'user_id':job['user_id'], 'username':config['username']}
        count = (summary or {}).get('total_count',0)
        title = ('Exported' if exporting else 'Loaded')+' FortiAuthenticator '+spec['activity']
        try:
            ActivityStore(str(store.instance)).record_event('Fortinet',title,
                f"{config['profile']['name']}: {count} records, {state}",
                counters={'fortinet':{'api_calls':int(bool(job.get('started'))),'failures':int(state!='succeeded')}},count_action=exporting,**identity)
        except Exception as exc:
            print(f'Inventory activity recording failed: {type(exc).__name__}',file=sys.stderr)
        if exporting or state!='succeeded':
            try:
                AuditStore(str(store.instance)).record(**identity,method='WORKER',endpoint='export_'+spec['endpoint'] if exporting else spec['endpoint'],
                    path='/fortiauthenticator/'+spec['path'],status_code=200,category='FortiAuthenticator',
                    action='fortiauthenticator.'+spec['audit']+('_export_' if exporting else '_preview_')+state,
                    summary=title+'.',resource_id=spec['path'],details={'outcome':state,'record count':count,'download format':config['csv_format']})
            except Exception as exc:
                print(f'Inventory audit recording failed: {type(exc).__name__}',file=sys.stderr)
        if not config.get('investigation_id'):
            return
        case_args = dict(investigation_id=config['investigation_id'], **identity,
            operation_id='fortiauthenticator-inventory:'+job['id'], tool_id=spec['tool_id'],
            event_type='external.export.completed' if summary and exporting else 'diagnostic.'+state,
            action=('Export ' if exporting else 'Preview ')+spec['label'],outcome='incomplete' if state=='unknown' else state,
            summary=f"{title}: {count} records, {state}.", targets={'profile':config['profile']['name']},
            parameters={'format':'CSV','download_format':config['csv_format']},metrics={'record_count':count},
            details={'error':error},started_at=job.get('started') or job['created'],completed_at=time.time())
        cases = InvestigationStore(str(store.instance))
        if summary and exporting:
            with (artifact_directory(store,job['id'],job['tool'])/'raw.csv').open('rb') as stream:
                saved = cases.add_generated_evidence_event(**case_args,filename=csv_download_filename(spec['path']+'-'+job['id'][:12]+'.csv','raw'),
                    content_type='text/csv',stream=stream,max_bytes=config['artifact_bytes'])
            event = saved['event']
        else:
            event = cases.record_for_case(**case_args)
        if summary is not None:
            summary = {**summary,'journal_event':{'id':event['id'],'investigation_id':event['investigation_id']}}
            sealed = store.cipher.seal(json.dumps(summary),job['id']+':diagnostic-summary')
            with store.connect(write=True) as db:
                db.execute("UPDATE diagnostic_jobs SET summary=? WHERE id=? AND state='succeeded'",(sealed,job['id']))
    except Exception as exc:
        print(f'Inventory outcome recording failed: {type(exc).__name__}',file=sys.stderr)
