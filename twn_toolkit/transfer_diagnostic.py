"""Isolated Bulk Transfer execution and owner-scoped retained artifacts."""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time
import zipfile

from .datastore import LocalDatastore, DatastoreError
from .network_tools import ToolInputError, parse_ssh_targets
from .transfer_tools import fetch_transfer_files, parse_remote_paths, validate_transfer_filename_pattern
from .transfer_deadlines import TransferPolicy


def prepare_transfer_config(form, password):
    hosts = parse_ssh_targets(form['hosts'], limit=50)
    paths = parse_remote_paths(form['remote_paths'])
    if not hosts or not paths or len(hosts) * len(paths) > 200:
        raise ToolInputError('Enter between 1 and 200 host/file transfers.')
    if form['protocol'] not in {'sftp', 'scp', 'ftp'}:
        raise ToolInputError('Choose SFTP, SCP, or FTP.')
    if form['output_mode'] not in {'download', 'datastore'}:
        raise ToolInputError('Choose a valid transfer output mode.')
    if not form['username'].strip() or not password:
        raise ToolInputError('Enter a transfer username and password.')
    if not 1 <= int(form['port']) <= 65535:
        raise ToolInputError('Transfer port must be between 1 and 65535.')
    validate_transfer_filename_pattern(form['filename_pattern'])
    return {'form': form, 'password': password, 'hosts': hosts, 'paths': paths}


def artifact_directory(store, job_id):
    if not re.fullmatch(r'[a-f0-9]{32}', job_id):
        raise ValueError('Invalid transfer artifact identity.')
    return store.instance / 'transfer_job_artifacts' / job_id


def cleanup_transfer_artifacts(store):
    root = store.instance / 'transfer_job_artifacts'
    try:
        paths = list(root.iterdir())
    except OSError:
        return  # Unavailable storage must not stop other finite jobs.
    with store.connect() as db:
        retained = {row['id'] for row in db.execute(
            "SELECT id FROM diagnostic_jobs WHERE tool='transfer' AND (state IN ('queued','running','cancel_requested','succeeded') OR token!='')")}
    for path in paths:
        if re.fullmatch(r'[a-f0-9]{32}', path.name) and path.name not in retained:
            try:
                if path.is_symlink():
                    path.unlink()
                else:
                    shutil.rmtree(path)
            except OSError:
                pass  # Retry next scheduler cleanup; never stop other jobs.


def execute_transfer(store, job, config):
    prepared = prepare_transfer_config(config['form'], config['password'])
    form = prepared['form']
    directory = artifact_directory(store, job['id'])
    directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory.parent, 0o700)
    directory.mkdir(mode=0o700)
    files = directory / 'files'
    files.mkdir(mode=0o700)
    published = []
    summary = {'published_paths': published, 'archive': False}

    def checkpoint(stage):
        summary['stage'] = stage
        if not store.progress(job['id'], job['token'], summary):
            raise InterruptedError('Transfer no longer owns execution.')

    try:
        checkpoint('Fetching files')
        rows = fetch_transfer_files(
            hosts=prepared['hosts'], remote_paths=prepared['paths'], username=form['username'],
            password=config['password'], port=int(form['port']),
            allow_unknown_hosts=form['allow_unknown_hosts'], allow_legacy_algorithms=form['allow_legacy_algorithms'],
            output_dir=files, filename_pattern=form['filename_pattern'], protocol=form['protocol'],
            instance_path=str(store.instance), policy=TransferPolicy(**config['transfer_policy']))
        # Remote errors belong in the encrypted result, never in logs/audit metadata.
        for row in rows:
            row['error'] = str(row.get('error', '')).replace(config['password'], '[redacted]')
        successes = [row for row in rows if row['status'] == 'success']
        if form['output_mode'] == 'datastore':
            datastore = LocalDatastore(str(store.instance))
            for row in successes:
                checkpoint('Publishing files to datastore')
                try:
                    with (files / row['filename']).open('rb') as source:
                        saved, _size = datastore.save_upload(form['destination'], row['filename'], source)
                    row['stored_path'] = datastore.relative(saved)
                    published.append(row['stored_path'])
                except (DatastoreError, OSError) as exc:
                    row['status'], row['error'] = 'error', str(exc).replace(config['password'], '[redacted]')
                checkpoint('Publishing files to datastore')
        elif successes:
            checkpoint('Preparing ZIP download')
            partial = directory / 'download.partial'
            with zipfile.ZipFile(partial, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for row in successes:
                    archive.write(files / row['filename'], row['filename'])
                archive.writestr('multi-transfer-report.txt', '\n'.join(
                    f"{row['status'].upper()} | {row.get('host_label') or row['host']} | {row['remote_path']} | {row.get('error') or row.get('filename', '')}"
                    for row in rows) + '\n')
            os.chmod(partial, 0o600)
            with partial.open("rb") as completed:
                os.fsync(completed.fileno())
            os.replace(partial, directory / 'download.zip')
            summary['archive'] = True
        successes = [row for row in rows if row['status'] == 'success']
        summary.update(stage='Complete', successful=len(successes), total=len(rows),
                       error='' if successes else 'No files were fetched or stored. Review the per-transfer errors below.')
        if store.finish(job['id'], job['token'], rows, summary):
            record_transfer_outcome(store, job, 'succeeded', '', config=config, rows=rows, summary=summary)
    finally:
        shutil.rmtree(files, ignore_errors=True)


def record_transfer_outcome(store, job, state, error, *, config=None, rows=None, summary=None):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .investigations import InvestigationStore
    try:
        config = config or json.loads(store.cipher.open(job['config'], job['id'] + ':diagnostic-config'))
        form = config['form']
        if summary is None:
            summary = json.loads(store.cipher.open(job.get('summary', '{}'), job['id'] + ':diagnostic-summary'))
        rows = rows or []
        successes = [row for row in rows if row['status'] == 'success']
        identity = {'user_id': job['user_id'], 'username': config['username']}
        metrics = {'protocol': form['protocol'], 'output mode': form['output_mode'],
                   'host count': len(config['hosts']), 'remote path count': len(config['paths']), 'transfer count': len(rows),
                   'successful transfer count': len(successes),
                   'transferred byte count': sum(int(row['size']) for row in successes),
                   'legacy SSH compatibility': bool(form['allow_legacy_algorithms']) if form['protocol'] != 'ftp' else False}
        outcome = ('succeeded' if len(successes) == len(rows) and successes else 'incomplete' if successes else 'failed') if state == 'succeeded' else state
        try:
            AuditStore(str(store.instance)).record(**identity, method='WORKER', endpoint='tools.multi_transfer',
                path='/tools/multi-transfer', status_code=200, category='Network tools',
                action='transfer.multi_host_fetch.run_' + outcome, summary='Bulk Transfer ' + outcome,
                resource_id=job['id'], details=metrics)
            if state == 'succeeded':
                ActivityStore(str(store.instance)).record_event('Network tools', 'Completed Bulk Transfer',
                    f"{len(successes)} of {len(rows)} transfer(s)", **identity, count_action=True,
                    counters={form['protocol']: {'files': len(successes), 'bytes': metrics['transferred byte count']}})
        except Exception as exc:
            print(f'Transfer activity/audit recording failed: {type(exc).__name__}', file=sys.stderr)
        if config.get('investigation_id'):
            arguments = dict(investigation_id=config['investigation_id'], **identity,
                operation_id='multi-transfer:' + job['id'], event_type='action.' + outcome,
                tool_id='tools.multi_sftp', action='Bulk Transfer', outcome='incomplete' if outcome == 'unknown' else outcome,
                summary=f"Bulk Transfer {outcome}: {len(successes)} of {len(rows)} confirmed transfers. " + error,
                targets=config['hosts'], parameters={
                    'protocol': form['protocol'], 'port': form['port'], 'remote_paths': config['paths'],
                    'output_mode': form['output_mode'], 'destination': form['destination'],
                    'filename_pattern': form['filename_pattern'], 'unknown_hosts_allowed': form['allow_unknown_hosts'],
                    'legacy_algorithms_allowed': form['allow_legacy_algorithms']},
                metrics={'host_count': len(config['hosts']), 'remote_path_count': len(config['paths']),
                    'transfer_count': len(rows), 'successful_transfers': len(successes),
                    'failed_transfers': len(rows)-len(successes), 'transferred_bytes': metrics['transferred byte count']}, details={'results': rows, 'error': error, 'published_paths': summary.get('published_paths', []),
                    'reconciliation': 'Interrupted datastore runs may have published files; inspect the destination before retrying.'},
                started_at=job.get('started') or job['created'], completed_at=time.time())
            cases = InvestigationStore(str(store.instance))
            if rows:
                event = cases.add_generated_evidence_event(**arguments, filename=f"multi-transfer-{job['id']}-manifest.json",
                    content_type='application/json', content=json.dumps(rows).encode())['event']
            else:
                event = cases.record_for_case(**arguments)
            if summary is not None:
                summary = {**summary, 'journal_event': {'id': event['id'], 'investigation_id': event['investigation_id']}}
                with store.connect(write=True) as db:
                    db.execute("UPDATE diagnostic_jobs SET summary=? WHERE id=? AND token=? AND state='succeeded'",
                        (store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary'), job['id'], job['token']))
    except Exception as exc:
        print(f'Transfer outcome recording failed: {type(exc).__name__}', file=sys.stderr)
