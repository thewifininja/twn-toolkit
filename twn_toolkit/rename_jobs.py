"""Supervised reviewed renames with durable intent, acknowledgement and verification."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import sys
import time

from .auth import load_or_create_secret_key
from .file_transactions import file_transaction
from .fortigate import FortiGateClient, FortiGateError
from .preview_binding import PreviewSigner
from .profiles import ProfileStore
from .rename_preview import _context, _SCOPE
from .switch_order_jobs import operation_target, interruption_outcome
from .tasks import RenameTask, get_task, _extract_rows, _flatten_dict, _first_value

TOOL = 'appliance_rename'
MAX_ENTRIES = 500
MAX_SUMMARY_BYTES = 1024 * 1024


def target_key(profile):
    return hashlib.sha256(operation_target(profile).encode()).hexdigest()


class RenameStopped(ValueError):
    pass


def execute_rename(store, job, config):
    summary = {'phase': 'waiting_for_target', 'results': [], 'attempted_moves': 0,
               'completed_moves': [], 'in_flight': None, 'api_calls': 0}
    task = get_task(config['task_id'])
    signer = PreviewSigner(load_or_create_secret_key(str(store.instance)), store.instance, job['user_id'])
    target = target_key(config['profile'])

    def checkpoint():
        if len(json.dumps(summary).encode()) > MAX_SUMMARY_BYTES:
            raise RenameStopped('Rename result exceeds the finite result envelope.')
        if not store.progress(job['id'], job['token'], summary):
            raise RenameStopped('The operation stopped before its next checkpoint.')

    def validate():
        if ProfileStore(str(store.instance)).get(config['profile']['name']) != config['profile']:
            raise RenameStopped('The appliance profile changed. Build a fresh preview before applying.')
        if not signer.valid(config['preview_token'], _SCOPE,
                            _context(task, config['profile'], config['endpoint'], config['entries'], config.get('target_revision', ''))):
            raise RenameStopped('The reviewed rename expired or changed. Build a fresh preview before applying.')

    try:
        if not isinstance(task, RenameTask) or not 1 <= len(config['entries']) <= MAX_ENTRIES:
            raise RenameStopped('Select between 1 and 500 reviewed rename entries.')
        checkpoint()
        with file_transaction(store.instance / 'appliance-operation-locks' / target):
            validate()
            if store.mutation_revision(target) != config.get('target_revision', ''):
                raise RenameStopped('Another operation attempted changes after this review. Load and review the current objects before applying.')
            client = FortiGateClient.from_profile(config['profile'])
            with client.pooled() as pooled:
                for index, entry in enumerate(config['entries'], start=1):
                    validate()
                    summary['phase'] = 'inspecting'
                    checkpoint()
                    first_read = True

                    class TrackedClient:
                        def get_object(self, endpoint, identifier, vdom):
                            nonlocal first_read
                            summary['api_calls'] += 1
                            checkpoint()
                            result = pooled.get_object(endpoint, identifier, vdom)
                            expected_name = entry.get('current_name', '').strip()
                            if first_read and expected_name:
                                rows = _extract_rows(result)
                                flattened = _flatten_dict(rows[0]) if rows else {}
                                actual = _first_value(flattened, task.name_fields) or identifier
                                if actual != expected_name:
                                    raise RenameStopped('An object name changed after review. Load its current state before applying.')
                            first_read = False
                            return result

                        def rename_object(self, endpoint, identifier, new_name, vdom, **kwargs):
                            validate()
                            intent = {'identifier': identifier, 'new_name': new_name, 'vdom': vdom}
                            summary['phase'] = 'applying'
                            summary['in_flight'] = intent
                            summary['attempted_moves'] += 1
                            summary['api_calls'] += 1
                            checkpoint()
                            if not store.advance_mutation_revision(target, job['id'], job['token'], config.get('target_revision', '')):
                                raise RenameStopped('Worker ownership or reviewed origin changed before sending the rename.')
                            try:
                                result = pooled.rename_object(endpoint, identifier, new_name, vdom, **kwargs)
                            except FortiGateError as exc:
                                # Escape the legacy per-row catch: never continue
                                # sending mutations after an unconfirmed attempt.
                                raise RenameStopped(str(exc)) from exc
                            summary['completed_moves'].append(intent)
                            summary['in_flight'] = None
                            summary['phase'] = 'verifying'
                            checkpoint()
                            return result

                    results = task.run_entries(client=TrackedClient(), entries=[entry], dry_run=False,
                                               endpoint_template=config['endpoint'], default_vdom=config['profile'].get('default_vdom', 'root'))
                    if len(results) != 1:
                        raise RenameStopped('The rename did not return a complete per-object result.')
                    result = {**asdict(results[0]), 'row_number': index}
                    secret = config['profile'].get('api_key')
                    if secret:
                        result['message'] = result['message'].replace(str(secret), '[redacted]')
                    summary['results'].append(result)
                    checkpoint()
                    if result['status'] != 'success':
                        raise RenameStopped(result['message'])
            summary['phase'] = 'verified'
            checkpoint()
            if not store.finish(job['id'], job['token'], [], summary):
                raise RenameStopped('The operation stopped before its result was committed.')
        record_rename_outcome(store, job, 'succeeded', config=config)
    except Exception as exc:
        error = str(exc) if isinstance(exc, (ValueError, FortiGateError)) else 'Rename operation failed (' + type(exc).__name__ + ').'
        secret = config['profile'].get('api_key')
        if secret:
            error = error.replace(str(secret), '[redacted]')
        current = store.owned(job['id'], job['token'])
        if current:
            state = 'cancelled' if current['state'] == 'cancel_requested' else 'failed'
            state, error = interruption_outcome(store, current, state, error)
            if store.abort(job['id'], job['token'], state, error):
                record_rename_outcome(store, job, state, config=config)


def record_rename_outcome(store, job, state, *, config=None):
    from .activity import ActivityStore
    from .audit import AuditStore, audit_reference, audit_changes
    from .investigations import InvestigationStore
    try:
        if config is None:
            config = json.loads(store.cipher.open(job['config'], job['id'] + ':diagnostic-config'))
        task = get_task(config['task_id'])
        summary = (store.get(job['id'], job['user_id']) or {}).get('summary', {})
        results = summary.get('results', [])
        successes = sum(row['status'] == 'success' for row in results)
        identity = {'user_id': job['user_id'], 'username': config['username']}
        details = {'operation id': job['id'], 'outcome': state, 'requested object count': len(config['entries']),
                   'successful object count': successes, 'acknowledged object count': len(summary.get('completed_moves', [])),
                   'attempted object count': summary.get('attempted_moves', 0), 'failed object count': sum(row['status'] == 'error' for row in results),
                   'omitted successful object count': max(0, successes - 20),
                   'profile': audit_reference('FortiGate profile', config['profile']['name'], config['profile']['name'])}
        ActivityStore(str(store.instance)).record_event('Fortinet', 'Ran FortiGate rename task', task.label + ': ' + state,
            counters={'fortinet': {'api_calls': summary.get('api_calls', 0), 'failures': int(state != 'succeeded')}}, count_action=True, **identity)
        if successes:
            completed = config['entries'][:successes][:20]
            details['changes'] = audit_changes({'objects': [audit_reference('FortiGate object', row['identifier'], row['current_name']) for row in completed]},
                                               {'objects': [audit_reference('FortiGate object', row['identifier'], row['new_name']) for row in completed]})
        AuditStore(str(store.instance)).record(**identity, method='WORKER', endpoint='rename_job',
            path='/tasks/' + task.id + '/rename-jobs/' + job['id'], status_code=200,
            category='FortiGate', action='fortigate.objects_renamed', summary=task.label + ': ' + state,
            resource_type='fortigate_task', resource_id=task.id, resource_name=task.label, details=details)
        if config.get('investigation_id'):
            InvestigationStore(str(store.instance)).record_for_case(investigation_id=config['investigation_id'], **identity,
                operation_id='rename:' + job['id'], tool_id='fortigate.' + task.id.replace('-', '_'),
                event_type='external.action.completed' if state == 'succeeded' else 'external.action.' + state,
                action=task.label, outcome='incomplete' if state == 'unknown' else state,
                summary=task.label + ': ' + state, targets={'profile': config['profile']['name']},
                parameters={'endpoint': config['endpoint']}, metrics=details,
                details={'acknowledged renames': summary.get('completed_moves', []), 'in-flight rename': summary.get('in_flight')},
                started_at=job.get('started') or job['created'], completed_at=time.time())
    except Exception as exc:
        # Keep the retained job authoritative when secondary recording fails.
        print('Rename outcome recording failed: ' + type(exc).__name__, file=sys.stderr)
        try:
            with store.connect(write=True) as db:
                row = db.execute('SELECT summary FROM diagnostic_jobs WHERE id=?', (job['id'],)).fetchone()
                if row:
                    summary = json.loads(store.cipher.open(row['summary'], job['id'] + ':diagnostic-summary'))
                    summary['recording_warning'] = 'Activity, audit or original case recording could not be fully confirmed.'
                    db.execute('UPDATE diagnostic_jobs SET summary=? WHERE id=?',
                               (store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary'), job['id']))
        except Exception as warning_error:
            print('Rename recording warning failed: ' + type(warning_error).__name__, file=sys.stderr)
