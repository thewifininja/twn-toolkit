"""Finite switch-order operations with durable before/after mutation checkpoints."""
from __future__ import annotations

import hashlib
import json
import sys
import time
from urllib.parse import urlsplit

from .auth import load_or_create_secret_key
from .file_transactions import file_transaction
from .fortigate import FortiGateClient, FortiGateError
from .preview_binding import PreviewSigner
from .profiles import ProfileStore
from .rename_preview import rename_target
from .switch_order import managed_switch_order, switch_order_moves, _switch_order_error_summary, _valid_switch_order

TOOL = 'switch_order'
MAX_SWITCHES = 500
MAX_SUMMARY_BYTES = 1024 * 1024


class SwitchOrderStopped(Exception):
    pass


def operation_target(profile):
    """Canonical origin for local serialization, including default-port aliases."""
    parsed = urlsplit(profile['host'])
    scheme = parsed.scheme.lower()
    if scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('The appliance target must be a valid HTTP or HTTPS origin.')
    port = parsed.port or (443 if scheme == 'https' else 80)
    return json.dumps([scheme, parsed.hostname.lower(), port], separators=(',', ':'))


def bounded_inventory(items):
    switches = managed_switch_order(items)
    if len(switches) > MAX_SWITCHES or any(len(row['id']) > 128 for row in switches):
        raise ValueError('Switch ordering supports at most 500 switches with identifiers up to 128 characters. No truncated inventory can authorize changes.')
    return [{key: value if key == 'id' else value[:256] for key, value in row.items()} for row in switches]


def review_context(config):
    context = {key: config[key] for key in ('profile', 'vdom', 'original_ids', 'desired_ids')}
    if config.get('target_revision'):
        context['target_revision'] = config['target_revision']
    return context


def interruption_outcome(store, job, state, error):
    try:
        summary = json.loads(store.cipher.open(job['summary'], job['id'] + ':diagnostic-summary'))
    except Exception:
        return 'unknown', 'The retained progress could not be decoded. Reconcile the appliance before another run.'
    if summary.get('attempted_moves', 0):
        return 'unknown', error[:280] + ' Changes may have reached the appliance. Review the retained progress and reconcile its current order; this run was not replayed.'
    return state, error


def execute_switch_order(store, job, config):
    summary = {'phase': 'waiting_for_target', 'completed_moves': [], 'attempted_moves': 0,
               'in_flight': None, 'api_calls': 0}

    def checkpoint():
        if len(json.dumps(summary).encode()) > MAX_SUMMARY_BYTES:
            raise ValueError('Switch-order result exceeds the finite browser envelope.')
        if not store.progress(job['id'], job['token'], summary):
            raise SwitchOrderStopped('The operation was stopped before its next checkpoint.')

    def validate():
        if ProfileStore(str(store.instance)).get(config['profile']['name']) != config['profile']:
            raise ValueError('The appliance profile changed after submission. Load and review the current target again.')
        if config['mode'] == 'apply' and not signer.valid(config['preview_token'], 'switch-order-apply-v1', review_context(config)):
            raise ValueError('The reviewed order expired or changed before execution. Load and review it again.')

    try:
        if config['mode'] not in {'load', 'apply'}:
            raise ValueError('Unknown switch-order operation.')
        if config['mode'] == 'apply' and not _valid_switch_order(config['original_ids'], config['desired_ids']):
            raise ValueError('The reviewed order must contain each original switch exactly once.')
        signer = PreviewSigner(load_or_create_secret_key(str(store.instance)), store.instance, job['user_id'])
        checkpoint()
        # A stable cross-process sidecar serializes this toolkit's operations on
        # the same origin, including profiles using different credentials/VDOMs.
        target = hashlib.sha256(operation_target(config['profile']).encode()).hexdigest()
        with file_transaction(store.instance / 'appliance-operation-locks' / target):
            validate()
            revision = store.mutation_revision(target)
            if config['mode'] == 'apply' and revision != config.get('target_revision', ''):
                raise ValueError('Another operation attempted changes after this inventory was loaded. Load and review the current order to reconcile before applying.')
            summary['target_revision'] = revision
            summary['phase'] = 'loading_current_order'
            summary['api_calls'] += 1
            checkpoint()
            client = FortiGateClient.from_profile(config['profile'])
            with client.pooled() as pooled:
                current = bounded_inventory(pooled.get_managed_switches(config['vdom']))
                summary['switches'] = current
                summary['row_count'] = len(current)
                summary['vdom'] = config['vdom']
                summary['target_origin'] = rename_target(config['profile'])
                current_ids = [row['id'] for row in current]
                if config['mode'] == 'apply':
                    if current_ids != config['original_ids'] or set(current_ids) != set(config['desired_ids']):
                        raise ValueError('The managed-switch list or order changed after it was loaded. Reload and review before applying.')
                    moves = switch_order_moves(current_ids, config['desired_ids'])
                    summary['planned_moves'] = moves
                    summary['original_switches'] = current
                    for move in moves:
                        # Recheck the stored target and expiring review before
                        # each attempt. Never send a move without durable intent.
                        validate()
                        summary['phase'] = 'applying'
                        summary['in_flight'] = move
                        summary['attempted_moves'] += 1
                        summary['api_calls'] += 1
                        checkpoint()
                        if not store.advance_mutation_revision(target, job['id'], job['token'], config.get('target_revision', '')):
                            raise SwitchOrderStopped('The operation lost ownership or its reviewed target changed before sending the move.')
                        summary['target_revision'] = job['id']
                        pooled.move_managed_switch_after(move['switch_id'], move['after'], config['vdom'])
                        summary['completed_moves'].append(move)
                        summary['in_flight'] = None
                        checkpoint()
                    summary['phase'] = 'verifying'
                    summary['api_calls'] += 1
                    checkpoint()
                    verified = bounded_inventory(pooled.get_managed_switches(config['vdom']))
                    summary['switches'] = verified
                    summary['row_count'] = len(verified)
                    checkpoint()
                    if [row['id'] for row in verified] != config['desired_ids']:
                        raise ValueError('FortiGate accepted the moves but the verified order does not match. Reconcile the current order before retrying.')
                    current_ids = config['desired_ids']
                summary['phase'] = 'verified' if config['mode'] == 'apply' else 'loaded'
                summary['message'] = ('Verified the new order of ' if config['mode'] == 'apply' else 'Loaded ') + str(len(current_ids)) + ' FortiSwitches.'
                summary['moves'] = summary['completed_moves']
                load_context = {'profile': config['profile'], 'vdom': config['vdom'], 'original_ids': current_ids}
                if summary['target_revision']:
                    load_context['target_revision'] = summary['target_revision']
                summary['load_token'] = signer.issue('switch-order-load-v1', load_context)
                checkpoint()
                if not store.finish(job['id'], job['token'], [], summary):
                    raise SwitchOrderStopped('The operation was stopped before its result was committed.')
        record_switch_outcome(store, job, 'succeeded', config=config)
    except Exception as exc:
        error = str(exc) if isinstance(exc, (FortiGateError, ValueError, SwitchOrderStopped)) else 'Switch-order operation failed (' + type(exc).__name__ + ').'
        if isinstance(exc, FortiGateError) and summary['attempted_moves']:
            error = _switch_order_error_summary(exc, f"{len(summary['completed_moves'])} move(s) confirmed. Reload to reconcile the current order.") + ' Technical detail: ' + str(exc)
        for key in ('api_key', 'password'):
            secret = config.get('profile', {}).get(key)
            if secret:
                error = error.replace(str(secret), '[redacted]')
        current = store.owned(job['id'], job['token'])
        if current:
            state = 'cancelled' if current['state'] == 'cancel_requested' else 'failed'
            state, error = interruption_outcome(store, current, state, error)
            if store.abort(job['id'], job['token'], state, error):
                record_switch_outcome(store, job, state, config=config)


def record_switch_outcome(store, job, state, *, config=None):
    from .activity import ActivityStore
    from .audit import AuditStore, audit_changes, audit_reference
    from .investigations import InvestigationStore
    try:
        if config is None:
            config = json.loads(store.cipher.open(job['config'], job['id'] + ':diagnostic-config'))
        retained = store.get(job['id'], job['user_id'])
        summary = (retained or {}).get('summary', {})
        apply = config['mode'] == 'apply'
        identity = {'user_id': job['user_id'], 'username': config['username']}
        title = 'Applied FortiSwitch order' if apply else 'Loaded FortiSwitch order'
        details = {'outcome': state, 'operation id': job['id'], 'profile': config['profile']['name'],
                   'VDOM': config['vdom'], 'completed move count': len(summary.get('completed_moves', [])),
                   'attempted move count': summary.get('attempted_moves', 0), 'phase': summary.get('phase', 'queued')}
        if apply and state == 'succeeded':
            def references(rows):
                return [audit_reference('FortiSwitch', row['id'], row['name']) for row in rows[:20]]
            # AuditStore.record accepts curated details, not the request
            # annotator's before/after arguments. Keep its 32 KiB envelope.
            original = summary.get('original_switches', [])
            observed = summary.get('switches', [])
            details['changes'] = audit_changes({'switch order': references(original)}, {'switch order': references(observed)})
            details['omitted switch references'] = max(0, max(len(original), len(observed)) - 20)
        ActivityStore(str(store.instance)).record_event('Fortinet', title, config['profile']['name'] + ': ' + state,
            counters={'fortinet': {'api_calls': summary.get('api_calls', 0), 'failures': int(state != 'succeeded')}},
            count_action=apply, **identity)
        AuditStore(str(store.instance)).record(**identity, method='WORKER', endpoint='switch_order_job',
            path='/fortigate/switch-order/jobs/' + job['id'], status_code=200,
            category='FortiGate', action='fortigate.switch_order_' + state if apply else 'fortigate.switch_order_load_' + state,
            summary=title + ': ' + state + '.', resource_type='fortigate_switch_order',
            resource_id=config['profile']['name'] + ':' + config['vdom'], details=details)
        if config.get('investigation_id'):
            InvestigationStore(str(store.instance)).record_for_case(
                investigation_id=config['investigation_id'], **identity,
                operation_id='switch-order:' + job['id'], tool_id='fortigate.switch_order',
                event_type=('external.action.completed' if state == 'succeeded' else 'external.action.' + state) if apply else 'diagnostic.' + state,
                action=title, outcome='incomplete' if state == 'unknown' else state,
                summary=title + ': ' + state + '.', targets={'profile': config['profile']['name']},
                parameters={'vdom': config['vdom'], 'mode': config['mode']}, metrics=details,
                details={'completed moves': summary.get('completed_moves', []), 'in-flight move': summary.get('in_flight')},
                started_at=job.get('started') or job['created'], completed_at=time.time())
    except Exception as exc:
        print('Switch-order outcome recording failed: ' + type(exc).__name__, file=sys.stderr)
        try:
            with store.connect(write=True) as db:
                row = db.execute('SELECT summary FROM diagnostic_jobs WHERE id=?', (job['id'],)).fetchone()
                if row:
                    summary = json.loads(store.cipher.open(row['summary'], job['id'] + ':diagnostic-summary'))
                    summary['recording_warning'] = 'Activity, audit or case recording could not be fully confirmed. Check the original case before relying on its evidence.'
                    db.execute('UPDATE diagnostic_jobs SET summary=? WHERE id=?',
                        (store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary'), job['id']))
        except Exception as warning_error:
            print('Switch-order recording warning failed: ' + type(warning_error).__name__, file=sys.stderr)
