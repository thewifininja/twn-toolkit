"""Supervised FAC cleanup reads and reviewed, non-replayed mutations."""
from __future__ import annotations

import json
import sys
import time

from .auth import load_or_create_secret_key
from .file_transactions import file_transaction
from .fortiauthenticator import FortiAuthenticatorClient, FortiAuthenticatorError
from .preview_binding import PreviewSigner
from .profiles import FortiAuthenticatorProfileStore
from .rename_jobs import target_key
from .switch_order_jobs import interruption_outcome

TOOL = 'fac_cleanup'
MAX_TARGETS = 500
MAX_PREVIEW_BYTES = 64 * 1024


def finite(value, limit=MAX_PREVIEW_BYTES):
    if len(json.dumps(value, ensure_ascii=False).encode()) > limit:
        raise ValueError('Cleanup review exceeds the finite preview envelope. Reduce the group size before reviewing it.')
    return value


def execute_cleanup(store, job, config):
    from .fortiauthenticator_routes import _mac_groups, _build_mac_cleanup_preview, _cleanup_preview_context, _cleanup_confirmation
    profile = config['profile']
    summary = {'phase': 'waiting_for_target', 'api_calls': 0, 'results': [],
               'attempted_moves': 0, 'completed_moves': [], 'in_flight': None}
    signer = PreviewSigner(load_or_create_secret_key(str(store.instance)), store.instance, job['user_id'])
    target = target_key(profile)

    def save():
        finite(summary, 1024 * 1024)
        if not store.progress(job['id'], job['token'], summary):
            raise ValueError('Cleanup stopped before the next checkpoint.')

    def current_profile():
        if FortiAuthenticatorProfileStore(str(store.instance)).get(profile['name']) != profile:
            raise ValueError('The profile changed. Build a fresh cleanup preview.')

    def read(method):
        summary['api_calls'] += 1
        save()
        return getattr(client, method)()

    def inventory():
        memberships = read('get_all_mac_group_memberships')
        devices = read('get_all_mac_devices')
        preview = _build_mac_cleanup_preview(memberships, devices, config['group_uri'], config['action'])
        if len(preview['targets']) > MAX_TARGETS:
            raise ValueError('Cleanup supports groups of up to 500 devices. Reduce the group size before reviewing it.')
        return finite(preview), memberships, devices

    try:
        save()
        with file_transaction(store.instance / 'appliance-operation-locks' / target):
            current_profile()
            client = FortiAuthenticatorClient.from_profile(profile)
            summary['phase'] = 'inspecting'
            if config['mode'] == 'groups':
                groups = _mac_groups(read('get_all_mac_group_memberships'))
                if len(groups) > MAX_TARGETS:
                    raise ValueError('Cleanup supports up to 500 groups per appliance review.')
                summary['groups'] = finite(groups)
            elif config['mode'] == 'preview':
                revision = store.mutation_revision(target)
                preview, memberships, _ = inventory()
                if config['group_uri'] not in {row['uri'] for row in _mac_groups(memberships)}:
                    raise ValueError('The selected MAC group is no longer available.')
                context = _cleanup_preview_context(profile, config['group_uri'], config['action'], revision)
                preview['context_token'] = signer.issue('mac-cleanup-context-v1', context)
                preview['candidate_token'] = signer.issue('mac-cleanup-candidates-v1', {**context, 'targets': preview['targets'], 'group_name': preview['group_name']})
                preview['target_revision'] = revision
                summary['preview'] = preview
            elif config['mode'] == 'apply':
                reviewed_job = store.get(config['preview_job'], job['user_id'])
                if not reviewed_job or reviewed_job['tool'] != TOOL or reviewed_job['state'] != 'succeeded' or reviewed_job['config']['mode'] != 'preview':
                    raise ValueError('The retained cleanup preview is unavailable. Build a fresh preview.')
                reviewed = reviewed_job['summary']['preview']
                revision = reviewed['target_revision']
                context = _cleanup_preview_context(profile, config['group_uri'], config['action'], revision)
                def validate():
                    current_profile()
                    if not signer.valid(config['context_token'], 'mac-cleanup-context-v1', context) or not signer.valid(config['candidate_token'], 'mac-cleanup-candidates-v1', {**context, 'targets': reviewed['targets'], 'group_name': reviewed['group_name']}):
                        raise ValueError('Cleanup preview expired or changed. Build a fresh preview.')
                validate()
                if store.mutation_revision(target) != revision:
                    raise ValueError('Another operation attempted changes after review. Build a fresh cleanup preview.')
                fresh, _, _ = inventory()
                if fresh['targets'] != reviewed['targets'] or fresh['group_name'] != reviewed['group_name']:
                    raise ValueError('Cleanup candidates changed. Build a fresh preview.')
                id_key = 'membership_id' if config['action'] == 'remove_memberships' else 'device_id'
                by_id = {row[id_key]: row for row in reviewed['targets']}
                identifiers = config['selected_ids']
                if not identifiers or len(identifiers) > MAX_TARGETS or len(set(identifiers)) != len(identifiers) or any(value not in by_id for value in identifiers):
                    raise ValueError('Select valid reviewed cleanup targets.')
                if config['confirmation'] != _cleanup_confirmation(config['action'], len(identifiers)):
                    raise ValueError('Cleanup confirmation does not match the selected count.')
                for identifier in identifiers:
                    validate()
                    fresh, _, _ = inventory()
                    found = next((row for row in fresh['targets'] if row[id_key] == identifier), None)
                    if found != by_id[identifier] or fresh['group_name'] != reviewed['group_name']:
                        raise ValueError('A remaining cleanup target changed. Review current state before continuing.')
                    validate()
                    intent = dict(found)
                    summary['phase'] = 'applying'
                    summary['in_flight'] = intent
                    summary['attempted_moves'] += 1
                    summary['api_calls'] += 1
                    save()
                    if not store.advance_mutation_revision(target, job['id'], job['token'], revision):
                        raise ValueError('Worker ownership or reviewed origin changed before deletion.')
                    method = 'delete_mac_group_membership' if config['action'] == 'remove_memberships' else 'delete_mac_device'
                    getattr(client, method)(identifier)
                    summary['completed_moves'].append(intent)
                    summary['in_flight'] = None
                    summary['phase'] = 'verifying'
                    save()
                    from .fortiauthenticator_routes import _resource_id
                    method = 'get_all_mac_group_memberships' if config['action'] == 'remove_memberships' else 'get_all_mac_devices'
                    remaining = read(method)
                    if any((str(row.get('id') or '') or _resource_id(str(row.get('resource_uri') or ''))) == identifier for row in remaining):
                        raise ValueError('The appliance acknowledged deletion but the object is still present. Reconcile current state.')
                    message = 'Group membership removed and absence verified.' if config['action'] == 'remove_memberships' else 'MAC device deleted globally and absence verified.'
                    summary['results'].append({**intent, 'status': 'success', 'message': message})
                    save()
            else:
                raise ValueError('Select a valid cleanup operation.')
            summary['phase'] = 'verified'
            save()
            if not store.finish(job['id'], job['token'], [], summary):
                raise ValueError('Cleanup stopped before its result was committed.')
        record_cleanup_outcome(store, job, 'succeeded', config=config)
    except Exception as exc:
        error = str(exc) if isinstance(exc, (ValueError, FortiAuthenticatorError)) else 'Cleanup failed (' + type(exc).__name__ + ').'
        error = error.replace(str(profile.get('password') or '\0'), '[redacted]')[:500]
        current = store.owned(job['id'], job['token'])
        if current:
            state = 'cancelled' if current['state'] == 'cancel_requested' else 'failed'
            state, error = interruption_outcome(store, current, state, error)
            if store.abort(job['id'], job['token'], state, error):
                record_cleanup_outcome(store, job, state, config=config)


def record_cleanup_outcome(store, job, state, *, config=None):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .investigations import InvestigationStore
    try:
        if config is None:
            config = json.loads(store.cipher.open(job['config'], job['id'] + ':diagnostic-config'))
        summary = (store.get(job['id'], job['user_id']) or {}).get('summary', {})
        identity = {'user_id': job['user_id'], 'username': config['username']}
        mutation = config['mode'] == 'apply'
        details = {'operation id': job['id'], 'outcome': state, 'requested target count': len(config.get('selected_ids', [])),
                   'successful target count': len(summary.get('results', [])), 'acknowledged target count': len(summary.get('completed_moves', [])), 'attempted target count': summary.get('attempted_moves', 0), 'failed target count': 0,
                   'unconfirmed target count': max(0, summary.get('attempted_moves', 0) - len(summary.get('results', [])))}
        ActivityStore(str(store.instance)).record_event('Fortinet', 'Ran FortiAuthenticator MAC cleanup' if mutation else 'Previewed FortiAuthenticator MAC cleanup', config['mode'] + ': ' + state,
            counters={'fortinet': {'api_calls': summary.get('api_calls', 0), 'failures': int(state != 'succeeded')}}, count_action=mutation, **identity)
        if mutation:
            AuditStore(str(store.instance)).record(**identity, method='WORKER', endpoint='fac_cleanup_job',
                path='/fortiauthenticator/mac-cleanup/jobs/' + job['id'], status_code=200,
                category='FortiAuthenticator', action='fortiauthenticator.mac_cleanup_' + state,
                summary=config['action'] + ': ' + state, resource_type='fortiauthenticator_mac_group',
                resource_id=config['group_uri'], resource_name=config['group_uri'], details=details)
        if config.get('investigation_id'):
            InvestigationStore(str(store.instance)).record_for_case(investigation_id=config['investigation_id'], **identity,
                operation_id='fac-cleanup:' + job['id'], tool_id='fortiauthenticator.mac_cleanup',
                event_type=('external.action.' + ('completed' if state == 'succeeded' else state)) if mutation else 'diagnostic.' + state,
                action='MAC cleanup ' + config['mode'], outcome='incomplete' if state == 'unknown' else state,
                summary='MAC cleanup ' + config['mode'] + ': ' + state, targets={'profile': config['profile']['name']},
                parameters={'action': config['action'], 'group': config['group_uri']}, metrics=details,
                details={'acknowledged deletions': summary.get('completed_moves', []), 'in-flight deletion': summary.get('in_flight')},
                started_at=job.get('started') or job['created'], completed_at=time.time())
    except Exception as exc:
        print('Cleanup outcome recording failed: ' + type(exc).__name__, file=sys.stderr)
        try:
            with store.connect(write=True) as db:
                row = db.execute('SELECT summary FROM diagnostic_jobs WHERE id=?', (job['id'],)).fetchone()
                if row:
                    summary = json.loads(store.cipher.open(row['summary'], job['id'] + ':diagnostic-summary'))
                    summary['recording_warning'] = 'Activity, audit or original case recording could not be fully confirmed.'
                    db.execute('UPDATE diagnostic_jobs SET summary=? WHERE id=?', (store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary'), job['id']))
        except Exception as warning_error:
            print('Cleanup recording warning failed: ' + type(warning_error).__name__, file=sys.stderr)
