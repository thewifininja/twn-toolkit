"""Finite Bulk SSH jobs with durable host intent and non-replayed outcomes."""
from __future__ import annotations

import hashlib
import hmac
import json
import time

from itsdangerous import URLSafeTimedSerializer

from .auth import AuthStore, load_or_create_secret_key
from .network_tools import run_ssh_host_plans, ToolInputError
from .ssh_commandlets import build_ssh_command_plans, ssh_command_plan_digest

CONFIG_BYTES = 2 * 1024 * 1024
RESULT_BYTES = 64 * 1024 * 1024
RETRY_SALT = 'multi-ssh-host-key-retry-v1'


def allowed(instance, user_id):
    auth = AuthStore(str(instance))
    users = auth.users()
    # The application's existing local test mode has no persisted users.
    if not users:
        return user_id == 'test-user'
    user = next((user for user in users if user['id'] == user_id), None)
    return bool(user and user.get('enabled', True) and (user.get('is_admin') or 'tools.multi_ssh' in (auth.effective_tool_ids(user) or set())))


def request_key(store, user_id, signed_token):
    key = load_or_create_secret_key(str(store.instance)).encode()
    return 'bulk-ssh:' + hmac.new(key, (user_id + ':' + signed_token).encode(), hashlib.sha256).hexdigest()


def prepare(form, preview, password, *, retry=None):
    login = str(form.get('username', '')).strip()
    if not login or not password:
        raise ToolInputError('Enter an SSH username and password.')
    if len(login) > 256 or len(password) > 4096:
        raise ToolInputError('SSH credentials exceed the input limit.')
    run_name = ' '.join(str(form.get('run_name', '')).split())
    if len(run_name) > 100:
        raise ToolInputError('Run names must not exceed 100 characters.')
    if not run_name:
        run_name = str(form.get('host_matrix_original_name') or form.get('host_matrix_name') or '')[:100]
    if not run_name:
        count = 1 if retry else len(preview['plans'])
        run_name = f"Bulk SSH · {count} {'host' if count == 1 else 'hosts'}"
    if retry:
        run_name = run_name[:92] + ' · retry'
    port = int(form['port'])
    if not 1 <= port <= 65535:
        raise ToolInputError('SSH port must be between 1 and 65535.')
    return {'run_name': run_name, 'matrix': str(form['matrix']), 'commands': str(form['commands']),
            'command_timeout': int(form['command_timeout']), 'port': port,
            'allow_unknown_hosts': bool(form.get('allow_unknown_hosts')),
            'allow_legacy_algorithms': bool(form.get('allow_legacy_algorithms')),
            'send_ctrl_y': bool(form.get('send_ctrl_y')), 'login': login, 'password': password,
            'digest': ssh_command_plan_digest(preview['plans']),
            'host_count': 1 if retry else len(preview['plans']), 'retry': retry}


def plans_for(config):
    plans = build_ssh_command_plans(config['matrix'], config['commands'], config['command_timeout'])['plans']
    if ssh_command_plan_digest(plans) != config['digest']:
        raise ValueError('The retained SSH plan does not match its reviewed commands.')
    if config.get('retry'):
        retry = config['retry']
        plan = dict(plans[int(retry['plan_index'])])
        if plan['host'] != retry['host'] or int(config['port']) != int(retry['port']):
            raise ValueError('The retained host-key retry target does not match.')
        plan['required_host_key_fingerprint'] = retry['presented_fingerprint']
        return [plan]
    return plans


def scrub_inputs(store, db, job_id=None):
    query = "SELECT id,config FROM diagnostic_jobs WHERE tool='bulk_ssh' AND completed IS NOT NULL AND token=''"
    if job_id:
        query += ' AND id=?'
    for row in db.execute(query, (job_id,) if job_id else ()):
        config = json.loads(store.cipher.open(row['config'], row['id'] + ':diagnostic-config'))
        if 'password' in config or 'login' in config:
            config.pop('password', None)
            config.pop('login', None)
            db.execute('UPDATE diagnostic_jobs SET config=? WHERE id=?',
                       (store.cipher.seal(json.dumps(config), row['id'] + ':diagnostic-config'), row['id']))


def interruption_state(store, db, job_id, state):
    if db.execute('SELECT 1 FROM diagnostic_rows WHERE job_id=? AND is_open>0 LIMIT 1', (job_id,)).fetchone():
        return 'unknown'
    return 'failed' if state == 'unknown' else state


def _persist_host(store, job, index, result, *, started=False):
    raw = json.dumps(result, ensure_ascii=False, separators=(',', ':'))
    sealed = store.cipher.seal(raw, f"{job['id']}:diagnostic-row:{index}")
    with store.connect(write=True) as db:
        row = db.execute('SELECT state FROM diagnostic_jobs WHERE id=? AND token=?', (job['id'], job['token'])).fetchone()
        # A completed host may acknowledge while cancellation is being processed.
        if not row or row['state'] not in (('running',) if started else ('running', 'cancel_requested')):
            raise InterruptedError('The SSH job no longer owns execution.')
        if started:
            db.execute('INSERT INTO diagnostic_rows VALUES (?,?,1,?)', (job['id'], index, sealed))
        else:
            db.execute('UPDATE diagnostic_rows SET payload=?,is_open=? WHERE job_id=? AND position=?',
                       (sealed, 2 if result['status'] == 'unknown' else 0, job['id'], index))


def _bounded_result(result, config, budget):
    result = dict(result)
    password = config.get('password', '')
    # Login passwords can appear in banners or exception strings; avoid retaining them.
    def redact(value):
        if isinstance(value, str):
            return value.replace(password, '[redacted]') if password else value
        if isinstance(value, dict):
            return {key: redact(child) for key, child in value.items()}
        return value
    result = redact(result)
    if result.pop('execution_unknown', False):
        result['status'] = 'unknown'
    result['error'] = str(result.get('error', ''))[:1000]
    output = str(result.get('output', ''))
    def size():
        return len(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode())
    if size() > budget:
        result['output_truncated'] = True
        low, high = 0, len(output)
        while low < high:
            middle = (low + high + 1) // 2
            result['output'] = output[:middle]
            if size() <= budget:
                low = middle
            else:
                high = middle - 1
        result['output'] = output[:low]
    if size() > budget:
        raise ValueError('SSH host result metadata exceeds its storage envelope.')
    return result


def execute_ssh(store, job, config):
    plans = plans_for(config)
    if len(plans) != config['host_count']:
        raise ValueError('The retained SSH host count changed.')
    if not config.get('delegated') and not allowed(store.instance, job['user_id']):
        raise ValueError('Bulk SSH access was revoked before execution.')
    budget = (RESULT_BYTES - 1024 * 1024) // len(plans)

    def start(index, plan):
        if not config.get('delegated') and not allowed(store.instance, job['user_id']):
            raise ValueError('Bulk SSH access was revoked before this host started.')
        _persist_host(store, job, index, {'host': plan['host'], 'host_label': plan['label'],
                                        'status': 'running', 'output': ''}, started=True)
        if config.get('retry'):
            # Admission and durable intent precede this conditional local mutation.
            from .ssh_security import forget_ssh_known_host
            retry = config['retry']
            forget_ssh_known_host(plan['host'], config['port'], retry['expected_fingerprint'],
                                  allow_missing=True, allow_existing_fingerprint=retry['presented_fingerprint'])

    def completed(index, result):
        result = _bounded_result(result, config, budget - 2048)
        if result.get('host_key_mismatch'):
            mismatch = result['host_key_mismatch']
            result['host_key_retry_token'] = URLSafeTimedSerializer(
                load_or_create_secret_key(str(store.instance)), salt=RETRY_SALT).dumps({
                    'digest': config['digest'],
                    'plan_index': int(config['retry']['plan_index']) if config.get('retry') else index,
                    'host': plans[index]['host'], 'port': config['port'],
                    'expected_fingerprint': mismatch['expected_fingerprint'],
                    'presented_fingerprint': mismatch['presented_fingerprint'],
                    'allow_legacy_algorithms': config['allow_legacy_algorithms'],
                    'send_ctrl_y': config['send_ctrl_y'], 'source_job': job['id'], 'position': index,
                })
        _persist_host(store, job, index, result)

    results = run_ssh_host_plans(plans, username=config['login'], password=config['password'],
                       port=config['port'], allow_unknown_hosts=config['allow_unknown_hosts'],
                       allow_legacy_algorithms=config['allow_legacy_algorithms'],
                       send_ctrl_y=config['send_ctrl_y'], instance_path=str(store.instance),
                       before_host=start, after_host=completed)
    with store.connect(write=True) as db:
        uncertain = db.execute('SELECT 1 FROM diagnostic_rows WHERE job_id=? AND is_open>0 LIMIT 1', (job['id'],)).fetchone()
        summary = {'successful_hosts': sum(result.get('status') == 'success' for result in results)}
        finished = db.execute("UPDATE diagnostic_jobs SET state=?,summary=?,completed=? WHERE id=? AND token=? AND state='running'",
                              ('unknown' if uncertain else 'succeeded', store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary'), time.time(), job['id'], job['token'])).rowcount
    if finished:
        record_outcome(store, job, 'succeeded', '')


def host_rows(store, job, *, offset=0, limit=100, plans=None):
    if plans is None:
        plans = plans_for(job['config'])
    with store.connect() as db:
        rows = {row['position']: json.loads(store.cipher.open(row['payload'],
                f"{job['id']}:diagnostic-row:{row['position']}")) for row in db.execute(
                    'SELECT position,payload FROM diagnostic_rows WHERE job_id=? AND position>=? AND position<? ORDER BY position',
                    (job['id'], offset, offset + limit))}
    active = job['state'] in ('queued', 'running', 'cancel_requested')
    result = []
    for index in range(offset, min(offset + limit, len(plans))):
        plan = plans[index]
        row = rows.get(index, {'host': plan['host'], 'host_label': plan['label'], 'status': 'not_started', 'output': ''})
        if row['status'] == 'running' and not active:
            row.update(status='unknown', error='Execution was interrupted. Commands may have run; verify the device before submitting another run.')
        result.append({**row, 'position': index})
    return result


def counts(store, job):
    with store.connect() as db:
        row = db.execute('SELECT COUNT(*) AS started,COALESCE(SUM(is_open=1),0) AS pending,COALESCE(SUM(is_open>0),0) AS uncertain FROM diagnostic_rows WHERE job_id=?', (job['id'],)).fetchone()
    return {'started': row['started'], 'completed': row['started'] - row['pending'],
            'unconfirmed': row['uncertain'], 'not_started': job['config']['host_count'] - row['started']}


def output_parts(store, job, *, position=None):
    plans = plans_for(job['config'])
    offsets = range(0, job['config']['host_count'], 100) if position is None else [position]
    for offset in offsets:
        for row in host_rows(store, job, offset=offset, limit=100 if position is None else 1, plans=plans):
            yield f"{row['host_label'] or row['host']} ({row['host']}) — {row['status']}\n".encode()
            yield str(row.get('output', '')).encode('utf-8')
            if row.get('output_truncated'):
                yield b'\n[Retained output shortened to fit the run storage limit.]'
            if row.get('error'):
                yield ('\nError: ' + row['error']).encode('utf-8')
            yield b'\n\n'


def record_outcome(store, previous, state, error):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .datastore import LocalDatastore
    from .investigations import InvestigationStore
    from .uploads import MultipartSpool
    job = store.get(previous['id'], previous['user_id'])
    if not job:
        return
    config = job['config']
    identity = {'user_id': job['user_id'], 'username': config['username']}
    stats = counts(store, job)
    plans = plans_for(config)
    command_count = len(plans[0]['command_specs'])
    audit_details = {**stats, 'mode': 'matrix', 'host count': config['host_count'],
                     'command count': command_count, 'legacy SSH compatibility': config['allow_legacy_algorithms']}
    state = job['state']
    description = f"Bulk SSH {state}: {stats['completed']} of {config['host_count']} hosts completed; {stats['unconfirmed']} unconfirmed, {stats['not_started']} not started."
    warnings = []
    for name, callback in (
        ('activity', lambda: ActivityStore(str(store.instance)).record_event('Automation', 'Ran Bulk SSH', description, counters={'ssh': {'hosts': stats['started'], 'commands': stats['started'] * command_count}}, count_action=True, **identity)),
        ('audit', lambda: AuditStore(str(store.instance)).record(**identity, method='WORKER', endpoint='tools.multi_ssh', path='/tools/multi-ssh', status_code=200,
            category='Network tools', action='ssh.multi_host_execution.run_' + state, summary=description, resource_id=job['id'], details=audit_details)),
    ):
        try:
            callback()
        except Exception:
            warnings.append(name)
    summary = {**job['summary'], **stats, 'stage': description}
    if config.get('investigation_id'):
        spool = None
        try:
            spool = MultipartSpool(LocalDatastore(str(store.instance)), RESULT_BYTES)
            for part in output_parts(store, job):
                spool.write(part)
            spool.seek(0)
            generated = InvestigationStore(str(store.instance)).add_generated_evidence_event(
                investigation_id=config['investigation_id'], **identity,
                operation_id='multi-ssh:' + job['id'], event_type='action.completed',
                tool_id='tools.multi_ssh', action='Bulk SSH', outcome=('succeeded' if summary.get('successful_hosts') == config['host_count'] else 'incomplete') if state in ('unknown','succeeded') else state,
                summary=description, targets={'host_count': config['host_count']},
                parameters={'port': config['port'], 'reviewed_plan_digest': config['digest']}, metrics=stats,
                details={'error': job['error']}, started_at=job.get('started') or job['created'], completed_at=time.time(),
                filename='multi-ssh-' + job['id'] + '-output.txt', content_type='text/plain', stream=spool, max_bytes=RESULT_BYTES)
            event = generated['event']
            summary['journal_event'] = {'id': event['id'], 'investigation_id': event['investigation_id']}
        except Exception:
            warnings.append('original case')
        finally:
            if spool:
                spool.close()
    if warnings:
        summary['recording_warning'] = 'Could not confirm recording to: ' + ', '.join(warnings) + '. The run will not be replayed.'
    with store.connect(write=True) as db:
        db.execute('UPDATE diagnostic_jobs SET summary=? WHERE id=?',
                   (store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary'), job['id']))


def describe_run(job, timezone):
    """Public presentation from the owner's retained, encrypted configuration."""
    from .time_settings import localized_time_values
    count = job['config']['host_count']
    job['run_name'] = job['config'].get('run_name') or f"Bulk SSH · {count} {'host' if count == 1 else 'hosts'}"
    job['created_display'] = localized_time_values(job['created'], timezone)['display']
    job['queue_seconds'] = round(max(0, job['started'] - job['created']), 2) if job.get('started') is not None else None
    return job


def recent_runs(store, user_id):
    from .time_settings import resolve_toolkit_timezone
    timezone = resolve_toolkit_timezone(store.instance)
    result = []
    for row in store.recent(user_id, 'bulk_ssh'):
        job = store.get(row['id'], user_id)
        if job:
            described = describe_run(job, timezone)
            result.append({key: described[key] for key in ('id', 'state', 'run_name', 'created_display')})
    return result


def progress_text(job, stats):
    if job['state'] == 'queued':
        return f"Waiting for a worker · {stats['not_started']} {'host' if stats['not_started'] == 1 else 'hosts'} not started."
    if job['state'] == 'running':
        pending = stats['started'] - stats['completed']
        return f"{pending} {'host' if pending == 1 else 'hosts'} in progress · {stats['completed']} completed · {stats['not_started']} not started."
    label = 'Finished' if job['state'] == 'succeeded' else job['state'].replace('_', ' ').capitalize()
    return f"{label} · {stats['completed']} {'host' if stats['completed'] == 1 else 'hosts'} completed; {stats['unconfirmed']} unconfirmed."
