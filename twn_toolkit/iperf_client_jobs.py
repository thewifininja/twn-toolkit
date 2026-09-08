"""Bounded iPerf client admission, worker execution, and original-case recording."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import time

from .iperf_tools import _iperf3_executable, run_iperf3_client, validate_iperf3_client_config
from .network_tools import ToolInputError


def _identity(path):
    stat = Path(path).stat()
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns]


def prepare_iperf_client(form):
    if form.get('authorized') != 'on':
        raise ToolInputError('Confirm that you are authorized to test this iPerf3 destination.')
    settings = validate_iperf3_client_config({**form, 'reverse': form['reverse'] == 'on'})
    executable = str(Path(_iperf3_executable()).resolve())
    return {'form': form, 'settings': settings, 'executable': executable,
            'executable_identity': _identity(executable)}


def execute_iperf_client(store, job, config):
    try:
        form = config['form']
        if form.get('authorized') != 'on':
            raise ToolInputError('Client authorization was not retained. Submit a new test.')
        settings = validate_iperf3_client_config({**form, 'reverse': form['reverse'] == 'on'})
        if settings != config['settings'] or _identity(config['executable']) != config['executable_identity']:
            raise ToolInputError('The client settings or installed executable changed. Submit a new test.')
        result = run_iperf3_client(settings, executable=config['executable'], owned_group=True)
        if store.finish(job['id'], job['token'], [], {'result': result}):
            record_iperf_client_outcome(store, job, 'succeeded', '', config=config)
    except (ToolInputError, OSError, ValueError) as exc:
        error = str(exc)[:1000] or 'The iPerf3 client failed.'
        current = store.owned(job['id'], job['token'])
        state = 'cancelled' if current and current['state'] == 'cancel_requested' else 'failed'
        if store.abort(job['id'], job['token'], state, error):
            record_iperf_client_outcome(store, job, state, error, config=config)


def record_iperf_client_outcome(store, job, state, error, *, config=None):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .investigations import InvestigationStore
    from .iperf_routes import _journal_iperf_result, _iperf_summary

    warnings = []
    if config is None:
        config = job['config']
        if isinstance(config, str):
            config = json.loads(store.cipher.open(config, job['id'] + ':diagnostic-config'))
    summary = (store.get(job['id'], job['user_id']) or {}).get('summary', {})
    result = summary.get('result') or {}
    safe = _journal_iperf_result(result)
    identity = {'user_id': job['user_id'], 'username': config['username']}
    form = config['form']
    metrics = {'transferred_bytes': safe.get('transferred_bytes', 0),
               'sender_mbps': (safe.get('sender') or {}).get('megabits_per_second'),
               'receiver_mbps': (safe.get('receiver') or {}).get('megabits_per_second')}
    description = _iperf_summary(result) if state == 'succeeded' else 'iPerf3 client ' + state + ': ' + error
    try:
        ActivityStore(str(store.instance)).record_event('Throughput', 'Ran iPerf3 client test', description,
            counters={'speedtest': {'runs': int(state == 'succeeded'),
                                   'bytes_transferred': int(result.get('transferred_bytes') or 0)}},
            count_action=True, **identity)
    except Exception:
        warnings.append('activity')
    try:
        AuditStore(str(store.instance)).record(**identity, method='WORKER', endpoint='tools.iperf3',
            path='/tools/iperf3', status_code=200, category='Network tools',
            action='iperf3.client.' + state, summary='iPerf3 client ' + state, resource_id=job['id'],
            details={'operation_id': job['id'], 'outcome': state, **metrics})
    except Exception:
        warnings.append('audit')
    if config.get('investigation_id'):
        try:
            event = InvestigationStore(str(store.instance)).record_for_case(
                investigation_id=config['investigation_id'], **identity,
                operation_id='iperf3-client:' + job['id'],
                event_type='diagnostic.' + ('completed' if state == 'succeeded' else state),
                tool_id='tools.iperf3', action='iPerf3 client test',
                outcome='incomplete' if state == 'unknown' else state, summary=description,
                targets={'host': form['host'], 'port': form['port']}, parameters=config['settings'],
                metrics=metrics, details={'error': error, 'result': safe},
                started_at=job.get('started') or job['created'], completed_at=time.time())
            summary['journal_event'] = {'id': event['id'], 'investigation_id': event['investigation_id']}
        except Exception:
            warnings.append('original case')
    if warnings:
        summary['recording_warning'] = 'Could not confirm recording to: ' + ', '.join(warnings) + '. The retained run will not be replayed.'
    try:
        with store.connect(write=True) as db:
            db.execute('UPDATE diagnostic_jobs SET summary=? WHERE id=?',
                       (store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary'), job['id']))
    except Exception as exc:
        print('iPerf3 recording metadata failed: ' + type(exc).__name__, file=sys.stderr)
