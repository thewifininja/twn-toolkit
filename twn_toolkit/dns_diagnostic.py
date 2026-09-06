"""DNS preflight, isolated execution, and durable outcome attribution."""
from __future__ import annotations

import json
import sys
import time

from .network_tools import (
    DNS_LOAD_MAX_SERVERS, ToolInputError, _validated_dns_query_settings,
    dns_load_test, dns_lookup_matrix, parse_dns_hosts, parse_dns_servers,
    validate_dns_load_settings,
)


def prepare_dns_config(form):
    if form['mode'] not in {'compare', 'load'}:
        raise ToolInputError('Select a valid DNS test mode.')
    hosts = parse_dns_hosts(form['hosts'], limit=100)
    servers = parse_dns_servers(form['servers'], limit=DNS_LOAD_MAX_SERVERS if form['mode'] == 'load' else 20)
    timeout = float(form['timeout'])
    _validated_dns_query_settings(form['record_type'], timeout)
    if form['mode'] == 'load':
        if form['authorized'] != 'on':
            raise ToolInputError('Confirm that you are authorized to load test these DNS servers.')
        validate_dns_load_settings(hosts, servers, form['record_type'], timeout,
                                  int(form['duration']), int(form['qps']), int(form['concurrency']))
    return {'form': form, 'hosts': hosts, 'servers': servers}


def execute_dns(store, job, config):
    form = config['form']
    # Revalidate durable input before sending traffic, including load consent.
    prepared = prepare_dns_config(form)
    hosts, servers = prepared['hosts'], prepared['servers']
    rows = []
    if form['mode'] == 'load':
        load = dns_load_test(hosts, servers, form['record_type'], float(form['timeout']),
                             duration_seconds=int(form['duration']), qps_per_server=int(form['qps']),
                             concurrency=int(form['concurrency']))
        summary = {'load_result': load, 'lookup_summary': None}
    else:
        rows = dns_lookup_matrix(hosts, servers, form['record_type'], float(form['timeout']))
        latencies = [float(row['response_ms']) for row in rows if row.get('status') == 'success']
        summary = {'load_result': None, 'lookup_summary': {
            'queries': len(rows), 'successful': len(latencies), 'failed': len(rows) - len(latencies),
            'average_ms': round(sum(latencies) / len(latencies), 1) if latencies else None,
            'slowest_ms': max(latencies) if latencies else None,
        }}
    if store.finish(job['id'], job['token'], rows, summary):
        record_dns_outcome(store, job, 'succeeded', '', config=config, rows=rows, summary=summary)


def record_dns_outcome(store, job, state, error, *, config=None, rows=None, summary=None):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .investigations import InvestigationStore

    try:
        if config is None:
            config = job['config']
            if isinstance(config, str):
                config = json.loads(store.cipher.open(config, job['id'] + ':diagnostic-config'))
        identity = {'user_id': job['user_id'], 'username': config['username']}
        form = config['form']
        load = (summary or {}).get('load_result')
        lookup = (summary or {}).get('lookup_summary')
        action = 'DNS load test' if form['mode'] == 'load' else 'DNS lookup'
        namespace = 'dns.load_test' if form['mode'] == 'load' else 'dns.lookup'
        if state == 'succeeded':
            query_count = load['completed_queries'] if load else len(rows or [])
            description = (f"Completed {query_count} DNS queries across {len(config['servers'])} resolver(s) "
                           f"with a {load['success_rate']}% success rate." if load else
                           f"Completed DNS lookup for {len(config['hosts'])} host(s) across {len(config['servers'])} resolver(s): "
                           f"{lookup['successful']} successful and {lookup['failed']} failed queries.")
            metrics = ({key: load[key] for key in ('completed_queries', 'failed_queries', 'success_rate', 'achieved_qps')}
                       if load else lookup)
            try:
                ActivityStore(str(store.instance)).record_event(
                    'Resolution', 'Ran ' + action, f"{query_count} queries across {len(config['servers'])} resolver(s)",
                    counters={'dns': {'queries': query_count}}, count_action=True, **identity)
            except Exception as exc:
                print(f'DNS activity recording failed: {type(exc).__name__}', file=sys.stderr)
        else:
            description = action + ' ' + state + ': ' + error
            metrics = {}
        try:
            AuditStore(str(store.instance)).record(
                **identity, method='WORKER', endpoint='tools.dns_response', path='/tools/dns-response', status_code=200,
                category='Network tools', action=namespace + '.' + ('completed' if state == 'succeeded' else state),
                summary=action + ' ' + state, resource_id=job['id'],
                details={'operation_id': job['id'], 'outcome': state, **metrics})
        except Exception as exc:
            print(f'DNS audit recording failed: {type(exc).__name__}', file=sys.stderr)
        if not config.get('investigation_id'):
            return
        event = InvestigationStore(str(store.instance)).record_for_case(
            investigation_id=config['investigation_id'], **identity,
            operation_id='dns:' + job['id'], event_type='diagnostic.' + ('completed' if state == 'succeeded' else state),
            tool_id='tools.dns_response', action=action, outcome='incomplete' if state == 'unknown' else state,
            summary=description, targets={'hosts': config['hosts'], 'resolvers': config['servers']},
            parameters={'mode': form['mode'], 'record_type': form['record_type'], 'timeout_seconds': form['timeout'],
                        'duration_seconds': form['duration'] if form['mode'] == 'load' else None,
                        'queries_per_second_per_resolver': form['qps'] if form['mode'] == 'load' else None,
                        'concurrency': form['concurrency'] if form['mode'] == 'load' else None},
            metrics=metrics, details={'error': error, 'results': rows or [], 'lookup_summary': lookup, 'load_result': load},
            started_at=job.get('started') or job['created'], completed_at=time.time())
        if summary is not None:
            summary = {**summary, 'journal_event': {'id': event['id'], 'investigation_id': event['investigation_id']}}
            sealed = store.cipher.seal(json.dumps(summary), job['id'] + ':diagnostic-summary')
            with store.connect(write=True) as db:
                db.execute("UPDATE diagnostic_jobs SET summary=? WHERE id=? AND state='succeeded'", (sealed, job['id']))
    except Exception as exc:
        # Failure to attribute an outcome must never replay network traffic.
        print(f'DNS outcome recording failed: {type(exc).__name__}', file=sys.stderr)
