"""CSV views of retained DNS results; never execute DNS during export."""
from datetime import datetime, timezone
import json

from .csv_exports import table_csv


def dns_run_csv(job, rows):
    config = job['config']
    form = config['form']
    metadata_headers = ['Run ID', 'Mode', 'Started (UTC)', 'Completed (UTC)']
    metadata = [job['id'], form['mode'], *[
        datetime.fromtimestamp(job[key], timezone.utc).isoformat() if job.get(key) else ''
        for key in ('started', 'completed')
    ]]
    if form['mode'] == 'compare':
        headers = metadata_headers + ['Query', 'Query label', 'Resolver', 'Resolver label',
                                      'Record type', 'Status', 'Answers', 'Response (ms)', 'Error']
        return table_csv(headers, (metadata + [
            row.get('host', ''), row.get('host_label', ''), row.get('server', ''),
            row.get('server_label', ''), row.get('record_type', ''), row.get('status', ''),
            '\n'.join(row.get('answers') or []), row.get('response_ms'), row.get('error', ''),
        ] for row in rows))

    load = job['summary']['load_result']
    headers = metadata_headers + [
        'Queries', 'Record type', 'Timeout (s)', 'Requested duration (s)', 'Elapsed (s)',
        'Concurrency', 'Target QPS per resolver', 'Planned queries (all resolvers)',
        'Resolver', 'Resolver label', 'Completed queries', 'Successful queries', 'Failed queries',
        'Success (%)', 'Achieved QPS', 'Average (ms)', 'p50 (ms)', 'p95 (ms)', 'p99 (ms)',
        'Max (ms)', 'Response counts (JSON)',
    ]
    settings = ['\n'.join(host['host'] for host in config['hosts']), form['record_type'],
                form['timeout'], load.get('requested_duration_seconds', form['duration']),
                load.get('elapsed_seconds'), load.get('concurrency', form['concurrency']),
                load.get('qps_per_server', form['qps']), load.get('planned_queries')]
    keys = ('server', 'server_label', 'completed_queries', 'successful_queries', 'failed_queries',
            'success_rate', 'achieved_qps', 'average_ms', 'p50_ms', 'p95_ms', 'p99_ms', 'max_ms')
    return table_csv(headers, (metadata + settings + [resolver.get(key) for key in keys] + [
        json.dumps(resolver.get('statuses', {}), ensure_ascii=False, sort_keys=True),
    ] for resolver in load.get('resolvers', [])))
