"""Display confirmed transfer outcomes separately from worker execution state."""
from __future__ import annotations


def completed_transfer_outcome(successful: int, total: int) -> str:
    """Keep case/audit and display classification aligned for completed work."""
    return 'succeeded' if successful and successful == total else 'incomplete' if successful else 'failed'


def transfer_display(job: dict, *, rows: list[dict] | None = None, expected_total: int | None = None) -> dict:
    state = str(job.get('state', 'unknown'))
    summary = job.get('summary') if isinstance(job.get('summary'), dict) else {}
    config = job.get('config') if isinstance(job.get('config'), dict) else {}
    form = config.get('form') if isinstance(config.get('form'), dict) else {}
    mode = form.get('output_mode')
    published = summary.get('published_paths', [])
    published_count = len(published) if isinstance(published, list) else 0
    successful, total = summary.get('successful'), summary.get('total')
    counts_known = all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in (successful, total))
    counts_known = counts_known and successful <= total
    evidence_matches = True
    if rows is not None:
        evidence_matches = counts_known and len(rows) == total and sum(row.get('status') == 'success' for row in rows) == successful
        evidence_matches = evidence_matches and all(row.get('status') in {'success', 'error'} for row in rows)
    if expected_total is not None and counts_known:
        evidence_matches = evidence_matches and total == expected_total
    outcome = state if state in {'queued', 'running', 'cancel_requested', 'succeeded', 'failed', 'cancelled', 'unknown', 'timed_out'} else 'unknown'
    if state == 'succeeded':
        outcome = completed_transfer_outcome(successful, total) if counts_known and evidence_matches else 'unknown'
        if successful and mode == 'download' and summary.get('archive') is not True:
            outcome = 'unknown'
    labels = {'queued': 'Queued', 'running': 'In progress', 'cancel_requested': 'Cancellation requested',
              'succeeded': 'Transfer complete', 'incomplete': 'Partially complete', 'failed': 'Transfer failed',
              'cancelled': 'Cancelled', 'unknown': 'Outcome unconfirmed', 'timed_out': 'Deadline reached'}
    label = labels.get(outcome, 'Outcome unconfirmed')
    tone = 'success' if outcome == 'succeeded' else 'error' if outcome in {'failed', 'timed_out'} else 'neutral' if outcome == 'cancelled' and not published_count else 'warning'
    if outcome in {'succeeded', 'incomplete'}:
        destination = 'stored in Datastore' if mode == 'datastore' else 'included in the retained ZIP' if mode == 'download' else 'confirmed complete'
        message = f'{successful} of {total} transfer(s) {destination}.'
        if outcome == 'incomplete':
            message += f' {total - successful} did not complete. Review the per-file errors.'
    elif outcome == 'queued':
        message = 'Queued — waiting for the transfer worker. No completed result is available yet.'
    elif outcome == 'running':
        message = 'Transfer in progress. Files may publish individually; this is not a complete result.'
    elif outcome == 'cancel_requested':
        message = 'Cancellation requested — waiting for the worker to stop. Some files may already have completed.'
    elif outcome == 'cancelled':
        message = ('Cancelled before execution started; no transfer was begun.' if 'started' in job and job['started'] is None else
                   'The run was cancelled. No complete result was retained; completed outputs are not rolled back.')
    elif outcome == 'failed':
        message = 'No complete transfer result was retained.' if state != 'succeeded' else 'No files completed. Review the per-file errors.'
    else:
        message = 'The final transfer outcome is not confirmed. Do not assume that no files were written.'
    if job.get('error') and state not in {'queued', 'running', 'cancel_requested'}:
        message += f" Worker reported: {job['error']}"
    if published_count and outcome not in {'succeeded', 'incomplete'}:
        message += f' {published_count} Datastore file(s) are confirmed published.'
    if state in {'queued', 'running', 'cancel_requested'} and summary.get('stage'):
        message += f" Latest reported step: {summary['stage']}."
    retry_advice = ''
    if outcome in {'incomplete', 'failed', 'cancelled', 'unknown', 'timed_out'}:
        retry_advice = ('Inspect the destination and confirmed published paths before queueing another fetch; already published files are not rolled back.'
                        if mode == 'datastore' else
                        'Review the retained results and any available ZIP before queueing another fetch. A new fetch repeats the requested host/file set.')
    return {'state': state, 'outcome': outcome, 'label': label, 'tone': tone, 'message': message,
            'successful': successful if counts_known else None, 'total': total if counts_known else None,
            'published_count': published_count, 'retry_advice': retry_advice}
