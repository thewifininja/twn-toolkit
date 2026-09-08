"""Owner-scoped cleanup admission and finite retained review pages."""
from __future__ import annotations

import hashlib

from flask import abort, flash, g, make_response, redirect, render_template, request, url_for

from .audit import suppress_audit_event, suppress_case_bridge_event
from .automation_heartbeat import read_automation_heartbeat
from .diagnostic_routes import diagnostic_store, owned_diagnostic
from .fac_cleanup_jobs import TOOL, MAX_TARGETS, record_cleanup_outcome
from .investigations import InvestigationStore
from .preview_binding import valid_bound_preview, PREVIEW_MAX_AGE_SECONDS


def queue_cleanup(app, profile, mode, *, reviewed=None):
    from .fortiauthenticator_routes import _cleanup_preview_context, _cleanup_confirmation
    if mode != 'apply':
        suppress_audit_event()
    suppress_case_bridge_event()
    action = request.form.get('action', 'remove_memberships')
    group_uri = request.form.get('group_uri', '')
    rejected_outcome = 'aborted_stale_preview'
    identifiers = []
    try:
        if not profile or mode not in {'groups', 'preview', 'apply'} or action not in {'remove_memberships', 'delete_devices'}:
            raise ValueError('Select a valid profile and cleanup action.')
        if len(group_uri) > 2048:
            raise ValueError('The selected group exceeds the review envelope.')
        case = InvestigationStore(app.instance_path).active_for_user(g.current_user['id'])
        config = dict(profile=profile, mode=mode, action=action, group_uri=group_uri,
                      username=g.current_user['username'], investigation_id=case['id'] if case and case.get('is_recording') else '')
        receipt = None
        if mode == 'apply':
            if not reviewed or reviewed['tool'] != TOOL or reviewed['state'] != 'succeeded' or reviewed['config']['mode'] != 'preview':
                raise ValueError('The retained cleanup preview is unavailable. Build a fresh preview.')
            preview = reviewed['summary']['preview']
            context = _cleanup_preview_context(profile, group_uri, action, preview['target_revision'])
            context_token = request.form.get('context_token', '')
            candidate_token = request.form.get('candidate_token', '')
            if not valid_bound_preview(context_token, 'mac-cleanup-context-v1', context) or not valid_bound_preview(candidate_token, 'mac-cleanup-candidates-v1', {**context, 'targets': preview['targets'], 'group_name': preview['group_name']}):
                raise ValueError('Cleanup preview expired or changed. Build a fresh preview.')
            identifiers = list(dict.fromkeys(value.strip() for value in request.form.getlist('selected_id') if value.strip()))
            key = 'membership_id' if action == 'remove_memberships' else 'device_id'
            candidates = {row[key] for row in preview['targets']}
            if not identifiers:
                rejected_outcome = 'aborted_no_selection'
                raise ValueError('Select at least one valid reviewed cleanup target.')
            if len(identifiers) > MAX_TARGETS or any(value not in candidates for value in identifiers):
                raise ValueError('The selected targets changed after the preview. Build a fresh preview.')
            confirmation = request.form.get('confirmation', '').strip()
            if confirmation != _cleanup_confirmation(action, len(identifiers)):
                rejected_outcome = 'aborted_confirmation'
                raise ValueError('Confirmation did not match the selected count.')
            config.update(preview_job=reviewed['id'], selected_ids=identifiers, context_token=context_token,
                          candidate_token=candidate_token, confirmation=confirmation)
            # A reviewed candidate set admits once, even if a retry changes selection.
            receipt = hashlib.sha256(('fac-cleanup:' + candidate_token).encode()).hexdigest()
        identifier = diagnostic_store().enqueue(user_id=g.current_user['id'], tool=TOOL, config=config, request_key=receipt)
    except ValueError as exc:
        if mode == 'apply' and profile:
            from .fortiauthenticator_routes import _annotate_mac_cleanup
            _annotate_mac_cleanup(profile, group_uri, action, outcome=rejected_outcome, requested_count=len(identifiers))
        flash(str(exc), 'error')
        return redirect(url_for('fortiauthenticator_mac_cleanup'))
    suppress_audit_event()
    return redirect(url_for('fac_cleanup_job', job_id=identifier), code=303)


def register_cleanup_jobs(app, profiles):
    @app.get('/fortiauthenticator/mac-cleanup/jobs/<job_id>')
    def fac_cleanup_job(job_id):
        job = owned_diagnostic(job_id, TOOL)
        data = job['summary']
        mode = job['config']['mode']
        template = 'fortiauthenticator/mac_cleanup.html' if mode != 'apply' else 'fortiauthenticator/mac_cleanup_job.html'
        try:
            page = max(1, min(10, int(request.args.get('page', '1'))))
        except ValueError:
            abort(400)
        rows = data.get('results', [])
        pages = max(1, (len(rows) + 49)//50)
        page = min(page, pages)
        response = make_response(render_template(template, diagnostic_job=job,
            diagnostic_label='MAC cleanup ' + mode,
            diagnostic_scheduler=read_automation_heartbeat(diagnostic_store().instance/'automation-heartbeat.json'),
            diagnostic_result_url=url_for('fac_cleanup_job', job_id=job_id),
            diagnostic_status_url=url_for('fac_cleanup_status', job_id=job_id),
            diagnostic_cancel_url=url_for('fac_cleanup_cancel', job_id=job_id),
            profiles=profiles.all(), groups=data.get('groups', []), selected_name=job['config']['profile']['name'],
            selected_group_uri=job['config']['group_uri'], selected_action=job['config']['action'],
            preview=data.get('preview') if job['state'] == 'succeeded' else None,
            preview_job=job_id, preview_minutes=PREVIEW_MAX_AGE_SECONDS//60,
            page=page, pages=pages, results=rows[(page-1)*50:page*50]))
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    @app.get('/fortiauthenticator/mac-cleanup/jobs/<job_id>/status')
    def fac_cleanup_status(job_id):
        from flask import jsonify
        job = owned_diagnostic(job_id, TOOL)
        response = jsonify(state=job['state'], error=job['error'], stage=job['summary'].get('phase', 'queued').replace('_', ' '))
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.post('/fortiauthenticator/mac-cleanup/jobs/<job_id>/cancel')
    def fac_cleanup_cancel(job_id):
        owned_diagnostic(job_id, TOOL)
        previous = diagnostic_store().cancel(job_id, g.current_user['id'])
        if previous:
            record_cleanup_outcome(diagnostic_store(), previous, 'cancelled')
        return redirect(url_for('fac_cleanup_job', job_id=job_id), code=303)


def recent_cleanup_links():
    return [{**row, 'mode': 'cleanup', 'url': url_for('fac_cleanup_job', job_id=row['id'])}
            for row in diagnostic_store().recent(g.current_user['id'], TOOL)]
