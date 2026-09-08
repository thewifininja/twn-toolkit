(() => {
  const forms = document.querySelectorAll('[data-ssh-job-api], [data-ssh-queued-retry]');
  forms.forEach((form) => {
    let pending = false;
    let status = form.querySelector('[data-ssh-admission-status]');
    if (!status) {
      status = document.createElement('p');
      status.dataset.sshAdmissionStatus = '';
      status.setAttribute('role', 'status');
      form.append(status);
    }
    form.addEventListener('submit', async (event) => {
      if (event.defaultPrevented || (form.hasAttribute('data-ssh-job-api') && event.submitter?.value !== 'run')) return;
      event.preventDefault();
      if (pending || !form.reportValidity()) return;
      const body = new FormData(form);
      if (event.submitter?.name) body.set(event.submitter.name, event.submitter.value);
      pending = true;
      window.TwnUnsavedForms?.capture(form);
      const controls = Array.from(form.elements, (field) => [field, field.disabled]);
      controls.forEach(([field]) => { field.disabled = true; });
      status.textContent = 'Submitting the reviewed run…';
      let accepted = false;
      try {
        const response = await fetch(form.getAttribute('action') || window.location.href, {
          method: 'POST', body, headers: { Accept: 'application/json' },
          signal: AbortSignal.timeout(15000),
        });
        if (!response.headers.get('content-type')?.includes('application/json')) {
          throw new Error('The server did not confirm admission. Check Recent Bulk SSH runs or retry this submission.');
        }
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Unable to admit this run.');
        form.querySelectorAll('input[type=password]').forEach((field) => { field.value = ''; });
        const link = document.createElement('a');
        link.href = payload.url;
        link.textContent = 'Open retained run';
        status.replaceChildren(document.createTextNode('Run accepted. You may leave this page. '), link,
          document.createTextNode(' Preview again to start another run.'));
        accepted = true;
      } catch (error) {
        status.textContent = `${error.message} Your inputs remain here. If admission was uncertain, retry this submission to recover the same run.`;
      } finally {
        controls.forEach(([field, disabled]) => { field.disabled = disabled; });
        pending = false;
        window.TwnUnsavedForms?.settle(form);
        if (accepted) window.TwnUnsavedForms?.reset(form);
        else window.TwnUnsavedForms?.failed(form);
      }
    });
  });
  const panel = document.querySelector('[data-diagnostic-status-url]');
  if (!panel) return;
  const status = panel.querySelector('[data-diagnostic-status]');
  let stopped = false;
  window.addEventListener('pagehide', () => { stopped = true; });
  async function poll() {
    if (stopped) return;
    try {
      const response = await fetch(panel.dataset.diagnosticStatusUrl, {
        headers: { Accept: 'application/json' }, cache: 'no-store', signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) throw new Error();
      const job = await response.json();
      status.textContent = `${job.state === 'succeeded' ? 'Finished' : job.state.replaceAll('_', ' ')} · ${job.completed} hosts completed; ${job.not_started} not started.`;
      if (!['queued', 'running', 'cancel_requested'].includes(job.state)) {
        const link = document.createElement('a');
        link.href = window.location.href;
        link.textContent = 'View completed host results';
        status.append(document.createTextNode(' '), link);
        return; // Never replace this page's unsubmitted retry credentials/drafts.
      }
    } catch (_) {
      status.textContent = 'Unable to refresh progress. Retrying; the run is not resubmitted.';
    }
    if (!stopped) window.setTimeout(poll, 2000);
  }
  window.setTimeout(poll, 1000);
})();
