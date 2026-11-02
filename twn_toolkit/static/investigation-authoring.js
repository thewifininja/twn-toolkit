(() => {
  document.querySelectorAll('form[data-investigation-note]').forEach((form) => {
    const note = form.querySelector('[name=note]'), save = form.querySelector('[type=submit]');
    if (!note || !save) return;
    const status = form.querySelector('[data-note-status]'), check = form.querySelector('[data-note-check]');
    const confirmation = form.querySelector('[data-note-confirmation]');
    let pending = false;
    form.addEventListener('submit', async (event) => {
      if (event.defaultPrevented) return;
      event.preventDefault();
      if (pending || !form.reportValidity()) return;
      const body = new FormData(form);
      // Match Python str.strip() used by the authoritative note validator.
      const whitespace = '[\\u0009-\\u000d\\u001c-\\u0020\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]';
      const submitted = String(body.get('note') || '').replace(new RegExp(`^${whitespace}+|${whitespace}+$`, 'g'), '').replace(/\r\n?/g, '\n');
      pending = true; window.TwnUnsavedForms?.capture(form);
      const controls = [...form.elements].map((field) => [field,field.disabled]);
      controls.forEach(([field]) => { field.disabled = true; });
      confirmation.hidden = true; check.hidden = true;
      status.textContent = 'Saving this note to the journal…';
      try {
        const response = await fetch(form.action, {method:'POST',body,headers:{Accept:'application/json'},signal:AbortSignal.timeout(15000)});
        if ([401,403,404].includes(response.status)) {
          const error = new Error(response.status === 401
            ? 'Your session is unavailable. Sign in again before checking the journal or trying again.'
            : 'This case is unavailable with your current access. Check with the case owner before trying again.');
          error.accessFailure = true; throw error;
        }
        if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('Unconfirmed response');
        const payload = await response.json();
        if (!response.ok) {
          const error = new Error(payload.error || 'The note could not be saved.');
          error.definiteFailure = response.status >= 400 && response.status < 500 && response.status !== 408;
          throw error;
        }
        const saved = payload.event;
        if (!saved || typeof saved.id !== 'string' || !/^evt_[0-9a-f]{24}$/.test(saved.id) || typeof saved.summary !== 'string' || saved.summary.replace(/\r\n?/g, '\n') !== submitted || !saved.summary || Array.from(saved.summary).length > 4000 || typeof saved.href !== 'string') throw new Error('Unconfirmed note');
        const actual = new URL(saved.href, window.location.href), expected = new URL(form.dataset.journalUrl, window.location.href);
        if (actual.origin !== expected.origin || actual.pathname !== expected.pathname || actual.search !== `?include_event=${saved.id}` || actual.hash !== `#event-${saved.id}`) throw new Error('Unconfirmed note location');
        const preview = Array.from(saved.summary);
        form.querySelector('[data-note-saved-preview]').textContent = preview.length > 280 ? preview.slice(0,280).join('') + '…' : saved.summary;
        form.querySelector('[data-note-saved-link]').href = actual.href;
        confirmation.hidden = false;
        note.value = '';
        window.TwnUnsavedForms?.settle(form); window.TwnUnsavedForms?.reset(form);
        status.textContent = 'Note saved. The confirmation links to its journal entry; this page and its settings stay here.';
      } catch (error) {
        window.TwnUnsavedForms?.failed(form);
        check.hidden = Boolean(error.definiteFailure);
        check.textContent = error.accessFailure ? 'Check journal when access is restored' : 'Check journal in a new tab';
        status.textContent = error.accessFailure ? `Save was not confirmed. ${error.message} Your note and page settings are kept here; the save may already have completed. No save is retried automatically.` : error.definiteFailure ? `${error.message} Your note is kept here.` : 'Save was not confirmed. Your note is kept here. Check the journal in a new tab before trying again; the save may already have completed. No save is retried automatically.';
      } finally {
        pending = false; controls.forEach(([field,disabled]) => { field.disabled = disabled; });
        window.TwnUnsavedForms?.settle(form);
      }
    });
  });
  const report = document.querySelector('form[data-report-choices]');
  if (report) {
    const status = document.querySelector('[data-report-export-status]'), save = document.querySelector('[data-report-save-first]');
    const sync = () => {
      const dirty = window.TwnUnsavedForms?.hasChanges(report);
      status.textContent = dirty ? 'Unsaved report choices. Save report changes to include them, or download the last SAVED choices in a new tab without losing this draft. The portable case always includes the complete journal and evidence.' : 'PDF and case package downloads use SAVED report choices. Downloads open in a new tab. The portable case always includes the complete journal and every evidence file.';
      if (save) save.hidden = !dirty;
    };
    report.addEventListener('input',sync); report.addEventListener('change',sync); sync();
  }
})();
