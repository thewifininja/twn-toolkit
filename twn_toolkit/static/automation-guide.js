(() => {
  const form = document.querySelector('[data-automation-guide]');
  if (!form) return;
  const status = form.querySelector('[data-guide-status]');
  const review = form.querySelector('[data-guide-review]');
  const summary = form.querySelector('[data-guide-summary]');
  let pending = false;
  function modes() {
    for (const type of ['source', 'action']) {
      const selected = form.querySelector(`[data-guide-${type}]`).value;
      form.querySelectorAll(`[data-guide-${type}-fields]`).forEach((panel) => {
        panel.hidden = panel.dataset[`guide${type[0].toUpperCase()}${type.slice(1)}Fields`] !== selected;
        panel.querySelectorAll('input,select,textarea').forEach((field) => { field.disabled = panel.hidden; });
      });
    }
  }
  modes();
  form.addEventListener('input', (event) => {
    if (event.target.name === 'confirm_review') return;
    form.elements.review_token.value = '';
    form.elements.confirm_review.checked = false;
    review.hidden = true;
  });
  form.addEventListener('change', modes);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (pending || !form.reportValidity()) return;
    const creating = event.submitter?.value === 'create';
    if (creating && !form.elements.confirm_review.checked) {
      status.textContent = 'Confirm that you reviewed the behavior before creating.';
      return;
    }
    const body = new FormData(form);
    const fields = Array.from(form.elements, (field) => [field, field.disabled]);
    pending = true;
    window.TwnUnsavedForms?.capture(form);
    fields.forEach(([field]) => { field.disabled = true; });
    status.textContent = creating ? 'Creating paused automation…' : 'Validating configuration…';
    let created = false;
    try {
      const response = await fetch(creating ? form.getAttribute('action') : form.dataset.previewUrl, {
        method: 'POST', body, headers: {Accept: 'application/json'}, signal: AbortSignal.timeout(15000),
      });
      if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('The server did not confirm the request. Your inputs remain here.');
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Unable to process this request.');
      if (creating) {
        form.querySelectorAll('input[type=password]').forEach((field) => { field.value = ''; });
        const link = document.createElement('a');link.href = payload.url;link.textContent = 'Open paused automation';
        status.replaceChildren(document.createTextNode('Created and paused. '),link);
        review.hidden = true;form.elements.review_token.value = '';created = true;
      } else {
        summary.replaceChildren();
        for (const key of ['when','doing','recovery','next_run']) {
          const paragraph = document.createElement('p');
          paragraph.textContent = Array.isArray(payload.review[key]) ? JSON.stringify(payload.review[key]) : payload.review[key];
          summary.append(paragraph);
        }
        const settings = document.createElement('pre');settings.className = 'result-output';settings.textContent = payload.review.settings;summary.append(settings);
        for (const host of payload.review.commands) {
          const heading = document.createElement('h3');heading.textContent = host.host;
          const output = document.createElement('pre');output.className = 'result-output';output.textContent = host.commands.join('\n');
          summary.append(heading,output);
        }
        form.elements.review_token.value = payload.review_token;form.elements.confirm_review.checked = false;review.hidden = false;
        status.textContent = 'Validation passed. Review the behavior below.';
      }
    } catch (error) { status.textContent = `${error.message} Your inputs have been kept.`; }
    finally {
      fields.forEach(([field,disabled]) => {field.disabled = disabled;});pending = false;
      window.TwnUnsavedForms?.settle(form);
      if (created) window.TwnUnsavedForms?.reset(form); else window.TwnUnsavedForms?.failed(form);
    }
  });
})();
