(() => {
  const guard = window.TwnUnsavedForms;
  document.querySelectorAll('form[data-certificate-job-form]').forEach((form) => {
    const updateKeyFields = () => {
      const upload = form.querySelector('.certificate-key-upload');
      if (upload) upload.hidden = form.querySelector('[name=key_source]:checked')?.value !== 'upload';
    };
    form.querySelectorAll('[name=key_source]').forEach((field) => field.addEventListener('change', updateKeyFields));
    updateKeyFields();
    const status = document.createElement('p');
    status.setAttribute('role', 'status');
    form.append(status);
    let pending = false;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (pending) return;
      pending = true;
      const body = new FormData(form);
      const snapshot = guard?.capture(form);
      const controls = Array.from(form.elements).map((field) => [field, field.disabled]);
      controls.forEach(([field]) => { field.disabled = true; });
      form.setAttribute('aria-busy', 'true');
      status.textContent = 'Queuing request…';
      try {
        const response = await fetch(form.action, {method: 'POST', headers: {Accept: 'application/json'}, body});
        let data;
        try { data = await response.json(); }
        catch (_) { throw new Error('Queue acknowledgement was lost. Check recent requests before retrying; your draft is still here.'); }
        if (!response.ok) throw new Error(data.error || 'The request could not be queued. Your draft is still here.');
        if (typeof data.location !== 'string' || !data.location.startsWith(`${document.body.dataset.instancePrefix || ""}/tools/certificate-automation/jobs/`)) {
          throw new Error('Queue acknowledgement was not recognized. Check recent requests before retrying.');
        }
        guard?.acknowledge(form, snapshot);
        form.querySelectorAll('input[type=password],input[type=file]').forEach((field) => { field.value = ''; });
        const nonce = form.querySelector('[name=job_nonce]');
        if (nonce) nonce.value = Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, '0')).join('');
        status.textContent = 'Request queued. ';
        const link = document.createElement('a');
        link.href = data.location;
        link.textContent = 'View request status and retained result';
        status.append(link);
        // Stay on this page so unrelated profile/request drafts survive.
      } catch (error) {
        guard?.settle(form);
        status.textContent = error instanceof TypeError
          ? 'Queue acknowledgement was lost. Check recent requests before retrying; your draft is still here.' : error.message;
      } finally {
        controls.forEach(([field, disabled]) => { field.disabled = disabled; });
        form.removeAttribute('aria-busy');
        pending = false;
        // Capture enabled field values; disabled controls are omitted by the guard.
        if (status.querySelector('a')) guard?.reset(form);
      }
    });
  });
})();
