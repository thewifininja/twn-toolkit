(() => {
  const form = document.querySelector('#api-request-form');
  if (!form) return;
  const workspace = form.closest('[data-tool-workspace]');
  const status = form.querySelector('[data-api-status]');
  const submit = form.querySelector('button[type=submit]');
  const token = form.elements.admission_token;
  const consent = form.elements.write_consent;
  const consentRow = form.querySelector('[data-api-consent]');
  const refresh = form.querySelector('[data-api-new-admission]');
  const viewResult = form.querySelector('[data-api-view-result]');
  viewResult.addEventListener('click', () => window.TwnToolWorkspace?.forElement(workspace)?.setState('results', {focusResults: true}));
  const composition = data => JSON.stringify(['method', 'url', 'headers', 'body', 'timeout', 'verify_tls'].map(name => [name, data.get(name)]));
  let pending = false;
  const sync = () => {
    consentRow.hidden = ['GET', 'HEAD', 'OPTIONS'].includes(form.elements.method.value);
    consent.required = !consentRow.hidden;
  };
  form.elements.method.addEventListener('change', () => { consent.checked = false; sync(); });
  form.addEventListener('input', event => { if (event.target !== consent) consent.checked = false; });
  form.addEventListener('change', event => { if (event.target !== consent) consent.checked = false; });
  sync();
  const uncertain = 'No response was confirmed. The remote operation may already have executed. Reconcile it before deliberately sending again. Your current draft stays here; nothing is retried automatically.';
  const node = (tag, text, className) => {
    const element = document.createElement(tag);
    element.textContent = String(text ?? '');
    if (className) element.className = className;
    return element;
  };
  function showResult(result, identity, newerEdits) {
    const anchor = workspace.querySelector('[data-tool-results-anchor]');
    const panel = node('section', '', 'panel');
    panel.append(node('h2', `${result.status} ${result.reason || ''}`));
    panel.append(node('p', identity));
    panel.append(node('p', `${result.elapsed_ms} ms · ${result.bytes} bytes`));
    if (result.redirect) panel.append(node('p', `Redirect target: ${result.redirect} (not followed)`, 'message'));
    if (result.truncated) panel.append(node('p', 'Response body truncated at 1 MiB.', 'message error'));
    panel.append(node('h3', 'Response headers'));
    const list = node('dl', '', 'result-output');
    Object.entries(result.response_headers || {}).forEach(([name, value]) => {
      list.append(node('dt', name), node('dd', value));
    });
    panel.append(list, node('h3', 'Response body'), node('pre', result.body, 'result-output'));
    anchor.replaceChildren(panel);
    const title = workspace.querySelector('[data-tool-runbar]');
    if (title) {
      title.setAttribute('aria-label', 'Confirmed HTTP response; edit before sending again');
      const summary = title.querySelector('.tool-runbar-state small');
      if (summary) summary.textContent = `${identity} · HTTP ${result.status} · ${result.elapsed_ms} ms`;
    }
    viewResult.hidden = !newerEdits;
    if (!newerEdits) window.TwnToolWorkspace?.forElement(workspace)?.setState('results', {focusResults: true});
  }
  refresh.addEventListener('click', async () => {
    if (pending) return;
    pending = true; refresh.disabled = true;
    try {
      const response = await fetch(form.dataset.admissionUrl, {headers: {Accept: 'application/json'}, cache: 'no-store'});
      if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw Error();
      const payload = await response.json();
      if (typeof payload.token !== 'string' || !payload.token) throw Error();
      token.value = payload.token;
      consent.checked = false;
      status.textContent = 'Ready for a new explicit send. Check the previous remote operation before sending again.';
      submit.disabled = false; refresh.hidden = true;
    } catch (_) {
      status.textContent = 'Could not prepare a new send. Check your session/access and try this read-only action again. Your draft is unchanged.';
    } finally { pending = false; refresh.disabled = false; }
  });
  if (!token.value) { submit.disabled = true; refresh.hidden = false; }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (pending || !form.reportValidity()) return;
    pending = true;
    const body = new FormData(form);
    const submittedToken = body.get('admission_token');
    const submittedURL = new URL(body.get('url'), window.location.href);
    const identity = `${body.get('method')} · ${submittedURL.origin}`;
    consent.checked = false;
    const snapshot = window.TwnUnsavedForms?.capture(form);
    submit.disabled = true; refresh.disabled = true;
    status.textContent = 'Sending once. Closing settings does not cancel a remote operation.';
    const receiptURL = new URL(form.action, window.location.href);
    receiptURL.search = '';
    receiptURL.searchParams.set('receipt', submittedToken);
    window.history.replaceState(null, '', receiptURL.href);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 40000);
    let response;
    try {
      response = await fetch(form.action, {method: 'POST', body, headers: {Accept: 'application/json'}, signal: controller.signal});
      if (response.redirected || !response.headers.get('content-type')?.includes('application/json')) throw Error();
      const payload = await response.json();
      if (payload.admission_token !== submittedToken || typeof payload.next_token !== 'string' || typeof payload.dispatched !== 'boolean') throw Error();
      if (payload.receipt_url) {
        const receipt = new URL(payload.receipt_url, window.location.href);
        const current = new URL(form.action, window.location.href);
        if (receipt.origin !== current.origin || receipt.pathname !== current.pathname || receipt.searchParams.get('receipt') !== submittedToken) throw Error();
        window.history.replaceState(null, '', receipt.href);
      }
      const newerEdits = composition(new FormData(form)) !== composition(body);
      token.value = payload.next_token;
      consent.checked = false;
      if (payload.result && payload.dispatched && Number.isInteger(payload.result.status) && typeof payload.result.body === 'string') {
        window.TwnUnsavedForms?.acknowledge(form, snapshot);
        // Sending is not saving: this transient composer still needs a leave warning.
        form.dataset.unsavedInitial = 'true';
        showResult(payload.result, identity, newerEdits);
        status.textContent = newerEdits ? `Response received for previous ${identity}. Your current edits are unsent.` : 'Response received. Edit settings and explicitly send again if needed.';
      } else {
        window.TwnUnsavedForms?.failed(form);
        status.textContent = payload.error || uncertain;
      }
      submit.disabled = !payload.next_token;
      refresh.hidden = Boolean(payload.next_token);
      if (payload.recording_warning) status.textContent += ` ${payload.recording_warning}`;
      if (!payload.next_token) status.textContent += ' Send preparation is busy; prepare another send later.';
    } catch (_) {
      window.TwnUnsavedForms?.failed(form);
      token.value = '';
      status.textContent = [401, 403, 404].includes(response?.status) ? `Your session, access, or this request page is unavailable. Keep this draft and sign in or check access before trying again. ${uncertain}` : uncertain;
      refresh.hidden = false;
    } finally {
      clearTimeout(timer); pending = false; refresh.disabled = false;
    }
  });
})();
