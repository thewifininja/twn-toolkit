/* Load saved gate results only on demand. No polling or firewall requests. */
(() => {
  async function load(gate, url) {
    const body = gate.querySelector('.dhcp-gate-body');
    if (body.getAttribute('aria-busy') === 'true') return;
    body.setAttribute('aria-busy', 'true');
    const status = document.createElement('p');
    status.className = 'field-note';
    status.setAttribute('role', 'status');
    status.textContent = 'Loading saved results…';
    body.prepend(status);
    try {
      const response = await fetch(url, {headers: {'Accept': 'text/html'}});
      if (!response.ok || response.redirected) throw new Error('Unavailable');
      const documentCopy = new DOMParser().parseFromString(await response.text(), 'text/html');
      const results = documentCopy.querySelector('.dhcp-gate-body[data-loaded="true"]');
      if (!results) throw new Error('Unavailable');
      body.replaceChildren(...results.childNodes);
      body.dataset.loaded = 'true';
    } catch (_) {
      status.textContent = 'Could not load saved results. Open the gate to try again.';
      if (!body.querySelector('.dhcp-load-gate')) {
        const retry = document.createElement('a');
        retry.className = 'button-link secondary dhcp-load-gate';
        retry.href = url;
        retry.textContent = 'Open gate';
        body.append(retry);
      }
    } finally {
      body.removeAttribute('aria-busy');
    }
  }
  document.querySelectorAll('.dhcp-gate').forEach(gate => {
    gate.addEventListener('toggle', () => {
      if (gate.open && !gate.querySelector('.dhcp-gate-body').dataset.loaded) load(gate, gate.dataset.url);
    });
    gate.addEventListener('click', event => {
      const link = event.target.closest('.dhcp-pagination a');
      if (!link || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button !== 0) return;
      event.preventDefault();
      load(gate, link.href);
    });
  });
})();
