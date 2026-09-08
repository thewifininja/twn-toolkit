(() => {
  const guard = window.TwnUnsavedForms;
  if (!guard) return;
  document.querySelectorAll('form[data-certificate-profile-editor]').forEach((form) => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (guard.isPending(form)) return;
      const body = new FormData(form);
      const snapshot = guard.capture(form);
      const lock = form.querySelector('[data-editor-lock]');
      const status = form.querySelector('[data-profile-editor-status]');
      const external = Array.from(form.elements).filter((field) => !form.contains(field) && 'disabled' in field)
        .map((field) => [field, field.disabled]);
      external.forEach(([field]) => { field.disabled = true; });
      lock.disabled = true;
      form.setAttribute('aria-busy', 'true');
      status.textContent = 'Saving profile…';
      try {
        const response = await fetch(form.action, {method: 'POST', headers: {'Accept': 'application/json'}, body});
        let data;
        try { data = await response.json(); }
        catch (_) { throw new Error('The save could not be confirmed. Keep this draft and check the saved profiles before retrying.'); }
        if (!response.ok) throw new Error(data.error || 'The profile could not be saved. Your draft is still here.');
        if (!data.saved?.id || typeof data.saved.name !== 'string') {
          throw new Error('The save could not be confirmed. Keep this draft and check the saved profiles before retrying.');
        }
        guard.acknowledge(form, snapshot);
        let id = form.querySelector('[name="id"]');
        if (!id) {
          id = document.createElement('input'); id.type = 'hidden'; id.name = 'id'; lock.append(id);
        }
        id.value = data.saved.id;
        form.querySelector('[name="name"]').value = data.saved.name;
        form.querySelectorAll('input[type="password"]').forEach((input) => {
          input.value = ''; input.required = false; input.placeholder = 'Leave blank to keep the saved password';
        });
        form.querySelectorAll('input[type="file"]').forEach((input) => { input.value = ''; });
        guard.reset(form);
        status.textContent = `Saved ${data.saved.name}. `;
        const reload = document.createElement('a');
        reload.href = window.location.href;
        reload.textContent = 'Reload to refresh profile lists';
        reload.addEventListener('click', (event) => { event.preventDefault(); window.location.reload(); });
        status.append(reload);
      } catch (error) {
        guard.settle(form);
        status.textContent = error instanceof TypeError
          ? 'The save could not be confirmed. Keep this draft and check the saved profiles before retrying.'
          : error.message;
      } finally {
        lock.disabled = false;
        external.forEach(([field, disabled]) => { field.disabled = disabled; });
        form.removeAttribute('aria-busy');
      }
    });
  });
})();
