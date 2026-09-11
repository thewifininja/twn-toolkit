/* Shared saved-list controls. Only explicit saves change sharing or content. */
(() => {
  const find = (container) => container?.matches?.('[data-mso-control]') ? container : container?.querySelector('[data-mso-control]');
  const states = new WeakMap();
  const render = (control, name, preserveToggle = false) => {
    const state = states.get(control);
    state.name = name;
    state.current = state.library[name] || null;
    const toggle = control.querySelector('[data-mso-switch]');
    if (!preserveToggle) toggle.checked = Boolean(state.current?.enabled);
    toggle.title = state.current?.state || 'Local';
    control.querySelector('[data-mso-attention]').hidden = !state.current?.conflict;
  };
  const initialize = () => document.querySelectorAll('[data-mso-control]').forEach((control) => {
    if (states.has(control)) return;
    states.set(control, {library: JSON.parse(control.dataset.msoLibrary || '{}')});
    const manager = control.closest('[data-saved-profile-manager]');
    const select = manager?.querySelector('[data-saved-profile-select]');
    const toggle = control.querySelector('[data-mso-switch]');
    const initialChecked = toggle.checked;
    render(control, select?.value || control.dataset.msoName || '');
    window.TwnUnsavedForms?.rebaseReference(control.closest('form'), toggle.name, initialChecked, toggle.checked);
    select?.addEventListener('change', () => render(control, select.value));
    manager?.addEventListener('savedprofilesaved', () => {
      if (!select?.value) render(control, '');
    });
  });
  window.TwnMso = {
    prepare(body, container, action = 'save') {
      const control = find(container);
      if (!control) return true;
      const state = states.get(control);
      const enabled = control.querySelector('[data-mso-switch]').checked;
      if (action === 'save' && state.current?.enabled && !enabled
        && !window.confirm('Turn MSO off? Keep this copy locally and remove the shared copies from the fleet.')) return false;
      if (!body.has('original_name') && state.current) body.set('original_name', state.name);
      body.set('mso_kind', control.dataset.msoKind);
      body.set('mso_enabled', String(enabled));
      state.submittedEnabled = enabled;
      if (state.current) {
        body.set('mso_id', state.current.id);
        body.set('mso_version', String(state.current.version));
      }
      return true;
    },
    saved(container, profile, resetSharing = false) {
      const control = find(container);
      if (!control || !profile?.mso) return;
      const state = states.get(control);
      if (!resetSharing && state.name && state.name !== profile.name) delete state.library[state.name];
      state.library[profile.name] = profile.mso;
      const editedWhileSaving = !resetSharing && control.querySelector('[data-mso-switch]').checked !== state.submittedEnabled;
      render(control, profile.name, editedWhileSaving);
    },
    deleteMessage(container, name) {
      const state = states.get(find(container));
      return state?.current?.enabled ? `Delete shared profile “${name}” from the entire fleet?` : `Delete profile “${name}”?`;
    },
  };
  initialize();
  document.querySelectorAll('form[data-mso-matrix]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const deleting = event.submitter?.hasAttribute('formaction');
      if (!deleting && event.submitter?.value !== 'save_host_matrix') return;
      if (deleting && !window.confirm(window.TwnMso.deleteMessage(form, form.elements.host_matrix_original_name.value))) {
        event.preventDefault(); return;
      }
      const body = new FormData(form);
      if (!window.TwnMso.prepare(body, form, deleting ? 'delete' : 'save')) {
        event.preventDefault(); return;
      }
      for (const [key, value] of body) {
        if (!key.startsWith('mso_')) continue;
        let input = form.querySelector(`input[name="${key}"]`);
        if (!input) {
          input = document.createElement('input'); input.type = 'hidden'; input.name = key; form.append(input);
        }
        input.value = value;
      }
    });
  });
  document.querySelectorAll('form[data-mso-appliance]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const deleting = event.submitter?.value === 'delete';
      if (!deleting && event.submitter?.value !== 'save') return;
      if (deleting && !window.confirm(window.TwnMso.deleteMessage(form, form.elements.original_name?.value || ''))) {
        event.preventDefault(); return;
      }
      const body = new FormData(form);
      if (!window.TwnMso.prepare(body, form, deleting ? 'delete' : 'save')) {
        event.preventDefault(); return;
      }
      for (const [key, value] of body) {
        if (!key.startsWith('mso_')) continue;
        let input = form.querySelector(`input[name="${key}"]`);
        if (!input) {
          input = document.createElement('input'); input.type = 'hidden'; input.name = key;
          form.append(input);
        }
        input.value = value;
      }
    });
  });
  document.querySelectorAll('form[data-mso-native]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (event.submitter?.value !== 'save') return;
      const body = new FormData(form);
      if (!window.TwnMso.prepare(body, form)) {
        event.preventDefault();
        return;
      }
      for (const [key, value] of body) {
        if (!key.startsWith('mso_')) continue;
        let input = form.querySelector(`input[name="${key}"]`);
        if (!input) {
          input = document.createElement('input'); input.type = 'hidden'; input.name = key;
          form.append(input);
        }
        input.value = value;
      }
    });
  });
  document.querySelectorAll('form[data-mso-delete-name]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const shared = form.elements.mso_enabled?.value === 'true';
      const message = shared ? `Delete shared persona “${form.dataset.msoDeleteName}” from the entire fleet?` : `Delete persona “${form.dataset.msoDeleteName}”?`;
      if (!window.confirm(message)) event.preventDefault();
    });
  });
})();
