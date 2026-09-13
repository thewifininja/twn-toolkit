(() => {
  const form = document.getElementById('task-form');
  const panel = document.getElementById('fabric-targets');
  if (!form || !panel) return;
  const discover = panel.querySelector('[data-discover-url]');
  const status = panel.querySelector('[role="status"]');
  const list = panel.querySelector('.fabric-target-list');
  const saved = panel.querySelector('[name="fabric_discovery"]');
  const summary = panel.querySelector('[data-target-summary]');
  const actions = panel.querySelector('[data-selection-actions]');
  function changed() {
    const selected = [...list.querySelectorAll('input:checked')];
    summary.textContent = saved.value ? `${selected.length} FortiGate${selected.length === 1 ? '' : 's'} selected` : 'Connected FortiGate';
    document.getElementById('data-preview').hidden = true;
    document.getElementById('field-list').replaceChildren();
    document.getElementById('apply-fields').disabled = true;
  }
  form.elements.profile.addEventListener('change', () => {
    saved.value = ''; list.replaceChildren(); actions.hidden = true;
    status.textContent = 'Discover the Fabric to choose downstream gates. Uses the profile’s default VDOM.';
    changed();
  });
  list.addEventListener('change', changed);
  actions.querySelector('[data-select-all]').addEventListener('click', () => {
    list.querySelectorAll('input').forEach(input => { input.checked = true; }); changed();
  });
  actions.querySelector('[data-select-root]').addEventListener('click', () => {
    list.querySelectorAll('input').forEach(input => { input.checked = input.dataset.root === 'true'; }); changed();
  });
  discover.addEventListener('click', async () => {
    const body = new FormData(form), profile = body.get('profile');
    discover.disabled = true;
    try {
      const data = await window.TwnApplianceRead(discover.dataset.discoverUrl, body, status);
      if (form.elements.profile.value !== profile) throw new Error('Profile changed. Discover again for the selected profile.');
      list.replaceChildren();
      data.targets.forEach(target => {
        const label = document.createElement('label'); label.className = 'field-check';
        const input = document.createElement('input'); input.type = 'checkbox'; input.name = 'fabric_serial';
        input.value = target.serial; input.checked = !target.path; input.dataset.root = String(!target.path);
        const text = document.createElement('span'); text.textContent = target.hostname;
        const detail = document.createElement('small'); detail.textContent = `${target.model || 'FortiGate'} · ${target.vdoms.join(', ')}${target.path ? '' : ' · Connected gate'}`;
        text.append(detail); label.append(input, text); list.append(label);
      });
      saved.value = data.discovery_id; actions.hidden = false;
      status.textContent = 'Choose gates below. Selection is saved into each run. Rediscover after changing the profile or if discovery expires (15 minutes).';
      changed();
    } catch (error) { status.textContent = error.message; }
    finally { discover.disabled = false; }
  });
})();

window.TwnRenderFabricResults = (container, data) => {
  container.replaceChildren();
  data.groups.forEach(group => {
    const box = document.createElement('details'); box.className = 'fabric-result';
    const summary = document.createElement('summary');
    const name = document.createElement('strong'); name.textContent = group.hostname;
    const count = document.createElement('span'); count.textContent = `${group.vdom} · ${group.error ? 'Count unavailable' : group.row_count + ' rows'}`;
    const state = document.createElement('span'); state.className = 'pill ' + (group.error ? 'warning' : 'success');
    state.textContent = group.error ? 'Unavailable' : 'Read OK'; summary.append(name, count, state); box.append(summary);
    const body = document.createElement('div'); body.className = 'fabric-result-body';
    const identity = document.createElement('p'); identity.className = 'field-note'; identity.textContent = group.serial;
    body.append(identity);
    if (group.error) {
      const error = document.createElement('p'); error.className = 'message warning'; error.textContent = group.error; body.append(error);
    } else {
      const note = document.createElement('p'); note.className = 'field-note'; note.textContent = `${group.rows.length} of ${group.row_count} rows shown. CSV retains all collected rows.`; body.append(note);
      const wrap = document.createElement('div'); wrap.className = 'preview-table-wrap';
      const table = document.createElement('table'), head = table.createTHead().insertRow(), tbody = table.createTBody();
      const columns = data.columns.slice(3);
      columns.forEach(column => { const cell = document.createElement('th'); cell.scope = 'col'; cell.textContent = column; head.append(cell); });
      group.rows.forEach(row => { const tr = tbody.insertRow(); columns.forEach(column => { tr.insertCell().textContent = row[column] ?? ''; }); });
      wrap.append(table); body.append(wrap);
    }
    box.append(body); container.append(box);
  });
};
