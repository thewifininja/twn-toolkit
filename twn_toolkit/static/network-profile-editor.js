/* Dependency editors: acknowledged saves update choices, never execute a tool or reload a draft. */
(() => {
  const root = document.querySelector('[data-network-profiles]');
  if (!root) return;
  const tool = root.dataset.networkProfiles;
  const groups = tool === 'snmp' ? ['credentials', 'hosts', 'oids']: ['servers', 'credentials', 'attributes'];
  const forms = [...root.querySelectorAll('.snmp-profile-form,.radius-profile-form')];
  let catalog = Object.fromEntries(groups.map(kind => [kind, []])), epoch = 0, catalogReady = false, refreshPending = false;
  const defaults = new Map(), editorStates = new WeakMap();
  let hostReturn = null;
  root.addEventListener('focusin', event => {
    const host = event.target.closest('.snmp-profile-form[data-kind="hosts"]');
    if (host) hostReturn = host;
  });
  const noun = kind => ({
    credentials: 'credential',
    hosts: 'host',
    servers: 'server',
    oids: 'OID collection',
    attributes: 'attribute set',
  })[kind];
  const strip = window.TwnNetworkProfileReceipt.strip;
  const valid = window.TwnNetworkProfileReceipt.validName;
  const choiceFields = {
    credentials: tool === 'snmp' ? ['name', 'version'] : ['name', 'username'],
    hosts: ['name', 'host', 'port', 'credential_name'],
    oids: ['name', 'count'],
    servers: ['name', 'host', 'port'],
    attributes: ['name', 'count'],
  };
  const publicChoice = (kind, item) => Object.fromEntries(
    choiceFields[kind].filter(key => Object.hasOwn(item, key)).map(key => [key, item[key]]),
  );
  const validChoice = (kind, item) => {
    if (!valid(item)) return false;
    if (kind === 'hosts' || kind === 'servers') {
      return typeof item.host === 'string' && Number.isInteger(item.port)
        && item.port >= 1 && item.port <= 65535;
    }
    if (kind === 'oids' || kind === 'attributes') {
      return Number.isInteger(item.count) && item.count >= 0 && item.count <= 50;
    }
    return tool === 'snmp' ? ['v2c', 'v3'].includes(item.version)
      : typeof item.username === 'string';
  };
  const label = (kind, item) => {
    if (item.host) return `${item.name} · ${item.host}${item.port ? ':' + item.port : ''}`;
    if (item.username) return `${item.name} · ${item.username}`;
    if (item.version) return `${item.name} · ${item.version}`;
    if (item.count !== undefined) {
      return `${item.name} · ${item.count} ${item.count === 1 ? 'entry' : 'entries'}`;
    }
    return item.name;
  };
  const verifySave = (kind, profile, body) => window.TwnNetworkProfileReceipt.verify(tool, kind, profile, body);
  const counts = () => {
    const totals = {};
    groups.forEach(kind => {
      const names = new Set(catalog[kind].map(item => item.name));
      root.querySelectorAll(`[data-profile-choice-select="${kind}"] option`).forEach(option => {
        if (option.value && !option.dataset.profileMissing)names.add(option.value);
      });
      root.querySelectorAll(`[data-profile-choice-group="${kind}"] input`).forEach(input => {
        if (!input.dataset.profileMissing)names.add(input.value);
      });
      totals[kind] = names.size;
      const detail = root.querySelector(`.network-section-${kind} > summary small`);
      if (detail) {
        const tail = detail.textContent.split(' · ').slice(1).join(' · ');
        detail.textContent = `${names.size} saved${tail?' · '+tail:''}`;
      }
    });
    const profileCount = root.querySelector('[data-network-count="profiles"]');
    if (profileCount)profileCount.textContent = `${Object.values(totals).reduce((sum,value)=>sum+value,0)} saved items`;
    const runCount = root.querySelector('[data-network-count="run"]');
    if (runCount)runCount.textContent = `${totals.hosts} ${totals.hosts===1?'host':'hosts'} · ${totals.oids} ${totals.oids===1?'collection':'collections'}`;
  };
  const saveUrl = form => form.dataset.saveUrl || root.dataset.profileSaveTemplate.replace('__KIND__', form.dataset.kind);
  const statusFor = form => {
    let status = form.querySelector('.snmp-form-status,[data-profile-form-status]');
    if (!status) {
      status = document.createElement('p');
      status.className = 'tool-status';
      status.dataset.profileFormStatus = '';
      status.setAttribute('role', 'status');
      form.append(status);
    }
    return status;
  };
  const checkboxName = kind => ({
    hosts: 'host_names', oids: 'oid_profile_names', servers: 'server_names'
  })[kind];
  const apply = () => {
    groups.forEach(kind => {
      const items = catalog[kind];
      root.querySelectorAll(`[data-profile-choice-select="${kind}"]`).forEach(select => {
        const selected = select.value;
        items.forEach(item => {
          let option = [...select.options].find(option => option.value === item.name);
          if (!option) {
            option = new Option('', item.name);
            select.append(option);
          }
          option.textContent = label(kind, item);
          delete option.dataset.profileMissing;
        });
        [...select.options].filter(option => catalogReady && option.value && !items.some(item => item.name === option.value)).forEach(option => {
          option.textContent = `Unavailable saved profile: ${option.value}`;
          option.dataset.profileMissing = 'true';
        });
        select.value = selected;
        select.disabled = false;
        window.TwnSelectControls?.sync(select);
      });
      root.querySelectorAll(`[data-profile-choice-group="${kind}"]`).forEach(group => {
        const form = group.closest('form'), added = [];
        items.forEach(item => {
          let input = [...group.querySelectorAll('input[type=checkbox]')].find(input => input.value === item.name);
          if (!input) {
            const row = document.createElement('label');
            row.className = 'check';
            input = document.createElement('input');
            input.type = 'checkbox';
            input.name = checkboxName(kind);
            input.value = item.name;
            const text = document.createElement('span');
            row.append(input, text);
            group.append(row);
            added.push(input);
          }
          input.parentElement.querySelector('span').textContent = label(kind, item);
          delete input.dataset.profileMissing;
        });
        group.querySelectorAll('input[type=checkbox]').forEach(input => {
          if (catalogReady && !items.some(item => item.name === input.value)) {
            input.dataset.profileMissing = 'true';
            input.parentElement.querySelector('span').textContent = `Unavailable saved profile: ${input.value}`;
          }
        });
        if (added.length)window.TwnUnsavedForms?.registerControls(form, added);
        group.querySelectorAll('[data-profile-empty]').forEach(empty => {
          empty.hidden = items.length>0;
        });
      });
    });
    const availableHosts = [...root.querySelectorAll('[data-profile-choice-group="hosts"] input')].some(input => !input.dataset.profileMissing);
    root.querySelectorAll('[data-profile-setup-empty]').forEach(node => {
      node.hidden = availableHosts;
    });
    const run = root.querySelector('#snmp-test-form [type=submit]');
    if (run)run.disabled = !availableHosts;
    const discover = root.querySelector('.snmp-monitor-discover');
    if (discover)discover.disabled = !availableHosts;
    counts();
  };
  const known = (kind, item, previous = '') => {
    if (!validChoice(kind, item))throw new Error('The saved profile could not be verified.');
    item = publicChoice(kind, item);
    epoch++;
    if (refreshPending) {
      refreshPending = false;
      root.querySelector('[data-profile-choice-status]').textContent = 'Choices updated; drafts kept.';
    }
    if (previous && previous !== item.name) {
      root.querySelectorAll(`[data-profile-choice-select="${kind}"]`).forEach(select => {
        [...select.options].filter(option => option.value === previous).forEach(option => {
          option.value = item.name;
        });
        window.TwnUnsavedForms?.rebaseReference(select.form, select.name, previous, item.name);
      });
      root.querySelectorAll(`[data-profile-choice-group="${kind}"] input`).forEach(input => {
        if (input.value === previous)input.value = item.name;
      });
      if (tool === 'snmp' && kind === 'credentials')catalog.hosts.forEach(host => {
        if (host.credential_name === previous)host.credential_name = item.name;
      });
    }
    catalog[kind] = [...catalog[kind].filter(current => current.name !== previous && current.name !== item.name), item];
    apply();
  };
  const refresh = async ({silent = false} = {}) => {
    const sequence = ++epoch;
    refreshPending = true;
    const status = root.querySelector('[data-profile-choice-status]');
    if (!silent)status.textContent = 'Refreshing saved choices…';
    try {
      const response = await fetch(root.dataset.profileChoicesUrl, {
        headers: {
          Accept: 'application/json'
        }, cache: 'no-store', signal: AbortSignal.timeout(10000)
      });
      if (!response.ok || !response.headers.get('content-type')?.includes('application/json'))throw new Error('Choices unavailable. Check your session/tool access, then try again.');
      const data = await response.json();
      if (!groups.every(kind => Array.isArray(data[kind]) && data[kind].every(item => validChoice(kind, item))))throw new Error('Saved choices were not recognized.');
      if (sequence !== epoch)return;
      catalog = Object.fromEntries(groups.map(kind => [kind, data[kind].map(item => publicChoice(kind, item))]));
      catalogReady = true;
      refreshPending = false;
      apply();
      status.textContent = silent?'': 'Choices refreshed; selections and drafts kept.';
    } catch (error) {
      if (sequence !== epoch) return;
      refreshPending = false;
      status.textContent = error.message + ' Your drafts stay here.';
    }
  };
  root.querySelector('[data-profile-choices-refresh]').addEventListener('click', refresh);
  forms.forEach(form => {
    if (!form.elements.original_name.value && !defaults.has(form.dataset.kind))defaults.set(form.dataset.kind, [...form.elements].filter(field => field.name).map(field => ({
      name: field.name, type: field.type, value: field.value, checked: field.checked
    })));
  });
  forms.forEach(form => {
    const kind = form.dataset.kind;
    const status = statusFor(form);
    const submit = form.querySelector('[type=submit]');
    let pending = false;
    let deleted = false;
    editorStates.set(form, {
      isPending: () => pending, isDeleted: () => deleted, setDeleted: value => { deleted = value; }, setPending: value => {
        pending = value;
      }
    });
    const returnButton = document.createElement('button');
    returnButton.type = 'button';
    returnButton.className = 'secondary';
    returnButton.hidden = true;
    returnButton.textContent = tool === 'snmp' && kind === 'credentials'?'Continue host setup': 'Return to Run tests';
    form.append(returnButton);
    returnButton.addEventListener('click', () => {
      const toHosts = tool === 'snmp' && kind === 'credentials';
      const tabId = toHosts ? 'snmp-profiles-tab'
        : tool === 'snmp' ? 'snmp-tests-tab' : 'radius-workflows-tab';
      document.getElementById(tabId).click();
      let target;
      if (toHosts) {
        const hostEditor = hostReturn
          || [...root.querySelectorAll('.snmp-profile-form[data-kind="hosts"]')]
            .find(editor => !editor.elements.original_name.value)
          || root.querySelector('.snmp-profile-form[data-kind="hosts"]');
        target = hostEditor?.querySelector('[name=credential_name]');
      } else {
        target = root.querySelector(tool === 'snmp' ? '#snmp-test-form' : '#radius-test-form');
      }
      if (!target) return;
      for (let parent = target.parentElement; parent && parent !== root; parent = parent.parentElement) {
        if (parent.tagName === 'DETAILS') parent.open = true;
      }
      target.scrollIntoView({block: 'center'});
      const control = target.matches('form')
        ? target.querySelector('input:not([type=hidden]),select') : target;
      const visible = control?.matches('select')
        ? control.closest('.toolkit-select')?.querySelector('.toolkit-select-trigger') || control
        : control;
      visible?.focus();
    });
    const newButton = document.createElement('button');
    newButton.type = 'button';
    newButton.className = 'secondary';
    newButton.textContent = `Create another ${noun(kind)}`;
    newButton.hidden = !form.elements.original_name.value;
    form.append(newButton);
    newButton.addEventListener('click', () => {
      if (pending || (window.TwnUnsavedForms?.hasChanges(form) && !window.confirm('Discard only this editor’s unsaved changes and start a new profile? Other drafts stay here.')))return;
      const initial = defaults.get(kind) || [];
      [...form.elements].filter(field => field.name).forEach(field => {
        const start = initial.find(item => item.name === field.name && item.type === field.type);
        if (start) {
          field.value = start.value;
          field.checked = start.checked;
        }
      });
      form.elements.original_name.value = '';
      deleted = false;
      submit.disabled = false;
      window.TwnMso.newProfile(form);
      newButton.hidden = true;
      form.querySelectorAll('input[type=password]').forEach(field => {
        field.value = '';
        field.placeholder = '';
      });
      form.querySelectorAll('.secret-note,.snmp-community-note').forEach(note => {
        note.textContent = 'Enter required secrets for this new profile; no saved secret is carried over.';
      });
      form.querySelectorAll('[data-profile-duplicate],.snmp-delete-profile,.radius-delete-profile').forEach(button => {
        button.hidden = true;
        button.disabled = false;
      });
      const summary = form.closest('details')?.querySelector(':scope > summary');
      if (summary)summary.textContent = `New ${noun(kind)}`;
      submit.textContent = 'Save new profile';
      form.elements.version?.dispatchEvent(new Event('change'));
      window.TwnUnsavedForms?.reset(form);
      status.textContent = 'New profile defaults are ready. Enter a new name and required secrets; other drafts are unchanged.';
      form.elements.name.focus();
    });
    form.addEventListener('submit', async event => {
      if (event.defaultPrevented)return;
      event.preventDefault();
      if (deleted) {
        status.textContent = 'This saved profile was deleted. Use Create another before saving.';
        return;
      }
      if (pending || !form.reportValidity())return;
      const body = new FormData(form);
      if (!window.TwnMso?.prepare) {
        status.textContent = 'Saved-list controls are still loading. Your draft is kept.';
        return;
      }
      if (!window.TwnMso.prepare(body, form)) {
        status.textContent = 'Save canceled; draft kept.';
        return;
      }
      const snapshot = window.TwnUnsavedForms?.capture(form), previous = form.elements.original_name.value;
      const actionStates = [...form.querySelectorAll('[data-profile-duplicate],.snmp-delete-profile,.radius-delete-profile')].map(button => [button, button.disabled]);
      actionStates.forEach(([button]) => {
        button.disabled = true;
      });
      pending = true;
      submit.disabled = true;
      newButton.disabled = true;
      status.textContent = 'Saving profile; no test is running…';
      try{
        const response = await fetch(saveUrl(form), {
          method: 'POST', body, headers: {
            Accept: 'application/json'
          }, signal: AbortSignal.timeout(15000)
        });
        if ([401, 403, 404].includes(response.status)) {
          const error = new Error('Your session or tool access is unavailable. Sign in or check access before trying again.');
          error.access = true;
          throw error;
        }
        if (!response.headers.get('content-type')?.includes('application/json'))throw new Error('Save was not confirmed.');
        const payload = await response.json();
        if (!response.ok) {
          const error = new Error(payload.error || 'Profile could not be saved.');
          error.definite = response.status === 400 || response.status === 409;
          throw error;
        }
        const profile = payload.profile;
        if (!verifySave(kind, profile, body))throw new Error('Save acknowledgment did not match the submitted profile.');
        window.TwnMso.saved(form, profile);
        form.elements.original_name.value = profile.name;
        const savedValues = {
          name: profile.name
        };
        if (form.elements.name.value === body.get('name'))form.elements.name.value = profile.name;
        form.querySelectorAll('input[type=password]').forEach(field => {
          savedValues[field.name] = '';
          if (field.value === body.get(field.name))field.value = '';
        });
        window.TwnUnsavedForms?.acknowledge(form, snapshot, savedValues);
        known(kind, profile, previous);
        const card = form.closest('details');
        if (card) {
          card.classList.remove('profile-create-details', 'card-action-details', 'saved-profile-create');
          card.classList.add('access-profile-card', 'nested-profile-card', 'saved-profile-record');
        }
        const summary = card?.querySelector(':scope > summary');
        if (summary)summary.textContent = `Editing ${profile.name}`;
        form.querySelectorAll('.secret-note,.snmp-community-note').forEach(note => {
          note.textContent = 'Saved secrets are write-only. Leave blank to keep the saved value.';
        });
        form.querySelectorAll('[data-profile-duplicate],.snmp-delete-profile,.radius-delete-profile').forEach(button => {
          button.hidden = false;
          button.dataset.profileName = profile.name;
          button.dataset.name = profile.name;
        });
        if (!form.querySelector('[data-profile-duplicate]')) {
          const duplicate = document.createElement('button');
          duplicate.type = 'button';
          duplicate.className = 'secondary duplicate-action';
          duplicate.textContent = 'Duplicate';
          duplicate.dataset.profileDuplicate = saveUrl(form) + '/duplicate';
          duplicate.dataset.profileName = profile.name;
          form.append(duplicate);
        }
        if (!form.querySelector('.snmp-delete-profile,.radius-delete-profile')) {
          const remove = document.createElement('button');
          remove.type = 'button';
          remove.className = tool === 'snmp'?'danger snmp-delete-profile': 'danger radius-delete-profile';
          remove.textContent = 'Delete';
          form.append(remove);
        }
        form.querySelectorAll('[data-profile-duplicate],.snmp-delete-profile,.radius-delete-profile').forEach(button => {
          button.hidden = false;
          button.dataset.profileName = profile.name;
          button.dataset.name = profile.name;
        });
        newButton.hidden = false;
        returnButton.hidden = false;
        submit.textContent = 'Update saved profile';
        status.textContent = `Saved ${profile.name}. It is available in the current choices; select it where needed. No test was run.` + (window.TwnUnsavedForms?.hasChanges(form)?' Newer edits in this editor are still unsaved.': '');
      } catch (error) {
        window.TwnUnsavedForms?.failed(form);
        status.textContent = (error.access?error.message + ' Save is unconfirmed; it may already have completed.': error.definite?error.message: 'Save is unconfirmed. It may already have completed. Use Refresh saved choices or open the saved library before trying again.') + ' Drafts are kept; no save is retried automatically.';
      }
      finally{
        pending = false;
        submit.disabled = false;
        newButton.disabled = false;
        actionStates.forEach(([button, disabled]) => {
          button.disabled = disabled;
        });
        window.TwnUnsavedForms?.settle(form);
      }
    });
  });
  root.addEventListener('click', async event => {
    const button = event.target.closest('[data-profile-duplicate],.snmp-delete-profile,.radius-delete-profile');
    if (!button || !root.contains(button) || button.disabled)return;
    const form = button.closest('form'), state = editorStates.get(form), status = statusFor(form);
    if (!state || state.isPending() || state.isDeleted())return;
    const name = form.elements.original_name.value;
    if (!name)return;
    const deleting = button.matches('.snmp-delete-profile,.radius-delete-profile');
    if (deleting && !window.confirm(window.TwnMso.deleteMessage(form, name)))return;
    const body = new FormData();
    body.set('name', name);
    if (deleting && !window.TwnMso.prepare(body, form, 'delete'))return;
    state.setPending(true);
    window.TwnUnsavedForms?.capture(form);
    const buttons = [...form.querySelectorAll('button')].map(control => [control, control.disabled]);
    buttons.forEach(([control]) => {
      control.disabled = true;
    });
    try{
      const response = await fetch(deleting?(form.dataset.deleteUrl || saveUrl(form) + '/delete'): button.dataset.profileDuplicate, {
        method: 'POST', body, headers: {
          Accept: 'application/json'
        }, signal: AbortSignal.timeout(15000)
      });
      if ([401, 403, 404].includes(response.status))throw new Error('Your session or tool access is unavailable. Sign in or check access before trying again.');
      if (!response.headers.get('content-type')?.includes('application/json'))throw new Error('Operation unconfirmed.');
      const data = await response.json();
      if (!response.ok) {
        const error = new Error(data.error || 'Operation unconfirmed.');
        error.definite = response.status === 400 || response.status === 409;
        throw error;
      }
      if (deleting) {
        if (data.deleted !== name)throw new Error('Delete acknowledgment did not match.');
        state.setDeleted(true);
        const summary = form.closest('details')?.querySelector(':scope > summary');
        if (summary) summary.textContent = `Deleted ${name} — draft kept`;
        status.textContent = `Deleted ${name}. This editor and other drafts remain here; use Create another to start again.`;
        await refresh();
      }
      else {
        if (data.source_name !== name || !validChoice(form.dataset.kind, data.profile) || data.profile.name === name)throw new Error('Copy acknowledgment did not match.');
        known(form.dataset.kind, data.profile);
        status.textContent = `Copied as ${data.profile.name}. The new choice is available but not selected; drafts are unchanged.`;
      }
    } catch (error) {
      status.textContent = error.message + (error.definite
        ? ' Drafts are kept.'
        : ' The operation may already have completed. Refresh saved choices before retrying; no operation is retried automatically.');
    }
    finally{
      state.setPending(false);
      buttons.forEach(([control, disabled]) => {
        control.disabled = disabled;
        if (state.isDeleted() && control.matches('[type=submit],[data-profile-duplicate],.snmp-delete-profile,.radius-delete-profile')) control.disabled = true;
      });
      window.TwnUnsavedForms?.settle(form);
    }
  });
  root.querySelectorAll('[data-network-setup]').forEach(button => button.addEventListener('click', () => {
    const tab = document.getElementById(tool === 'snmp'?'snmp-profiles-tab': 'radius-profiles-tab');
    tab.click();
    tab.focus();
  }));
  refresh({
    silent: true
  });
})();
