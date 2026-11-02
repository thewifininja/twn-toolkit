(() => {
  const showWorkspace = (workspace, { updateUrl = true } = {}) => {
    const tabs = [...document.querySelectorAll("[data-ssh-workspace-tab]")];
    const panels = [...document.querySelectorAll("[data-ssh-workspace-panel]")];
    if (!tabs.some((tab) => tab.dataset.sshWorkspaceTab === workspace)) return;
    tabs.forEach((tab) => {
      const selected = tab.dataset.sshWorkspaceTab === workspace;
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    panels.forEach((panel) => {
      panel.hidden = panel.dataset.sshWorkspacePanel !== workspace;
    });
    document.querySelectorAll('input[name="workspace"]').forEach((input) => {
      if (input.closest(".multi-ssh-matrix-picker")) input.value = workspace;
    });
    document.dispatchEvent(new CustomEvent('twn:ssh-workspace', { detail: { workspace } }));
    if (updateUrl) {
      const url = new URL(window.location.href);
      url.searchParams.set("workspace", workspace);
      window.history.replaceState({}, "", url);
    }
  };

  const workspaceTabs = document.querySelector("[data-ssh-workspace-tabs]");
  workspaceTabs?.addEventListener("click", (event) => {
    const tab = event.target.closest("[data-ssh-workspace-tab]");
    if (tab) showWorkspace(tab.dataset.sshWorkspaceTab);
  });
  workspaceTabs?.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    const tabs = [...workspaceTabs.querySelectorAll("[data-ssh-workspace-tab]")];
    const current = tabs.indexOf(document.activeElement);
    if (current < 0) return;
    event.preventDefault();
    const next = event.key === "Home"
      ? 0
      : event.key === "End"
        ? tabs.length - 1
        : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].focus();
    showWorkspace(tabs[next].dataset.sshWorkspaceTab);
  });
  document.querySelectorAll("[data-ssh-open-workspace]").forEach((button) => {
    button.addEventListener("click", () => {
      const workspace = button.dataset.sshOpenWorkspace;
      showWorkspace(workspace);
      document.querySelector(`[data-ssh-workspace-tab="${workspace}"]`)?.focus();
    });
  });

  const matrixSelector = document.querySelector("[data-ssh-matrix-selector]");
  matrixSelector?.addEventListener("change", () => matrixSelector.form?.requestSubmit());
  const activeTab = document.querySelector('[data-ssh-workspace-tab][aria-selected="true"]');
  if (activeTab) showWorkspace(activeTab.dataset.sshWorkspaceTab);
  const actionSelector = document.querySelector("[data-ssh-action-selector]");
  const actionForm = document.querySelector(".multi-ssh-action-editor");
  if (actionForm && actionSelector) {
    const fields = {
      name: "matrix_action_name", description: "matrix_action_description",
      platform: "matrix_action_platform", commands: "commands",
      command_timeout: "command_timeout", original_name: "matrix_action_original_name",
    };
    const read = () => Object.fromEntries(Object.entries(fields).map(([key, name]) => [key, actionForm.elements.namedItem(name).value]));
    const empty = { name: "", description: "", platform: "", commands: "", command_timeout: "300", original_name: "" };
    const baseline = new Map([["", empty]]);
    JSON.parse(document.querySelector("[data-ssh-action-library]").textContent).forEach((action) => {
      baseline.set(action.name, Object.fromEntries(Object.keys(fields).map((key) => [key, String(key === "original_name" ? action.name : action[key] ?? "")])));
    });
    const drafts = new Map([...baseline].map(([key, value]) => [key, { ...value }]));
    let current = read().original_name;
    drafts.set(current, read());
    const initialUrl = new URL(window.location.href);
    if (matrixSelector?.value) {
      initialUrl.searchParams.set("host_matrix", matrixSelector.value);
      initialUrl.searchParams.delete("duplicate_matrix");
    }
    initialUrl.searchParams.delete("new_action");
    if (current) initialUrl.searchParams.set("matrix_action", current);
    else initialUrl.searchParams.set("new_action", "1");
    window.history.replaceState({}, "", initialUrl);
    const changed = (key, draft) => JSON.stringify(draft) !== JSON.stringify(baseline.get(key));
    const remember = () => {
      drafts.set(current, read());
      const dirty = [...drafts].some(([key, draft]) => changed(key, draft));
      actionForm.dataset.unsavedInitial = String(dirty);
      if (!dirty) window.TwnUnsavedForms?.reset(actionForm);
      document.dispatchEvent(new Event('twn:ssh-library-draft'));
    };
    const selectAction = (name) => {
      remember();
      current = name;
      const draft = drafts.get(name) || empty;
      Object.entries(fields).forEach(([key, field]) => { actionForm.elements.namedItem(field).value = draft[key]; });
      actionSelector.value = name;
      window.TwnSelectControls?.sync(actionSelector);
      actionForm.querySelector(".eyebrow").textContent = name ? "Edit saved commands" : "Create saved commands";
      actionForm.querySelector("h2").textContent = draft.name || "New saved command set";
      const badge = actionForm.querySelector(".pill");
      if (badge) badge.hidden = true;
      actionForm.querySelector('[value="save_matrix_action"]').textContent = name ? "Save library changes" : "Save to library";
      actionForm.querySelector("[data-ssh-action-delete]").hidden = !name;
      const url = new URL(window.location.href);
      url.searchParams.delete("new_action");
      url.searchParams.set("matrix_action", name);
      if (!name) url.searchParams.set("new_action", "1");
      window.history.replaceState({}, "", url);
      remember();
    };
    actionSelector.addEventListener("change", () => selectAction(actionSelector.value));
    document.querySelector("[data-ssh-new-action]")?.addEventListener("click", () => {
      selectAction("");
      actionForm.elements.namedItem("matrix_action_name").focus();
    });
    document.querySelector('[data-ssh-discard-library]')?.addEventListener('click', () => {
      drafts.clear();
      baseline.forEach((value, key) => drafts.set(key, { ...value }));
      const draft = baseline.get(current) || empty;
      Object.entries(fields).forEach(([key, field]) => { actionForm.elements.namedItem(field).value = draft[key]; });
      remember();
      window.TwnUnsavedForms?.reset(actionForm);
    });
    actionForm.addEventListener("input", remember);
    actionForm.addEventListener("submit", (event) => {
      remember();
      if ([...drafts].some(([key, draft]) => key !== current && changed(key, draft))
        && !window.confirm("Other CLI actions have unsaved drafts. Continue and leave those drafts?")) {
        event.preventDefault();
      }
    });
    actionForm.querySelector("[data-ssh-action-delete]")?.addEventListener("click", (event) => {
      if (!window.confirm(`Delete CLI action “${read().original_name}”?`)) event.preventDefault();
    });
  }

  const actionCommands = document.querySelector("[data-ssh-action-commands]");
  document.querySelector("[data-ssh-action-variable-picker]")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-ssh-variable]");
    if (!button || !actionCommands) return;
    const insertion = `{{ ${button.dataset.sshVariable} }}`;
    const start = actionCommands.selectionStart ?? actionCommands.value.length;
    const end = actionCommands.selectionEnd ?? actionCommands.value.length;
    actionCommands.setRangeText(insertion, start, end, "end");
    actionCommands.focus();
    actionCommands.dispatchEvent(new Event("input", { bubbles: true }));
  });

  const hostForm = document.querySelector("[data-ssh-host-form]");
  const matrixRoot = hostForm?.querySelector("[data-ssh-matrix-editor]");
  let matrixEditor = null;
  if (hostForm && matrixRoot && globalThis.TwnSshMatrixEditor) {
    matrixEditor = globalThis.TwnSshMatrixEditor.create(matrixRoot);
    const hostImport = hostForm.querySelector("[data-ssh-host-import]");
    const hostImportInput = hostImport?.querySelector("[data-ssh-host-import-input]");
    const hostImportMode = hostImport?.querySelector("[data-ssh-host-import-mode]");
    const hostImportButton = hostImport?.querySelector("[data-ssh-host-import-submit]");
    const hostImportError = hostImport?.querySelector("[data-ssh-host-import-error]");
    const setHostImportError = (message = "") => {
      if (!hostImportError) return;
      hostImportError.textContent = message;
      hostImportError.hidden = !message;
    };

    hostImportInput?.addEventListener("input", () => setHostImportError());
    hostImportButton?.addEventListener("click", async () => {
      const hosts = hostImportInput.value.trim();
      if (!hosts) {
        setHostImportError("Enter at least one host or IP range to import.");
        hostImportInput.focus();
        return;
      }
      const originalLabel = hostImportButton.textContent;
      hostImportButton.disabled = true;
      hostImportButton.textContent = "Importing…";
      setHostImportError();
      try {
        const response = await fetch(hostImport.dataset.sshHostImportUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
          body: new URLSearchParams({ hosts }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "The host list could not be imported.");
        matrixEditor.importTargets(payload.targets, {
          replace: hostImportMode.value === "replace",
        });
        hostImportInput.value = "";
        hostImport.open = false;
      } catch (error) {
        setHostImportError(error.message || "The host list could not be imported.");
      } finally {
        hostImportButton.disabled = false;
        hostImportButton.textContent = originalLabel;
      }
    });

    hostForm.addEventListener("submit", (event) => {
      if (event.submitter?.name === "name") return; // Delete does not save editor contents.
      const matrix = hostForm.querySelector("[data-ssh-matrix]");
      if (matrixEditor.mode === "grid") matrixEditor.sync();
      if (matrixEditor.mode === "grid" && !matrixEditor.validate({ focus: true, requireTargets: true })) {
        event.preventDefault();
        return;
      }
      if (matrixEditor.mode === "raw") {
        try {
          matrixEditor.parse(matrix.value);
        } catch (error) {
          event.preventDefault();
          const message = matrixRoot.querySelector("[data-ssh-matrix-error]");
          message.textContent = error.message;
          message.hidden = false;
          matrix.focus();
        }
      }
    });
  }

  document.querySelector("[data-ssh-rename-matrix]")?.addEventListener("click", () => {
    showWorkspace("hosts");
    const name = hostForm?.elements.namedItem("host_matrix_name");
    name?.focus();
    name?.select();
  });

  const copyDialog = document.querySelector("[data-ssh-copy-dialog]");
  const copyName = copyDialog?.querySelector("[data-ssh-copy-name]");
  const copyActions = copyDialog?.querySelector("[data-ssh-copy-actions]");
  let copyKind = null;
  let copyTrigger = null;
  document.querySelectorAll("[data-ssh-copy]").forEach((button) => {
    button.addEventListener("click", () => {
      copyKind = button.dataset.sshCopy;
      copyTrigger = button;
      const source = copyKind === "matrix" ? hostForm : document.querySelector(".multi-ssh-action-editor");
      const name = source.elements.namedItem(copyKind === "matrix" ? "host_matrix_name" : "matrix_action_name");
      copyName.value = `Copy of ${name.value}`.slice(0, 100);
      copyActions.checked = true;
      copyDialog.querySelector("[data-ssh-copy-actions-label]").hidden = copyKind !== "matrix";
      copyDialog.querySelector("[data-ssh-copy-note]").textContent = copyKind === "matrix"
        ? "Copies the current host editor contents into a new local matrix. Saved CLI actions can be included. The original stays unchanged."
        : "Copies the current action editor contents into this matrix's library. The original stays unchanged; nothing runs.";
      copyDialog.showModal();
      copyName.focus();
      copyName.select();
    });
  });
  copyDialog?.querySelector("[data-ssh-copy-cancel]").addEventListener("click", () => copyDialog.close());
  copyDialog?.addEventListener("close", () => copyTrigger?.focus());
  const setHidden = (form, name, value) => {
    let input = form.querySelector(`input[name="${name}"]`);
    if (!input) {
      input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.dataset.unsavedIgnore = "";
      form.append(input);
    }
    input.value = value;
  };
  copyDialog?.querySelector("form").addEventListener("submit", (event) => {
    event.preventDefault();
    const source = copyKind === "matrix" ? hostForm : document.querySelector(".multi-ssh-action-editor");
    setHidden(source, "copy_name", copyName.value.trim());
    setHidden(source, "copy_actions", copyActions.checked ? "on" : "");
    copyDialog.close();
    showWorkspace(copyKind === "matrix" ? "hosts" : "actions");
    // requestSubmit preserves editor validation, serialization and unsaved guards.
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.name = "action";
    submit.value = copyKind === "matrix" ? "save_host_matrix_copy" : "save_matrix_action_copy";
    submit.hidden = true;
    source.append(submit);
    // Finish the dialog submit first so its cancelled event cannot clear the
    // shared unsaved guard's acknowledgement of the real editor submission.
    setTimeout(() => {
      source.requestSubmit(submit);
      submit.remove();
    }, 0);
  });

  const runForm = document.querySelector("[data-multi-ssh]");
  if (!runForm) return;
  const selectedNames = () => [...document.querySelectorAll('[data-ssh-runbook-action] input[name="selected_actions"]')].map((input) => input.value);
  document.querySelectorAll(".multi-ssh-action-editor, .multi-ssh-action-copy-form, [data-ssh-host-form], [data-ssh-action-picker]").forEach((form) => {
    form.addEventListener("submit", () => {
      form.querySelectorAll('[name="selected_actions"]').forEach((input) => input.remove());
      setHidden(form, 'run_steps', runForm.querySelector('[data-ssh-run-steps]')?.value || '');
      setHidden(form, 'inline_draft_commands', document.querySelector('[data-ssh-inline-draft]')?.value || '');
      setHidden(form, 'inline_draft_timeout', document.querySelector('[data-ssh-inline-draft-timeout]')?.value || '300');
      selectedNames().forEach((name) => {
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = "selected_actions";
        input.value = name;
        input.dataset.unsavedIgnore = "";
        form.append(input);
      });
    });
  });
  const token = runForm.querySelector("[data-ssh-preview-token]");
  const status = runForm.querySelector("[data-ssh-preview-status]");
  const confirmation = runForm.querySelector("[data-ssh-run-confirmation]");
  const preview = runForm.querySelector("[data-ssh-preview]");
  const previewButton = runForm.querySelector("[data-ssh-preview-button]");
  const summary = runForm.querySelector("[data-ssh-run-summary]");
  const runbook = document.querySelector("[data-ssh-runbook]");
  const runbookPicker = document.querySelector("[data-ssh-runbook-picker]");
  const runbookAdd = document.querySelector("[data-ssh-runbook-add]");
  const runbookCount = document.querySelector("[data-ssh-runbook-count]");
  const runbookEmpty = document.querySelector("[data-ssh-runbook-empty]");
  const hostCount = Number(runForm.dataset.sshHostCount || 0);

  const reviewContent = runForm.querySelector('[data-ssh-review-content]');
  const connectionContent = runForm.querySelector('[data-ssh-connection-content]') || reviewContent;
  const stepsInput = runForm.querySelector('[data-ssh-run-steps]');
  const inlineDraft = document.querySelector('[data-ssh-inline-draft]');
  const inlineTimeout = document.querySelector('[data-ssh-inline-draft-timeout]');
  const addInline = document.querySelector('[data-ssh-add-inline]');
  const continueReview = document.querySelector('[data-ssh-continue-review]');
  const composerNote = document.querySelector('[data-ssh-composer-note]');
  const finalSummary = runForm.querySelector('[data-ssh-final-summary]');
  const serializeSteps = () => [...(runbook?.querySelectorAll('[data-ssh-runbook-action]') || [])].map((row) =>
    row.dataset.stepSource === 'inline'
      ? { source: 'inline', id: row.dataset.stepId, name: row.dataset.sshRunbookAction,
          commands: row.querySelector('[data-ssh-inline-commands]').value,
          command_timeout: row.querySelector('[data-ssh-inline-timeout]').value }
      : { source: 'saved', name: row.dataset.sshRunbookAction });
  const updateFinalReadiness = () => {
    if (!reviewContent || !runButton) return;
    const count = runbook?.querySelectorAll('[data-ssh-runbook-action]').length || 0;
    const draftPending = Boolean(inlineDraft?.value.trim());
    const libraryPending = actionForm?.dataset.unsavedInitial === 'true';
    const hostsPending = Boolean(window.TwnUnsavedForms?.hasChanges(hostForm));
    const invalidInline = [...(runbook?.querySelectorAll('[data-ssh-inline-timeout]') || [])].some((field) => !field.validity.valid);
    if (inlineTimeout) inlineTimeout.disabled = !draftPending;
    const username = runForm.querySelector('[name=username]');
    const password = runForm.querySelector('[name=password]');
    const port = runForm.querySelector('[name=port]');
    const credentialsPresent = Boolean(username?.value.trim() && password?.value.length);
    let next = !count ? 'Add commands in step 2.'
      : draftPending ? 'Add or clear the typed draft in Commands.'
      : hostsPending ? 'Save host edits in Hosts before reviewing this run.'
      : invalidInline ? 'Correct typed command timeouts in Commands.'
      : libraryPending ? 'Save or discard library edits in Commands.'
      : !token?.value ? 'Command review is not current.'
      : !port?.validity.valid ? 'Enter a valid SSH port.'
      : !credentialsPresent ? 'Enter username and password.'
      : 'Command review is current. Ready to submit; connection checks happen when running.';
    runButton.disabled = !count || draftPending || hostsPending || invalidInline || libraryPending || !token?.value || !port?.validity.valid || !credentialsPresent;
    if (finalSummary) finalSummary.textContent = `${hostCount} host(s) · ${count} command set(s). ${next}`;
    if (addInline) addInline.disabled = !draftPending;
    if (continueReview) continueReview.disabled = !count || draftPending || invalidInline;
    if (composerNote) composerNote.textContent = invalidInline ? 'Correct the timeout in the selected typed commands (1–3600 seconds).' : draftPending ? 'Typed draft is not in this run yet. Click Add typed commands.' : '';
  };
  const runButton = runForm.querySelector('[data-ssh-run-button]');
  let reviewGeneration = 0;
  let reviewTimer;
  const choicesState = runForm.querySelector('[data-ssh-choices-state]');
  const readChoices = () => JSON.stringify([...runForm.querySelectorAll(
    '[name="unknown_key_hosts"]:checked, [name="legacy_algorithm_hosts"]:checked')]
    .map((field) => [field.name, field.value]));
  const initialChoices = readChoices();
  const runbookState = runForm.querySelector('[data-ssh-runbook-state]');
  const initialRunbook = JSON.stringify(selectedNames());
  const syncChoiceGroups = () => {
    if (choicesState) {
      const current = readChoices();
      choicesState.value = current === initialChoices ? '' : current;
    }
    const choiceSummary = connectionContent?.querySelector('[data-ssh-choice-summary]');
    if (choiceSummary) {
      const unknown = connectionContent.querySelectorAll('[name="unknown_key_hosts"]:checked').length;
      const legacy = connectionContent.querySelectorAll('[name="legacy_algorithm_hosts"]:checked').length;
      const total = connectionContent.querySelectorAll('[name="unknown_key_hosts"]').length;
      choiceSummary.textContent = `Unrecognized keys: ${unknown}/${total} hosts · Legacy algorithms: ${legacy}/${total} hosts.`;
    }
    connectionContent?.querySelectorAll('[data-ssh-choice-all]').forEach((all) => {
      const fields = [...connectionContent.querySelectorAll(`input[name="${all.dataset.sshChoiceAll}"]`)];
      const checked = fields.filter((field) => field.checked).length;
      all.checked = fields.length > 0 && checked === fields.length;
      all.indeterminate = checked > 0 && checked < fields.length;
    });
  };
  connectionContent?.addEventListener('change', (event) => {
    const all = event.target.closest('[data-ssh-choice-all]');
    if (all) connectionContent.querySelectorAll(`input[name="${all.dataset.sshChoiceAll}"]`)
      .forEach((field) => { field.checked = all.checked; });
    syncChoiceGroups();
  });
  const refreshReview = async () => {
    if (!reviewContent) return; // Preserve the direct/legacy submission flow.
    const generation = ++reviewGeneration;
    const body = new FormData(runForm);
    // Review only resolves saved commands locally. Never send credentials or
    // connection permissions as part of an automatic review request.
    ['username', 'password', 'confirm_execution', 'unknown_key_hosts',
      'legacy_algorithm_hosts', 'allow_unknown_hosts', 'allow_legacy_algorithms',
      'per_host_options', 'connection_choices_draft', 'runbook_draft', 'preview_token', 'inline_draft_commands', 'inline_draft_timeout'].forEach((name) => body.delete(name));
    body.set('action', 'preview');
    if (token) token.value = '';
    if (runButton) runButton.disabled = true;
    updateFinalReadiness();
    status.hidden = false;
    status.textContent = 'Preparing command review…';
    try {
      const response = await fetch(runForm.getAttribute('action') || window.location.href, {
        method: 'POST', body, headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(15000),
      });
      if (!response.headers.get('content-type')?.includes('application/json')) {
        throw new Error('The server did not return a review. Check your session.');
      }
      const payload = await response.json();
      if (generation !== reviewGeneration) return;
      if (!response.ok) throw new Error(payload.error || 'Unable to prepare review.');
      // Carry only the user's current, explicit choices for unchanged host names.
      const choices = [...connectionContent.querySelectorAll('input[type=checkbox]:checked')]
        .map((input) => [input.name, input.value]);
      const overridesOpen = connectionContent.querySelector('[data-ssh-host-overrides]')?.open || false;
      reviewContent.innerHTML = payload.html;
      connectionContent.innerHTML = payload.connection_html;
      const overrides = connectionContent.querySelector('[data-ssh-host-overrides]');
      if (overrides) overrides.open = overridesOpen;
      connectionContent.querySelectorAll('input[type=checkbox]').forEach((input) => {
        input.checked = choices.some(([name, host]) => name === input.name && host === input.value);
      });
      token.value = payload.token;
      status.textContent = 'Command review is current.';
      updateRunSummary();
      syncChoiceGroups();
      updateFinalReadiness();
    } catch (error) {
      if (generation !== reviewGeneration) return;
      status.textContent = `${error.message} Use Refresh command review to retry. Nothing has run.`;
      updateFinalReadiness();
    }
  };
  const markPreviewStale = () => {
    if (!reviewContent) {
      if (token) token.value = '';
      if (confirmation) confirmation.hidden = true;
      return;
    }
    ++reviewGeneration; // Reject an older response even before the next request.
    if (token) token.value = '';
    if (runButton) runButton.disabled = true;
    updateFinalReadiness();
    status.hidden = false;
    status.textContent = 'Commands changed — updating review…';
    clearTimeout(reviewTimer);
    if (runbook?.querySelector('[data-ssh-runbook-action]')) {
      reviewTimer = setTimeout(refreshReview, 150);
    } else {
      // Removing the last action cancels this draft plan and its exceptions.
      reviewContent.textContent = 'No commands selected. Return to Commands to add them.';
      connectionContent.textContent = 'Connection choices appear after commands are prepared.';
      syncChoiceGroups();
      status.textContent = 'Add commands in step 2. Nothing has run.';
      updateFinalReadiness();
    }
  };

  runForm.querySelector('[name="port"]')?.addEventListener('input', () => {
    if (!reviewContent) return;
    connectionContent.querySelectorAll('input[type=checkbox]').forEach((input) => { input.checked = false; });
    syncChoiceGroups();
    markPreviewStale();
  });

  const updateRunSummary = () => {
    // Direct/legacy previews have no runbook; their refresh stays available.
    if (!runbook) return;
    const rows = [...(runbook?.querySelectorAll("[data-ssh-runbook-action]") || [])];
    const selected = rows.length;
    if (stepsInput) stepsInput.value = JSON.stringify(serializeSteps());
    if (runbookState) {
      const current = JSON.stringify(rows.map((row) => row.dataset.sshRunbookAction));
      runbookState.value = current === initialRunbook ? '' : current;
    }
    rows.forEach((row, index) => {
      row.querySelector("[data-ssh-runbook-number]").textContent = String(index + 1);
      const up = row.querySelector('[data-ssh-runbook-move="up"]');
      const down = row.querySelector('[data-ssh-runbook-move="down"]');
      if (up) up.disabled = index === 0;
      if (down) down.disabled = index === rows.length - 1;
    });
    const selectedNames = new Set(rows.filter((row) => row.dataset.stepSource !== 'inline').map((row) => row.dataset.sshRunbookAction));
    [...(runbookPicker?.options || [])].forEach((option) => {
      if (option.value) option.disabled = selectedNames.has(option.value);
    });
    previewButton.disabled = selected === 0;
    if (runbookCount) runbookCount.textContent = `${selected} command set${selected === 1 ? "" : "s"}`;
    if (runbookEmpty) runbookEmpty.hidden = selected > 0;
    const currentSummary = runForm.querySelector('[data-ssh-run-summary]');
    if (currentSummary) {
      currentSummary.textContent = selected
        ? `${hostCount} host(s) · ${selected} command set(s)`
        : "Add commands in step 2 to prepare this run.";
    }
    updateFinalReadiness();
  };

  const buildRunbookRow = (option) => {
    const row = document.createElement("article");
    row.className = "multi-ssh-runbook-row";
    row.dataset.sshRunbookAction = option.value;
    row.dataset.stepSource = 'saved';

    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "selected_actions";
    input.setAttribute('form', 'multi-ssh-run-form');
    input.dataset.unsavedIgnore = "";
    input.value = option.value;

    const number = document.createElement("span");
    number.className = "multi-ssh-action-number";
    number.dataset.sshRunbookNumber = "";

    const description = document.createElement("span");
    const name = document.createElement("strong");
    name.textContent = option.value;
    const variables = document.createElement("small");
    variables.textContent = option.dataset.variables === "No custom variables"
      ? option.dataset.variables
      : `Uses ${option.dataset.variables}`;
    description.append(name, variables);

    const readiness = document.createElement("span");
    readiness.className = "pill";
    readiness.textContent = "Selected";

    const controls = document.createElement("span");
    controls.className = "button-row compact-actions";
    [
      ["↑", "up", `Move ${option.value} up`],
      ["↓", "down", `Move ${option.value} down`],
    ].forEach(([text, direction, label]) => {
      const button = document.createElement("button");
      button.className = "secondary compact";
      button.type = "button";
      button.dataset.sshRunbookMove = direction;
      button.setAttribute('form', 'multi-ssh-run-form');
      button.setAttribute("aria-label", label);
      button.textContent = text;
      controls.append(button);
    });
    const remove = document.createElement("button");
    remove.className = "danger compact";
    remove.type = "button";
    remove.dataset.sshRunbookRemove = "";
    remove.setAttribute('form', 'multi-ssh-run-form');
    remove.setAttribute("aria-label", `Remove ${option.value} from run`);
    remove.textContent = "Remove";
    controls.append(remove);

    row.append(input, number, description, readiness, controls);
    return row;
  };

  runbookPicker?.addEventListener("change", () => {
    const option = runbookPicker.selectedOptions[0];
    if (runbookAdd) runbookAdd.disabled = !option?.value || option.disabled;
  });
  runbookAdd?.addEventListener("click", () => {
    const option = runbookPicker?.selectedOptions[0];
    if (!option?.value || option.disabled || !runbook) return;
    runbook.insertBefore(buildRunbookRow(option), runbookEmpty || null);
    runbookPicker.value = "";
    runbookAdd.disabled = true;
    const added = runbook.querySelector('[data-ssh-runbook-action]:last-of-type');
    if (added) { added.tabIndex = -1; added.focus(); }
    markPreviewStale();
    updateRunSummary();
  });
  runbook?.addEventListener("click", (event) => {
    const row = event.target.closest("[data-ssh-runbook-action]");
    if (!row) return;
    let focusAfter = null;
    if (event.target.closest("[data-ssh-runbook-remove]")) {
      focusAfter = row.nextElementSibling?.querySelector('[data-ssh-runbook-remove]') || row.previousElementSibling?.querySelector('[data-ssh-runbook-remove]') || runbookPicker;
      row.remove();
    } else {
      const move = event.target.closest("[data-ssh-runbook-move]");
      if (!move) return;
      focusAfter = move;
      const rows = [...runbook.querySelectorAll("[data-ssh-runbook-action]")];
      const index = rows.indexOf(row);
      if (move.dataset.sshRunbookMove === "up" && index > 0) {
        runbook.insertBefore(row, rows[index - 1]);
      } else if (move.dataset.sshRunbookMove === "down" && index < rows.length - 1) {
        rows[index + 1].after(row);
      } else {
        return;
      }
    }
    markPreviewStale();
    updateRunSummary();
    if (focusAfter?.disabled) focusAfter = row.querySelector('[data-ssh-runbook-move]:not(:disabled)') || row.querySelector('[data-ssh-runbook-remove]');
    focusAfter?.focus();
  });
  let inlineSequence = 0;
  addInline?.addEventListener('click', () => {
    if (!inlineDraft?.value.trim() || !runbook) return;
    if (inlineTimeout && !inlineTimeout.validity.valid) {
      inlineTimeout.closest('details').open = true;
      inlineTimeout.reportValidity();
      return;
    }
    const names = new Set([...runbook.querySelectorAll('[data-ssh-runbook-action]')].map((row) => row.dataset.sshRunbookAction));
    do { ++inlineSequence; } while (names.has(`Typed commands ${inlineSequence}`));
    const option = { value: `Typed commands ${inlineSequence}`, dataset: { variables: 'This run only' } };
    const row = buildRunbookRow(option);
    row.dataset.stepSource = 'inline';
    row.dataset.stepId = crypto.randomUUID();
    row.querySelector('input[name="selected_actions"]').remove();
    row.querySelector('small').textContent = 'Typed · this run only';
    const details = document.createElement('details');
    details.className = 'multi-ssh-inline-fields';
    const heading = document.createElement('summary');
    heading.textContent = 'Edit typed commands';
    const fields = document.createElement('div');
    fields.className = 'form';
    const commandsLabel = document.createElement('label');
    commandsLabel.textContent = `Commands for ${option.value}`;
    const commands = document.createElement('textarea');
    commands.rows = 5;
    commands.dataset.sshInlineCommands = '';
    commands.dataset.unsavedIgnore = '';
    commands.setAttribute('form', 'multi-ssh-run-form');
    commands.value = inlineDraft.value;
    commandsLabel.append(commands);
    const timeoutLabel = document.createElement('label');
    timeoutLabel.textContent = 'Timeout per command (seconds)';
    const timeout = document.createElement('input');
    Object.assign(timeout, { type: 'number', min: '1', max: '3600', value: inlineTimeout?.value || '300' });
    timeout.dataset.sshInlineTimeout = '';
    timeout.dataset.unsavedIgnore = '';
    timeout.setAttribute('form', 'multi-ssh-run-form');
    timeoutLabel.append(timeout);
    fields.append(commandsLabel, timeoutLabel);
    details.append(heading, fields);
    row.append(details);
    runbook.insertBefore(row, runbookEmpty || null);
    inlineDraft.value = '';
    if (inlineTimeout) inlineTimeout.value = '300';
    markPreviewStale();
    updateRunSummary();
    row.tabIndex = -1;
    row.focus();
  });
  document.querySelector('[data-ssh-discard-inline]')?.addEventListener('click', () => {
    inlineDraft.value = '';
    if (inlineTimeout) inlineTimeout.value = '300';
    updateFinalReadiness();
    inlineDraft.focus();
  });
  continueReview?.addEventListener('click', () => {
    if (continueReview.disabled) return;
    showWorkspace('run');
    document.querySelector('[data-ssh-workspace-tab="run"]')?.focus();
    updateFinalReadiness();
  });
  runbook?.addEventListener('input', () => {
    updateRunSummary();
    markPreviewStale();
  });
  document.addEventListener('input', (event) => {
    if (event.target.form === runForm || event.target.form === hostForm) updateFinalReadiness();
  });
  document.addEventListener('twn:ssh-library-draft', updateFinalReadiness);
  document.addEventListener('twn:ssh-workspace', updateFinalReadiness);
  updateRunSummary();
  if (reviewContent && runbook?.querySelector('[data-ssh-runbook-action]')) refreshReview();

  runForm.addEventListener("submit", (event) => {
    const action = event.submitter?.value;
    if (action === 'preview' && reviewContent) {
      event.preventDefault();
      clearTimeout(reviewTimer);
      refreshReview();
      return;
    }
    if (action === 'run' && reviewContent && runButton?.disabled) {
      event.preventDefault();
      status.textContent = 'Wait for a current review before running.';
      return;
    }
    if (["preview", "run"].includes(action) && runbook && !runbook.querySelector("[data-ssh-runbook-action]")) {
      event.preventDefault();
      summary?.scrollIntoView({ block: "nearest" });
      return;
    }
    if (action === "run") {
      runForm.dataset.loadingMessage = "Running previewed SSH actions…";
      return;
    }
    if (confirmation) {
      confirmation.querySelectorAll('[name="username"], [name="password"]').forEach((control) => {
        control.disabled = true;
      });
    }
    delete runForm.dataset.loadingMessage;
  });
})();
